"""Key persistence.

Three backends share one interface:

* memory — lost when the process exits
* file — a JSON document containing PEM key material
* sqlite — a local database file

File and sqlite are safe for a single server process. Run one worker;
multiple processes need an external database and a distributed lock.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import Settings
from app.crypto import validate_keypair
from app.models import KeyRecord


class StoreError(Exception):
    """Raised when a key store cannot be read or written."""


class MemoryKeyStore:
    """Process-local map of key id to key record."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, KeyRecord] = {}

    def list_keys(self) -> list[KeyRecord]:
        with self._lock:
            return list(self._records.values())

    def get(self, kid: str) -> KeyRecord | None:
        with self._lock:
            return self._records.get(kid)

    def upsert(self, record: KeyRecord) -> None:
        _require_valid_pair(record)
        with self._lock:
            self._records[record.kid] = record


class FileKeyStore:
    """JSON file store. Writes are replaced atomically in the same directory."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._records: dict[str, KeyRecord] = {}
        self._load()

    def list_keys(self) -> list[KeyRecord]:
        with self._lock:
            return list(self._records.values())

    def get(self, kid: str) -> KeyRecord | None:
        with self._lock:
            return self._records.get(kid)

    def upsert(self, record: KeyRecord) -> None:
        _require_valid_pair(record)
        with self._lock:
            self._records[record.kid] = record
            self._write()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise StoreError(f"Key store is not valid JSON: {self._path}") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise StoreError(f"Unsupported key store version in {self._path}")
        items = raw.get("keys")
        if not isinstance(items, list):
            raise StoreError(f"Key store is missing a keys array: {self._path}")
        loaded: dict[str, KeyRecord] = {}
        for item in items:
            if not isinstance(item, dict):
                raise StoreError(f"Key store entry is not an object: {self._path}")
            try:
                record = KeyRecord.from_dict(item)
                _require_valid_pair(record)
            except (KeyError, TypeError, ValueError, StoreError) as exc:
                raise StoreError(f"Key store entry is invalid: {self._path}") from exc
            if record.kid in loaded:
                raise StoreError(f"Duplicate key id '{record.kid}' in {self._path}")
            loaded[record.kid] = record
        self._records = loaded

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "keys": [record.to_dict() for record in self._records.values()],
        }
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self._path)
        _restrict_private_file(self._path)


class SqliteKeyStore:
    """SQLite store. The private key is a column in the keys table."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    kid TEXT PRIMARY KEY,
                    alg TEXT NOT NULL,
                    private_pem TEXT NOT NULL,
                    public_pem TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL
                )
                """
            )
        _restrict_private_file(self._path)

    def list_keys(self) -> list[KeyRecord]:
        with self._lock, self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM keys ORDER BY created_at ASC"
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def get(self, kid: str) -> KeyRecord | None:
        with self._lock, self._session() as connection:
            row = connection.execute("SELECT * FROM keys WHERE kid = ?", (kid,)).fetchone()
        if row is None:
            return None
        return _row_to_record(row)

    def upsert(self, record: KeyRecord) -> None:
        _require_valid_pair(record)
        payload = record.to_dict()
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT INTO keys (
                    kid, alg, private_pem, public_pem, created_at, not_before, expires_at, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(kid) DO UPDATE SET
                    alg = excluded.alg,
                    private_pem = excluded.private_pem,
                    public_pem = excluded.public_pem,
                    created_at = excluded.created_at,
                    not_before = excluded.not_before,
                    expires_at = excluded.expires_at,
                    revoked = excluded.revoked
                """,
                (
                    payload["kid"],
                    payload["alg"],
                    payload["private_pem"],
                    payload["public_pem"],
                    payload["created_at"],
                    payload["not_before"],
                    payload["expires_at"],
                    1 if record.revoked else 0,
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def build_store(settings: Settings) -> MemoryKeyStore | FileKeyStore | SqliteKeyStore:
    """Construct the store selected by ``JWKS_STORAGE_BACKEND``."""
    if settings.storage_backend == "memory":
        return MemoryKeyStore()
    path = settings.resolved_storage_path()
    if settings.storage_backend == "file":
        return FileKeyStore(path)
    if settings.storage_backend == "sqlite":
        return SqliteKeyStore(path)
    raise StoreError(f"Unsupported storage backend '{settings.storage_backend}'")


def _require_valid_pair(record: KeyRecord) -> None:
    try:
        validate_keypair(record.private_pem, record.public_pem)
    except ValueError as exc:
        raise StoreError(str(exc)) from exc


def _row_to_record(row: sqlite3.Row) -> KeyRecord:
    try:
        record = KeyRecord.from_dict(dict(row))
        _require_valid_pair(record)
    except (KeyError, TypeError, ValueError, StoreError) as exc:
        raise StoreError("A row in the key database is invalid") from exc
    return record


def _restrict_private_file(path: Path) -> None:
    """Best-effort owner-only permissions. Windows ACLs are left unchanged."""
    if os.name != "posix" or not path.exists():
        return
    os.chmod(path, 0o600)
