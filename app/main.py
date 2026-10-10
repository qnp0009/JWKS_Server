"""Application factory and background key rotation."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import admin_router, public_router, token_router
from app.config import Settings
from app.keys import KeyManager
from app.ratelimit import RateLimitMiddleware, SlidingWindowLimiter
from app.stores import build_store

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application. Key generation runs during startup."""
    settings = settings or Settings()
    app = FastAPI(
        title="JWKS Server",
        version=__version__,
        summary="Publish a JSON Web Key Set and sign JSON Web Tokens.",
        description=(
            "Generates RSA signing keys, publishes the active public keys, and "
            "issues RS256 JWTs. Pending, expired, and revoked keys are left out "
            "of the JWKS document. Token requests can mint an already-expired "
            "token, or sign with a key that is not active yet or has expired."
        ),
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.manager = KeyManager(build_store(settings), settings)
    app.state.limiter = SlidingWindowLimiter(settings.rate_limit_per_second)
    origins = [item.strip() for item in settings.cors_origins.split(",") if item.strip()]
    # Added first so CORS stays outermost and can annotate a 429 response.
    app.add_middleware(RateLimitMiddleware, limiter=app.state.limiter)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins or ["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        expose_headers=["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )
    app.include_router(public_router)
    app.include_router(token_router)
    app.include_router(admin_router)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": "jwks",
            "jwks_uri": "/.well-known/jwks.json",
            "token_endpoint": "/auth",
            "docs": "/docs",
        }

    return app


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    manager: KeyManager = app.state.manager
    _log_startup(settings)
    manager.bootstrap()
    logger.info(
        "JWKS server ready backend=%s active_keys=%d rate_limit_per_second=%d",
        settings.storage_backend,
        manager.active_count(),
        settings.rate_limit_per_second,
    )
    stop = asyncio.Event()
    task: asyncio.Task[None] | None = None
    if settings.auto_rotate:
        task = asyncio.create_task(
            _rotation_loop(manager, settings.rotation_interval_seconds, stop),
            name="jwks-rotation",
        )
    try:
        yield
    finally:
        stop.set()
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def _rotation_loop(manager: KeyManager, interval: int, stop: asyncio.Event) -> None:
    """Sleep for one rotation interval, then publish a new key when the newest is old enough."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            if stop.is_set():
                return
            try:
                await asyncio.to_thread(manager.rotate_if_due)
            except Exception:
                logger.exception("Automatic key rotation failed")
            continue
        return


def _log_startup(settings: Settings) -> None:
    if not settings.admin_api_key:
        logger.warning(
            "JWKS_ADMIN_API_KEY is empty. Token issuance and key management are "
            "unauthenticated. Set a secret before exposing this process beyond localhost."
        )
    if settings.auto_rotate and settings.rotation_interval_seconds >= settings.key_lifetime_seconds:
        logger.warning(
            "Rotation interval is at least as long as the key lifetime. Keep the "
            "interval shorter so the previous public key stays in JWKS while tokens "
            "signed with it are still valid."
        )
