"""Shared fixtures. RSA generation is expensive, so the happy-path client is reused."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from tests.helpers import open_client


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    test_client = open_client()
    try:
        yield test_client
    finally:
        test_client.__exit__(None, None, None)


@pytest.fixture
def fresh_client() -> Iterator[TestClient]:
    test_client = open_client()
    try:
        yield test_client
    finally:
        test_client.__exit__(None, None, None)
