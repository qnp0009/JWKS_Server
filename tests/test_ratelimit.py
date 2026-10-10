"""Per-address limit of 10 requests in a rolling second."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.ratelimit import SlidingWindowLimiter
from tests.helpers import make_settings, open_client


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_eleven_requests_in_one_second_are_rejected() -> None:
    client = open_client(make_settings(admin_api_key="", rate_limit_per_second=10))
    try:
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200
            assert response.headers["x-ratelimit-limit"] == "10"
        blocked = client.get("/health")
        assert blocked.status_code == 429
        assert blocked.json()["detail"] == "Rate limit exceeded. Try again later."
        assert blocked.headers["x-ratelimit-limit"] == "10"
        assert blocked.headers["x-ratelimit-remaining"] == "0"
        assert int(blocked.headers["retry-after"]) >= 1
    finally:
        client.__exit__(None, None, None)


def test_window_reopens_and_clients_have_separate_budgets() -> None:
    clock = _Clock()
    limiter = SlidingWindowLimiter(10, clock=clock)
    for _ in range(10):
        allowed, remaining, _ = limiter.allow("10.0.0.1")
        assert allowed
    assert remaining == 0
    allowed, _, retry_after = limiter.allow("10.0.0.1")
    assert not allowed
    assert retry_after > 0
    other, other_remaining, _ = limiter.allow("10.0.0.2")
    assert other
    assert other_remaining == 9
    clock.now += 1
    allowed, remaining, _ = limiter.allow("10.0.0.1")
    assert allowed
    assert remaining == 9


def test_disabled_limit_accepts_every_request() -> None:
    with TestClient(open_app()) as client:
        for _ in range(12):
            assert client.get("/health").status_code == 200


def open_app():
    from app.main import create_app

    return create_app(make_settings(admin_api_key=""))
