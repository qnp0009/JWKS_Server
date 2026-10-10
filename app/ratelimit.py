"""Per-client request limit.

Each client address may send ``limit`` requests inside a rolling one-second
window. A limit of zero turns the check off.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
Clock = Callable[[], float]


class SlidingWindowLimiter:
    """Allow up to ``limit`` hits per key during the last ``window_seconds``."""

    def __init__(self, limit: int, window_seconds: float = 1.0, clock: Clock | None = None) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> tuple[bool, int, float]:
        """Return whether the hit is allowed, how many remain, and seconds to wait."""
        if self.limit <= 0:
            return True, 0, 0.0
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            self._drop_expired(cutoff)
            hits = self._hits.setdefault(key, deque())
            if len(hits) >= self.limit:
                retry_after = self.window_seconds - (now - hits[0])
                return False, 0, max(retry_after, 0.0)
            hits.append(now)
            return True, self.limit - len(hits), 0.0

    def _drop_expired(self, cutoff: float) -> None:
        stale: list[str] = []
        for key, hits in self._hits.items():
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if not hits:
                stale.append(key)
        for key in stale:
            del self._hits[key]


class RateLimitMiddleware:
    """Reject HTTP requests that exceed the configured per-address limit."""

    def __init__(self, app: Callable, limiter: SlidingWindowLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.limiter.limit <= 0:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        key = client[0] if client else "unknown"
        allowed, remaining, retry_after = self.limiter.allow(key)
        if not allowed:
            await _send_limited(send, self.limiter.limit, retry_after)
            return
        limit = str(self.limiter.limit).encode("ascii")
        left = str(remaining).encode("ascii")

        async def send_with_limit(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-ratelimit-limit", limit))
                headers.append((b"x-ratelimit-remaining", left))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_limit)


async def _send_limited(send: Send, limit: int, retry_after: float) -> None:
    body = json.dumps({"detail": "Rate limit exceeded. Try again later."}).encode("utf-8")
    wait = str(max(1, math.ceil(retry_after))).encode("ascii")
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", wait),
                (b"x-ratelimit-limit", str(limit).encode("ascii")),
                (b"x-ratelimit-remaining", b"0"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
