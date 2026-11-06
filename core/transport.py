"""Transport helpers: rate limiting, retry configuration, and response size limits.

Separates concurrency (max in-flight requests) from rate limiting (requests per second).
Provides Retry-After header parsing and exponential backoff with cap.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime


@dataclass
class RetryConfig:
    """Retry configuration for HTTP requests.

    Attributes:
        max_retries: Maximum retry attempts for 429/503 and transient errors.
        backoff_base: Base for exponential backoff (2^attempt).
        max_wait: Maximum wait time in seconds for any single retry.
    """

    max_retries: int = 3
    backoff_base: int = 2
    max_wait: float = 30.0


@dataclass
class TransportConfig:
    """Transport configuration for HTTP requests.

    Attributes:
        timeout_total: Overall request timeout in seconds.
        timeout_connect: Connection establishment timeout in seconds.
        sock_read: Socket read timeout in seconds.
        max_response_size: Maximum response body size in bytes.
    """

    timeout_total: int = 20
    timeout_connect: int = 10
    sock_read: int = 10
    max_response_size: int = 10 * 1024 * 1024


class RateLimiter:
    """Token bucket rate limiter for requests per second.

    Tokens are replenished at rate ``rps`` per second. Each request consumes
    one token. If no token is available, the caller waits until one is.
    """

    def __init__(self, rps: float) -> None:
        """Initialize the rate limiter.

        Args:
            rps: Maximum requests per second (must be positive).

        Raises:
            ValueError: If rps is not positive.
        """
        if rps <= 0:
            raise ValueError(f"rps must be positive, got {rps}")
        self._rps = rps
        self._tokens = rps
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rps, self._tokens + elapsed * self._rps)
            self._last_refill = now

            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rps
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


def parse_retry_after(header_value: str) -> float | None:
    """Parse Retry-After header value.

    Supports both integer (seconds) and HTTP-date formats per RFC 7231.

    Args:
        header_value: The Retry-After header value.

    Returns:
        Wait time in seconds, or None if the value is malformed.
    """
    try:
        seconds = int(header_value)
        return float(seconds) if seconds >= 0 else None
    except ValueError:
        pass

    try:
        dt = parsedate_to_datetime(header_value)
        if dt is not None:
            wait = dt.timestamp() - time.time()
            return max(0.0, wait)
    except (TypeError, ValueError):
        pass

    return None


def compute_backoff(
    attempt: int,
    config: RetryConfig,
    retry_after: float | None = None,
) -> float:
    """Compute backoff wait time for a retry attempt.

    If ``retry_after`` is provided (from a 429/503 response), it takes
    precedence over exponential backoff. The result is capped at
    ``config.max_wait``.

    Args:
        attempt: Zero-based attempt number.
        config: Retry configuration.
        retry_after: Parsed Retry-After header value, if available.

    Returns:
        Wait time in seconds.
    """
    if retry_after is not None:
        return min(retry_after, config.max_wait)
    return min(float(config.backoff_base**attempt), config.max_wait)
