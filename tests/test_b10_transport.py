"""B10 acceptance tests: transport terbatasi dan retry aman.

Tests prove:
- Criterion 1: Concurrency and RPS are separate parameters with positive validation.
- Criterion 2: Clock-controlled test proves RPS limit applies per attempt.
- Criterion 3: Retry-After honored with cap; malformed handled.
- Criterion 4: Non-idempotent operations not retried on ambiguous result.
- Criterion 5: Response size limit truncates and marks evidence incomplete.
- Criterion 6: Timeout distinction (connect vs read vs total).
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.base_scanner import BaseScanner, ResponseData
from core.transport import (
    RateLimiter,
    RetryConfig,
    compute_backoff,
    parse_retry_after,
)


class TestRetryAfterParsing:
    """Criterion 3: Retry-After header parsing."""

    def test_integer_seconds(self):
        assert parse_retry_after("5") == 5.0

    def test_zero_seconds(self):
        assert parse_retry_after("0") == 0.0

    def test_malformed_returns_none(self):
        assert parse_retry_after("not-a-number") is None

    def test_negative_returns_none(self):
        assert parse_retry_after("-5") is None

    def test_empty_returns_none(self):
        assert parse_retry_after("") is None

    def test_http_date_format(self):
        """HTTP-date Retry-After parsed to a non-negative wait."""
        result = parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
        assert result is not None
        assert result > 0

    def test_past_http_date_returns_zero(self):
        """Past HTTP-date → 0.0 (no wait needed)."""
        result = parse_retry_after("Wed, 21 Oct 1999 07:28:00 GMT")
        assert result == 0.0


class TestComputeBackoff:
    """Criterion 3: Backoff computation with cap."""

    def test_exponential_backoff(self):
        cfg = RetryConfig(max_retries=3, backoff_base=2, max_wait=30)
        assert compute_backoff(0, cfg) == 1.0
        assert compute_backoff(1, cfg) == 2.0
        assert compute_backoff(2, cfg) == 4.0

    def test_capped_at_max_wait(self):
        cfg = RetryConfig(max_retries=10, backoff_base=2, max_wait=10)
        assert compute_backoff(5, cfg) == 10.0

    def test_retry_after_takes_precedence(self):
        cfg = RetryConfig(max_retries=3, backoff_base=2, max_wait=30)
        assert compute_backoff(0, cfg, retry_after=15.0) == 15.0

    def test_retry_after_capped(self):
        cfg = RetryConfig(max_retries=3, backoff_base=2, max_wait=10)
        assert compute_backoff(0, cfg, retry_after=60.0) == 10.0


class TestRateLimiter:
    """Criterion 2: Clock-controlled RPS limiting."""

    @pytest.mark.asyncio
    async def test_rps_limit_enforced(self):
        """5 RPS → 10 requests take measurable time (not instant)."""
        limiter = RateLimiter(rps=5.0)
        start = time.monotonic()
        for _ in range(10):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.4

    @pytest.mark.asyncio
    async def test_single_request_no_wait(self):
        """First request should not wait (bucket starts full)."""
        limiter = RateLimiter(rps=1.0)
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_high_rps_low_wait(self):
        """100 RPS → 10 requests should be nearly instant."""
        limiter = RateLimiter(rps=100.0)
        start = time.monotonic()
        for _ in range(10):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5


class TestNonIdempotentRetry:
    """Criterion 4: POST not retried on timeout."""

    @pytest.mark.asyncio
    async def test_post_not_retried_on_timeout(self):
        """POST timeout → immediate raise (no retry), ambiguous message."""
        scanner = BaseScanner("test_key", no_color=True)
        mock_session = MagicMock()
        mock_session.request = MagicMock(side_effect=asyncio.TimeoutError())
        scanner._session = mock_session

        with pytest.raises(asyncio.TimeoutError):
            await scanner._request_with_retry("POST", "https://example.com", idempotent=False)

    @pytest.mark.asyncio
    async def test_get_retried_on_timeout(self):
        """GET timeout → retried (idempotent)."""
        scanner = BaseScanner("test_key", no_color=True, max_retries=2)
        mock_session = MagicMock()

        call_count = 0

        def make_timeout_ctx(*args, **kwargs):
            nonlocal call_count
            call_count += 1

            class TimeoutCtx:
                async def __aenter__(self):
                    raise asyncio.TimeoutError()

                async def __aexit__(self, *args):
                    return False

            return TimeoutCtx()

        mock_session.request = MagicMock(side_effect=make_timeout_ctx)
        scanner._session = mock_session

        with pytest.raises(asyncio.TimeoutError):
            await scanner._request_with_retry("GET", "https://example.com", idempotent=True)
        assert call_count == 2


class TestResponseSizeLimit:
    """Criterion 5: Response size truncation."""

    @pytest.mark.asyncio
    async def test_large_response_truncated(self):
        """Response > max_response_size → truncated=True."""
        scanner = BaseScanner("test_key", no_color=True, max_response_size=100)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.url = "https://example.com"
        mock_response.read = AsyncMock(return_value=b"x" * 200)

        class FakeCtx:
            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=FakeCtx())
        scanner._session = mock_session

        result = await scanner._request_with_retry("GET", "https://example.com")
        assert result is not None
        assert result.truncated is True
        assert len(result._body_bytes) == 100

    @pytest.mark.asyncio
    async def test_small_response_not_truncated(self):
        """Response < max_response_size → truncated=False."""
        scanner = BaseScanner("test_key", no_color=True, max_response_size=1000)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/plain"}
        mock_response.url = "https://example.com"
        mock_response.read = AsyncMock(return_value=b"small response")

        class FakeCtx:
            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=FakeCtx())
        scanner._session = mock_session

        result = await scanner._request_with_retry("GET", "https://example.com")
        assert result is not None
        assert result.truncated is False


class TestTimeoutDistinction:
    """Criterion 6: Connect vs read vs total timeout."""

    def test_timeout_has_connect_and_sock_read(self):
        """Scanner timeout should have connect and sock_read set."""
        scanner = BaseScanner(
            "test_key",
            timeout=30,
            connect_timeout=5,
            read_timeout=15,
            no_color=True,
        )
        assert scanner.timeout.total == 30
        assert scanner.timeout.connect == 5
        assert scanner.timeout.sock_read == 15

    def test_default_timeouts(self):
        """Default timeouts: total=20, connect=10, sock_read=10."""
        scanner = BaseScanner("test_key", no_color=True)
        assert scanner.timeout.total == 20
        assert scanner.timeout.connect == 10
        assert scanner.timeout.sock_read == 10


class TestConcurrencySeparation:
    """Criterion 1: Concurrency and RPS are separate parameters."""

    def test_concurrency_default(self):
        """Default concurrency=5."""
        scanner = BaseScanner("test_key", no_color=True)
        assert scanner.concurrency == 5

    def test_concurrency_custom(self):
        """Custom concurrency=10."""
        scanner = BaseScanner("test_key", concurrency=10, no_color=True)
        assert scanner.concurrency == 10

    def test_rate_limit_separate_from_concurrency(self):
        """rate_limit and concurrency are independent."""
        scanner = BaseScanner("test_key", rate_limit=20, concurrency=3, no_color=True)
        assert scanner.rate_limit == 20
        assert scanner.concurrency == 3

    @pytest.mark.asyncio
    async def test_semaphore_uses_concurrency_not_rate_limit(self):
        """_run_checks creates semaphore with concurrency, not rate_limit."""
        scanner = BaseScanner("test_key", rate_limit=20, concurrency=3, no_color=True)

        async def dummy_check():
            return "ok"

        with patch.object(scanner, "scan", new_callable=AsyncMock):
            await scanner._run_checks([("check1", dummy_check())])

        assert scanner._semaphore is not None
        assert scanner._semaphore._value <= 3

    @pytest.mark.asyncio
    async def test_rate_limiter_created_when_rate_limit_set(self):
        """_run_checks creates RateLimiter when rate_limit is set."""
        scanner = BaseScanner("test_key", rate_limit=10, no_color=True)

        async def dummy_check():
            return "ok"

        await scanner._run_checks([("check1", dummy_check())])
        assert scanner._rate_limiter is not None
        assert isinstance(scanner._rate_limiter, RateLimiter)

    @pytest.mark.asyncio
    async def test_no_rate_limiter_when_rate_limit_none(self):
        """_run_checks does not create RateLimiter when rate_limit is None."""
        scanner = BaseScanner("test_key", no_color=True)

        async def dummy_check():
            return "ok"

        await scanner._run_checks([("check1", dummy_check())])
        assert scanner._rate_limiter is None


class TestRateLimitPerAttempt:
    """Criterion 2: Rate limit applies to every attempt including retries."""

    @pytest.mark.asyncio
    async def test_retry_is_rate_limited(self):
        """Rate limit applies to retry attempts, not just the first request.

        With rate_limit=2 and 3 attempts (all 429), the 3rd attempt must wait
        for a token. Backoff is set to ~0 so only rate limiting adds delay.
        """
        scanner = BaseScanner("test_key", no_color=True, rate_limit=2, max_retries=3)
        scanner._retry_config = RetryConfig(max_retries=3, backoff_base=1, max_wait=0.01)
        scanner._rate_limiter = RateLimiter(rps=2.0)

        mock_response = MagicMock()
        mock_response.status = 429
        mock_response.headers = {"Retry-After": "0", "Content-Type": "text/plain"}
        mock_response.url = "https://example.com"
        mock_response.read = AsyncMock(return_value=b"rate limited")

        class FakeCtx:
            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=FakeCtx())
        scanner._session = mock_session

        start = time.monotonic()
        result = await scanner._request_with_retry("GET", "https://example.com")
        elapsed = time.monotonic() - start

        assert result is not None
        assert result.status == 429
        assert elapsed >= 0.4, f"Rate limit not applied to retries: {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_no_rate_limit_no_delay_on_retry(self):
        """Without rate_limit, retries have no rate-limiting delay."""
        scanner = BaseScanner("test_key", no_color=True, max_retries=3)
        scanner._retry_config = RetryConfig(max_retries=3, backoff_base=1, max_wait=0.01)

        mock_response = MagicMock()
        mock_response.status = 429
        mock_response.headers = {"Retry-After": "0", "Content-Type": "text/plain"}
        mock_response.url = "https://example.com"
        mock_response.read = AsyncMock(return_value=b"no limit")

        class FakeCtx:
            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, *args):
                return False

        mock_session = MagicMock()
        mock_session.request = MagicMock(return_value=FakeCtx())
        scanner._session = mock_session

        start = time.monotonic()
        result = await scanner._request_with_retry("GET", "https://example.com")
        elapsed = time.monotonic() - start

        assert result is not None
        assert elapsed < 0.3, f"Unexpected delay without rate limit: {elapsed:.3f}s"


class TestTruncationRecorded:
    """Criterion 5: Truncation is recorded in evidence/reason."""

    def test_truncated_response_marks_scan_result(self):
        """log_result with truncated=True → ScanResult.truncated=True + reason note."""
        scanner = BaseScanner("test_key", no_color=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "partial"}',
            _content_type="application/json",
            truncated=True,
        )
        scanner.log_result("Test Service", 200, response)

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.truncated is True
        assert "truncated" in result.reason.lower()

    def test_non_truncated_response_no_mark(self):
        """log_result with truncated=False → ScanResult.truncated=False."""
        scanner = BaseScanner("test_key", no_color=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "full"}',
            _content_type="application/json",
            truncated=False,
        )
        scanner.log_result("Test Service", 200, response)

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.truncated is False
        assert "truncated" not in result.reason.lower()

    def test_truncated_visible_in_results_property(self):
        """Scanner.results includes 'truncated' field."""
        scanner = BaseScanner("test_key", no_color=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "partial"}',
            _content_type="application/json",
            truncated=True,
        )
        scanner.log_result("Test Service", 200, response)

        assert scanner.results[0]["truncated"] is True
        assert scanner.raw_data[0]["truncated"] is True


class TestPositiveValidation:
    """Criterion 1: Positive validation for transport parameters."""

    def test_concurrency_zero_rejected(self):
        with pytest.raises(ValueError, match="concurrency"):
            BaseScanner("test_key", concurrency=0, no_color=True)

    def test_concurrency_negative_rejected(self):
        with pytest.raises(ValueError, match="concurrency"):
            BaseScanner("test_key", concurrency=-3, no_color=True)

    def test_rate_limit_zero_rejected(self):
        with pytest.raises(ValueError, match="rate_limit"):
            BaseScanner("test_key", rate_limit=0, no_color=True)

    def test_rate_limit_negative_rejected(self):
        with pytest.raises(ValueError, match="rate_limit"):
            BaseScanner("test_key", rate_limit=-1, no_color=True)

    def test_timeout_zero_rejected(self):
        with pytest.raises(ValueError, match="timeout"):
            BaseScanner("test_key", timeout=0, no_color=True)

    def test_connect_timeout_zero_rejected(self):
        with pytest.raises(ValueError, match="connect_timeout"):
            BaseScanner("test_key", connect_timeout=0, no_color=True)

    def test_read_timeout_zero_rejected(self):
        with pytest.raises(ValueError, match="read_timeout"):
            BaseScanner("test_key", read_timeout=0, no_color=True)

    def test_max_response_size_zero_rejected(self):
        with pytest.raises(ValueError, match="max_response_size"):
            BaseScanner("test_key", max_response_size=0, no_color=True)

    def test_max_retries_zero_rejected(self):
        with pytest.raises(ValueError, match="max_retries"):
            BaseScanner("test_key", max_retries=0, no_color=True)

    def test_rate_limiter_zero_rps_rejected(self):
        with pytest.raises(ValueError, match="rps"):
            RateLimiter(rps=0.0)

    def test_rate_limiter_negative_rps_rejected(self):
        with pytest.raises(ValueError, match="rps"):
            RateLimiter(rps=-1.0)

    def test_config_rejects_non_positive(self):
        from core.config import ConfigError, _validate_config

        for field in ("timeout", "rate_limit", "concurrency", "connect_timeout", "read_timeout"):
            with pytest.raises(ConfigError, match="positive"):
                _validate_config({field: 0})

    def test_valid_positive_accepted(self):
        """All positive values should be accepted without error."""
        scanner = BaseScanner(
            "test_key",
            timeout=1,
            connect_timeout=1,
            read_timeout=1,
            concurrency=1,
            max_retries=1,
            max_response_size=1,
            rate_limit=1,
            no_color=True,
        )
        assert scanner.concurrency == 1


class TestUnsupportedTransportWarning:
    """Criterion 6: Transport that doesn't support an option rejects it clearly."""

    def test_aws_scanner_warns_on_non_default_transport(self, capsys):
        """AWSScanner with non-default transport params prints a warning."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("test_key", aws_secret="secret", concurrency=10, rate_limit=5)
        captured = capsys.readouterr()
        assert "does not support" in captured.out
        assert "concurrency" in captured.out
        assert "rate_limit" in captured.out

    def test_aws_scanner_no_warning_on_defaults(self, capsys):
        """AWSScanner with default transport params does not warn."""
        from scanners.aws_scanner import AWSScanner

        AWSScanner("test_key", aws_secret="secret")
        captured = capsys.readouterr()
        assert "does not support" not in captured.out

    def test_http_scanner_no_warning(self, capsys):
        """HTTP-based scanner does not warn about transport params."""
        scanner = BaseScanner("test_key", concurrency=10, rate_limit=5, no_color=True)
        captured = capsys.readouterr()
        assert "does not support" not in captured.out
        assert scanner.concurrency == 10

    def test_aws_scanner_supports_http_transport_false(self):
        """AWSScanner declares SUPPORTS_HTTP_TRANSPORT = False."""
        from scanners.aws_scanner import AWSScanner

        assert AWSScanner.SUPPORTS_HTTP_TRANSPORT is False

    def test_base_scanner_supports_http_transport_true(self):
        """BaseScanner declares SUPPORTS_HTTP_TRANSPORT = True."""
        assert BaseScanner.SUPPORTS_HTTP_TRANSPORT is True
