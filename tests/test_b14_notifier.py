"""B14 acceptance tests: kegagalan plugin/notifier terlihat.

Tests prove:
- Criterion 2: Notification failure gets structured delivery outcome; scan results intact.
- Criterion 3: Timeout and failed response tested without network; exception does not
  display full webhook URL.
- Criterion 4: No real webhook calls — all transport mocked.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import aiohttp
import pytest

from core.base_scanner import BaseScanner, ResponseData
from core.notifier import NotificationResult, notify_discord, notify_slack, send_notifications

WEBHOOK_URL = "https://hooks.slack.test.invalid/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"


class FakeResponse:
    """Fake aiohttp response with a configurable status code."""

    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass


class FakePostContext:
    """Fake context manager for session.post() — can raise on enter."""

    def __init__(self, status: int | None = None, exc: Exception | None = None) -> None:
        self._status = status
        self._exc = exc

    async def __aenter__(self) -> FakeResponse:
        if self._exc:
            raise self._exc
        return FakeResponse(self._status or 200)

    async def __aexit__(self, *args: object) -> None:
        pass


class FakeSession:
    """Fake aiohttp.ClientSession — configurable response or exception."""

    def __init__(self, status: int = 200, exc: Exception | None = None) -> None:
        self._status = status
        self._exc = exc

    def post(self, url: str, **kwargs: object) -> FakePostContext:
        return FakePostContext(status=self._status, exc=self._exc)

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass


def _make_scanner_with_results() -> BaseScanner:
    """Create a scanner with a few results for notification tests."""
    scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)
    for svc in ["Service A", "Service B"]:
        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url=f"https://example.com/{svc.replace(' ', '_')}",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result(svc, 200, response)
    return scanner


class TestNotificationResult:
    """Criterion 2: Structured delivery outcome."""

    def test_notification_result_fields(self):
        """NotificationResult has channel, success, error, status_code fields."""
        result = NotificationResult(channel="slack", success=True)
        assert result.channel == "slack"
        assert result.success is True
        assert result.error is None
        assert result.status_code is None

    def test_notification_result_with_error(self):
        """NotificationResult can represent a failure with error + status."""
        result = NotificationResult(
            channel="discord",
            success=False,
            error="HTTP 500",
            status_code=500,
        )
        assert result.channel == "discord"
        assert result.success is False
        assert result.error == "HTTP 500"
        assert result.status_code == 500


class TestNotifySlack:
    """Criterion 2+3: Slack notification with structured outcome, URL redaction."""

    @pytest.mark.asyncio
    async def test_success_returns_result(self, capsys):
        """HTTP 200 → NotificationResult(success=True, status_code=200)."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=200)):
            result = await notify_slack(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.channel == "slack"
        assert result.success is True
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_http_failure_returns_result(self, capsys):
        """HTTP 500 → NotificationResult(success=False, status_code=500)."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=500)):
            result = await notify_slack(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_connection_error_returns_result(self, capsys):
        """Connection error → NotificationResult(success=False, error set)."""
        scanner = _make_scanner_with_results()
        exc = aiohttp.ClientConnectionError("Connection refused")
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(exc=exc)):
            result = await notify_slack(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_timeout_returns_result(self, capsys):
        """Timeout → NotificationResult(success=False, error mentions timeout)."""
        scanner = _make_scanner_with_results()
        with patch(
            "core.notifier.aiohttp.ClientSession",
            return_value=FakeSession(exc=asyncio.TimeoutError()),
        ):
            result = await notify_slack(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert result.error is not None
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_error_does_not_leak_full_url(self, capsys):
        """Error message must not contain the full webhook URL."""
        scanner = _make_scanner_with_results()
        exc = aiohttp.ClientConnectionError("Connection refused")
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(exc=exc)):
            await notify_slack(WEBHOOK_URL, scanner, "test")
        captured = capsys.readouterr()
        assert WEBHOOK_URL not in captured.out
        assert "XXXXXXXXXXXXXXXXXXXXXXXX" not in captured.out

    @pytest.mark.asyncio
    async def test_scan_results_unchanged_after_notification(self, capsys):
        """Notification must not modify scanner.scan_results."""
        scanner = _make_scanner_with_results()
        original_count = len(scanner.scan_results)
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=200)):
            await notify_slack(WEBHOOK_URL, scanner, "test")
        assert len(scanner.scan_results) == original_count


class TestNotifyDiscord:
    """Criterion 2+3: Discord notification with structured outcome."""

    @pytest.mark.asyncio
    async def test_success_200(self, capsys):
        """HTTP 200 → NotificationResult(success=True)."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=200)):
            result = await notify_discord(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.channel == "discord"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_success_204(self, capsys):
        """HTTP 204 → NotificationResult(success=True) — Discord uses 204."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=204)):
            result = await notify_discord(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_http_failure(self, capsys):
        """HTTP 500 → NotificationResult(success=False)."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=500)):
            result = await notify_discord(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_timeout(self, capsys):
        """Timeout → NotificationResult(success=False, error mentions timeout)."""
        scanner = _make_scanner_with_results()
        with patch(
            "core.notifier.aiohttp.ClientSession",
            return_value=FakeSession(exc=asyncio.TimeoutError()),
        ):
            result = await notify_discord(WEBHOOK_URL, scanner, "test")
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert "timeout" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_error_does_not_leak_full_url(self, capsys):
        """Error message must not contain the full webhook URL."""
        scanner = _make_scanner_with_results()
        exc = aiohttp.ClientConnectionError("Connection refused")
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(exc=exc)):
            await notify_discord(WEBHOOK_URL, scanner, "test")
        captured = capsys.readouterr()
        assert WEBHOOK_URL not in captured.out
        assert "XXXXXXXXXXXXXXXXXXXXXXXX" not in captured.out


class TestSendNotifications:
    """Criterion 2: send_notifications returns structured outcomes."""

    @pytest.mark.asyncio
    async def test_returns_list_of_results(self, capsys):
        """send_notifications returns list[NotificationResult]."""
        scanner = _make_scanner_with_results()
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=200)):
            results = await send_notifications(scanner, "test", slack_url=WEBHOOK_URL, discord_url=WEBHOOK_URL)
        assert isinstance(results, list)
        assert all(isinstance(r, NotificationResult) for r in results)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_empty_when_no_urls(self, capsys):
        """No URLs → empty list."""
        scanner = _make_scanner_with_results()
        results = await send_notifications(scanner, "test")
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_results_unchanged(self, capsys):
        """send_notifications must not modify scan results."""
        scanner = _make_scanner_with_results()
        original = list(scanner.scan_results)
        with patch("core.notifier.aiohttp.ClientSession", return_value=FakeSession(status=200)):
            await send_notifications(scanner, "test", slack_url=WEBHOOK_URL, discord_url=WEBHOOK_URL)
        assert scanner.scan_results == original

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure(self, capsys):
        """One channel succeeds, one fails — both outcomes returned."""
        scanner = _make_scanner_with_results()

        slack_session = FakeSession(status=200)
        discord_session = FakeSession(status=500)

        call_count = 0

        class AlternatingSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def post(self, url, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return slack_session.post(url, **kwargs)
                return discord_session.post(url, **kwargs)

        with patch("core.notifier.aiohttp.ClientSession", return_value=AlternatingSession()):
            results = await send_notifications(scanner, "test", slack_url=WEBHOOK_URL, discord_url=WEBHOOK_URL)
        assert len(results) == 2
        successes = [r.success for r in results]
        assert True in successes
        assert False in successes
