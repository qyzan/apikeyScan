"""B04 blocker fix tests: exit code and notifier use outcome field.

Tests prove:
- Exit code 1 when scan has ACCESSIBLE findings (not 0 as with old VULNERABLE match).
- Exit code 0 when scan has no ACCESSIBLE findings.
- Slack/Discord notifier counts and colors use outcome field, not status_text.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    ScanResult,
    Severity,
)
from core.notifier import notify_discord, notify_slack


def _make_scanner_with_outcomes(outcomes: list[CheckOutcome]) -> BaseScanner:
    """Create a scanner with scan_results having the given outcomes.

    Args:
        outcomes: List of CheckOutcome values to populate.

    Returns:
        A BaseScanner with the given scan_results.
    """
    scanner = BaseScanner("test_key", no_color=True)
    scanner.scan_results = [
        ScanResult(
            check_id="",
            service_name=f"Check-{i}",
            provider="test",
            execution_status=ExecutionStatus.COMPLETED,
            outcome=oc,
            reason="test",
            status_code=200 if oc == CheckOutcome.ACCESSIBLE else 403,
            url="https://example.com/test",
            headers={},
            response_body={},
            auto_severity=Severity.HIGH if oc == CheckOutcome.ACCESSIBLE else Severity.INFO,
        )
        for i, oc in enumerate(outcomes)
    ]
    return scanner


class TestExitCodeUsesOutcome:
    """B04 blocker: exit code must use outcome field, not VULNERABLE string."""

    @pytest.mark.asyncio
    async def test_exit_code_1_when_accessible_findings(self):
        """Scan with ACCESSIBLE results should exit 1."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        args = cli.build_parser().parse_args(["scan", "-k", "dummy", "-p", "github"])

        fake_scanner = _make_scanner_with_outcomes(
            [CheckOutcome.ACCESSIBLE, CheckOutcome.RESTRICTED, CheckOutcome.INCONCLUSIVE]
        )

        with (
            patch.object(cli, "auto_detect_provider", new_callable=AsyncMock),
            patch.object(cli, "run_single_scan", new_callable=AsyncMock, return_value=fake_scanner),
            patch.object(cli, "_write_report_bundle", return_value=False),
        ):
            exit_code = await cli.run_scan_command(args)

        assert exit_code == 1

    @pytest.mark.asyncio
    async def test_exit_code_0_when_no_accessible_findings(self):
        """Scan with no ACCESSIBLE results should exit 0."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        args = cli.build_parser().parse_args(["scan", "-k", "dummy", "-p", "github"])

        fake_scanner = _make_scanner_with_outcomes(
            [CheckOutcome.RESTRICTED, CheckOutcome.UNAUTHORIZED, CheckOutcome.NOT_FOUND]
        )

        with (
            patch.object(cli, "auto_detect_provider", new_callable=AsyncMock),
            patch.object(cli, "run_single_scan", new_callable=AsyncMock, return_value=fake_scanner),
            patch.object(cli, "_write_report_bundle", return_value=False),
        ):
            exit_code = await cli.run_scan_command(args)

        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_exit_code_0_when_all_inconclusive(self):
        """Scan with only INCONCLUSIVE results should exit 0."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        args = cli.build_parser().parse_args(["scan", "-k", "dummy", "-p", "github"])

        fake_scanner = _make_scanner_with_outcomes([CheckOutcome.INCONCLUSIVE, CheckOutcome.INCONCLUSIVE])

        with (
            patch.object(cli, "auto_detect_provider", new_callable=AsyncMock),
            patch.object(cli, "run_single_scan", new_callable=AsyncMock, return_value=fake_scanner),
            patch.object(cli, "_write_report_bundle", return_value=False),
        ):
            exit_code = await cli.run_scan_command(args)

        assert exit_code == 0


class TestNotifierUsesOutcome:
    """B04 blocker: Slack/Discord notifier must use outcome field."""

    @pytest.mark.asyncio
    async def test_slack_counts_accessible_as_vulnerable(self):
        """Slack notifier should count ACCESSIBLE outcomes and set danger color."""
        scanner = _make_scanner_with_outcomes(
            [CheckOutcome.ACCESSIBLE, CheckOutcome.ACCESSIBLE, CheckOutcome.RESTRICTED]
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("core.notifier.aiohttp.ClientSession", return_value=mock_session):
            await notify_slack("https://hooks.slack.com/test", scanner, "test")

        call_args = mock_session.post.call_args
        payload = call_args.kwargs["json"]
        assert payload["attachments"][0]["color"] == "danger"
        fields = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
        assert fields["Accessible"] == "2"
        assert fields["Restricted"] == "1"

    @pytest.mark.asyncio
    async def test_slack_green_when_no_accessible(self):
        """Slack notifier should use good color when no ACCESSIBLE outcomes."""
        scanner = _make_scanner_with_outcomes([CheckOutcome.RESTRICTED, CheckOutcome.UNAUTHORIZED])

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("core.notifier.aiohttp.ClientSession", return_value=mock_session):
            await notify_slack("https://hooks.slack.com/test", scanner, "test")

        call_args = mock_session.post.call_args
        payload = call_args.kwargs["json"]
        assert payload["attachments"][0]["color"] == "good"
        fields = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
        assert fields["Accessible"] == "0"

    @pytest.mark.asyncio
    async def test_discord_counts_accessible_and_uses_red(self):
        """Discord notifier should count ACCESSIBLE outcomes and use red color."""
        scanner = _make_scanner_with_outcomes([CheckOutcome.ACCESSIBLE, CheckOutcome.RESTRICTED])

        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("core.notifier.aiohttp.ClientSession", return_value=mock_session):
            await notify_discord("https://discord.com/api/webhooks/test", scanner, "test")

        call_args = mock_session.post.call_args
        payload = call_args.kwargs["json"]
        assert payload["embeds"][0]["color"] == 0xFF0000
        fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
        assert fields["Accessible"] == "1"
        assert fields["Restricted"] == "1"

    @pytest.mark.asyncio
    async def test_discord_green_when_no_accessible(self):
        """Discord notifier should use green color when no ACCESSIBLE outcomes."""
        scanner = _make_scanner_with_outcomes([CheckOutcome.RESTRICTED])

        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("core.notifier.aiohttp.ClientSession", return_value=mock_session):
            await notify_discord("https://discord.com/api/webhooks/test", scanner, "test")

        call_args = mock_session.post.call_args
        payload = call_args.kwargs["json"]
        assert payload["embeds"][0]["color"] == 0x00FF00
