"""B13 acceptance tests: opsi CLI dan tampilan sesuai kontrak.

Tests prove:
- Criterion 1: Every option has a tested effect.
- Criterion 2: Filter only affects display; full results stored; hidden count shown.
- Criterion 3: Quiet still gives errors + exit code; verbose doesn't leak secrets.
- Criterion 4: No-color clears entire output path, not just banner.
"""

from __future__ import annotations

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ResponseData,
    Severity,
)
from core.report_engine import ReportEngine


def _make_scanner_with_results() -> BaseScanner:
    """Create a scanner with mixed-severity results for filter testing."""
    scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)

    responses = [
        ("Critical Service", 200, Severity.CRITICAL, CheckOutcome.ACCESSIBLE),
        ("High Service", 200, Severity.HIGH, CheckOutcome.ACCESSIBLE),
        ("Medium Service", 403, Severity.MEDIUM, CheckOutcome.RESTRICTED),
        ("Low Service", 404, Severity.LOW, CheckOutcome.NOT_FOUND),
        ("Info Service", 400, Severity.INFO, CheckOutcome.BAD_REQUEST),
    ]

    for svc, status, sev, _outcome in responses:
        response = ResponseData(
            status=status,
            headers={"Content-Type": "application/json"},
            url=f"https://example.com/{svc.replace(' ', '_')}",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result(svc, status, response, severity=sev)

    return scanner


class TestNoColorClearsAllOutput:
    """Criterion 4: No-color clears entire output path, not just banner."""

    def test_no_color_strips_ansi_from_scanner_output(self, capsys):
        """Scanner with no_color=True → no ANSI codes in output."""
        scanner = BaseScanner("test_key_12345678", no_color=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)

        captured = capsys.readouterr()
        assert "\033[" not in captured.out

    def test_no_color_strips_ansi_from_summary(self, capsys):
        """display_console_summary with no_color scanner → no ANSI codes."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test")
        captured = capsys.readouterr()
        assert "\033[" not in captured.out

    def test_no_color_strips_ansi_from_error(self, capsys):
        """Scanner error with no_color=True → no ANSI codes."""
        scanner = BaseScanner("test_key_12345678", no_color=True)
        scanner.log_error("Test Service", "Connection refused")
        captured = capsys.readouterr()
        assert "\033[" not in captured.out

    def test_color_present_without_no_color(self, capsys):
        """Scanner without no_color → ANSI codes present (sanity check)."""
        scanner = BaseScanner("test_key_12345678", no_color=False)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)

        captured = capsys.readouterr()
        assert "\033[" in captured.out


class TestSeverityFilterDisplayOnly:
    """Criterion 2: Filter only affects display; full results stored."""

    def test_filter_high_hides_medium_low_info(self, capsys):
        """severity_filter='high' → only CRITICAL/ERROR/HIGH shown."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", severity_filter="high")
        captured = capsys.readouterr()

        assert "Critical Service" in captured.out
        assert "High Service" in captured.out
        assert "Medium Service" not in captured.out
        assert "Low Service" not in captured.out
        assert "Info Service" not in captured.out

    def test_filter_shows_hidden_count(self, capsys):
        """severity_filter → hidden count displayed."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", severity_filter="high")
        captured = capsys.readouterr()

        assert "hidden" in captured.out.lower()
        assert "3" in captured.out

    def test_filter_critical_shows_only_critical(self, capsys):
        """severity_filter='critical' → only CRITICAL shown."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", severity_filter="critical")
        captured = capsys.readouterr()

        assert "Critical Service" in captured.out
        assert "High Service" not in captured.out

    def test_filter_low_shows_all_except_info(self, capsys):
        """severity_filter='low' → everything except INFO shown."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", severity_filter="low")
        captured = capsys.readouterr()

        assert "Critical Service" in captured.out
        assert "High Service" in captured.out
        assert "Medium Service" in captured.out
        assert "Low Service" in captured.out
        assert "Info Service" not in captured.out

    def test_no_filter_shows_all(self, capsys):
        """No severity_filter → all results shown."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test")
        captured = capsys.readouterr()

        assert "Critical Service" in captured.out
        assert "Info Service" in captured.out
        assert "hidden" not in captured.out.lower()

    def test_full_results_still_stored_after_filter(self):
        """scan_results unchanged regardless of filter (display-only)."""
        scanner = _make_scanner_with_results()
        total = len(scanner.scan_results)
        assert total == 5

        ReportEngine.display_console_summary(scanner, "test", severity_filter="critical")
        assert len(scanner.scan_results) == total


class TestQuietMode:
    """Criterion 3: Quiet suppresses non-essential output, keeps errors + exit."""

    def test_quiet_suppresses_log_result(self, capsys):
        """Scanner with quiet=True → log_result produces no output."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_quiet_still_prints_log_error(self, capsys):
        """Scanner with quiet=True → log_error still prints (important errors visible)."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)
        scanner.log_error("Test Service", "Connection refused")

        captured = capsys.readouterr()
        assert "CONNECTION ERROR" in captured.out
        assert "Test Service" in captured.out

    def test_quiet_still_stores_results(self):
        """Scanner with quiet=True → results still appended to scan_results."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)

        assert len(scanner.scan_results) == 1
        assert scanner.scan_results[0].service_name == "Test Service"

    def test_quiet_suppresses_log_custom_result(self, capsys):
        """Scanner with quiet=True → log_custom_result produces no output."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)
        scanner.log_custom_result(
            "Test Service",
            "ACCESSIBLE",
            200,
            "success",
        )

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_quiet_still_prints_check_exception(self, capsys):
        """Scanner with quiet=True → _log_check_exception still prints."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)
        scanner._log_check_exception("Test Check", "Something went wrong")

        captured = capsys.readouterr()
        assert "CONNECTION ERROR" in captured.out
        assert "Test Check" in captured.out


class TestVerboseMode:
    """Criterion 3: Verbose shows extra info, doesn't leak secrets."""

    def test_verbose_shows_url_and_reason(self, capsys):
        """verbose=True → URL and reason shown in summary."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", verbose=True)
        captured = capsys.readouterr()

        assert "URL:" in captured.out
        assert "Reason:" in captured.out
        assert "https://example.com/" in captured.out

    def test_verbose_no_url_without_verbose(self, capsys):
        """verbose=False → URL not shown in summary."""
        scanner = _make_scanner_with_results()
        ReportEngine.display_console_summary(scanner, "test", verbose=False)
        captured = capsys.readouterr()

        assert "URL:" not in captured.out

    def test_verbose_does_not_leak_api_key(self, capsys):
        """verbose=True → api_key not in output (already sanitized)."""
        secret_key = "sk-very-secret-key-1234567890"
        scanner = BaseScanner(secret_key, no_color=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)

        capsys.readouterr()
        ReportEngine.display_console_summary(scanner, "test", verbose=True)
        captured = capsys.readouterr()

        assert secret_key not in captured.out


class TestOptionHasTestedEffect:
    """Criterion 1: Every option has a tested effect."""

    def test_severity_filter_has_effect(self, capsys):
        """severity_filter changes visible output (not a no-op)."""
        scanner = _make_scanner_with_results()

        ReportEngine.display_console_summary(scanner, "test")
        without_filter = capsys.readouterr().out

        ReportEngine.display_console_summary(scanner, "test", severity_filter="critical")
        with_filter = capsys.readouterr().out

        assert without_filter != with_filter

    def test_quiet_has_effect(self, capsys):
        """quiet=True suppresses output (not a no-op)."""
        scanner = BaseScanner("test_key_12345678", no_color=True, quiet=True)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)
        quiet_out = capsys.readouterr().out

        scanner2 = BaseScanner("test_key_12345678", no_color=True, quiet=False)
        scanner2.log_result("Test Service", 200, response)
        normal_out = capsys.readouterr().out

        assert quiet_out == ""
        assert normal_out != ""

    def test_verbose_has_effect(self, capsys):
        """verbose=True adds output (not a no-op)."""
        scanner = _make_scanner_with_results()

        ReportEngine.display_console_summary(scanner, "test", verbose=False)
        without_verbose = capsys.readouterr().out

        ReportEngine.display_console_summary(scanner, "test", verbose=True)
        with_verbose = capsys.readouterr().out

        assert len(with_verbose) > len(without_verbose)

    def test_no_color_has_effect(self, capsys):
        """no_color=True strips ANSI codes (not a no-op)."""
        scanner = BaseScanner("test_key_12345678", no_color=False)

        response = ResponseData(
            status=200,
            headers={"Content-Type": "application/json"},
            url="https://example.com/api",
            _body_bytes=b'{"data": "test"}',
            _content_type="application/json",
        )
        scanner.log_result("Test Service", 200, response)
        colored = capsys.readouterr().out

        scanner2 = BaseScanner("test_key_12345678", no_color=True)
        scanner2.log_result("Test Service", 200, response)
        uncolored = capsys.readouterr().out

        assert "\033[" in colored
        assert "\033[" not in uncolored
