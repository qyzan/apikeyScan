"""B06 acceptance tests: exit code based on execution and finding.

Tests prove:
- Exit 0: clean scan completed, no accessible findings, no errors.
- Exit 1: scan completed without errors, at least one accessible finding.
- Exit 2: any check execution_status=ERROR (error wins over finding).
- Exit 2: partial failure (run_single_scan returns None).
- Exit 2: all checks UNAUTHORIZED (credential invalid).
- Exit 2: no scanners ran (all keys unknown).
- Exit 2: input errors (no key, keyfile not found).
- Exit 0: all checks SKIPPED (no errors, no findings).
- Report persists both error and finding simultaneously via CLI flow.
- Tests check process exit (SystemExit) and persisted output, not just return helper.
"""

import json
import sys
from contextlib import nullcontext as _dummy_cm
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    ScanResult,
    Severity,
)


def _make_scanner_with_results(
    outcomes: list[tuple[CheckOutcome, ExecutionStatus]],
) -> BaseScanner:
    """Create a scanner with scan_results having the given outcome/execution pairs."""
    scanner = BaseScanner("test_key", no_color=True)
    scanner.scan_results = [
        ScanResult(
            check_id=f"check-{i}",
            service_name=f"Check-{i}",
            provider="test",
            execution_status=es,
            outcome=oc,
            reason="test",
            status_code=200 if oc == CheckOutcome.ACCESSIBLE else None,
            url="https://example.com/test",
            headers={},
            response_body={},
            auto_severity=Severity.HIGH if oc == CheckOutcome.ACCESSIBLE else Severity.INFO,
        )
        for i, (oc, es) in enumerate(outcomes)
    ]
    return scanner


def _run_cli_expect_exit(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    fake_scanner: BaseScanner | None = None,
    scan_fails: bool = False,
) -> int:
    """Run CLI main() and return the process exit code via SystemExit."""
    import importlib

    cli = importlib.import_module("apiKeyScan")
    monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", *argv])

    auto_cm = patch.object(cli, "auto_detect_provider", new_callable=AsyncMock) if not scan_fails else _dummy_cm()
    scan_cm = (
        patch.object(cli, "run_single_scan", new_callable=AsyncMock, return_value=None) if scan_fails else _dummy_cm()
    )
    get_cm = (
        patch.object(cli, "get_scanner", return_value=fake_scanner)
        if (fake_scanner is not None and not scan_fails)
        else _dummy_cm()
    )
    write_cm = patch.object(cli, "_write_report_bundle", return_value=False)

    with auto_cm, scan_cm, get_cm, write_cm:
        if fake_scanner is not None and not scan_fails:
            fake_scanner.run = AsyncMock()
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
    return excinfo.value.code


class TestProcessExitClean:
    """B06: Process exit 0 for clean scan without findings or errors."""

    def test_exit_0_all_restricted(self, monkeypatch):
        """All RESTRICTED → exit 0 (credential valid, access denied, scan clean)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED),
                (CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 0

    def test_exit_0_all_skipped(self, monkeypatch):
        """All SKIPPED → exit 0 (no errors, no findings)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.SKIPPED, ExecutionStatus.SKIPPED),
                (CheckOutcome.SKIPPED, ExecutionStatus.SKIPPED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 0

    def test_exit_0_inconclusive_only(self, monkeypatch):
        """All INCONCLUSIVE → exit 0 (no accessible, no errors)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.INCONCLUSIVE, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 0

    def test_exit_0_mixed_restricted_inconclusive(self, monkeypatch):
        """Mixed RESTRICTED + INCONCLUSIVE → exit 0 (no accessible, no errors)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED),
                (CheckOutcome.INCONCLUSIVE, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 0


class TestProcessExitFinding:
    """B06: Process exit 1 for accessible finding without errors."""

    def test_exit_1_accessible_found(self, monkeypatch):
        """ACCESSIBLE finding, no errors → exit 1."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 1

    def test_exit_1_multiple_accessible(self, monkeypatch):
        """Multiple ACCESSIBLE findings, no errors → exit 1."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 1


class TestProcessExitError:
    """B06: Process exit 2 when errors present (error wins over finding)."""

    def test_exit_2_check_execution_error(self, monkeypatch):
        """Any check with execution_status=ERROR → exit 2."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.ERROR, ExecutionStatus.ERROR),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 2

    def test_exit_2_error_wins_over_finding(self, monkeypatch):
        """Error + ACCESSIBLE finding coexist → exit 2 (error wins)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.ERROR, ExecutionStatus.ERROR),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 2

    def test_exit_2_all_requests_fail(self, monkeypatch):
        """All checks have outcome=ERROR → exit 2."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ERROR, ExecutionStatus.ERROR),
                (CheckOutcome.ERROR, ExecutionStatus.ERROR),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 2

    def test_exit_2_partial_failure_scan_level(self, monkeypatch):
        """Partial failure (run_single_scan returns None) → exit 2."""
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scan_fails=True)
        assert code == 2

    def test_exit_2_all_unauthorized(self, monkeypatch):
        """All checks UNAUTHORIZED → exit 2 (credential invalid)."""
        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.UNAUTHORIZED, ExecutionStatus.COMPLETED),
                (CheckOutcome.UNAUTHORIZED, ExecutionStatus.COMPLETED),
            ]
        )
        code = _run_cli_expect_exit(monkeypatch, ["scan", "-k", "dummy", "-p", "github"], scanner)
        assert code == 2


class TestProcessExitInputErrors:
    """B06: Process exit 2 for input errors."""

    def test_exit_2_no_key(self, monkeypatch):
        """No --key or --keyfile → exit 2."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "scan"])
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        assert excinfo.value.code == 2

    def test_exit_2_keyfile_not_found(self, monkeypatch):
        """Keyfile not found → exit 2."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "scan", "--keyfile", "nonexistent.txt"])
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        assert excinfo.value.code == 2

    def test_exit_2_all_keys_unknown(self, monkeypatch, tmp_path):
        """Keyfile with all keys unknown → exit 2."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("dummy-key-1\ndummy-key-2\n", encoding="utf-8")

        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "scan", "--keyfile", str(keyfile)])
        with (
            patch.object(
                cli,
                "auto_detect_provider",
                new_callable=AsyncMock,
                return_value={"provider": "unknown"},
            ),
            pytest.raises(SystemExit) as excinfo,
        ):
            cli.main()
        assert excinfo.value.code == 2


class TestReportPersistsErrorAndFinding:
    """B06: Report saves error and finding simultaneously via CLI flow."""

    def test_report_contains_both_error_and_finding(self, monkeypatch, tmp_path):
        """CLI flow with --json should persist report containing both ERROR and ACCESSIBLE."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        output_prefix = str(tmp_path / "test_report")

        scanner = _make_scanner_with_results(
            [
                (CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED),
                (CheckOutcome.ERROR, ExecutionStatus.ERROR),
                (CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED),
            ]
        )
        scanner.run = AsyncMock()

        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "-k", "dummy", "-p", "github", "--json", "-o", output_prefix, "--no-color"],
        )

        with (
            patch.object(cli, "auto_detect_provider", new_callable=AsyncMock),
            patch.object(cli, "get_scanner", return_value=scanner),
            pytest.raises(SystemExit) as excinfo,
        ):
            cli.main()

        assert excinfo.value.code == 2

        json_path = Path(f"{output_prefix}.json")
        assert json_path.exists(), "report file should be persisted by CLI flow"
        report = json.loads(json_path.read_text(encoding="utf-8"))

        outcomes = [r.get("outcome") for r in report.get("results", [])]
        assert "accessible" in outcomes, "report must contain the finding"
        assert "error" in outcomes, "report must contain the error"
