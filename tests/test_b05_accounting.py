"""B05 acceptance tests: every check has an outcome.

Tests prove:
- Exception in a check creates ScanResult with ERROR outcome, check_id, and sanitized error.
- Sibling checks still complete when one check raises.
- Planned = completed + failed + skipped for a completed scan (missing == 0).
- CancelledError is recorded as interruption, not a clean exit.
- AWS separate path records SKIPPED outcome when boto3 unavailable or credentials missing.
- Blocker 1 regression: check_id comes from paired name, not CHECKS[i] global index.
- Blocker 2 regression: Google scanner without project_id records SKIPPED per dropped check.
"""

import asyncio
from typing import Any

import pytest

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    Severity,
)
from scanners.aws_scanner import AWSScanner
from scanners.google_scanner import GoogleScanner


class _TestScanner(BaseScanner):
    """Test scanner with configurable checks for B05 accounting tests."""

    PROVIDER_NAME = "test"
    CHECKS = ["test-check-0", "test-check-1", "test-check-2"]


def _make_success_coro(scanner: BaseScanner, index: int) -> Any:
    """Create a coroutine that logs a successful result."""

    async def _check() -> None:
        scanner.log_custom_result(
            service_name=f"Service {index}",
            status_text="ACCESSIBLE",
            status_code=200,
            response_body="ok",
            outcome=CheckOutcome.ACCESSIBLE,
        )

    return _check()


def _make_error_coro(scanner: BaseScanner, msg: str = "boom") -> Any:
    """Create a coroutine that raises a RuntimeError."""

    async def _check() -> None:
        raise RuntimeError(msg)

    return _check()


def _make_cancel_coro() -> Any:
    """Create a coroutine that raises CancelledError."""

    async def _check() -> None:
        raise asyncio.CancelledError()

    return _check()


class TestCheckExceptionRecording:
    """B05: Exception check dummy recorded with check ID and sanitized error."""

    @pytest.mark.asyncio
    async def test_exception_creates_error_scanresult(self):
        """A check that raises should produce a ScanResult with ERROR outcome."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks([("check-0", _make_error_coro(scanner, "test failure"))])

        error_results = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.ERROR]
        assert len(error_results) == 1
        assert error_results[0].outcome == CheckOutcome.ERROR
        assert error_results[0].auto_severity == Severity.ERROR

    @pytest.mark.asyncio
    async def test_exception_records_check_id_from_paired_name(self):
        """The ERROR ScanResult should have check_id from the paired name, not CHECKS[i]."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks([("my-paired-name", _make_error_coro(scanner))])

        assert len(scanner.scan_results) == 1
        assert scanner.scan_results[0].check_id == "my-paired-name"

    @pytest.mark.asyncio
    async def test_exception_error_message_is_sanitized(self):
        """The error message in ScanResult should be sanitized (no raw key)."""
        scanner = _TestScanner("secret-key-12345", no_color=True)
        await scanner._run_checks([("check-0", _make_error_coro(scanner, "failed with secret-key-12345 in trace"))])

        assert len(scanner.scan_results) == 1
        msg = scanner.scan_results[0].error_message or ""
        assert "secret-key-12345" not in msg
        assert "REDACTED" in msg or "test_key" not in msg

    @pytest.mark.asyncio
    async def test_sibling_checks_complete_when_one_raises(self):
        """Sibling checks should still produce results when one check raises."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("check-0", _make_success_coro(scanner, 0)),
                ("check-1", _make_error_coro(scanner)),
                ("check-2", _make_success_coro(scanner, 2)),
            ]
        )

        completed = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.COMPLETED]
        errors = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.ERROR]
        assert len(completed) == 2
        assert len(errors) == 1
        assert len(scanner.scan_results) == 3


class TestCheckAccountingInvariant:
    """B05: Planned = completed + failed + skipped; no missing outcomes."""

    @pytest.mark.asyncio
    async def test_accounting_balanced_all_succeed(self):
        """When all checks succeed, missing should be 0."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("check-0", _make_success_coro(scanner, 0)),
                ("check-1", _make_success_coro(scanner, 1)),
                ("check-2", _make_success_coro(scanner, 2)),
            ]
        )

        acc = scanner.check_accounting
        assert acc["planned"] == 3
        assert acc["completed"] == 3
        assert acc["failed"] == 0
        assert acc["skipped"] == 0
        assert acc["missing"] == 0

    @pytest.mark.asyncio
    async def test_accounting_balanced_with_exception(self):
        """When one check raises, missing should still be 0."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("check-0", _make_success_coro(scanner, 0)),
                ("check-1", _make_error_coro(scanner)),
                ("check-2", _make_success_coro(scanner, 2)),
            ]
        )

        acc = scanner.check_accounting
        assert acc["planned"] == 3
        assert acc["completed"] == 2
        assert acc["failed"] == 1
        assert acc["skipped"] == 0
        assert acc["missing"] == 0

    @pytest.mark.asyncio
    async def test_accounting_no_double_outcomes(self):
        """Each check should produce exactly one ScanResult — no doubles."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("check-0", _make_success_coro(scanner, 0)),
                ("check-1", _make_error_coro(scanner)),
            ]
        )

        assert len(scanner.scan_results) == 2
        services = [r.service_name for r in scanner.scan_results]
        assert len(services) == len(set(services))

    @pytest.mark.asyncio
    async def test_planned_checks_set_by_run_checks(self):
        """_run_checks should set planned_checks to len(checks)."""
        scanner = _TestScanner("test_key", no_color=True)
        assert scanner.planned_checks == 0
        await scanner._run_checks([("check-0", _make_success_coro(scanner, 0))])
        assert scanner.planned_checks == 1


class TestCancellationRecording:
    """B05: Cancellation/interrupted declared, not clean."""

    @pytest.mark.asyncio
    async def test_cancelled_error_recorded_as_error(self):
        """CancelledError should produce a ScanResult with ERROR execution status."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks([("check-0", _make_cancel_coro())])

        assert len(scanner.scan_results) == 1
        assert scanner.scan_results[0].execution_status == ExecutionStatus.ERROR
        assert scanner.scan_results[0].outcome == CheckOutcome.ERROR

    @pytest.mark.asyncio
    async def test_cancelled_error_has_interruption_reason(self):
        """CancelledError reason should mention cancellation or interruption."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks([("check-0", _make_cancel_coro())])

        reason = scanner.scan_results[0].reason.lower()
        assert "cancel" in reason or "interrupt" in reason

    @pytest.mark.asyncio
    async def test_cancelled_with_sibling_still_completes(self):
        """Sibling check should complete even when another is cancelled."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("check-0", _make_cancel_coro()),
                ("check-1", _make_success_coro(scanner, 1)),
            ]
        )

        acc = scanner.check_accounting
        assert acc["planned"] == 2
        assert acc["completed"] == 1
        assert acc["failed"] == 1
        assert acc["missing"] == 0


class TestAWSSkipRecording:
    """B05: AWS separate path records SKIPPED when prerequisite unavailable."""

    @pytest.mark.asyncio
    async def test_aws_missing_credentials_records_skipped(self):
        """AWS scan with missing credentials should produce a SKIPPED ScanResult."""
        scanner = AWSScanner("", aws_secret=None, no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert result.execution_status == ExecutionStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_aws_missing_secret_records_skipped(self):
        """AWS scan with key but no secret should produce a SKIPPED ScanResult."""
        scanner = AWSScanner("AKIATEST", aws_secret=None, no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        assert scanner.scan_results[0].outcome == CheckOutcome.SKIPPED

    @pytest.mark.asyncio
    async def test_aws_missing_credentials_has_skip_reason(self):
        """The SKIPPED result should have a reason explaining missing credentials."""
        scanner = AWSScanner("", aws_secret=None, no_color=True)
        await scanner.scan()

        reason = scanner.scan_results[0].reason
        assert "MISSING" in reason or "CREDENTIAL" in reason.upper()

    @pytest.mark.asyncio
    async def test_aws_missing_credentials_accounting_balanced(self):
        """Accounting should be balanced: planned=1, skipped=1, missing=0."""
        scanner = AWSScanner("", aws_secret=None, no_color=True)
        await scanner.scan()

        acc = scanner.check_accounting
        assert acc["planned"] == 1
        assert acc["skipped"] == 1
        assert acc["missing"] == 0

    @pytest.mark.asyncio
    async def test_aws_boto3_unavailable_records_skipped(self, monkeypatch):
        """When boto3 is unavailable, AWS scan should produce a SKIPPED ScanResult."""
        import scanners.aws_scanner as aws_mod

        monkeypatch.setattr(aws_mod, "BOTO3_AVAILABLE", False)
        scanner = AWSScanner("AKIATEST", aws_secret="secret", no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 1
        result = scanner.scan_results[0]
        assert result.outcome == CheckOutcome.SKIPPED
        assert result.execution_status == ExecutionStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_aws_boto3_unavailable_has_prerequisite_reason(self, monkeypatch):
        """SKIPPED result should mention prerequisite/boto3 in reason."""
        import scanners.aws_scanner as aws_mod

        monkeypatch.setattr(aws_mod, "BOTO3_AVAILABLE", False)
        scanner = AWSScanner("AKIATEST", aws_secret="secret", no_color=True)
        await scanner.scan()

        reason = scanner.scan_results[0].reason
        assert "PREREQUISITE" in reason.upper() or "BOTO3" in reason.upper()

    @pytest.mark.asyncio
    async def test_aws_boto3_unavailable_accounting_balanced(self, monkeypatch):
        """Accounting should be balanced when boto3 unavailable."""
        import scanners.aws_scanner as aws_mod

        monkeypatch.setattr(aws_mod, "BOTO3_AVAILABLE", False)
        scanner = AWSScanner("AKIATEST", aws_secret="secret", no_color=True)
        await scanner.scan()

        acc = scanner.check_accounting
        assert acc["planned"] == 1
        assert acc["skipped"] == 1
        assert acc["missing"] == 0

    @pytest.mark.asyncio
    async def test_aws_cannot_finish_silently_without_credentials(self):
        """AWS scan must not return with zero scan_results when credentials missing."""
        scanner = AWSScanner("", aws_secret=None, no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) > 0


class TestCheckIdMisattributionRegression:
    """B05 blocker 1: check_id must come from paired name, not CHECKS[i].

    Regression: Google scanner's checks list is dynamic — order != CHECKS.
    An exception in Identity Toolkit (index 0 in checks) was misattributed
    to "GCS Bucket List" (index 0 in CHECKS) before the fix.
    """

    @pytest.mark.asyncio
    async def test_check_id_uses_paired_name_not_checks_index(self):
        """check_id should be the paired name, not CHECKS[i]."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("actual-name-A", _make_success_coro(scanner, 0)),
                ("actual-name-B", _make_error_coro(scanner)),
            ]
        )

        error_result = next(r for r in scanner.scan_results if r.execution_status == ExecutionStatus.ERROR)
        assert error_result.check_id == "actual-name-B"
        assert error_result.check_id != scanner.CHECKS[1]

    @pytest.mark.asyncio
    async def test_dynamic_list_check_id_not_from_checks(self):
        """With a dynamic list where order != CHECKS, check_id must still be correct."""
        scanner = _TestScanner("test_key", no_color=True)
        await scanner._run_checks(
            [
                ("Identity Toolkit", _make_error_coro(scanner)),
                ("GCS Bucket List", _make_success_coro(scanner, 1)),
            ]
        )

        error_result = next(r for r in scanner.scan_results if r.execution_status == ExecutionStatus.ERROR)
        assert error_result.check_id == "Identity Toolkit"
        assert error_result.check_id != "GCS Bucket List"


class TestGoogleSkipRecording:
    """B05 blocker 2: Google scanner without project_id records SKIPPED per dropped check."""

    @pytest.mark.asyncio
    async def test_google_without_project_id_records_skipped_checks(self):
        """Google scan without project_id should record SKIPPED for project-scoped checks."""
        scanner = GoogleScanner("test_key", no_color=True)
        await scanner.scan()

        skipped = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.SKIPPED]
        assert len(skipped) == 10

    @pytest.mark.asyncio
    async def test_google_without_project_id_skipped_have_reason(self):
        """Each SKIPPED result should mention missing parameter."""
        scanner = GoogleScanner("test_key", no_color=True)
        await scanner.scan()

        skipped = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.SKIPPED]
        for result in skipped:
            body = str(result.response_body).lower()
            assert "project_id" in body or "parameter" in body

    @pytest.mark.asyncio
    async def test_google_without_project_id_accounting_balanced(self):
        """Accounting should be balanced: planned=24, skipped=10, missing=0."""
        scanner = GoogleScanner("test_key", no_color=True)
        await scanner.scan()

        acc = scanner.check_accounting
        assert acc["planned"] == 24
        assert acc["skipped"] == 10
        assert acc["missing"] == 0

    @pytest.mark.asyncio
    async def test_google_without_project_id_no_silent_drop(self):
        """No check should be silently dropped — all 24 must have an outcome."""
        scanner = GoogleScanner("test_key", no_color=True)
        await scanner.scan()

        assert len(scanner.scan_results) == 24

    @pytest.mark.asyncio
    async def test_google_with_project_id_no_extra_skips(self):
        """Google scan with project_id should not skip project-scoped checks."""
        scanner = GoogleScanner("test_key", project_id="test-project", no_color=True)
        await scanner.scan()

        skipped = [r for r in scanner.scan_results if r.execution_status == ExecutionStatus.SKIPPED]
        project_scoped_skips = [r for r in skipped if "project_id" in r.reason]
        assert len(project_scoped_skips) == 0
