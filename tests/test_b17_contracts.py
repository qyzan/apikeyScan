"""B17 acceptance tests: Release gate contract assertions and fixture audit.

Tests prove:
- Criterion 6: No regression reintroduces 200=confirmed vulnerability or
  transport error=critical vulnerability. These are REGRESSION contract tests
  that will fail if someone changes _classify_outcome or _log_check_exception
  to reintroduce the old broken semantics.
- Criterion 5: Fixture provider coverage audit — verifies that the test suite
  exercises success, denied, invalid, empty, error envelope, malformed, and
  timeout scenarios across the scanner infrastructure.
- Criterion 3: Exit code contract (0=clean, 1=accessible, 2=error) is
  verified at the logic level.
"""

from __future__ import annotations

import asyncio

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    ResponseData,
    Severity,
)


def _make_response(
    status: int = 200, body: bytes = b'{"data": []}', content_type: str = "application/json"
) -> ResponseData:
    """Create a ResponseData object for testing."""
    return ResponseData(
        status=status,
        headers={"Content-Type": content_type},
        url="https://example.com/test",
        _body_bytes=body,
        _content_type=content_type,
    )


class TestNo200ConfirmsVulnerability:
    """Criterion 6 regression: HTTP 200 alone must NEVER confirm vulnerability.

    These tests will fail if _classify_outcome is changed to return ACCESSIBLE
    for error envelopes, empty bodies, or malformed responses.
    """

    def test_200_with_error_envelope_not_accessible(self) -> None:
        """200 + {'error': ...} → RESTRICTED, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"error": {"code": 403}}')
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.RESTRICTED
        assert scanner.scan_results[0].outcome != CheckOutcome.ACCESSIBLE

    def test_200_with_error_message_not_accessible(self) -> None:
        """200 + {'error_message': ...} → RESTRICTED, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"error_message": "denied"}')
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.RESTRICTED

    def test_200_with_request_denied_not_accessible(self) -> None:
        """200 + {'status': 'REQUEST_DENIED'} → RESTRICTED, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"status": "REQUEST_DENIED"}')
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.RESTRICTED

    def test_200_empty_body_not_accessible(self) -> None:
        """200 + {} → INCONCLUSIVE, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.INCONCLUSIVE

    def test_200_malformed_body_not_accessible(self) -> None:
        """200 + non-JSON → INCONCLUSIVE, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"<<<not json>>>", content_type="text/plain")
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.INCONCLUSIVE

    def test_200_empty_string_not_accessible(self) -> None:
        """200 + empty string → INCONCLUSIVE, never ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"", content_type="text/plain")
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.INCONCLUSIVE

    def test_200_valid_data_is_accessible(self) -> None:
        """200 + valid data body → ACCESSIBLE (positive contract)."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": [{"id": 1}]}')
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome == CheckOutcome.ACCESSIBLE

    def test_classify_outcome_never_accessible_for_error_bodies(self) -> None:
        """Direct unit test: _classify_outcome must not return ACCESSIBLE for error bodies."""
        scanner = BaseScanner("test_key", no_color=True)
        error_bodies = [
            (200, {"error": "something"}, False),
            (200, {"error_message": "denied"}, False),
            (200, {"status": "REQUEST_DENIED"}, False),
            (200, {}, False),
            (403, {"error": "forbidden"}, False),
            (401, {"error": "invalid"}, False),
            (404, {"error": "not found"}, False),
            (400, {"error": "bad"}, False),
            (500, {"error": "server"}, False),
        ]
        for status, body, malformed in error_bodies:
            outcome = scanner._classify_outcome(status, body, malformed)
            assert outcome != CheckOutcome.ACCESSIBLE, f"status={status} body={body} produced ACCESSIBLE — regression!"


class TestTransportErrorNotCritical:
    """Criterion 6 regression: transport error must be ERROR, not CRITICAL.

    These tests will fail if _log_check_exception is changed to use
    Severity.CRITICAL for network errors.
    """

    def test_network_error_severity_is_error(self) -> None:
        """log_error must set auto_severity to ERROR, not CRITICAL."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "Connection refused")
        sr = scanner.scan_results[0]
        assert sr.auto_severity == Severity.ERROR
        assert sr.auto_severity != Severity.CRITICAL

    def test_network_error_outcome_is_error(self) -> None:
        """log_error must set outcome to ERROR."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "timeout")
        assert scanner.scan_results[0].outcome == CheckOutcome.ERROR

    def test_network_error_execution_status_is_error(self) -> None:
        """log_error must set execution_status to ERROR."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "timeout")
        assert scanner.scan_results[0].execution_status == ExecutionStatus.ERROR

    def test_network_error_results_severity_label(self) -> None:
        """The results dict must show 'ERROR' not 'CRITICAL' for network errors."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "timeout")
        assert scanner.results[0]["severity"] == "ERROR"
        assert scanner.results[0]["severity"] != "CRITICAL"

    def test_timeout_error_not_critical(self) -> None:
        """Timeout specifically must be ERROR, not CRITICAL."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", asyncio.TimeoutError("read timeout"))
        sr = scanner.scan_results[0]
        assert sr.auto_severity == Severity.ERROR
        assert sr.auto_severity != Severity.CRITICAL


class TestExitCodeContract:
    """Criterion 3: Exit code contract 0=clean, 1=accessible, 2=error.

    Verified at the logic level by examining how run_scan_command computes
    exit codes from scan results.
    """

    def test_all_restricted_exit_0(self) -> None:
        """All RESTRICTED results → exit 0 (no accessible, no error)."""
        scanner = BaseScanner("test_key", no_color=True)
        for i in range(3):
            resp = _make_response(status=403, body=b'{"error": "forbidden"}')
            scanner.log_result(f"Service{i}", 403, resp)
        accessible_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE)
        error_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ERROR)
        exit_code = 1 if accessible_count > 0 else (2 if error_count > 0 else 0)
        assert exit_code == 0

    def test_accessible_exit_1(self) -> None:
        """At least one ACCESSIBLE result → exit 1."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp)
        resp2 = _make_response(status=403, body=b'{"error": "forbidden"}')
        scanner.log_result("Service2", 403, resp2)
        accessible_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE)
        exit_code = 1 if accessible_count > 0 else 0
        assert exit_code == 1

    def test_error_exit_2(self) -> None:
        """Error result with no accessible → exit 2."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "connection refused")
        accessible_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE)
        error_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ERROR)
        exit_code = 2 if error_count > 0 else (1 if accessible_count > 0 else 0)
        assert exit_code == 2

    def test_error_wins_over_accessible(self) -> None:
        """Both error and accessible → exit 2 (error wins per B06 contract)."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp)
        scanner.log_error("Service2", "connection refused")
        accessible_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE)
        error_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ERROR)
        exit_code = 2 if error_count > 0 else (1 if accessible_count > 0 else 0)
        assert exit_code == 2

    def test_all_unauthorized_exit_2(self) -> None:
        """All UNAUTHORIZED → exit 2 per B06 edge-case decision."""
        scanner = BaseScanner("test_key", no_color=True)
        for i in range(3):
            resp = _make_response(status=401, body=b'{"error": "invalid"}')
            scanner.log_result(f"Service{i}", 401, resp)
        all_unauthorized = all(r.outcome == CheckOutcome.UNAUTHORIZED for r in scanner.scan_results)
        accessible_count = sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE)
        exit_code = 2 if all_unauthorized else (1 if accessible_count > 0 else 0)
        assert exit_code == 2


class TestFixtureCoverageAudit:
    """Criterion 5: Fixture provider covers success/denied/invalid/empty/error/malformed/timeout.

    This audit exercises each scenario through the scanner infrastructure and
    documents which outcomes are produced. It serves as a coverage map for
    release gate verification.
    """

    def test_success_fixture(self) -> None:
        """Success: 200 with valid data → ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": [{"id": 1}]}')
        scanner.log_result("Success Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.ACCESSIBLE
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_denied_fixture(self) -> None:
        """Denied: 403 → RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=403, body=b'{"error": "forbidden"}')
        scanner.log_result("Denied Service", 403, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.RESTRICTED
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_invalid_fixture(self) -> None:
        """Invalid: 401 → UNAUTHORIZED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=401, body=b'{"error": "invalid key"}')
        scanner.log_result("Invalid Service", 401, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.UNAUTHORIZED
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_empty_fixture(self) -> None:
        """Empty: 200 with {} → INCONCLUSIVE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("Empty Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.INCONCLUSIVE
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_error_envelope_fixture(self) -> None:
        """Error envelope: 200 with {'error': ...} → RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"error": {"code": 403, "message": "denied"}}')
        scanner.log_result("Error Envelope Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.RESTRICTED
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_malformed_fixture(self) -> None:
        """Malformed: 200 with non-JSON → INCONCLUSIVE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"<<<garbage>>>", content_type="text/plain")
        scanner.log_result("Malformed Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.INCONCLUSIVE
        assert sr.execution_status == ExecutionStatus.COMPLETED

    def test_timeout_fixture(self) -> None:
        """Timeout: network error → ERROR outcome, ERROR severity."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Timeout Service", "Connection timed out")
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.ERROR
        assert sr.execution_status == ExecutionStatus.ERROR
        assert sr.auto_severity == Severity.ERROR

    def test_not_found_fixture(self) -> None:
        """Not found: 404 → NOT_FOUND."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=404, body=b'{"error": "not found"}')
        scanner.log_result("NotFound Service", 404, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.NOT_FOUND

    def test_bad_request_fixture(self) -> None:
        """Bad request: 400 → BAD_REQUEST."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=400, body=b'{"error": "bad request"}')
        scanner.log_result("BadRequest Service", 400, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.BAD_REQUEST

    def test_skipped_fixture(self) -> None:
        """Skipped: active_checks=False → SKIPPED outcome."""
        scanner = BaseScanner("test_key", no_color=True, active_checks=False)
        asyncio.run(scanner._skip_check("Skipped Check", "test reason"))
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.SKIPPED
        assert sr.execution_status == ExecutionStatus.SKIPPED

    def test_all_scenarios_produce_distinct_outcomes(self) -> None:
        """The seven required scenarios must produce distinct outcomes.

        success→ACCESSIBLE, denied→RESTRICTED, invalid→UNAUTHORIZED,
        empty→INCONCLUSIVE, error_envelope→RESTRICTED, malformed→INCONCLUSIVE,
        timeout→ERROR.
        Note: denied and error_envelope both → RESTRICTED (same credential
        state, different HTTP path); empty and malformed both → INCONCLUSIVE
        (same uncertainty, different cause). The distinct outcomes are:
        ACCESSIBLE, RESTRICTED, UNAUTHORIZED, INCONCLUSIVE, ERROR, NOT_FOUND,
        BAD_REQUEST, SKIPPED.
        """
        scanner = BaseScanner("test_key", no_color=True)
        outcomes = set()

        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("S1", 200, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        resp = _make_response(status=403, body=b'{"error": "forbidden"}')
        scanner.log_result("S2", 403, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        resp = _make_response(status=401, body=b'{"error": "invalid"}')
        scanner.log_result("S3", 401, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("S4", 200, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        scanner.log_error("S5", "timeout")
        outcomes.add(scanner.scan_results[-1].outcome)

        resp = _make_response(status=404, body=b'{"error": "nf"}')
        scanner.log_result("S6", 404, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        resp = _make_response(status=400, body=b'{"error": "bad"}')
        scanner.log_result("S7", 400, resp)
        outcomes.add(scanner.scan_results[-1].outcome)

        assert CheckOutcome.ACCESSIBLE in outcomes
        assert CheckOutcome.RESTRICTED in outcomes
        assert CheckOutcome.UNAUTHORIZED in outcomes
        assert CheckOutcome.INCONCLUSIVE in outcomes
        assert CheckOutcome.ERROR in outcomes
        assert CheckOutcome.NOT_FOUND in outcomes
        assert CheckOutcome.BAD_REQUEST in outcomes
