"""B04 acceptance tests: unified result contract and outcome semantics.

Tests prove:
- ScanResult unifies check, outcome, reason, and evidence in one object.
- Execution status is separate from credential outcome.
- Distinct outcomes for 200 empty, error envelope, denied, timeout, malformed, success.
- 200 alone does not claim confirmed vulnerability; network error is not CRITICAL.
- Inconclusive candidates are stored; reviewer severity is not auto-overridden.
- results/raw_data are derived from scan_results (no parallel-list association).
"""

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    ResponseData,
    ScanResult,
    Severity,
)


def _make_response(
    status: int = 200, body: bytes = b'{"data": []}', content_type: str = "application/json"
) -> ResponseData:
    """Create a ResponseData object for testing.

    Args:
        status: HTTP status code.
        body: Response body bytes.
        content_type: Content-Type header value.

    Returns:
        A ResponseData instance.
    """
    return ResponseData(
        status=status,
        headers={"Content-Type": content_type},
        url="https://example.com/test",
        _body_bytes=body,
        _content_type=content_type,
    )


class TestScanResultModel:
    """B04: ScanResult unifies check, outcome, reason, and evidence."""

    def test_scan_results_is_list_of_scanresult(self):
        """scan_results should be a list of ScanResult objects."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        assert len(scanner.scan_results) == 1
        assert isinstance(scanner.scan_results[0], ScanResult)

    def test_results_derived_from_scan_results(self):
        """results property should derive from scan_results, not be a separate list."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        assert len(scanner.results) == len(scanner.scan_results)
        assert scanner.results[0]["service"] == scanner.scan_results[0].service_name

    def test_raw_data_derived_from_scan_results(self):
        """raw_data property should derive from scan_results, not be a separate list."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        assert len(scanner.raw_data) == len(scanner.scan_results)
        assert scanner.raw_data[0]["url"] == scanner.scan_results[0].url

    def test_outcome_field_present_in_derived_views(self):
        """Both results and raw_data should include the outcome field."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        assert "outcome" in scanner.results[0]
        assert "outcome" in scanner.raw_data[0]

    def test_execution_status_separate_from_outcome(self):
        """ExecutionStatus and CheckOutcome should be separate enums."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.execution_status == ExecutionStatus.COMPLETED
        assert sr.outcome == CheckOutcome.ACCESSIBLE
        assert sr.execution_status != sr.outcome

    def test_status_text_is_display_not_contract(self):
        """status_text should be a derived display string, not the machine contract."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.status_text == "ACCESSIBLE"
        assert sr.outcome == CheckOutcome.ACCESSIBLE
        assert sr.outcome.value == "accessible"


class TestDistinctOutcomes:
    """B04: Different fixtures produce different outcomes with traceable reasons."""

    def test_200_success_is_accessible(self):
        """200 with valid data should be ACCESSIBLE, not VULNERABLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.ACCESSIBLE
        assert sr.status_text == "ACCESSIBLE"
        assert sr.auto_severity == Severity.HIGH
        assert "valid response" in sr.reason

    def test_200_empty_body_is_inconclusive(self):
        """200 with empty body should be INCONCLUSIVE, not ACCESSIBLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.INCONCLUSIVE
        assert sr.status_text == "INCONCLUSIVE"
        assert "inconclusive" in sr.reason

    def test_200_empty_string_body_is_inconclusive(self):
        """200 with empty string body should be INCONCLUSIVE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"", content_type="text/plain")
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.INCONCLUSIVE

    def test_200_error_envelope_is_restricted(self):
        """200 with error envelope in body should be RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"error": {"code": 403, "message": "denied"}}')
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.RESTRICTED
        assert sr.status_text == "RESTRICTED"
        assert sr.auto_severity == Severity.MEDIUM

    def test_200_request_denied_is_restricted(self):
        """200 with REQUEST_DENIED status in body should be RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"status": "REQUEST_DENIED"}')
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.RESTRICTED

    def test_403_denied_is_restricted(self):
        """403 should be RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=403, body=b'{"error": "forbidden"}')
        scanner.log_result("Service", 403, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.RESTRICTED
        assert sr.auto_severity == Severity.INFO

    def test_401_unauthorized(self):
        """401 should be UNAUTHORIZED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=401, body=b'{"error": "invalid"}')
        scanner.log_result("Service", 401, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.UNAUTHORIZED
        assert sr.auto_severity == Severity.INFO

    def test_404_not_found(self):
        """404 should be NOT_FOUND."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=404, body=b'{"error": "not found"}')
        scanner.log_result("Service", 404, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.NOT_FOUND
        assert sr.auto_severity == Severity.LOW

    def test_400_bad_request(self):
        """400 should be BAD_REQUEST."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=400, body=b'{"error": "bad request"}')
        scanner.log_result("Service", 400, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.BAD_REQUEST
        assert sr.auto_severity == Severity.MEDIUM

    def test_network_error_is_error_not_critical(self):
        """Network error should be ERROR severity, not CRITICAL."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "Connection refused")
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.ERROR
        assert sr.execution_status == ExecutionStatus.ERROR
        assert sr.auto_severity == Severity.ERROR
        assert sr.auto_severity != Severity.CRITICAL

    def test_malformed_body_is_inconclusive(self):
        """200 with malformed (non-JSON) body should be INCONCLUSIVE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"<<<not json>>>", content_type="text/plain")
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.INCONCLUSIVE
        assert "malformed" in sr.reason

    def test_image_response_is_accessible(self):
        """200 with image content should be ACCESSIBLE (not malformed)."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"\x89PNG\r\n\x1a\n", content_type="image/png")
        scanner.log_result("Service", 200, resp)
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.ACCESSIBLE

    def test_skipped_check_is_skipped_outcome(self):
        """Skipped check should have SKIPPED outcome and execution status."""
        scanner = BaseScanner("test_key", no_color=True, active_checks=False)
        scanner.scan_results = []
        import asyncio

        asyncio.run(scanner._skip_check("Test Check", "test reason"))
        sr = scanner.scan_results[0]
        assert sr.outcome == CheckOutcome.SKIPPED
        assert sr.execution_status == ExecutionStatus.SKIPPED
        assert sr.status_text == "SKIPPED (ACTIVE CHECK)"


class TestNoFalseClaims:
    """B04: 200 alone ≠ confirmed vulnerability; network error ≠ CRITICAL."""

    def test_200_empty_does_not_claim_accessible(self):
        """200 with empty body must not produce ACCESSIBLE outcome."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].outcome != CheckOutcome.ACCESSIBLE

    def test_network_error_not_critical_vulnerability(self):
        """Network error must not be CRITICAL severity."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "timeout")
        assert scanner.scan_results[0].auto_severity != Severity.CRITICAL
        assert scanner.results[0]["severity"] == "ERROR"


class TestInconclusiveAndReviewerSeverity:
    """B04: Inconclusive stored; reviewer severity not auto-overridden."""

    def test_inconclusive_result_is_stored(self):
        """Inconclusive results should be stored, not dropped."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b"{}")
        scanner.log_result("Service", 200, resp)
        assert len(scanner.scan_results) == 1
        assert scanner.scan_results[0].outcome == CheckOutcome.INCONCLUSIVE

    def test_reviewer_severity_not_auto_overridden(self):
        """reviewer_severity should be None by default, not auto-set."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp)
        assert scanner.scan_results[0].reviewer_severity is None

    def test_effective_severity_uses_reviewer_when_set(self):
        """effective_severity should prefer reviewer_severity over auto."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp)
        scanner.scan_results[0].reviewer_severity = Severity.CRITICAL
        assert scanner.scan_results[0].effective_severity == Severity.CRITICAL
        assert scanner.results[0]["severity"] == "CRITICAL"

    def test_explicit_severity_preserved(self):
        """Explicit severity passed to log_result should be preserved as auto_severity."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Service", 200, resp, severity=Severity.CRITICAL)
        assert scanner.scan_results[0].auto_severity == Severity.CRITICAL


class TestReasonTraceability:
    """B04: Every outcome has a traceable reason string."""

    def test_reason_non_empty_for_completed_checks(self):
        """Completed checks should have non-empty reason strings."""
        scanner = BaseScanner("test_key", no_color=True)
        for status, body in [
            (200, b'{"data": []}'),
            (200, b"{}"),
            (200, b'{"error": "denied"}'),
            (403, b'{"error": "forbidden"}'),
            (401, b'{"error": "invalid"}'),
            (404, b'{"error": "not found"}'),
            (400, b'{"error": "bad"}'),
        ]:
            scanner.scan_results = []
            resp = _make_response(status=status, body=body)
            scanner.log_result("Service", status, resp)
            assert scanner.scan_results[0].reason != "", f"reason empty for status {status}"

    def test_reason_non_empty_for_errors(self):
        """Error checks should have non-empty reason strings."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Service", "Connection refused")
        assert scanner.scan_results[0].reason != ""
        assert "Network error" in scanner.scan_results[0].reason
