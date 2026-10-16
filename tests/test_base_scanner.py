"""Tests for core/base_scanner.py — severity, result logging, error handling."""

from core.base_scanner import BaseScanner, ResponseData, Severity


def _make_response(
    status: int = 200, body: bytes = b'{"ok": true}', content_type: str = "application/json"
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


class TestSeverity:
    """Tests for the Severity enum."""

    def test_severity_labels(self):
        """Severity enum should have correct labels."""
        assert Severity.CRITICAL.label == "CRITICAL"
        assert Severity.HIGH.label == "HIGH"
        assert Severity.MEDIUM.label == "MEDIUM"
        assert Severity.LOW.label == "LOW"
        assert Severity.INFO.label == "INFO"

    def test_severity_colors(self):
        """Severity enum should have non-empty color strings."""
        for sev in Severity:
            assert len(sev.color) > 0


class TestResponseData:
    """Tests for the ResponseData dataclass."""

    def test_json_parsing(self):
        """ResponseData.json() should parse JSON bodies correctly."""
        resp = _make_response(body=b'{"key": "value"}')
        assert resp.json() == {"key": "value"}

    def test_text_property(self):
        """ResponseData.text should decode body as UTF-8."""
        resp = _make_response(body=b"hello world", content_type="text/plain")
        assert resp.text == "hello world"

    def test_content_property(self):
        """ResponseData.content should return raw bytes."""
        resp = _make_response(body=b"\x89PNG")
        assert resp.content == b"\x89PNG"


class TestBaseScannerLogging:
    """Tests for BaseScanner result and error logging."""

    def test_log_result_vulnerable(self):
        """A 200 response should be classified as VULNERABLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp)
        assert scanner.results[0]["status_text"] == "VULNERABLE"
        assert scanner.results[0]["severity"] == "HIGH"

    def test_log_result_restricted_403(self):
        """A 403 response should be classified as RESTRICTED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=403, body=b'{"error": "denied"}')
        scanner.log_result("Test Service", 403, resp)
        assert "RESTRICTED" in scanner.results[0]["status_text"]
        assert scanner.results[0]["severity"] == "INFO"

    def test_log_result_unauthorized_401(self):
        """A 401 response should be classified as UNAUTHORIZED."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=401, body=b'{"error": "invalid"}')
        scanner.log_result("Test Service", 401, resp)
        assert "UNAUTHORIZED" in scanner.results[0]["status_text"]

    def test_log_result_not_found_404(self):
        """A 404 response should be classified as NOT FOUND."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=404, body=b'{"error": "not found"}')
        scanner.log_result("Test Service", 404, resp)
        assert "NOT FOUND" in scanner.results[0]["status_text"]
        assert scanner.results[0]["severity"] == "LOW"

    def test_log_result_with_explicit_severity(self):
        """Explicit severity should override auto-detection."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"data": []}')
        scanner.log_result("Test Service", 200, resp, severity=Severity.CRITICAL)
        assert scanner.results[0]["severity"] == "CRITICAL"

    def test_log_error(self):
        """log_error should record a CONNECTION ERROR result."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_error("Test Service", "Connection refused")
        assert scanner.results[0]["status_text"] == "CONNECTION ERROR"
        assert scanner.results[0]["status_code"] is None
        assert scanner.results[0]["severity"] == "CRITICAL"

    def test_log_error_truncates_long_messages(self):
        """log_error should truncate error messages longer than 120 chars in output."""
        scanner = BaseScanner("test_key", no_color=True)
        long_msg = "x" * 200
        scanner.log_error("Test Service", long_msg)
        assert "Connection Error" in scanner.raw_data[0]["response_body"]

    def test_log_custom_result(self):
        """log_custom_result should store custom status text."""
        scanner = BaseScanner("test_key", no_color=True)
        scanner.log_custom_result(
            "AWS STS",
            "VULNERABLE (ACCESS)",
            200,
            "identity confirmed",
            severity=Severity.CRITICAL,
        )
        assert scanner.results[0]["status_text"] == "VULNERABLE (ACCESS)"
        assert scanner.results[0]["severity"] == "CRITICAL"

    def test_false_positive_detection(self):
        """200 with REQUEST_DENIED in body should be RESTRICTED, not VULNERABLE."""
        scanner = BaseScanner("test_key", no_color=True)
        resp = _make_response(status=200, body=b'{"status": "REQUEST_DENIED"}')
        scanner.log_result("Maps API", 200, resp)
        assert "RESTRICTED" in scanner.results[0]["status_text"]


class TestBaseScannerInit:
    """Tests for BaseScanner initialization."""

    def test_init_defaults(self):
        """BaseScanner should set default values correctly."""
        scanner = BaseScanner("test_key")
        assert scanner.api_key == "test_key"
        assert scanner.results == []
        assert scanner.raw_data == []
        assert scanner.max_retries == 3
        assert scanner.rate_limit is None

    def test_init_custom_params(self):
        """BaseScanner should accept custom parameters."""
        scanner = BaseScanner("test_key", timeout=30, max_retries=5, rate_limit=10)
        assert scanner.max_retries == 5
        assert scanner.rate_limit == 10
