"""Tests for core/report_engine.py — all 5 report formats."""

import json
import os

from core.base_scanner import BaseScanner, ResponseData, Severity
from core.report_engine import ReportEngine


def _make_test_scanner() -> BaseScanner:
    """Create a scanner with test results for report generation.

    Returns:
        A BaseScanner instance with sample results populated.
    """
    scanner = BaseScanner("test_key_12345", no_color=True)
    resp = ResponseData(
        status=200,
        headers={"Content-Type": "application/json"},
        url="https://api.example.com/test",
        _body_bytes=b'{"data": "test"}',
        _content_type="application/json",
    )
    scanner.log_result("Test Service 1", 200, resp, severity=Severity.HIGH)
    resp2 = ResponseData(
        status=403,
        headers={"Content-Type": "application/json"},
        url="https://api.example.com/denied",
        _body_bytes=b'{"error": "denied"}',
        _content_type="application/json",
    )
    scanner.log_result("Test Service 2", 403, resp2, severity=Severity.INFO)
    return scanner


class TestReportEngine:
    """Tests for all report format generation."""

    def test_json_report(self, tmp_path):
        """JSON report should be valid JSON with metadata."""
        scanner = _make_test_scanner()
        filename = str(tmp_path / "report.json")
        ReportEngine.generate_json_report(scanner, "test", filename)
        with open(filename) as f:
            data = json.load(f)
        assert "scan_metadata" in data
        assert data["scan_metadata"]["provider"] == "test"
        assert "results" in data
        assert len(data["results"]) == 2

    def test_csv_report(self, tmp_path):
        """CSV report should have correct headers and rows."""
        scanner = _make_test_scanner()
        filename = str(tmp_path / "report.csv")
        ReportEngine.generate_csv_report(scanner, "test", filename)
        with open(filename) as f:
            content = f.read()
        assert "service" in content
        assert "status_text" in content
        assert "severity" in content
        assert "Test Service 1" in content

    def test_sarif_report(self, tmp_path):
        """SARIF report should be valid SARIF 2.1.0 format."""
        scanner = _make_test_scanner()
        filename = str(tmp_path / "report.sarif")
        ReportEngine.generate_sarif_report(scanner, "test", filename)
        with open(filename) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "apiKeyScan"

    def test_html_report(self, tmp_path):
        """HTML report should contain dashboard and results."""
        scanner = _make_test_scanner()
        filename = str(tmp_path / "report.html")
        ReportEngine.generate_html_report(scanner, "test", filename)
        with open(filename) as f:
            content = f.read()
        assert "<html" in content
        assert "Summary Dashboard" in content
        assert "Severity Breakdown" in content
        assert "Test Service 1" in content

    def test_mask_key(self):
        """_mask_key should mask keys correctly."""
        assert ReportEngine._mask_key("1234567890ABCDE") == "12345...ABCDE"
        assert ReportEngine._mask_key("short") == "***"

    def test_all_reports(self, tmp_path):
        """generate_all_reports should produce all 4 format files."""
        scanner = _make_test_scanner()
        prefix = str(tmp_path / "report")
        files = ReportEngine.generate_all_reports(scanner, "test", prefix)
        assert len(files) == 4
        for f in files:
            assert os.path.exists(f)
