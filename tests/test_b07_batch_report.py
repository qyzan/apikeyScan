"""B07 acceptance tests: report batch intact without overwrite.

Tests prove:
- Criterion 1: Two inputs with same prefix have traceable outcomes in output.
- Criterion 2: Failed/skipped items in manifest; counts reconciled.
- Criterion 3: No raw secret in filenames; explicit overwrite policy.
- Criterion 4: Write failure not reported as success; partial output marked.
"""

import importlib
import json
import sys
from contextlib import nullcontext
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
    api_key: str = "test_key_12345",
) -> BaseScanner:
    """Create a scanner with scan_results for the given outcome/execution pairs."""
    scanner = BaseScanner(api_key, no_color=True)
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


def _run_cli(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    scanners: list[BaseScanner | None] | None = None,
    auto_providers: list[str] | None = None,
) -> int:
    """Run CLI main() and return exit code via SystemExit."""
    cli = importlib.import_module("apiKeyScan")
    monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", *argv])

    run_cm = (
        patch.object(cli, "run_single_scan", AsyncMock(side_effect=scanners)) if scanners is not None else nullcontext()
    )
    auto_cm = (
        patch.object(
            cli,
            "auto_detect_provider",
            AsyncMock(side_effect=[{"provider": p} for p in auto_providers]),
        )
        if auto_providers is not None
        else nullcontext()
    )

    with run_cm, auto_cm, pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


class TestBatchTraceability:
    """Criterion 1: Two inputs with same prefix have traceable outcomes."""

    def test_batch_same_provider_same_prefix(self, monkeypatch, tmp_path):
        """Two github keys, same --output: both outcomes in JSON report."""
        scanner1 = _make_scanner_with_results(
            [(CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED)],
            api_key="ghp_key1_123456789",
        )
        scanner2 = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_key2_123456789",
        )

        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("ghp_key1_123456789\nghp_key2_123456789\n", encoding="utf-8")

        prefix = str(tmp_path / "report")
        code = _run_cli(
            monkeypatch,
            ["scan", "--keyfile", str(keyfile), "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner1, scanner2],
        )

        assert code == 1

        json_path = Path(f"{prefix}.json")
        assert json_path.exists()
        report = json.loads(json_path.read_text(encoding="utf-8"))

        assert "scans" in report
        assert len(report["scans"]) == 2

        all_outcomes = [r.get("outcome") for scan in report["scans"] for r in scan.get("results", [])]
        assert "accessible" in all_outcomes
        assert "restricted" in all_outcomes

    def test_batch_different_providers_same_prefix(self, monkeypatch, tmp_path):
        """Github + openai, same --output: both outcomes in JSON report."""
        scanner1 = _make_scanner_with_results(
            [(CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED)],
            api_key="ghp_key1_123456789",
        )
        scanner2 = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="sk-key2_1234567890",
        )

        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("ghp_key1_123456789\nsk-key2_1234567890\n", encoding="utf-8")

        prefix = str(tmp_path / "report")
        code = _run_cli(
            monkeypatch,
            ["scan", "--keyfile", str(keyfile), "--json", "-o", prefix, "--no-color"],
            scanners=[scanner1, scanner2],
            auto_providers=["github", "openai"],
        )

        assert code == 1

        json_path = Path(f"{prefix}.json")
        assert json_path.exists()
        report = json.loads(json_path.read_text(encoding="utf-8"))

        assert "scans" in report
        assert len(report["scans"]) == 2

        providers_in_report = [s.get("provider") for s in report["scans"]]
        assert "github" in providers_in_report
        assert "openai" in providers_in_report

    def test_single_key_preserves_flat_structure(self, monkeypatch, tmp_path):
        """Single-key mode: JSON report has flat structure (backward compatible)."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 1

        json_path = Path(f"{prefix}.json")
        assert json_path.exists()
        report = json.loads(json_path.read_text(encoding="utf-8"))

        assert "results" in report
        assert "scans" not in report


class TestManifestReconciliation:
    """Criterion 2: Failed/skipped items in manifest; counts reconciled."""

    def test_manifest_file_exists(self, monkeypatch, tmp_path):
        """Manifest file {prefix}_manifest.json is written."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 0

        manifest_path = Path(f"{prefix}_manifest.json")
        assert manifest_path.exists()

    def test_manifest_includes_skipped_inputs(self, monkeypatch, tmp_path):
        """Manifest records skipped inputs (unknown provider)."""
        scanner1 = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_key1_123456789",
        )

        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("ghp_key1_123456789\nunknown_key_format\n", encoding="utf-8")

        prefix = str(tmp_path / "report")
        _run_cli(
            monkeypatch,
            ["scan", "--keyfile", str(keyfile), "--json", "-o", prefix, "--no-color"],
            scanners=[scanner1],
            auto_providers=["github", "unknown"],
        )

        manifest_path = Path(f"{prefix}_manifest.json")
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert "inputs" in manifest
        assert len(manifest["inputs"]) == 2

        statuses = [inp.get("status") for inp in manifest["inputs"]]
        assert "completed" in statuses
        assert "skipped" in statuses

        skipped = next(inp for inp in manifest["inputs"] if inp.get("status") == "skipped")
        assert "reason" in skipped

    def test_manifest_includes_failed_inputs(self, monkeypatch, tmp_path):
        """Manifest records failed scan inputs (run_single_scan returns None)."""
        scanner1 = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_key1_123456789",
        )

        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("ghp_key1_123456789\nghp_key2_123456789\n", encoding="utf-8")

        prefix = str(tmp_path / "report")
        _run_cli(
            monkeypatch,
            ["scan", "--keyfile", str(keyfile), "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner1, None],
        )

        manifest_path = Path(f"{prefix}_manifest.json")
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert "inputs" in manifest
        assert len(manifest["inputs"]) == 2

        statuses = [inp.get("status") for inp in manifest["inputs"]]
        assert "completed" in statuses
        assert "failed" in statuses

    def test_manifest_reconciliation_counts(self, monkeypatch, tmp_path):
        """Manifest reconciliation: inputs_total == outcomes_recorded."""
        scanner1 = _make_scanner_with_results(
            [(CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED)],
            api_key="ghp_key1_123456789",
        )
        scanner2 = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_key2_123456789",
        )

        keyfile = tmp_path / "keys.txt"
        keyfile.write_text("ghp_key1_123456789\nghp_key2_123456789\n", encoding="utf-8")

        prefix = str(tmp_path / "report")
        _run_cli(
            monkeypatch,
            ["scan", "--keyfile", str(keyfile), "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner1, scanner2],
        )

        manifest_path = Path(f"{prefix}_manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert "reconciliation" in manifest
        recon = manifest["reconciliation"]
        assert recon["inputs_total"] == 2
        assert recon["outcomes_recorded"] == 2


class TestFilenameSafetyAndOverwrite:
    """Criterion 3: No raw secret in filenames; explicit overwrite."""

    def test_no_raw_key_in_default_filename(self, monkeypatch, tmp_path):
        """Default filename doesn't contain raw key."""
        raw_key = "ghp_secretkey_123456789"
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key=raw_key,
        )

        prefix = str(tmp_path / "pentest_github_report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", raw_key, "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 0

        json_path = Path(f"{prefix}.json")
        assert json_path.exists()
        assert raw_key not in json_path.name

        manifest_path = Path(f"{prefix}_manifest.json")
        assert manifest_path.exists()
        assert raw_key not in manifest_path.name

    def test_overwrite_without_flag_errors(self, monkeypatch, tmp_path):
        """Existing file without --overwrite → error exit 2."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        json_path = Path(f"{prefix}.json")
        json_path.write_text('{"existing": true}', encoding="utf-8")

        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2

        assert json.loads(json_path.read_text(encoding="utf-8")) == {"existing": True}

    def test_overwrite_with_flag_replaces(self, monkeypatch, tmp_path):
        """Existing file with --overwrite → replaced."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.ACCESSIBLE, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        json_path = Path(f"{prefix}.json")
        json_path.write_text('{"existing": true}', encoding="utf-8")

        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--overwrite", "--no-color"],
            scanners=[scanner],
        )

        assert code == 1

        report = json.loads(json_path.read_text(encoding="utf-8"))
        assert "existing" not in report
        assert "results" in report


class TestWriteFailureHandling:
    """Criterion 4: Write failure not success; partial output marked."""

    def test_write_failure_exit_2(self, monkeypatch, tmp_path):
        """Write failure → exit 2, not 0."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--no-color"],
        )

        with (
            patch.object(cli, "run_single_scan", AsyncMock(return_value=scanner)),
            patch.object(cli.ReportEngine, "generate_json_report", side_effect=OSError("disk full")),
            pytest.raises(SystemExit) as excinfo,
        ):
            cli.main()

        assert excinfo.value.code == 2

    def test_partial_output_marked_in_manifest(self, monkeypatch, tmp_path):
        """Some writes fail → manifest bundle_status = 'partial'."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "apiKeyScan.py",
                "scan",
                "-k",
                "ghp_test_123456789",
                "-p",
                "github",
                "--json",
                "--html",
                "-o",
                prefix,
                "--no-color",
            ],
        )

        with (
            patch.object(cli, "run_single_scan", AsyncMock(return_value=scanner)),
            patch.object(cli.ReportEngine, "generate_html_report", side_effect=OSError("disk full")),
            pytest.raises(SystemExit) as excinfo,
        ):
            cli.main()

        assert excinfo.value.code == 2

        manifest_path = Path(f"{prefix}_manifest.json")
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert manifest["bundle_status"] == "partial"

    def test_all_writes_success_bundle_complete(self, monkeypatch, tmp_path):
        """All writes succeed → manifest bundle_status = 'complete'."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        prefix = str(tmp_path / "report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 0

        manifest_path = Path(f"{prefix}_manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        assert manifest["bundle_status"] == "complete"


class TestOutputPrefixSanitization:
    """Blocker 1: Secret-like patterns in --output must be rejected."""

    def test_secret_in_output_prefix_rejected(self, monkeypatch, tmp_path):
        """--output with ghp_ prefix → exit 2, no file written."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        secret_prefix = str(tmp_path / "ghp_secretkey_123456789_report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", secret_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2
        assert not Path(f"{secret_prefix}.json").exists()
        assert not Path(f"{secret_prefix}_manifest.json").exists()

    def test_sk_prefix_in_output_rejected(self, monkeypatch, tmp_path):
        """--output with sk- prefix → exit 2."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        secret_prefix = str(tmp_path / "sk-live-key1234567890")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", secret_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2
        assert not Path(f"{secret_prefix}.json").exists()

    def test_safe_output_prefix_accepted(self, monkeypatch, tmp_path):
        """--output without secret pattern → normal operation."""
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key="ghp_test_123456789",
        )

        safe_prefix = str(tmp_path / "pentest_github_report")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test_123456789", "-p", "github", "--json", "-o", safe_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 0
        assert Path(f"{safe_prefix}.json").exists()

    def test_arbitrary_key_in_output_rejected(self, monkeypatch, tmp_path):
        """Non-standard key format in --output → exit 2 (credential comparison)."""
        raw_key = "RAW_SECRET_KEY_ABCDEFGH1234567890"
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key=raw_key,
        )

        secret_prefix = str(tmp_path / f"report_{raw_key}_data")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", raw_key, "-p", "github", "--json", "-o", secret_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2
        assert not Path(f"{secret_prefix}.json").exists()
        assert not Path(f"{secret_prefix}_manifest.json").exists()

    def test_short_key_in_output_rejected(self, monkeypatch, tmp_path):
        """Short key in --output → exit 2 (credential comparison catches it)."""
        raw_key = "abc123"
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key=raw_key,
        )

        secret_prefix = str(tmp_path / f"report_{raw_key}_data")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", raw_key, "-p", "github", "--json", "-o", secret_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2
        assert not Path(f"{secret_prefix}.json").exists()
        assert not Path(f"{secret_prefix}_manifest.json").exists()

    def test_key_fragment_in_output_rejected(self, monkeypatch, tmp_path):
        """≥8-char fragment of key in --output → exit 2 (fragment check)."""
        raw_key = "MySecretApiKey1234567890"
        scanner = _make_scanner_with_results(
            [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)],
            api_key=raw_key,
        )

        fragment_prefix = str(tmp_path / "report_SecretAp_data")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", raw_key, "-p", "github", "--json", "-o", fragment_prefix, "--no-color"],
            scanners=[scanner],
        )

        assert code == 2
        assert not Path(f"{fragment_prefix}.json").exists()
        assert not Path(f"{fragment_prefix}_manifest.json").exists()


class TestManifestReconciliationAnomalous:
    """Blocker 2: outcomes_recorded must count only terminal-status entries."""

    def test_anomalous_entry_not_counted(self, tmp_path):
        """Entry without status → outcomes_recorded < inputs_total."""
        from core.report_engine import ReportEngine

        inputs = [
            {"key_masked": "ghp_1...5678", "provider": "github", "status": "completed"},
            {"key_masked": "unknown", "provider": "unknown"},
        ]
        filename = str(tmp_path / "manifest.json")
        ReportEngine.generate_manifest(inputs, [], filename, "complete")
        manifest = json.loads(Path(filename).read_text(encoding="utf-8"))

        recon = manifest["reconciliation"]
        assert recon["inputs_total"] == 2
        assert recon["outcomes_recorded"] == 1

    def test_all_terminal_entries_counted(self, tmp_path):
        """All entries with terminal status → outcomes_recorded == inputs_total."""
        from core.report_engine import ReportEngine

        inputs = [
            {"key_masked": "ghp_1...5678", "provider": "github", "status": "completed"},
            {"key_masked": "ghp_2...5678", "provider": "github", "status": "failed"},
            {"key_masked": "unknown", "provider": "unknown", "status": "skipped"},
        ]
        filename = str(tmp_path / "manifest.json")
        ReportEngine.generate_manifest(inputs, [], filename, "complete")
        manifest = json.loads(Path(filename).read_text(encoding="utf-8"))

        recon = manifest["reconciliation"]
        assert recon["inputs_total"] == 3
        assert recon["outcomes_recorded"] == 3
