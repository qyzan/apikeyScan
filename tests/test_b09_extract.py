"""B09 acceptance tests: kontrak extract yang jujur.

Tests prove:
- Criterion 1: extract --scan no longer claims to run a scan.
- Criterion 2: --scan rejected with exit 2; no credential validation.
- Criterion 3: Exit semantics distinguish candidates found, not found,
  and inspection failure.
- Criterion 4: Tests do not send keys to providers.
"""

import importlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


def _run_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """Run CLI main() and return exit code via SystemExit."""
    cli = importlib.import_module("apiKeyScan")
    monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", *argv])
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def _make_repo_with_key(tmp_path: Path) -> Path:
    """Create a temp directory with a file containing a Google API key."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text('API_KEY = "AIzaSyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n', encoding="utf-8")
    return repo


class TestScanFlagRejected:
    """Criterion 1+2: --scan rejected, no scan claim, no credential validation."""

    def test_scan_flag_rejected_exit_2(self, monkeypatch, tmp_path):
        """extract --scan → exit 2, not exit 0 or 1."""
        repo = _make_repo_with_key(tmp_path)
        code = _run_cli(monkeypatch, ["extract", str(repo), "--scan", "--no-color"])
        assert code == 2

    def test_scan_rejected_before_extraction(self, monkeypatch, tmp_path):
        """--scan rejected before path inspection — non-existent path still exit 2."""
        code = _run_cli(
            monkeypatch,
            ["extract", str(tmp_path / "nonexistent"), "--scan", "--no-color"],
        )
        assert code == 2

    def test_no_scan_dispatch_called(self, monkeypatch, tmp_path):
        """--scan must not invoke any scanner or auto_detect_provider."""
        repo = _make_repo_with_key(tmp_path)
        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "extract", str(repo), "--scan", "--no-color"])
        with (
            patch.object(cli, "run_single_scan") as mock_scan,
            patch.object(cli, "auto_detect_provider") as mock_detect,
            pytest.raises(SystemExit) as excinfo,
        ):
            cli.main()
        assert excinfo.value.code == 2
        mock_scan.assert_not_called()
        mock_detect.assert_not_called()


class TestExitSemantics:
    """Criterion 3: Exit codes distinguish found, not found, failure."""

    def test_candidates_found_exit_1(self, monkeypatch, tmp_path):
        """Keys found in path → exit 1."""
        repo = _make_repo_with_key(tmp_path)
        code = _run_cli(monkeypatch, ["extract", str(repo), "--no-color"])
        assert code == 1

    def test_no_candidates_found_exit_0(self, monkeypatch, tmp_path):
        """No keys in path → exit 0."""
        repo = tmp_path / "clean_repo"
        repo.mkdir()
        (repo / "README.md").write_text("# Clean project\nNo secrets here.\n", encoding="utf-8")
        code = _run_cli(monkeypatch, ["extract", str(repo), "--no-color"])
        assert code == 0

    def test_nonexistent_path_exit_2(self, monkeypatch, tmp_path):
        """Path does not exist → exit 2."""
        code = _run_cli(
            monkeypatch,
            ["extract", str(tmp_path / "does_not_exist"), "--no-color"],
        )
        assert code == 2

    def test_file_not_directory_exit_2(self, monkeypatch, tmp_path):
        """Path is a file, not a directory → exit 2."""
        filepath = tmp_path / "not_a_dir.txt"
        filepath.write_text("content", encoding="utf-8")
        code = _run_cli(monkeypatch, ["extract", str(filepath), "--no-color"])
        assert code == 2

    def test_output_write_failure_exit_2(self, monkeypatch, tmp_path):
        """Output file in non-existent directory → exit 2."""
        repo = _make_repo_with_key(tmp_path)
        bad_output = str(tmp_path / "nonexistent_dir" / "keys.txt")
        code = _run_cli(
            monkeypatch,
            ["extract", str(repo), "--output", bad_output, "--no-color"],
        )
        assert code == 2

    def test_output_written_success_exit_1(self, monkeypatch, tmp_path):
        """Output file written successfully → exit 1 (candidates found)."""
        repo = _make_repo_with_key(tmp_path)
        output_file = tmp_path / "found_keys.txt"
        code = _run_cli(
            monkeypatch,
            ["extract", str(repo), "--output", str(output_file), "--no-color"],
        )
        assert code == 1
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "google:" in content


class TestNoProviderContact:
    """Criterion 4: Tests do not send keys to providers."""

    def test_extract_does_not_call_run_single_scan(self, monkeypatch, tmp_path):
        """extract (without --scan) must not invoke run_single_scan."""
        repo = _make_repo_with_key(tmp_path)
        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "extract", str(repo), "--no-color"])
        with patch.object(cli, "run_single_scan") as mock_scan, pytest.raises(SystemExit):
            cli.main()
        mock_scan.assert_not_called()

    def test_extract_does_not_call_auto_detect(self, monkeypatch, tmp_path):
        """extract must not invoke auto_detect_provider (no probe)."""
        repo = _make_repo_with_key(tmp_path)
        cli = importlib.import_module("apiKeyScan")
        monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", "extract", str(repo), "--no-color"])
        with patch.object(cli, "auto_detect_provider") as mock_detect, pytest.raises(SystemExit):
            cli.main()
        mock_detect.assert_not_called()


class TestHelpText:
    """Help text and subparser description are honest."""

    def test_extract_help_no_scan_claim(self, monkeypatch, tmp_path, capsys):
        """extract --help should not claim 'Auto-scan found keys'."""
        _run_cli(monkeypatch, ["extract", "--help"])
        captured = capsys.readouterr()
        assert "Auto-scan found keys" not in captured.out
        assert "Not yet supported" in captured.out

    def test_subparser_description_no_scan_claim(self, monkeypatch, tmp_path, capsys):
        """Top-level --help should not say 'Extract & scan'."""
        _run_cli(monkeypatch, ["--help"])
        captured = capsys.readouterr()
        assert "Extract & scan" not in captured.out
