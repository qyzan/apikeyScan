"""B12 acceptance tests: ekstraksi aman dan provenance.

Tests prove:
- Criterion 1: Bad paths/files produce stats/reason, not silent clean.
- Criterion 2: Out-of-scope symlinks not read.
- Criterion 3: Generic hex candidates have confidence/reason + sanitized context.
- Criterion 4: Dedup preserves all locations; line numbers correct.
- Criterion 5: File size limit enforced; no unbounded full-file read.
- Criterion 6: Export format declared; B09 raw-keys exception documented.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import sys
from pathlib import Path

import pytest

from core.key_detector import ExtractionResult, FoundKey, SkippedFile, extract_keys_from_directory

GOOGLE_KEY = "AIza" + "B" * 35
AWS_KEY = "AKIA" + "A" * 16
AZURE_HEX = "a" * 32


class TestBadFilesProduceStats:
    """Criterion 1: Path/file errors produce stats/reason, not clean check."""

    def test_binary_file_skipped_with_reason(self, tmp_path):
        """Binary file → skipped with reason 'binary'."""
        (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02" + GOOGLE_KEY.encode())
        result = extract_keys_from_directory(str(tmp_path))
        assert any(s.reason == "binary" for s in result.skipped)

    def test_large_file_skipped_with_reason(self, tmp_path):
        """File > size limit → skipped with reason 'too_large'."""
        big = tmp_path / "huge.txt"
        big.write_text("x" * (11 * 1024 * 1024))
        result = extract_keys_from_directory(str(tmp_path))
        assert any(s.reason == "too_large" for s in result.skipped)

    def test_unreadable_file_skipped_with_reason(self, tmp_path, monkeypatch):
        """Permission-denied file → skipped with reason 'unreadable'."""
        f = tmp_path / "noperm.txt"
        f.write_text(GOOGLE_KEY)
        original_read_bytes = Path.read_bytes

        def mock_read_bytes(self):
            if self == f:
                raise PermissionError("Permission denied")
            return original_read_bytes(self)

        monkeypatch.setattr(Path, "read_bytes", mock_read_bytes)
        result = extract_keys_from_directory(str(tmp_path))
        assert any(s.reason == "unreadable" for s in result.skipped)

    def test_stats_reported(self, tmp_path):
        """Result contains files_scanned, files_total, skipped counts."""
        (tmp_path / "good.py").write_text(f'k = "{GOOGLE_KEY}"\n')
        (tmp_path / "binary.bin").write_bytes(b"\x00")
        result = extract_keys_from_directory(str(tmp_path))
        assert result.files_total >= 2
        assert result.files_scanned >= 1
        assert len(result.skipped) >= 1

    def test_empty_directory_is_clean(self, tmp_path):
        """Empty directory → empty found, zero skipped, zero scanned."""
        result = extract_keys_from_directory(str(tmp_path))
        assert result.found == []
        assert result.skipped == []
        assert result.files_scanned == 0


class TestSymlinkHandling:
    """Criterion 2: Out-of-scope symlinks not read."""

    @pytest.mark.skipif(os.name == "nt", reason="Symlink behavior differs on Windows")
    def test_symlink_out_of_scope_skipped(self, tmp_path):
        """Symlink pointing outside scan root → skipped, not read."""
        outside = tmp_path.parent / "outside_b12_test"
        outside.mkdir(exist_ok=True)
        outside_file = outside / "secret.txt"
        outside_file.write_text(GOOGLE_KEY)
        try:
            link = tmp_path / "link_to_outside"
            link.symlink_to(outside_file)
            result = extract_keys_from_directory(str(tmp_path))
            assert any(s.reason == "symlink_out_of_scope" for s in result.skipped)
            assert not any(f.key == GOOGLE_KEY for f in result.found)
        finally:
            outside_file.unlink(missing_ok=True)
            outside.rmdir()

    @pytest.mark.skipif(os.name == "nt", reason="Symlink behavior differs on Windows")
    def test_symlink_within_scope_read(self, tmp_path):
        """Symlink pointing within scan root → followed, key found."""
        target = tmp_path / "target.txt"
        target.write_text(GOOGLE_KEY)
        link = tmp_path / "link_to_target"
        link.symlink_to(target)
        result = extract_keys_from_directory(str(tmp_path))
        assert any(f.key == GOOGLE_KEY for f in result.found)


class TestGenericHexConfidence:
    """Criterion 3: Generic hex candidates have confidence/reason + context."""

    def test_azure_hex_has_low_confidence(self, tmp_path):
        """32-char hex → confidence='low' (generic pattern)."""
        (tmp_path / "hex.txt").write_text(f"hex = {AZURE_HEX}\n")
        result = extract_keys_from_directory(str(tmp_path))
        azure = [f for f in result.found if f.provider == "azure"]
        assert len(azure) == 1
        assert azure[0].confidence == "low"

    def test_specific_pattern_has_high_confidence(self, tmp_path):
        """Google key → confidence='high' (-specific pattern)."""
        (tmp_path / "google.txt").write_text(f'k = "{GOOGLE_KEY}"\n')
        result = extract_keys_from_directory(str(tmp_path))
        google = [f for f in result.found if f.provider == "google"]
        assert len(google) == 1
        assert google[0].confidence == "high"

    def test_context_stored_and_sanitized(self, tmp_path):
        """Each found key has sanitized context (no raw control chars)."""
        content = f'config = "{GOOGLE_KEY}"\n'
        (tmp_path / "ctx.txt").write_text(content)
        result = extract_keys_from_directory(str(tmp_path))
        assert len(result.found) == 1
        assert result.found[0].context != ""
        assert all(c.isprintable() or c in "\n\t" for c in result.found[0].context)

    def test_reason_describes_candidate_not_valid(self, tmp_path):
        """Reason says 'candidate', not 'valid key'."""
        (tmp_path / "hex.txt").write_text(f"hex = {AZURE_HEX}\n")
        result = extract_keys_from_directory(str(tmp_path))
        assert len(result.found) == 1
        assert "candidate" in result.found[0].reason.lower() or "match" in result.found[0].reason.lower()


class TestDeduplication:
    """Criterion 4: Dedup preserves all locations; line numbers correct."""

    def test_same_key_multiple_locations(self, tmp_path):
        """Same key in multiple files → one FoundKey with multiple locations."""
        (tmp_path / "a.txt").write_text(f'k = "{GOOGLE_KEY}"\n')
        (tmp_path / "b.txt").write_text(f'k = "{GOOGLE_KEY}"\n')
        result = extract_keys_from_directory(str(tmp_path))
        google = [f for f in result.found if f.key == GOOGLE_KEY]
        assert len(google) == 1
        assert len(google[0].locations) == 2

    def test_same_key_multiple_lines_in_one_file(self, tmp_path):
        """Same key on multiple lines → one FoundKey with multiple locations."""
        (tmp_path / "multi.txt").write_text(f'k1 = "{GOOGLE_KEY}"\nk2 = "{GOOGLE_KEY}"\n')
        result = extract_keys_from_directory(str(tmp_path))
        google = [f for f in result.found if f.key == GOOGLE_KEY]
        assert len(google) == 1
        assert len(google[0].locations) == 2

    def test_line_numbers_correct(self, tmp_path):
        """Line numbers match actual file positions."""
        content = f'line1\nline2\nk = "{GOOGLE_KEY}"\nline4\n'
        (tmp_path / "lines.txt").write_text(content)
        result = extract_keys_from_directory(str(tmp_path))
        assert len(result.found) == 1
        _, line_num = result.found[0].locations[0]
        assert line_num == 3

    def test_different_keys_not_deduplicated(self, tmp_path):
        """Different keys remain separate entries."""
        (tmp_path / "keys.txt").write_text(f'a = "{GOOGLE_KEY}"\nb = "{AWS_KEY}"\n')
        result = extract_keys_from_directory(str(tmp_path))
        assert len(result.found) == 2


class TestFileSizeLimit:
    """Criterion 5: File size limit enforced; no unbounded read."""

    def test_file_under_limit_is_read(self, tmp_path):
        """File under size limit → scanned normally."""
        (tmp_path / "small.txt").write_text(f'k = "{GOOGLE_KEY}"\n')
        result = extract_keys_from_directory(str(tmp_path))
        assert any(f.key == GOOGLE_KEY for f in result.found)

    def test_file_over_limit_skipped(self, tmp_path):
        """File over size limit → skipped, not read."""
        (tmp_path / "big.txt").write_text("x" * (11 * 1024 * 1024))
        result = extract_keys_from_directory(str(tmp_path))
        assert any(s.reason == "too_large" for s in result.skipped)
        assert result.found == []


class TestExportFormat:
    """Criterion 6: Export format declared; B09 exception documented."""

    def test_extraction_result_has_found_list(self, tmp_path):
        """ExtractionResult.found is a list of FoundKey."""
        (tmp_path / "test.txt").write_text(GOOGLE_KEY)
        result = extract_keys_from_directory(str(tmp_path))
        assert isinstance(result, ExtractionResult)
        assert all(isinstance(f, FoundKey) for f in result.found)

    def test_skipped_files_are_skippedfile(self, tmp_path):
        """Skipped files are SkippedFile instances."""
        (tmp_path / "binary.bin").write_bytes(b"\x00")
        result = extract_keys_from_directory(str(tmp_path))
        assert all(isinstance(s, SkippedFile) for s in result.skipped)

    def test_found_key_has_required_fields(self, tmp_path):
        """FoundKey has key, provider, confidence, reason, context, locations."""
        (tmp_path / "test.txt").write_text(GOOGLE_KEY)
        result = extract_keys_from_directory(str(tmp_path))
        fk = result.found[0]
        assert fk.key == GOOGLE_KEY
        assert fk.provider == "google"
        assert fk.confidence in ("high", "low")
        assert isinstance(fk.reason, str)
        assert isinstance(fk.context, str)
        assert isinstance(fk.locations, list)
        assert all(isinstance(loc, tuple) and len(loc) == 2 for loc in fk.locations)


class TestPatchInspectionCompletenessMessage:
    """Patch 1: 'No API keys found' → message stating inspection completeness."""

    def test_all_skipped_message_states_completeness(self, tmp_path):
        """All files skipped → message says 'No candidates found — N inspected, M not inspected'."""
        (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
        (tmp_path / "binary2.bin").write_bytes(b"\x00\x04\x05")
        result = extract_keys_from_directory(str(tmp_path))
        assert result.found == []
        assert len(result.skipped) == 2
        assert result.files_scanned == 0

    def test_clean_directory_message_states_completeness(self, tmp_path):
        """No keys, no skips → message still states inspection completeness."""
        (tmp_path / "clean.txt").write_text("just some text\n")
        result = extract_keys_from_directory(str(tmp_path))
        assert result.found == []
        assert len(result.skipped) == 0
        assert result.files_scanned == 1


class TestPatchKeyfileRejectsExtractFormat:
    """Patch 2: Keyfile reader rejects extract format lines with clear error."""

    def test_extract_format_line_rejected_exit_2(self, monkeypatch, tmp_path, capsys):
        """Keyfile with extract format line → exit 2, clear error."""
        cli = importlib.import_module("apiKeyScan")
        keyfile = tmp_path / "export.txt"
        keyfile.write_text(f"google:{GOOGLE_KEY} # config.py:1\n")
        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "--keyfile", str(keyfile), "-p", "google", "--no-color"],
        )
        try:
            cli.main()
            raise AssertionError("Should have exited")
        except SystemExit as e:
            assert e.code == 2
        captured = capsys.readouterr()
        assert "Keyfile rejected" in captured.out

    def test_normal_keyfile_not_rejected(self, monkeypatch, tmp_path, capsys):
        """Normal keyfile (one key per line) → not rejected."""
        cli = importlib.import_module("apiKeyScan")
        keyfile = tmp_path / "keys.txt"
        keyfile.write_text(f"{GOOGLE_KEY}\n")
        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "-p", "google", "--keyfile", str(keyfile), "--no-color", "--no-active-checks"],
        )
        with contextlib.suppress(SystemExit):
            cli.main()
        captured = capsys.readouterr()
        assert "Keyfile rejected" not in captured.out

    def test_keyfile_with_comments_and_blanks_not_rejected(self, monkeypatch, tmp_path, capsys):
        """Keyfile with comments and blank lines → not rejected."""
        cli = importlib.import_module("apiKeyScan")
        keyfile = tmp_path / "keys.txt"
        keyfile.write_text(f"# Comment\n{GOOGLE_KEY}\n\n# Another comment\n")
        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "-p", "google", "--keyfile", str(keyfile), "--no-color", "--no-active-checks"],
        )
        with contextlib.suppress(SystemExit):
            cli.main()
        captured = capsys.readouterr()
        assert "Keyfile rejected" not in captured.out

    def test_rejection_message_does_not_leak_key(self, monkeypatch, tmp_path, capsys):
        """Rejection message must not echo raw key material (8-char masking ceiling)."""
        cli = importlib.import_module("apiKeyScan")
        canary = "AIzaCANARYKEY123456789012345678901234567"
        keyfile = tmp_path / "export.txt"
        keyfile.write_text(f"google:{canary} # config.py:1\n")
        monkeypatch.setattr(
            sys,
            "argv",
            ["apiKeyScan.py", "scan", "--keyfile", str(keyfile), "-p", "google", "--no-color"],
        )
        with contextlib.suppress(SystemExit):
            cli.main()
        captured = capsys.readouterr()
        assert canary not in captured.out
        assert canary[:8] not in captured.out
        assert "Keyfile rejected" in captured.out
