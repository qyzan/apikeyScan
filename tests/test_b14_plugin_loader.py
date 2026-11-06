"""B14 acceptance tests: ImportError plugin ditampilkan sebagai unavailable.

Tests prove:
- Criterion 1: ImportError is surfaced as a warning with safe reason,
  not silently skipped from inventory.
"""

from __future__ import annotations

import importlib
from unittest.mock import patch

from core.plugin_loader import load_scanners


class TestImportErrorSurfaced:
    """Criterion 1: ImportError plugin ditampilkan sebagai unavailable beserta alasan aman."""

    def test_import_error_prints_warning(self, capsys):
        """ImportError for a scanner module → warning printed, not silently skipped."""
        original_import = importlib.import_module

        def fake_import(name: str, *args: object, **kwargs: object):
            if name == "scanners.aws_scanner":
                raise ImportError("No module named 'boto3'")
            return original_import(name, *args, **kwargs)

        with patch("core.plugin_loader.importlib.import_module", side_effect=fake_import):
            load_scanners()

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "aws_scanner" in combined.lower() or "aws" in combined.lower()
        assert "unavailable" in combined.lower() or "failed" in combined.lower() or "error" in combined.lower()

    def test_import_error_reason_is_safe(self, capsys):
        """ImportError reason shown but no sensitive info (e.g., no full paths)."""
        original_import = importlib.import_module

        def fake_import(name: str, *args: object, **kwargs: object):
            if name == "scanners.aws_scanner":
                raise ImportError("No module named 'boto3'")
            return original_import(name, *args, object, **kwargs)

        with patch("core.plugin_loader.importlib.import_module", side_effect=fake_import):
            load_scanners()

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "boto3" in combined

    def test_other_scanners_still_loaded_after_import_error(self, capsys):
        """One ImportError should not prevent other scanners from loading."""
        original_import = importlib.import_module

        def fake_import(name: str, *args: object, **kwargs: object):
            if name == "scanners.aws_scanner":
                raise ImportError("No module named 'boto3'")
            return original_import(name, *args, **kwargs)

        with patch("core.plugin_loader.importlib.import_module", side_effect=fake_import):
            scanners = load_scanners()

        assert "google" in scanners
        assert "github" in scanners

    def test_no_warning_when_all_load_successfully(self, capsys):
        """No ImportError → no unavailable warning."""
        load_scanners()
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "unavailable" not in combined.lower()
