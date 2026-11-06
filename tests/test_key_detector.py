"""Tests for core/key_detector.py — regex detection, probe, extraction."""

from typing import Any
from unittest.mock import patch

import pytest

from core.key_detector import (
    DetectionConfidence,
    auto_detect_provider,
    detect_by_probe,
    detect_by_regex,
    detect_provider,
    extract_keys_from_directory,
    interactive_confirm,
)


class TestRegexDetection:
    """Tests for regex-based provider detection."""

    def test_detect_google_key(self):
        """Google API key format should be detected."""
        key = "AIza" + "B" * 35
        result = detect_by_regex(key)
        assert len(result) == 1
        assert result[0]["provider"] == "google"
        assert result[0]["confidence"] == DetectionConfidence.HIGH

    def test_detect_openai_key(self):
        """OpenAI API key format should be detected."""
        key = "sk-" + "a" * 30
        result = detect_by_regex(key)
        assert any(r["provider"] == "openai" for r in result)

    def test_detect_aws_key(self):
        """AWS Access Key ID format should be detected."""
        key = "AKIA" + "A" * 16
        result = detect_by_regex(key)
        assert any(r["provider"] == "aws" for r in result)

    def test_detect_github_key(self):
        """GitHub token format should be detected."""
        key = "ghp_" + "A" * 36
        result = detect_by_regex(key)
        assert any(r["provider"] == "github" for r in result)

    def test_detect_stripe_key(self):
        """Stripe live key format should be detected."""
        key = "sk_live_" + "a" * 30
        result = detect_by_regex(key)
        assert any(r["provider"] == "stripe" for r in result)

    def test_detect_gitlab_key(self):
        """GitLab PAT format should be detected."""
        key = "glpat-" + "a" * 20
        result = detect_by_regex(key)
        assert any(r["provider"] == "gitlab" for r in result)

    def test_detect_digitalocean_key(self):
        """DigitalOcean PAT format should be detected."""
        key = "dop_v1_" + "a" * 64
        result = detect_by_regex(key)
        assert any(r["provider"] == "digitalocean" for r in result)

    def test_detect_unknown_key(self):
        """Unknown key format should return empty list."""
        result = detect_by_regex("totally_unknown_format_12345")
        assert result == []

    def test_detect_provider_single_match(self):
        """detect_provider should return the provider for a clear match."""
        key = "AKIA" + "A" * 16
        assert detect_provider(key) == "aws"

    def test_detect_provider_no_match(self):
        """detect_provider should return None for unknown keys."""
        assert detect_provider("unknown_key") is None


class TestKeyExtraction:
    """Tests for filesystem key extraction."""

    def test_extract_from_directory(self, tmp_path):
        """Should find API keys in files."""
        test_file = tmp_path / "config.py"
        google_key = "AIza" + "B" * 35
        test_file.write_text(f'GOOGLE_KEY = "{google_key}"\n')

        result = extract_keys_from_directory(str(tmp_path))
        assert any(f.provider == "google" for f in result.found)

    def test_extract_skips_directories(self, tmp_path):
        """Should skip .git, node_modules, __pycache__ directories."""
        skip_dir = tmp_path / ".git"
        skip_dir.mkdir()
        skip_file = skip_dir / "config"
        google_key = "AIza" + "B" * 35
        skip_file.write_text(google_key)

        result = extract_keys_from_directory(str(tmp_path))
        assert len(result.found) == 0

    def test_extract_multiple_keys(self, tmp_path):
        """Should find multiple keys in a single file."""
        test_file = tmp_path / "keys.py"
        google_key = "AIza" + "B" * 35
        aws_key = "AKIA" + "A" * 16
        test_file.write_text(f'google = "{google_key}"\naws = "{aws_key}"\n')

        result = extract_keys_from_directory(str(tmp_path))
        providers = {f.provider for f in result.found}
        assert "google" in providers
        assert "aws" in providers

    def test_extract_empty_directory(self, tmp_path):
        """Should return empty result for directory with no keys."""
        result = extract_keys_from_directory(str(tmp_path))
        assert result.found == []


class TestOfflineAutoDetect:
    """B03: auto_detect_provider must not make network requests in default mode."""

    @pytest.mark.asyncio
    async def test_unknown_key_returns_unknown_no_network(self):
        """Unknown key format returns 'unknown' without any network request."""
        with patch("core.key_detector.detect_by_probe") as mock_probe:
            result = await auto_detect_provider("totally_unknown_format_12345", interactive=False)
            mock_probe.assert_not_called()
        assert result["provider"] == "unknown"
        assert result["confidence"] == DetectionConfidence.UNKNOWN
        assert result["method"] == "regex"

    @pytest.mark.asyncio
    async def test_single_match_returns_candidate_no_network(self):
        """Single regex match returns the candidate without network."""
        key = "AIza" + "B" * 35
        with patch("core.key_detector.detect_by_probe") as mock_probe:
            result = await auto_detect_provider(key, interactive=False)
            mock_probe.assert_not_called()
        assert result["provider"] == "google"
        assert result["confidence"] == DetectionConfidence.HIGH

    @pytest.mark.asyncio
    async def test_ambiguous_non_interactive_no_network(self):
        """Ambiguous key in non-interactive mode returns first candidate, no network."""
        with patch("core.key_detector.detect_by_probe") as mock_probe:
            result = await auto_detect_provider("AKIA" + "A" * 16, interactive=False)
            mock_probe.assert_not_called()
        assert result["provider"] is not None
        assert result["confidence"] == DetectionConfidence.HIGH or result["confidence"] == DetectionConfidence.MEDIUM

    @pytest.mark.asyncio
    async def test_force_probe_rejected(self):
        """force_probe=True returns a rejection result, no network."""
        with patch("core.key_detector.detect_by_probe") as mock_probe:
            result = await auto_detect_provider("AIza" + "B" * 35, force_probe=True)
            mock_probe.assert_not_called()
        assert result["provider"] is None
        assert result["method"] == "rejected"
        assert "disabled" in result["description"].lower()

    @pytest.mark.asyncio
    async def test_unknown_key_interactive_no_network(self):
        """Unknown key in interactive mode still returns unknown without network."""
        with patch("core.key_detector.detect_by_probe") as mock_probe:
            result = await auto_detect_provider("totally_unknown_format_12345", interactive=True)
            mock_probe.assert_not_called()
        assert result["provider"] == "unknown"


class TestInteractiveConfirmNoProbe:
    """B03: interactive_confirm must not offer a probe option."""

    def test_no_probe_option_in_menu(self, capsys):
        """Menu must not contain 'probe' or 'Try all providers'."""
        candidates = [
            {"provider": "google", "confidence": DetectionConfidence.HIGH, "method": "regex", "description": "Google"},
            {"provider": "azure", "confidence": DetectionConfidence.HIGH, "method": "regex", "description": "Azure"},
        ]
        with patch("builtins.input", return_value="1"):
            interactive_confirm("AIzaSyTestKey12345678901234567890", candidates)
        captured = capsys.readouterr()
        assert "probe" not in captured.out.lower()
        assert "try all" not in captured.out.lower()

    def test_select_second_candidate(self, capsys):
        """User can select candidate 2."""
        candidates = [
            {"provider": "google", "confidence": DetectionConfidence.HIGH, "method": "regex", "description": "Google"},
            {"provider": "azure", "confidence": DetectionConfidence.HIGH, "method": "regex", "description": "Azure"},
        ]
        with patch("builtins.input", return_value="2"):
            result = interactive_confirm("AIzaSyTestKey12345678901234567890", candidates)
        assert result["provider"] == "azure"

    def test_default_is_first_candidate(self, capsys):
        """Empty input defaults to candidate 1."""
        candidates = [
            {"provider": "google", "confidence": DetectionConfidence.HIGH, "method": "regex", "description": "Google"},
        ]
        with patch("builtins.input", return_value=""):
            result = interactive_confirm("AIzaSyTestKey12345678901234567890", candidates)
        assert result["provider"] == "google"


class TestDetectByProbeOkFalse:
    """B03: HTTP 200 with ok:false must not be treated as successful auth."""

    class _MockResp:
        def __init__(self, status: int, body: Any) -> None:
            self.status = status
            self._body = body

        async def json(self, content_type: Any = None) -> Any:
            if isinstance(self._body, dict):
                return self._body
            raise ValueError("not JSON")

        async def __aenter__(self) -> "TestDetectByProbeOkFalse._MockResp":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    class _MockSession:
        def __init__(self, responses: list[Any]) -> None:
            self._responses = list(responses)

        def request(self, method: str, url: str, headers: Any = None) -> Any:
            return self._responses.pop(0)

        async def __aenter__(self) -> "TestDetectByProbeOkFalse._MockSession":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    @pytest.mark.asyncio
    async def test_ok_false_not_success(self):
        """200 with {'ok': false} must not be treated as a valid detection."""
        resp = self._MockResp(200, {"ok": False, "error": "invalid_auth"})
        session = self._MockSession([resp])
        with patch("aiohttp.ClientSession", return_value=session):
            result = await detect_by_probe("xoxb-fake-token", ["slack"])
        assert result is None, "ok:false must not be treated as successful auth"

    @pytest.mark.asyncio
    async def test_ok_true_is_success(self):
        """200 with {'ok': true} should be treated as a valid detection."""
        resp = self._MockResp(200, {"ok": True, "url": "https://team.slack.com"})
        session = self._MockSession([resp])
        with patch("aiohttp.ClientSession", return_value=session):
            result = await detect_by_probe("xoxb-fake-token", ["slack"])
        assert result is not None
        assert result["provider"] == "slack"

    @pytest.mark.asyncio
    async def test_200_without_ok_field_is_success(self):
        """200 without an 'ok' field (e.g. GitHub) should still be success."""
        resp = self._MockResp(200, {"login": "testuser"})
        session = self._MockSession([resp])
        with patch("aiohttp.ClientSession", return_value=session):
            result = await detect_by_probe("ghp_fake_token_1234567890123456789012", ["github"])
        assert result is not None
        assert result["provider"] == "github"

    @pytest.mark.asyncio
    async def test_403_not_success(self):
        """403 status must not be treated as success."""
        resp = self._MockResp(403, {"message": "Bad credentials"})
        session = self._MockSession([resp])
        with patch("aiohttp.ClientSession", return_value=session):
            result = await detect_by_probe("ghp_fake_token_1234560123456789012", ["github"])
        assert result is None


class TestCliForceProbeRejection:
    """B03: CLI --force-probe must be rejected with exit code 2."""

    @pytest.mark.asyncio
    async def test_force_probe_rejected_exit_2(self, capsys):
        """--force-probe should print a rejection message and exit 2."""
        import importlib

        cli = importlib.import_module("apiKeyScan")
        args = cli.build_parser().parse_args(["scan", "-k", "dummy", "--force-probe"])
        exit_code = await cli.run_scan_command(args)
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "disabled" in captured.out.lower() or "probe" in captured.out.lower()
