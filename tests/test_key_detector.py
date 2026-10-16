"""Tests for core/key_detector.py — regex detection, probe, extraction."""

from core.key_detector import (
    DetectionConfidence,
    detect_by_regex,
    detect_provider,
    extract_keys_from_directory,
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

        found = extract_keys_from_directory(str(tmp_path))
        assert any(f["provider"] == "google" for f in found)

    def test_extract_skips_directories(self, tmp_path):
        """Should skip .git, node_modules, __pycache__ directories."""
        skip_dir = tmp_path / ".git"
        skip_dir.mkdir()
        skip_file = skip_dir / "config"
        google_key = "AIza" + "B" * 35
        skip_file.write_text(google_key)

        found = extract_keys_from_directory(str(tmp_path))
        assert len(found) == 0

    def test_extract_multiple_keys(self, tmp_path):
        """Should find multiple keys in a single file."""
        test_file = tmp_path / "keys.py"
        google_key = "AIza" + "B" * 35
        aws_key = "AKIA" + "A" * 16
        test_file.write_text(f'google = "{google_key}"\naws = "{aws_key}"\n')

        found = extract_keys_from_directory(str(tmp_path))
        providers = {f["provider"] for f in found}
        assert "google" in providers
        assert "aws" in providers

    def test_extract_empty_directory(self, tmp_path):
        """Should return empty list for directory with no keys."""
        found = extract_keys_from_directory(str(tmp_path))
        assert found == []
