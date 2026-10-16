"""Tests for core/plugin_loader.py — scanner discovery."""

from core.plugin_loader import list_checks, list_providers, load_scanners


class TestPluginLoader:
    """Tests for plugin auto-discovery."""

    def test_load_scanners_finds_all(self):
        """Should discover all 14 scanner providers."""
        scanners = load_scanners()
        assert len(scanners) >= 14

    def test_load_scanners_includes_google(self):
        """Should discover the Google scanner."""
        scanners = load_scanners()
        assert "google" in scanners

    def test_load_scanners_includes_github(self):
        """Should discover the GitHub scanner."""
        scanners = load_scanners()
        assert "github" in scanners

    def test_load_scanners_includes_aws(self):
        """Should discover the AWS scanner."""
        scanners = load_scanners()
        assert "aws" in scanners

    def test_list_providers_sorted(self):
        """list_providers should return sorted list."""
        providers = list_providers()
        assert providers == sorted(providers)

    def test_list_checks_all(self):
        """list_checks should return checks for all providers."""
        checks = list_checks()
        assert "google" in checks
        assert len(checks["google"]) >= 20

    def test_list_checks_single_provider(self):
        """list_checks with provider should return only that provider."""
        checks = list_checks("github")
        assert "github" in checks
        assert len(checks) == 1
