"""B16 acceptance tests: Container/output hygiene dan dokumentasi.

Tests prove:
- Criterion 1: Build context (via .dockerignore) excludes credentials,
  reports, VCS, and cache.  Canary fixture verifies exclusion patterns.
- Criterion 2: Compose uses named persistent volume and non-root user.
- Criterion 3: Minimum Python consistent across README, Dockerfile, and
  pyproject.toml manifest.
- Criterion 4: Config example does not contain real credentials and does
  not promise unavailable features.
- Criterion 5: Operational docs use Kapan/Siapa markers.  Docker build
  runtime not executed in this session — noted as acceptance not yet met.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestDockerignoreCanary:
    """Criterion 1: .dockerignore excludes credentials, reports, VCS, cache."""

    @pytest.fixture
    def dockerignore_content(self) -> str:
        path = PROJECT_ROOT / ".dockerignore"
        assert path.exists(), ".dockerignore missing — build context not constrained"
        return path.read_text()

    def test_vcs_excluded(self, dockerignore_content: str) -> None:
        """.git/ must be excluded from build context."""
        assert ".git/" in dockerignore_content

    def test_credentials_excluded(self, dockerignore_content: str) -> None:
        """Credential files (.env, .akv, credentials) must be excluded."""
        assert ".env" in dockerignore_content
        assert "*.akv" in dockerignore_content
        assert "credentials" in dockerignore_content

    def test_reports_excluded(self, dockerignore_content: str) -> None:
        """Generated reports must be excluded from build context."""
        assert "pentest_*_report" in dockerignore_content
        assert "reports/" in dockerignore_content

    def test_cache_excluded(self, dockerignore_content: str) -> None:
        """Python caches must be excluded from build context."""
        assert "__pycache__/" in dockerignore_content
        assert ".pytest_cache/" in dockerignore_content
        assert ".mypy_cache/" in dockerignore_content

    def test_build_artifacts_excluded(self, dockerignore_content: str) -> None:
        """Build artifacts must be excluded from build context."""
        assert "build/" in dockerignore_content
        assert "dist/" in dockerignore_content
        assert "*.egg-info/" in dockerignore_content

    def test_tests_excluded(self, dockerignore_content: str) -> None:
        """Test files should not be in the runtime image."""
        assert "tests/" in dockerignore_content


class TestGitignoreCoverage:
    """B15 reviewer note: .gitignore must cover build artifacts."""

    @pytest.fixture
    def gitignore_content(self) -> str:
        path = PROJECT_ROOT / ".gitignore"
        assert path.exists()
        return path.read_text()

    def test_build_artifacts_ignored(self, gitignore_content: str) -> None:
        """build/ and dist/ must be in .gitignore."""
        assert "build/" in gitignore_content
        assert "dist/" in gitignore_content

    def test_wheel_ignored(self, gitignore_content: str) -> None:
        """*.whl must be in .gitignore."""
        assert "*.whl" in gitignore_content

    def test_egg_info_ignored(self, gitignore_content: str) -> None:
        """*.egg-info/ must be in .gitignore."""
        assert "*.egg-info/" in gitignore_content

    def test_vault_files_ignored(self, gitignore_content: str) -> None:
        """*.akv and .env must be in .gitignore."""
        assert "*.akv" in gitignore_content
        assert ".env" in gitignore_content


class TestDockerfileHygiene:
    """Criterion 3: Dockerfile Python version consistent with manifest."""

    @pytest.fixture
    def dockerfile_content(self) -> str:
        path = PROJECT_ROOT / "Dockerfile"
        assert path.exists()
        return path.read_text()

    def test_uses_python310(self, dockerfile_content: str) -> None:
        """Dockerfile must use python:3.10-slim (matching pyproject.toml >=3.10)."""
        assert "python:3.10" in dockerfile_content

    def test_non_root_user(self, dockerfile_content: str) -> None:
        """Dockerfile must run as non-root user."""
        assert "USER" in dockerfile_content
        assert "useradd" in dockerfile_content or "adduser" in dockerfile_content

    def test_entrypoint_is_apikeyscan(self, dockerfile_content: str) -> None:
        """ENTRYPOINT must use the apikeyscan console script, not python apiKeyScan.py."""
        assert "apikeyscan" in dockerfile_content
        assert '["python", "apiKeyScan.py"]' not in dockerfile_content

    def test_no_copy_dot_dot(self, dockerfile_content: str) -> None:
        """Dockerfile must not use 'COPY . .' which copies everything."""
        assert "COPY . ." not in dockerfile_content


class TestComposeHygiene:
    """Criterion 2: Compose uses named volume and non-root user."""

    @pytest.fixture
    def compose_content(self) -> str:
        path = PROJECT_ROOT / "docker-compose.yml"
        assert path.exists()
        return path.read_text()

    def test_no_deprecated_version_key(self, compose_content: str) -> None:
        """Compose file must not use deprecated 'version' key."""
        assert not re.search(r"^version:", compose_content, re.MULTILINE)

    def test_named_volume(self, compose_content: str) -> None:
        """Must use a named volume, not a bind mount for reports."""
        assert "apikeyscan-reports" in compose_content
        assert "volumes:" in compose_content
        assert "./reports:/app/reports" not in compose_content

    def test_user_specified(self, compose_content: str) -> None:
        """Must specify a non-root user."""
        assert "user:" in compose_content
        assert "1000:1000" in compose_content

    def test_read_only_rootfs(self, compose_content: str) -> None:
        """Root filesystem should be read-only for security."""
        assert "read_only" in compose_content


class TestConfigExampleNoRealCredentials:
    """Criterion 4: Config example does not contain real credentials."""

    @pytest.fixture
    def config_content(self) -> str:
        path = PROJECT_ROOT / "config.example.yaml"
        assert path.exists()
        return path.read_text()

    def test_no_real_google_key(self, config_content: str) -> None:
        """No real Google API key pattern (AIzaSy followed by 30+ chars)."""
        assert not re.search(r"AIzaSy[0-9A-Za-z_-]{30,}", config_content)

    def test_no_real_github_token(self, config_content: str) -> None:
        """No real GitHub token pattern (ghp_ followed by 36+ chars)."""
        assert not re.search(r"ghp_[0-9A-Za-z]{36,}", config_content)

    def test_no_real_stripe_key(self, config_content: str) -> None:
        """No real Stripe key pattern (sk_live_ followed by 24+ chars)."""
        assert not re.search(r"sk_live_[0-9A-Za-z]{24,}", config_content)

    def test_no_real_slack_webhook(self, config_content: str) -> None:
        """No real Slack webhook (hooks.slack.com/services/T.../B.../...)."""
        assert not re.search(
            r"hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+",
            config_content,
        )

    def test_placeholder_values_present(self, config_content: str) -> None:
        """Config must contain explicit placeholder markers."""
        assert "PLACEHOLDER" in config_content or "your-" in config_content.lower()

    def test_no_costly_smoke_test_suggestion(self, config_content: str) -> None:
        """Config must not suggest running costly operations as smoke test."""
        lower = config_content.lower()
        assert "smoke test" not in lower or "do not" in lower or "placeholder" in lower


class TestReadmeConsistency:
    """Criterion 3: README Python version consistent with manifest."""

    @pytest.fixture
    def readme_content(self) -> str:
        path = PROJECT_ROOT / "README.md"
        assert path.exists()
        return path.read_text()

    @pytest.fixture
    def pyproject_content(self) -> str:
        path = PROJECT_ROOT / "pyproject.toml"
        assert path.exists()
        return path.read_text()

    def test_readme_says_python310(self, readme_content: str) -> None:
        """README must say Python 3.10+, not 3.8+."""
        assert "Python 3.10+" in readme_content
        assert "Python 3.8+" not in readme_content

    def test_pyproject_requires_python310(self, pyproject_content: str) -> None:
        """pyproject.toml must declare requires-python >=3.10."""
        assert 'requires-python = ">=3.10"' in pyproject_content

    def test_readme_no_probe_stale(self, readme_content: str) -> None:
        """README must not claim probe-based detection is active."""
        assert "network probe-based provider identification" not in readme_content

    def test_readme_documents_no_active_checks(self, readme_content: str) -> None:
        """README must document --no-active-checks flag."""
        assert "--no-active-checks" in readme_content

    def test_readme_documents_force_probe_deprecation(self, readme_content: str) -> None:
        """README must document --force-probe deprecation."""
        assert "--force-probe" in readme_content
        assert "deprecated" in readme_content.lower() or "rejected" in readme_content.lower()

    def test_readme_has_kapan_siapa_markers(self, readme_content: str) -> None:
        """Operational docs must use Kapan/Siapa markers (criterion 5)."""
        assert "Kapan" in readme_content
        assert "Siapa" in readme_content

    def test_readme_docker_status_noted(self, readme_content: str) -> None:
        """README must note Docker build/runtime status (criterion 5)."""
        assert "belum dieksekusi" in readme_content.lower() or "not yet" in readme_content.lower()


class TestReadmeArchitectureUpdated:
    """README architecture section must reflect current module structure."""

    @pytest.fixture
    def readme_content(self) -> str:
        return (PROJECT_ROOT / "README.md").read_text()

    def test_config_module_listed(self, readme_content: str) -> None:
        """Architecture section must list core/config.py."""
        assert "config.py" in readme_content

    def test_transport_module_listed(self, readme_content: str) -> None:
        """Architecture section must list core/transport.py."""
        assert "transport.py" in readme_content

    def test_redaction_module_listed(self, readme_content: str) -> None:
        """Architecture section must list core/redaction.py."""
        assert "redaction.py" in readme_content

    def test_vault_module_listed(self, readme_content: str) -> None:
        """Architecture section must list core/vault.py."""
        assert "vault.py" in readme_content
