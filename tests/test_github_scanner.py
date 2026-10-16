"""Tests for scanners/github_scanner.py — async check execution with mocks."""

from unittest.mock import AsyncMock

import pytest

from core.base_scanner import ResponseData
from scanners.github_scanner import GitHubScanner

GITHUB_HEADERS = {"Authorization": "Bearer ghp_test_token", "Accept": "application/vnd.github+json"}


def _mock_response(status: int = 200, body: bytes = b'{"data": []}') -> ResponseData:
    """Create a mock ResponseData for testing.

    Args:
        status: HTTP status code.
        body: Response body bytes.

    Returns:
        A ResponseData instance.
    """
    return ResponseData(
        status=status,
        headers={"X-OAuth-Scopes": "repo, read:user", "Content-Type": "application/json"},
        url="https://api.github.com/user",
        _body_bytes=body,
        _content_type="application/json",
    )


@pytest.mark.asyncio
async def test_github_scanner_user_profile():
    """GitHub user profile check should record a result with scopes."""
    scanner = GitHubScanner("ghp_test_token", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b'{"login": "testuser"}')))
    await scanner._check_user_profile(GITHUB_HEADERS)
    assert any("User Profile" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_github_scanner_repos():
    """GitHub repos check should record a result."""
    scanner = GitHubScanner("ghp_test_token", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b"[]")))
    await scanner._check_repos(GITHUB_HEADERS)
    assert any("Repos" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_github_scanner_unauthorized():
    """Invalid GitHub token should get UNAUTHORIZED status."""
    scanner = GitHubScanner("ghp_invalid_token", no_color=True)
    invalid_headers = {"Authorization": "Bearer ghp_invalid_token", "Accept": "application/vnd.github+json"}
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(401, b'{"message": "Bad credentials"}')))
    await scanner._check_user_profile(invalid_headers)
    assert any("UNAUTHORIZED" in r["status_text"] for r in scanner.results)


@pytest.mark.asyncio
async def test_github_scanner_gists():
    """GitHub gists check should record a result."""
    scanner = GitHubScanner("ghp_test_token", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b"[]")))
    await scanner._check_gists(GITHUB_HEADERS)
    assert any("Gists" in r["service"] for r in scanner.results)


def test_github_scanner_checks_attribute():
    """GitHubScanner should define CHECKS with 9 entries."""
    assert len(GitHubScanner.CHECKS) == 9


def test_github_scanner_provider_name():
    """GitHubScanner should have correct PROVIDER_NAME."""
    assert GitHubScanner.PROVIDER_NAME == "github"
