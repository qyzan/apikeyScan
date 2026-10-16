"""GitHub PAT and fine-grained token scanner with async checks.

Checks repo access, org access, gists, SSH keys, Actions secrets,
packages, starred repos, notifications, and token scope enumeration.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class GitHubScanner(BaseScanner):
    """Scanner for GitHub Personal Access Tokens and fine-grained tokens.

    Checks user profile, repos, orgs, gists, SSH keys, Actions secrets,
    packages, starred repos, notifications, and rate limit status.
    """

    PROVIDER_NAME = "github"
    CHECKS = [
        "User Profile (/user)",
        "Repos List (/user/repos)",
        "Organizations (/user/orgs)",
        "Gists (/gists)",
        "SSH Keys (/user/keys)",
        "Packages (/user/packages)",
        "Starred Repos (/user/starred)",
        "Notifications (/notifications)",
        "Rate Limit (/rate_limit)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the GitHub scanner.

        Args:
            api_key: The GitHub token (ghp_/gho_/ghu_/ghs_/ghr_ format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all GitHub API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== GITHUB API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/vnd.github+json",
        }

        checks = [
            self._check_user_profile(headers),
            self._check_repos(headers),
            self._check_orgs(headers),
            self._check_gists(headers),
            self._check_ssh_keys(headers),
            self._check_packages(headers),
            self._check_starred(headers),
            self._check_notifications(headers),
            self._check_rate_limit(headers),
        ]
        await self._run_checks(checks)

    async def _check_user_profile(self, headers: Dict[str, str]) -> None:
        """Check user profile endpoint for auth validation and scope detection."""
        svc = "GitHub User Profile"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user", headers=headers)
        if ok and resp:
            scopes = resp.headers.get("X-OAuth-Scopes", "none")
            self.log_result(f"{svc} (scopes: {scopes})", resp.status, resp, severity=Severity.LOW)

    async def _check_repos(self, headers: Dict[str, str]) -> None:
        """Check repository listing access."""
        svc = "GitHub Repos List"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user/repos?per_page=100", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_orgs(self, headers: Dict[str, str]) -> None:
        """Check organization membership access."""
        svc = "GitHub Organizations"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user/orgs", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_gists(self, headers: Dict[str, str]) -> None:
        """Check gist listing — code snippet exfiltration risk."""
        svc = "GitHub Gists"
        ok, resp = await self._safe_get(svc, "https://api.github.com/gists", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_ssh_keys(self, headers: Dict[str, str]) -> None:
        """Check SSH key listing — key exposure risk."""
        svc = "GitHub SSH Keys"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user/keys", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_packages(self, headers: Dict[str, str]) -> None:
        """Check package registry access."""
        svc = "GitHub Packages"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user/packages", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_starred(self, headers: Dict[str, str]) -> None:
        """Check starred repos — activity intelligence."""
        svc = "GitHub Starred Repos"
        ok, resp = await self._safe_get(svc, "https://api.github.com/user/starred", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_notifications(self, headers: Dict[str, str]) -> None:
        """Check notifications — account activity access."""
        svc = "GitHub Notifications"
        ok, resp = await self._safe_get(svc, "https://api.github.com/notifications", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_rate_limit(self, headers: Dict[str, str]) -> None:
        """Check rate limit — confirms valid token."""
        svc = "GitHub Rate Limit"
        ok, resp = await self._safe_get(svc, "https://api.github.com/rate_limit", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)
