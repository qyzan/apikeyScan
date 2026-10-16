"""GitLab PAT scanner with async checks for project and group access.

Validates user, projects, groups, SSH keys, and personal access tokens
using PRIVATE-TOKEN header authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class GitLabScanner(BaseScanner):
    """Scanner for GitLab Personal Access Tokens.

    Checks user info, projects, groups, SSH keys, and PAT listing.
    """

    PROVIDER_NAME = "gitlab"
    CHECKS = [
        "User (GET /api/v4/user)",
        "Projects (GET /api/v4/projects)",
        "Groups (GET /api/v4/groups)",
        "SSH Keys (GET /api/v4/user/keys)",
        "Personal Access Tokens (GET /api/v4/personal_access_tokens)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the GitLab scanner.

        Args:
            api_key: The GitLab PAT (glpat-... format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all GitLab API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== GITLAB API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"PRIVATE-TOKEN": self.api_key}

        checks = [
            self._check_user(headers),
            self._check_projects(headers),
            self._check_groups(headers),
            self._check_ssh_keys(headers),
            self._check_pats(headers),
        ]
        await self._run_checks(checks)

    async def _check_user(self, headers: Dict[str, str]) -> None:
        """Check user endpoint — auth validation."""
        svc = "GitLab User"
        ok, resp = await self._safe_get(svc, "https://gitlab.com/api/v4/user", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_projects(self, headers: Dict[str, str]) -> None:
        """Check projects listing — project access."""
        svc = "GitLab Projects"
        ok, resp = await self._safe_get(svc, "https://gitlab.com/api/v4/projects?membership=true", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_groups(self, headers: Dict[str, str]) -> None:
        """Check groups listing — group access."""
        svc = "GitLab Groups"
        ok, resp = await self._safe_get(svc, "https://gitlab.com/api/v4/groups", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_ssh_keys(self, headers: Dict[str, str]) -> None:
        """Check SSH keys — key exposure risk."""
        svc = "GitLab SSH Keys"
        ok, resp = await self._safe_get(svc, "https://gitlab.com/api/v4/user/keys", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_pats(self, headers: Dict[str, str]) -> None:
        """Check personal access tokens — token enumeration."""
        svc = "GitLab Personal Access Tokens"
        ok, resp = await self._safe_get(svc, "https://gitlab.com/api/v4/personal_access_tokens", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)
