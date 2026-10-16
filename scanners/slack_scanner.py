"""Slack API scanner with async checks for workspace access.

Validates auth test, channels, users, team info, and files listing
using Bearer token authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class SlackScanner(BaseScanner):
    """Scanner for Slack API tokens (bot, user, app, refresh, session).

    Checks auth test, conversations, users, team info, and files access.
    """

    PROVIDER_NAME = "slack"
    CHECKS = [
        "Auth Test (GET /api/auth.test)",
        "Channels List (GET /api/conversations.list)",
        "Users List (GET /api/users.list)",
        "Team Info (GET /api/team.info)",
        "Files List (GET /api/files.list)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the Slack scanner.

        Args:
            api_key: The Slack token (xoxb-/xoxp-/xoxa-/xoxr-/xoxs- format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all Slack API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== SLACK API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"Authorization": f"Bearer {self.api_key}"}

        checks = [
            self._check_auth_test(headers),
            self._check_conversations(headers),
            self._check_users(headers),
            self._check_team_info(headers),
            self._check_files(headers),
        ]
        await self._run_checks(checks)

    async def _check_auth_test(self, headers: Dict[str, str]) -> None:
        """Check auth test — auth validation and workspace info."""
        svc = "Slack Auth Test"
        ok, resp = await self._safe_get(svc, "https://slack.com/api/auth.test", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_conversations(self, headers: Dict[str, str]) -> None:
        """Check conversations listing — channel access."""
        svc = "Slack Channels List"
        ok, resp = await self._safe_get(svc, "https://slack.com/api/conversations.list", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_users(self, headers: Dict[str, str]) -> None:
        """Check users listing — member enumeration."""
        svc = "Slack Users List"
        ok, resp = await self._safe_get(svc, "https://slack.com/api/users.list", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_team_info(self, headers: Dict[str, str]) -> None:
        """Check team info — workspace details."""
        svc = "Slack Team Info"
        ok, resp = await self._safe_get(svc, "https://slack.com/api/team.info", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_files(self, headers: Dict[str, str]) -> None:
        """Check files listing — file access."""
        svc = "Slack Files List"
        ok, resp = await self._safe_get(svc, "https://slack.com/api/files.list", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)
