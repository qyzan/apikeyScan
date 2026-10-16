"""Discord bot token scanner with async checks for server access.

Validates user info, guilds (servers), and application info
using Bot token authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class DiscordScanner(BaseScanner):
    """Scanner for Discord bot tokens.

    Checks user info, guild listing, and application info including scopes.
    """

    PROVIDER_NAME = "discord"
    CHECKS = [
        "Get User (GET /users/@me)",
        "Get Guilds (GET /users/@me/guilds)",
        "Get Application (GET /oauth2/applications/@me)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the Discord scanner.

        Args:
            api_key: The Discord bot token.
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all Discord API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== DISCORD API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"Authorization": f"Bot {self.api_key}"}

        checks = [
            self._check_user(headers),
            self._check_guilds(headers),
            self._check_application(headers),
        ]
        await self._run_checks(checks)

    async def _check_user(self, headers: Dict[str, str]) -> None:
        """Check user endpoint — auth validation and bot info."""
        svc = "Discord User"
        ok, resp = await self._safe_get(svc, "https://discord.com/api/v10/users/@me", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_guilds(self, headers: Dict[str, str]) -> None:
        """Check guilds listing — server access."""
        svc = "Discord Guilds"
        ok, resp = await self._safe_get(svc, "https://discord.com/api/v10/users/@me/guilds", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_application(self, headers: Dict[str, str]) -> None:
        """Check application info — app details and scopes."""
        svc = "Discord Application"
        ok, resp = await self._safe_get(svc, "https://discord.com/api/v10/oauth2/applications/@me", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
