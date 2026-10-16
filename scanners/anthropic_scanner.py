"""Anthropic Claude API scanner with async checks.

Validates Messages API, Models listing, and token counting endpoints
using x-api-key authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class AnthropicScanner(BaseScanner):
    """Scanner for Anthropic (Claude) API keys.

    Checks Messages API, Models listing, and Count Tokens endpoints.
    """

    PROVIDER_NAME = "anthropic"
    CHECKS = [
        "Messages API (POST /v1/messages)",
        "Models List (GET /v1/models)",
        "Count Tokens (POST /v1/messages/count_tokens)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the Anthropic scanner.

        Args:
            api_key: The Anthropic API key (sk-ant-... format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all Anthropic API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== ANTHROPIC API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        checks = [
            self._check_messages(headers),
            self._check_models(headers),
            self._check_count_tokens(headers),
        ]
        await self._run_checks(checks)

    async def _check_messages(self, headers: Dict[str, str]) -> None:
        """Check Messages API — auth validation and quota."""
        svc = "Anthropic Messages API"
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "Hi"}],
        }
        ok, resp = await self._safe_post(
            svc, "https://api.anthropic.com/v1/messages", headers=headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_models(self, headers: Dict[str, str]) -> None:
        """Check Models listing — available model access."""
        svc = "Anthropic Models List"
        ok, resp = await self._safe_get(svc, "https://api.anthropic.com/v1/models", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_count_tokens(self, headers: Dict[str, str]) -> None:
        """Check Count Tokens — token counting access."""
        svc = "Anthropic Count Tokens"
        payload = {"model": "claude-3-5-sonnet-20241022", "messages": [{"role": "user", "content": "Hi"}]}
        ok, resp = await self._safe_post(
            svc, "https://api.anthropic.com/v1/messages/count_tokens", headers=headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)
