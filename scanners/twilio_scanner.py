"""Twilio API scanner with async checks for communication account access.

Validates account, messages, calls, phone numbers, and usage records
using HTTP Basic authentication (Account SID + Auth Token or API Key).
"""

import base64
from typing import Any, Dict, Optional

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class TwilioScanner(BaseScanner):
    """Scanner for Twilio API credentials.

    Checks account info, messages, calls, phone numbers, and usage records
    using HTTP Basic auth (SID:token or APIKey:secret).
    """

    PROVIDER_NAME = "twilio"
    CHECKS = [
        "Account (GET /Accounts/{sid}.json)",
        "Messages List (GET /Accounts/{sid}/Messages.json)",
        "Calls List (GET /Accounts/{sid}/Calls.json)",
        "Phone Numbers (GET /Accounts/{sid}/IncomingPhoneNumbers.json)",
        "Usage Records (GET /Accounts/{sid}/Usage/Records.json)",
    ]

    def __init__(
        self,
        api_key: str,
        account_sid: Optional[str] = None,
        api_secret: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Twilio scanner.

        Args:
            api_key: The Account SID or API Key ID (SK... format).
            account_sid: The Twilio Account SID (AC... format). Required if api_key is an API Key.
            api_secret: The auth token or API key secret.
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)
        self.account_sid = account_sid or api_key
        self.api_secret = api_secret or ""

    def _get_auth_headers(self) -> Dict[str, str]:
        """Build HTTP Basic auth headers for Twilio API.

        Returns:
            Dict with Authorization header using base64-encoded credentials.
        """
        credentials = f"{self.api_key}:{self.api_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    async def scan(self) -> None:
        """Run all Twilio API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== TWILIO API RECON ==={Style.RESET_ALL}\n")

        headers = self._get_auth_headers()
        base = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}"

        checks = [
            self._check_account(headers, base),
            self._check_messages(headers, base),
            self._check_calls(headers, base),
            self._check_phone_numbers(headers, base),
            self._check_usage(headers, base),
        ]
        await self._run_checks(checks)

    async def _check_account(self, headers: Dict[str, str], base: str) -> None:
        """Check account endpoint — auth validation."""
        svc = "Twilio Account"
        ok, resp = await self._safe_get(svc, f"{base}.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_messages(self, headers: Dict[str, str], base: str) -> None:
        """Check messages listing — SMS history access."""
        svc = "Twilio Messages List"
        ok, resp = await self._safe_get(svc, f"{base}/Messages.json?PageSize=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_calls(self, headers: Dict[str, str], base: str) -> None:
        """Check calls listing — call history access."""
        svc = "Twilio Calls List"
        ok, resp = await self._safe_get(svc, f"{base}/Calls.json?PageSize=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_phone_numbers(self, headers: Dict[str, str], base: str) -> None:
        """Check phone numbers — phone number inventory access."""
        svc = "Twilio Phone Numbers"
        ok, resp = await self._safe_get(svc, f"{base}/IncomingPhoneNumbers.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_usage(self, headers: Dict[str, str], base: str) -> None:
        """Check usage records — billing usage access."""
        svc = "Twilio Usage Records"
        ok, resp = await self._safe_get(svc, f"{base}/Usage/Records.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
