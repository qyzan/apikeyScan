"""Twilio API scanner with async checks for communication account access.

Validates account, messages, calls, phone numbers, and usage records
using HTTP Basic authentication (Account SID + Auth Token or API Key).
"""

import base64
from typing import Any

from colorama import Fore, Style

from core.base_scanner import BaseScanner, CheckOutcome, ExecutionStatus, Severity


class TwilioScanner(BaseScanner):
    """Scanner for Twilio API credentials.

    Checks account, messages, calls, phone numbers, and usage records
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
        account_sid: str | None = None,
        api_secret: str | None = None,
        aws_secret: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the Twilio scanner.

        Args:
            api_key: The API Key ID (SK... format).
            account_sid: The Twilio Account SID (AC... format). Required.
            api_secret: The API key secret / auth token. Required.
            aws_secret: Alias for api_secret (allows --secret reuse).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)
        self.account_sid = account_sid or ""
        self.api_secret = api_secret or aws_secret or ""

    def _get_auth_headers(self) -> dict[str, str]:
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

        if not self.account_sid:
            self.planned_checks = 1
            self.log_custom_result(
                service_name="Twilio (all checks)",
                status_text="SKIPPED (MISSING CREDENTIALS)",
                status_code=None,
                response_body="Twilio scanning requires Account SID (--account-sid or config account_sid, AC... format)",
                url="N/A",
                severity=Severity.INFO,
                color=self._c(Fore.YELLOW),
                outcome=CheckOutcome.SKIPPED,
                execution_status=ExecutionStatus.SKIPPED,
            )
            return

        if not self.account_sid.startswith("AC"):
            self.planned_checks = 1
            self.log_custom_result(
                service_name="Twilio (all checks)",
                status_text="SKIPPED (INVALID CREDENTIALS)",
                status_code=None,
                response_body="Account SID must start with 'AC' — got value that does not match Twilio Account SID format",
                url="N/A",
                severity=Severity.INFO,
                color=self._c(Fore.YELLOW),
                outcome=CheckOutcome.SKIPPED,
                execution_status=ExecutionStatus.SKIPPED,
            )
            return

        if not self.api_secret:
            self.planned_checks = 1
            self.log_custom_result(
                service_name="Twilio (all checks)",
                status_text="SKIPPED (MISSING CREDENTIALS)",
                status_code=None,
                response_body="Twilio scanning requires API secret / auth token (--secret or config api_secret)",
                url="N/A",
                severity=Severity.INFO,
                color=self._c(Fore.YELLOW),
                outcome=CheckOutcome.SKIPPED,
                execution_status=ExecutionStatus.SKIPPED,
            )
            return

        headers = self._get_auth_headers()
        base = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}"

        checks = [
            ("Account", self._check_account(headers, base)),
            ("Messages List", self._check_messages(headers, base)),
            ("Calls List", self._check_calls(headers, base)),
            ("Phone Numbers", self._check_phone_numbers(headers, base)),
            ("Usage Records", self._check_usage(headers, base)),
        ]
        await self._run_checks(checks)

    async def _check_account(self, headers: dict[str, str], base: str) -> None:
        """Check account endpoint — auth validation."""
        svc = "Twilio Account"
        ok, resp = await self._safe_get(svc, f"{base}.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_messages(self, headers: dict[str, str], base: str) -> None:
        """Check messages listing — SMS history access."""
        svc = "Twilio Messages List"
        ok, resp = await self._safe_get(svc, f"{base}/Messages.json?PageSize=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_calls(self, headers: dict[str, str], base: str) -> None:
        """Check calls listing — call history access."""
        svc = "Twilio Calls List"
        ok, resp = await self._safe_get(svc, f"{base}/Calls.json?PageSize=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_phone_numbers(self, headers: dict[str, str], base: str) -> None:
        """Check phone numbers — phone number inventory access."""
        svc = "Twilio Phone Numbers"
        ok, resp = await self._safe_get(svc, f"{base}/IncomingPhoneNumbers.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_usage(self, headers: dict[str, str], base: str) -> None:
        """Check usage records — billing usage access."""
        svc = "Twilio Usage Records"
        ok, resp = await self._safe_get(svc, f"{base}/Usage/Records.json", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
