"""SendGrid API scanner with async checks for email infrastructure access.

Validates API keys, suppressions, templates, and stats using Bearer token
authentication. Mail send is checked with an invalid payload to avoid
actually sending emails.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class SendGridScanner(BaseScanner):
    """Scanner for SendGrid API keys.

    Checks API keys listing, mail send auth (dry-run), suppressions,
    templates, and stats. Never actually sends emails.
    """

    PROVIDER_NAME = "sendgrid"
    CHECKS = [
        "API Keys List (GET /v3/api_keys)",
        "Mail Send Auth (POST /v3/mail/send — dry-run)",
        "Suppressions (GET /v3/suppressions/bounces)",
        "Templates (GET /v3/templates)",
        "Stats (GET /v3/stats)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the SendGrid scanner.

        Args:
            api_key: The SendGrid API key (SG.xxx.yyy format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all SendGrid API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== SENDGRID API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"Authorization": f"Bearer {self.api_key}"}

        checks = [
            self._check_api_keys(headers),
            self._check_mail_send(headers),
            self._check_suppressions(headers),
            self._check_templates(headers),
            self._check_stats(headers),
        ]
        await self._run_checks(checks)

    async def _check_api_keys(self, headers: Dict[str, str]) -> None:
        """Check API keys listing — auth validation and key enumeration."""
        svc = "SendGrid API Keys"
        ok, resp = await self._safe_get(svc, "https://api.sendgrid.com/v3/api_keys", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_mail_send(self, headers: Dict[str, str]) -> None:
        """Check mail send auth with invalid payload — no actual email sent."""
        svc = "SendGrid Mail Send (dry-run)"
        send_headers = {**headers, "Content-Type": "application/json"}
        payload = {
            "personalizations": [{"to": [{"email": "invalid"}]}],
            "from": {"email": "invalid"},
            "subject": "test",
            "content": [{"type": "text/plain", "value": "test"}],
        }
        ok, resp = await self._safe_post(
            svc, "https://api.sendgrid.com/v3/mail/send", headers=send_headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_suppressions(self, headers: Dict[str, str]) -> None:
        """Check suppressions — bounce list access."""
        svc = "SendGrid Suppressions"
        ok, resp = await self._safe_get(svc, "https://api.sendgrid.com/v3/suppressions/bounces", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_templates(self, headers: Dict[str, str]) -> None:
        """Check templates — email template access."""
        svc = "SendGrid Templates"
        ok, resp = await self._safe_get(svc, "https://api.sendgrid.com/v3/templates", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_stats(self, headers: Dict[str, str]) -> None:
        """Check stats — sending statistics access."""
        svc = "SendGrid Stats"
        ok, resp = await self._safe_get(
            svc, "https://api.sendgrid.com/v3/stats?start_date=2024-01-01&end_date=2024-01-02", headers=headers
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
