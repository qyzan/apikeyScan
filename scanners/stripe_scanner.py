"""Stripe API scanner with async checks for financial exposure.

Validates balance, charges, customers, payouts, refunds, products,
and webhook endpoints using Bearer token authentication.
"""

from typing import Any

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class StripeScanner(BaseScanner):
    """Scanner for Stripe API keys (live and test).

    Checks balance, charges, customers, payouts, refunds, products,
    and webhook endpoints for financial data exposure.
    """

    PROVIDER_NAME = "stripe"
    CHECKS = [
        "Balance (GET /v1/balance)",
        "Charges List (GET /v1/charges)",
        "Customers List (GET /v1/customers)",
        "Payouts List (GET /v1/payouts)",
        "Refunds List (GET /v1/refunds)",
        "Products List (GET /v1/products)",
        "Webhooks List (GET /v1/webhook_endpoints)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the Stripe scanner.

        Args:
            api_key: The Stripe API key (sk_live_ or sk_test_ format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all Stripe API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== STRIPE API RECON ==={Style.RESET_ALL}\n")

        headers: dict[str, str] = {"Authorization": f"Bearer {self.api_key}"}

        checks = [
            self._check_balance(headers),
            self._check_charges(headers),
            self._check_customers(headers),
            self._check_payouts(headers),
            self._check_refunds(headers),
            self._check_products(headers),
            self._check_webhooks(headers),
        ]
        await self._run_checks(checks)

    async def _check_balance(self, headers: dict[str, str]) -> None:
        """Check balance endpoint — auth validation and financial exposure."""
        svc = "Stripe Balance"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/balance", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.CRITICAL)

    async def _check_charges(self, headers: dict[str, str]) -> None:
        """Check charges listing — payment history access."""
        svc = "Stripe Charges List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/charges?limit=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.CRITICAL)

    async def _check_customers(self, headers: dict[str, str]) -> None:
        """Check customers listing — PII exposure risk."""
        svc = "Stripe Customers List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/customers?limit=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.CRITICAL)

    async def _check_payouts(self, headers: dict[str, str]) -> None:
        """Check payouts listing — bank transfer access."""
        svc = "Stripe Payouts List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/payouts?limit=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_refunds(self, headers: dict[str, str]) -> None:
        """Check refunds listing — refund ability."""
        svc = "Stripe Refunds List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/refunds?limit=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_products(self, headers: dict[str, str]) -> None:
        """Check products listing — catalog access."""
        svc = "Stripe Products List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/products?limit=1", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_webhooks(self, headers: dict[str, str]) -> None:
        """Check webhook endpoints — webhook interception risk."""
        svc = "Stripe Webhooks List"
        ok, resp = await self._safe_get(svc, "https://api.stripe.com/v1/webhook_endpoints", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)
