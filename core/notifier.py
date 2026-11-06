"""Webhook notification module for Slack and Discord.

Sends scan result summaries to Slack and Discord webhooks
asynchronously using aiohttp. All delivery outcomes are returned as
structured NotificationResult objects — scan results are never modified.
"""

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import aiohttp
from colorama import Fore, Style

from core.base_scanner import BaseScanner

_NOTIFIER_TIMEOUT = 10


@dataclass
class NotificationResult:
    """Structured outcome of a notification delivery attempt.

    Attributes:
        channel: The notification channel ("slack" or "discord").
        success: Whether the notification was delivered successfully.
        error: Error message if failed (URL redacted), None if successful.
        status_code: HTTP status code if a response was received, None otherwise.
    """

    channel: str
    success: bool
    error: str | None = None
    status_code: int | None = None


def _redact_url(url: str) -> str:
    """Redact a webhook URL for safe display — show scheme + host only.

    Args:
        url: The full webhook URL.

    Returns:
        A redacted URL showing only the scheme and host, with the path
        replaced by "...".  Falls back to "[redacted]" if parsing fails.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme and parsed.hostname:
            return f"{parsed.scheme}://{parsed.hostname}/..."
    except Exception:
        pass
    return "[redacted]"


async def notify_slack(webhook_url: str, scanner: BaseScanner, provider: str) -> NotificationResult:
    """Send scan summary to a Slack webhook.

    Args:
        webhook_url: The Slack incoming webhook URL.
        scanner: The scanner instance with results.
        provider: The provider name for the message title.

    Returns:
        NotificationResult describing the delivery outcome.
    """
    accessible = sum(1 for r in scanner.results if r.get("outcome") == "accessible")
    total = len(scanner.results)
    restricted = sum(1 for r in scanner.results if r.get("outcome") == "restricted")

    payload = {
        "text": f"apiKeyScan Results for {provider.upper()}",
        "attachments": [
            {
                "color": "danger" if accessible > 0 else "good",
                "fields": [
                    {"title": "Total Checks", "value": str(total), "short": True},
                    {"title": "Accessible", "value": str(accessible), "short": True},
                    {"title": "Restricted", "value": str(restricted), "short": True},
                ],
            }
        ],
    }

    try:
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_NOTIFIER_TIMEOUT)) as session,
            session.post(webhook_url, json=payload) as resp,
        ):
            if resp.status == 200:
                print(f"{Fore.GREEN}[INFO] Slack notification sent successfully.{Style.RESET_ALL}")
                return NotificationResult(channel="slack", success=True, status_code=200)
            print(f"{Fore.RED}[!] Slack notification failed: HTTP {resp.status}{Style.RESET_ALL}")
            return NotificationResult(
                channel="slack", success=False, error=f"HTTP {resp.status}", status_code=resp.status
            )
    except asyncio.TimeoutError:
        redacted = _redact_url(webhook_url)
        print(f"{Fore.RED}[!] Slack notification timeout: {redacted}{Style.RESET_ALL}")
        return NotificationResult(channel="slack", success=False, error=f"Timeout: {redacted}")
    except aiohttp.ClientError as e:
        redacted = _redact_url(webhook_url)
        print(f"{Fore.RED}[!] Slack notification error ({redacted}): {e}{Style.RESET_ALL}")
        return NotificationResult(channel="slack", success=False, error=f"ClientError: {redacted}")


async def notify_discord(webhook_url: str, scanner: BaseScanner, provider: str) -> NotificationResult:
    """Send scan summary to a Discord webhook.

    Args:
        webhook_url: The Discord incoming webhook URL.
        scanner: The scanner instance with results.
        provider: The provider name for the message title.

    Returns:
        NotificationResult describing the delivery outcome.
    """
    accessible = sum(1 for r in scanner.results if r.get("outcome") == "accessible")
    total = len(scanner.results)
    restricted = sum(1 for r in scanner.results if r.get("outcome") == "restricted")

    color = 0xFF0000 if accessible > 0 else 0x00FF00
    payload = {
        "embeds": [
            {
                "title": f"apiKeyScan Results for {provider.upper()}",
                "color": color,
                "fields": [
                    {"name": "Total Checks", "value": str(total), "inline": True},
                    {"name": "Accessible", "value": str(accessible), "inline": True},
                    {"name": "Restricted", "value": str(restricted), "inline": True},
                ],
            }
        ]
    }

    try:
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_NOTIFIER_TIMEOUT)) as session,
            session.post(webhook_url, json=payload) as resp,
        ):
            if resp.status in (200, 204):
                print(f"{Fore.GREEN}[INFO] Discord notification sent successfully.{Style.RESET_ALL}")
                return NotificationResult(channel="discord", success=True, status_code=resp.status)
            print(f"{Fore.RED}[!] Discord notification failed: HTTP {resp.status}{Style.RESET_ALL}")
            return NotificationResult(
                channel="discord", success=False, error=f"HTTP {resp.status}", status_code=resp.status
            )
    except asyncio.TimeoutError:
        redacted = _redact_url(webhook_url)
        print(f"{Fore.RED}[!] Discord notification timeout: {redacted}{Style.RESET_ALL}")
        return NotificationResult(channel="discord", success=False, error=f"Timeout: {redacted}")
    except aiohttp.ClientError as e:
        redacted = _redact_url(webhook_url)
        print(f"{Fore.RED}[!] Discord notification error ({redacted}): {e}{Style.RESET_ALL}")
        return NotificationResult(channel="discord", success=False, error=f"ClientError: {redacted}")


async def send_notifications(
    scanner: BaseScanner,
    provider: str,
    slack_url: Any = None,
    discord_url: Any = None,
) -> list[NotificationResult]:
    """Send notifications to all configured webhooks.

    Args:
        scanner: The scanner instance with results.
        provider: The provider name.
        slack_url: Optional Slack webhook URL.
        discord_url: Optional Discord webhook URL.

    Returns:
        List of NotificationResult objects, one per configured channel.
        Scan results on the scanner are never modified.
    """
    tasks: list[Any] = []
    if slack_url:
        tasks.append(notify_slack(slack_url, scanner, provider))
    if discord_url:
        tasks.append(notify_discord(discord_url, scanner, provider))
    if not tasks:
        return []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    outcomes: list[NotificationResult] = []
    for r in results:
        if isinstance(r, NotificationResult):
            outcomes.append(r)
        else:
            outcomes.append(
                NotificationResult(
                    channel="unknown",
                    success=False,
                    error=f"Unexpected exception: {type(r).__name__}",
                )
            )
    return outcomes
