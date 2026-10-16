"""Webhook notification module for Slack and Discord.

Sends scan result summaries to Slack and Discord webhooks
asynchronously using aiohttp.
"""

from typing import Any

import aiohttp
from colorama import Fore, Style

from core.base_scanner import BaseScanner


async def notify_slack(webhook_url: str, scanner: BaseScanner, provider: str) -> bool:
    """Send scan summary to a Slack webhook.

    Args:
        webhook_url: The Slack incoming webhook URL.
        scanner: The scanner instance with results.
        provider: The provider name for the message title.

    Returns:
        True if notification was sent successfully, False otherwise.
    """
    vulnerable = sum(1 for r in scanner.results if "VULNERABLE" in r["status_text"])
    total = len(scanner.results)
    restricted = sum(1 for r in scanner.results if "RESTRICTED" in r["status_text"])

    payload = {
        "text": f"apiKeyScan Results for {provider.upper()}",
        "attachments": [
            {
                "color": "danger" if vulnerable > 0 else "good",
                "fields": [
                    {"title": "Total Checks", "value": str(total), "short": True},
                    {"title": "Vulnerable", "value": str(vulnerable), "short": True},
                    {"title": "Restricted", "value": str(restricted), "short": True},
                ],
            }
        ],
    }

    try:
        async with aiohttp.ClientSession() as session, session.post(webhook_url, json=payload) as resp:
            if resp.status == 200:
                print(f"{Fore.GREEN}[INFO] Slack notification sent successfully.{Style.RESET_ALL}")
                return True
            print(f"{Fore.RED}[!] Slack notification failed: HTTP {resp.status}{Style.RESET_ALL}")
            return False
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[!] Slack notification error: {e}{Style.RESET_ALL}")
        return False


async def notify_discord(webhook_url: str, scanner: BaseScanner, provider: str) -> bool:
    """Send scan summary to a Discord webhook.

    Args:
        webhook_url: The Discord webhook URL.
        scanner: The scanner instance with results.
        provider: The provider name for the message title.

    Returns:
        True if notification was sent successfully, False otherwise.
    """
    vulnerable = sum(1 for r in scanner.results if "VULNERABLE" in r["status_text"])
    total = len(scanner.results)
    restricted = sum(1 for r in scanner.results if "RESTRICTED" in r["status_text"])

    color = 0xFF0000 if vulnerable > 0 else 0x00FF00
    payload = {
        "embeds": [
            {
                "title": f"apiKeyScan Results for {provider.upper()}",
                "color": color,
                "fields": [
                    {"name": "Total Checks", "value": str(total), "inline": True},
                    {"name": "Vulnerable", "value": str(vulnerable), "inline": True},
                    {"name": "Restricted", "value": str(restricted), "inline": True},
                ],
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session, session.post(webhook_url, json=payload) as resp:
            if resp.status in (200, 204):
                print(f"{Fore.GREEN}[INFO] Discord notification sent successfully.{Style.RESET_ALL}")
                return True
            print(f"{Fore.RED}[!] Discord notification failed: HTTP {resp.status}{Style.RESET_ALL}")
            return False
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}[!] Discord notification error: {e}{Style.RESET_ALL}")
        return False


async def send_notifications(
    scanner: BaseScanner,
    provider: str,
    slack_url: Any = None,
    discord_url: Any = None,
) -> None:
    """Send notifications to all configured webhooks.

    Args:
        scanner: The scanner instance with results.
        provider: The provider name.
        slack_url: Optional Slack webhook URL.
        discord_url: Optional Discord webhook URL.
    """
    tasks = []
    if slack_url:
        tasks.append(notify_slack(slack_url, scanner, provider))
    if discord_url:
        tasks.append(notify_discord(discord_url, scanner, provider))
    if tasks:
        import asyncio

        await asyncio.gather(*tasks, return_exceptions=True)
