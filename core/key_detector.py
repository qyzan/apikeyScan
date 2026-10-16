"""Key detection and extraction module for multi-provider API key identification.

Provides regex-based provider auto-detection, network probe-based detection
for ambiguous keys, interactive confirmation, and filesystem key extraction
for the extract subcommand.
"""

import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from colorama import Fore, Style


class DetectionConfidence(Enum):
    """Confidence levels for provider detection results."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


KEY_PATTERNS: Dict[str, Dict[str, Any]] = {
    "google": {
        "pattern": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
        "description": "Google API Key (AIza...)",
    },
    "openai": {
        "pattern": re.compile(r"^sk-(proj-)?[a-zA-Z0-9]{20,}$"),
        "description": "OpenAI API Key (sk-...)",
    },
    "aws": {
        "pattern": re.compile(r"^AKIA[0-9A-Z]{16}$"),
        "description": "AWS Access Key ID (AKIA...)",
    },
    "azure": {
        "pattern": re.compile(r"^[a-f0-9]{32}$"),
        "description": "Azure Subscription Key (32-char hex)",
    },
    "github": {
        "pattern": re.compile(r"^gh[pousr]_[A-Za-z0-9]{36}$"),
        "description": "GitHub Token (ghp_/gho_/ghu_/ghs_/ghr_)",
    },
    "anthropic": {
        "pattern": re.compile(r"^sk-ant-[A-Za-z0-9_-]{95}$"),
        "description": "Anthropic API Key (sk-ant-...)",
    },
    "huggingface": {
        "pattern": re.compile(r"^hf_[A-Za-z0-9]{34}$"),
        "description": "HuggingFace Token (hf_...)",
    },
    "stripe": {
        "pattern": re.compile(r"^sk_(live|test)_[a-zA-Z0-9]{24,}$"),
        "description": "Stripe API Key (sk_live_/sk_test_)",
    },
    "twilio": {
        "pattern": re.compile(r"^SK[a-fA-F0-9]{32}$"),
        "description": "Twilio API Key (SK...)",
    },
    "slack": {
        "pattern": re.compile(r"^xox[baprs]-[A-Za-z0-9-]+$"),
        "description": "Slack Token (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-)",
    },
    "discord": {
        "pattern": re.compile(r"^[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}$"),
        "description": "Discord Bot Token",
    },
    "sendgrid": {
        "pattern": re.compile(r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$"),
        "description": "SendGrid API Key (SG.xxx.yyy)",
    },
    "gitlab": {
        "pattern": re.compile(r"^glpat-[A-Za-z0-9_-]{20}$"),
        "description": "GitLab PAT (glpat-...)",
    },
    "digitalocean": {
        "pattern": re.compile(r"^dop_v1_[a-f0-9]{64}$"),
        "description": "DigitalOcean PAT (dop_v1_...)",
    },
}

EXTRACT_PATTERNS: Dict[str, re.Pattern] = {
    "google": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "openai": re.compile(r"sk-(proj-)?[a-zA-Z0-9]{20,}"),
    "aws": re.compile(r"AKIA[0-9A-Z]{16}"),
    "azure": re.compile(r"[a-f0-9]{32}"),
    "github": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "anthropic": re.compile(r"sk-ant-[A-Za-z0-9_-]{95}"),
    "huggingface": re.compile(r"hf_[A-Za-z0-9]{34}"),
    "stripe": re.compile(r"sk_(live|test)_[a-zA-Z0-9]{24,}"),
    "twilio": re.compile(r"SK[a-fA-F0-9]{32}"),
    "slack": re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    "discord": re.compile(r"[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}"),
    "sendgrid": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "gitlab": re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    "digitalocean": re.compile(r"dop_v1_[a-f0-9]{64}"),
}

PROBE_ENDPOINTS: Dict[str, Dict[str, Any]] = {
    "google": {
        "url": "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key}",
        "method": "GET",
        "valid_status": [200],
    },
    "openai": {
        "url": "https://api.openai.com/v1/models",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "github": {
        "url": "https://api.github.com/user",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "anthropic": {
        "url": "https://api.anthropic.com/v1/models",
        "method": "GET",
        "headers": lambda k: {"x-api-key": k},
        "valid_status": [200],
    },
    "huggingface": {
        "url": "https://huggingface.co/api/whoami-v2",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "stripe": {
        "url": "https://api.stripe.com/v1/balance",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "slack": {
        "url": "https://slack.com/api/auth.test",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "gitlab": {
        "url": "https://gitlab.com/api/v4/user",
        "method": "GET",
        "headers": lambda k: {"PRIVATE-TOKEN": k},
        "valid_status": [200],
    },
    "digitalocean": {
        "url": "https://api.digitalocean.com/v2/account",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
    "discord": {
        "url": "https://discord.com/api/v10/users/@me",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bot {k}"},
        "valid_status": [200],
    },
    "sendgrid": {
        "url": "https://api.sendgrid.com/v3/api_keys",
        "method": "GET",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "valid_status": [200],
    },
}


def detect_by_regex(key: str) -> List[Dict[str, Any]]:
    """Match a key against known regex patterns.

    Args:
        key: The API key string to identify.

    Returns:
        List of candidate dicts with provider, confidence, method, description.
        May contain multiple entries for ambiguous keys.
    """
    candidates: List[Dict[str, Any]] = []
    for provider, info in KEY_PATTERNS.items():
        if info["pattern"].match(key):
            candidates.append(
                {
                    "provider": provider,
                    "confidence": DetectionConfidence.HIGH,
                    "method": "regex",
                    "description": info["description"],
                }
            )
    return candidates


def detect_provider(key: str) -> Optional[str]:
    """Quick regex-only provider detection (no network).

    Args:
        key: The API key string to identify.

    Returns:
        Provider name string if exactly one match, None otherwise.
    """
    candidates = detect_by_regex(key)
    if len(candidates) == 1:
        return candidates[0]["provider"]
    if len(candidates) > 1:
        return candidates[0]["provider"]
    return None


async def detect_by_probe(
    key: str,
    candidates: Optional[List[str]] = None,
    timeout: int = 10,
) -> Optional[Dict[str, Any]]:
    """Send lightweight probe requests to candidate providers.

    Args:
        key: The API key to probe.
        candidates: Optional list of provider names to probe. If None, probes all.
        timeout: Per-request timeout in seconds.

    Returns:
        Detection result dict if a provider accepted the key, None otherwise.
    """
    providers_to_probe = candidates or list(PROBE_ENDPOINTS.keys())
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        for provider in providers_to_probe:
            config = PROBE_ENDPOINTS.get(provider)
            if not config:
                continue
            url = config["url"].format(key=key)
            headers = config.get("headers", lambda k: {})(key) if config.get("headers") else {}
            try:
                async with session.request(config["method"], url, headers=headers) as resp:
                    if resp.status in config["valid_status"]:
                        return {
                            "provider": provider,
                            "confidence": DetectionConfidence.MEDIUM,
                            "method": "probe",
                            "description": KEY_PATTERNS.get(provider, {}).get("description", provider),
                        }
            except (aiohttp.ClientError, OSError):
                continue
    return None


def interactive_confirm(key: str, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Show candidates and let the user choose a provider interactively.

    Args:
        key: The API key being identified (masked in output).
        candidates: List of candidate detection results.

    Returns:
        The selected candidate dict, or a probe-all action dict.
    """
    masked = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else key
    print(f"\n{Fore.YELLOW}[?] Multiple possible providers detected for key: {masked}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Detected candidates:{Style.RESET_ALL}")
    for i, c in enumerate(candidates, 1):
        conf = c["confidence"].value if isinstance(c["confidence"], DetectionConfidence) else c["confidence"]
        print(f"  {i}) {c['provider'].upper()} — {c['description']} (confidence: {conf})")
    print("  0) Try all providers (probe)")
    choice = input(f"\nSelect provider (0-{len(candidates)}) [default: 1]: ").strip() or "1"
    try:
        idx = int(choice)
    except ValueError:
        idx = 1
    if idx == 0:
        return {"provider": None, "action": "probe_all"}
    if 1 <= idx <= len(candidates):
        return candidates[idx - 1]
    return candidates[0]


async def auto_detect_provider(
    key: str,
    interactive: bool = True,
    force_probe: bool = False,
) -> Dict[str, Any]:
    """Full auto-detection pipeline: regex → probe → interactive.

    Args:
        key: The API key to identify.
        interactive: If True, prompt user on ambiguous matches.
        force_probe: If True, skip regex and probe all providers directly.

    Returns:
        Detection result dict with provider, confidence, method, description.
    """
    if not force_probe:
        candidates = detect_by_regex(key)
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            if interactive:
                return interactive_confirm(key, candidates)
            result = await detect_by_probe(key, [c["provider"] for c in candidates])
            if result:
                return result
            return candidates[0]

    result = await detect_by_probe(key)
    if result:
        return result

    unknown_result: Dict[str, Any] = {
        "provider": "unknown",
        "confidence": DetectionConfidence.UNKNOWN,
        "method": "failed",
        "description": "Could not detect provider",
    }
    if interactive:
        return interactive_confirm(key, [unknown_result])
    return unknown_result


def extract_keys_from_directory(path: str) -> List[Dict[str, Any]]:
    """Scan all files in a directory tree for potential API keys.

    Args:
        path: Root directory path to scan.

    Returns:
        List of found key dicts with provider, key, file, line.
    """
    found: List[Dict[str, Any]] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".codeartsdoer"}

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            filepath = Path(root) / file
            try:
                content = filepath.read_text(errors="ignore")
                for provider, pattern in EXTRACT_PATTERNS.items():
                    for match in pattern.finditer(content):
                        found.append(
                            {
                                "provider": provider,
                                "key": match.group(),
                                "file": str(filepath),
                                "line": content[: match.start()].count("\n") + 1,
                            }
                        )
            except (OSError, UnicodeDecodeError):
                continue
    return found
