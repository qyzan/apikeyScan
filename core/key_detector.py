"""Key detection and extraction module for multi-provider API key identification.

Provides regex-based provider auto-detection, network probe-based detection
for ambiguous keys, interactive confirmation, and filesystem key extraction
for the extract subcommand.
"""

import bisect
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import aiohttp
from colorama import Fore, Style

_MAX_FILE_SIZE = 10 * 1024 * 1024
_CONTEXT_CHARS = 20
_BINARY_CHECK_SIZE = 8192
_GENERIC_PATTERNS = {"azure"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".codeartsdoer"}


class DetectionConfidence(Enum):
    """Confidence levels for provider detection results."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


KEY_PATTERNS: dict[str, dict[str, Any]] = {
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

EXTRACT_PATTERNS: dict[str, re.Pattern] = {
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

PROBE_ENDPOINTS: dict[str, dict[str, Any]] = {
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


def detect_by_regex(key: str) -> list[dict[str, Any]]:
    """Match a key against known regex patterns.

    Args:
        key: The API key string to identify.

    Returns:
        List of candidate dicts with provider, confidence, method, description.
        May contain multiple entries for ambiguous keys.
    """
    candidates: list[dict[str, Any]] = []
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


def detect_provider(key: str) -> str | None:
    """Quick regex-only provider detection (no network).

    Args:
        key: The API key string to identify.

    Returns:
        Provider name string if exactly one match, None otherwise.
    """
    candidates = detect_by_regex(key)
    if len(candidates) == 1:
        return str(candidates[0]["provider"])
    if len(candidates) > 1:
        return str(candidates[0]["provider"])
    return None


async def detect_by_probe(
    key: str,
    candidates: list[str] | None = None,
    timeout: int = 10,
) -> dict[str, Any] | None:
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
                        try:
                            body = await resp.json(content_type=None)
                        except ValueError:
                            body = None
                        if isinstance(body, dict) and body.get("ok") is False:
                            continue
                        return {
                            "provider": provider,
                            "confidence": DetectionConfidence.MEDIUM,
                            "method": "probe",
                            "description": KEY_PATTERNS.get(provider, {}).get("description", provider),
                        }
            except (aiohttp.ClientError, OSError):
                continue
    return None


def interactive_confirm(key: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Show candidates and let the user choose a provider interactively.

    No probe option is offered; the credential is never sent to providers.

    Args:
        key: The API key being identified (masked in output).
        candidates: List of candidate detection results.

    Returns:
        The selected candidate dict.
    """
    masked = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else key
    print(f"\n{Fore.YELLOW}[?] Multiple possible providers detected for key: {masked}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Detected candidates:{Style.RESET_ALL}")
    for i, c in enumerate(candidates, 1):
        conf = c["confidence"].value if isinstance(c["confidence"], DetectionConfidence) else c["confidence"]
        print(f"  {i}) {c['provider'].upper()} — {c['description']} (confidence: {conf})")
    choice = input(f"\nSelect provider (1-{len(candidates)}) [default: 1]: ").strip() or "1"
    try:
        idx = int(choice)
    except ValueError:
        idx = 1
    if 1 <= idx <= len(candidates):
        return candidates[idx - 1]
    return candidates[0]


async def auto_detect_provider(
    key: str,
    interactive: bool = True,
    force_probe: bool = False,
) -> dict[str, Any]:
    """Offline provider detection: regex match → interactive menu → unknown.

    Default mode never makes network requests or sends the credential to any
    provider. Probe-based detection is rejected; specify the provider with -p.

    Args:
        key: The API key to identify.
        interactive: If True, prompt user on ambiguous matches.
        force_probe: Rejected — probe sends credentials to provider endpoints.

    Returns:
        Detection result dict with provider, confidence, method, description.
    """
    if force_probe:
        return {
            "provider": None,
            "confidence": DetectionConfidence.UNKNOWN,
            "method": "rejected",
            "description": "Probe-based detection is disabled: it sends credentials to provider endpoints.",
        }

    candidates = detect_by_regex(key)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if interactive:
            return interactive_confirm(key, candidates)
        result = dict(candidates[0])
        result["confidence"] = DetectionConfidence.MEDIUM
        result["method"] = "regex-ambiguous"
        result["description"] += " (ambiguous match, first candidate)"
        return result

    return {
        "provider": "unknown",
        "confidence": DetectionConfidence.UNKNOWN,
        "method": "regex",
        "description": "No pattern matched; specify provider with -p",
    }


@dataclass
class FoundKey:
    """A potential API key candidate found during extraction.

    Attributes:
        key: The matched key string.
        provider: Provider name inferred from the pattern.
        confidence: "high" for specific patterns, "low" for generic ones.
        reason: Human-readable description of why this is a candidate.
        context: Sanitized surrounding text (non-printable chars replaced).
        locations: List of (file_path, line_number) tuples for all occurrences.
    """

    key: str
    provider: str
    confidence: str
    reason: str
    context: str
    locations: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class SkippedFile:
    """A file skipped during extraction with a reason.

    Attributes:
        path: The file path that was skipped.
        reason: Why the file was skipped ("binary", "too_large",
            "unreadable", "symlink_out_of_scope").
    """

    path: str
    reason: str


@dataclass
class ExtractionResult:
    """Result of extracting keys from a directory tree.

    Attributes:
        found: Deduplicated list of FoundKey candidates.
        skipped: Files skipped with reasons.
        files_scanned: Number of files successfully scanned.
        files_total: Total number of files encountered.
    """

    found: list[FoundKey] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    files_scanned: int = 0
    files_total: int = 0


def _sanitize_context(text: str) -> str:
    """Replace non-printable characters with dots for safe context display."""
    return "".join(c if c.isprintable() or c in "\n\t" else "." for c in text)


def _is_within_scope(file_path: Path, root: Path) -> bool:
    """Check if a resolved file path is within the scan root."""
    try:
        file_path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def extract_keys_from_directory(path: str) -> ExtractionResult:
    """Scan all files in a directory tree for potential API key candidates.

    Files that are binary, too large, unreadable, or out-of-scope symlinks
    are skipped with a reason — never silently dropped. Generic pattern
    matches (e.g., 32-char hex) are marked with low confidence. Found keys
    are deduplicated by key string while preserving all locations.

    Args:
        path: Root directory path to scan.

    Returns:
        ExtractionResult with found candidates, skipped files, and stats.
    """
    result = ExtractionResult()
    root = Path(path)
    key_map: dict[str, FoundKey] = {}

    for root_dir, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for file in files:
            filepath = Path(root_dir) / file
            result.files_total += 1

            if filepath.is_symlink() and not _is_within_scope(filepath, root):
                result.skipped.append(SkippedFile(str(filepath), "symlink_out_of_scope"))
                continue

            try:
                file_size = filepath.stat().st_size
            except OSError:
                result.skipped.append(SkippedFile(str(filepath), "unreadable"))
                continue

            if file_size > _MAX_FILE_SIZE:
                result.skipped.append(SkippedFile(str(filepath), "too_large"))
                continue

            try:
                raw = filepath.read_bytes()
            except OSError:
                result.skipped.append(SkippedFile(str(filepath), "unreadable"))
                continue

            if b"\x00" in raw[:_BINARY_CHECK_SIZE]:
                result.skipped.append(SkippedFile(str(filepath), "binary"))
                continue

            try:
                content = raw.decode("utf-8", errors="ignore")
            except (UnicodeDecodeError, ValueError):
                result.skipped.append(SkippedFile(str(filepath), "unreadable"))
                continue

            result.files_scanned += 1

            newline_positions = [i for i, c in enumerate(content) if c == "\n"]

            for provider, pattern in EXTRACT_PATTERNS.items():
                for match in pattern.finditer(content):
                    line_num = bisect.bisect_right(newline_positions, match.start()) + 1
                    ctx_start = max(0, match.start() - _CONTEXT_CHARS)
                    ctx_end = min(len(content), match.end() + _CONTEXT_CHARS)
                    context = _sanitize_context(content[ctx_start:ctx_end])
                    confidence = "low" if provider in _GENERIC_PATTERNS else "high"
                    desc = KEY_PATTERNS.get(provider, {}).get("description", provider)
                    if confidence == "low":
                        reason = f"Generic candidate match: {desc}"
                    else:
                        reason = f"Pattern candidate match: {desc}"

                    if match.group() in key_map:
                        key_map[match.group()].locations.append((str(filepath), line_num))
                    else:
                        key_map[match.group()] = FoundKey(
                            key=match.group(),
                            provider=provider,
                            confidence=confidence,
                            reason=reason,
                            context=context,
                            locations=[(str(filepath), line_num)],
                        )

    result.found = list(key_map.values())
    return result
