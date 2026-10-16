# apiKeyScan — Full-Featured Framework Development Plan
## Project Overview
Transform `apiKeyScan` from a lightweight API key scanner (~655 lines, 9 files) into a comprehensive, async, multi-provider API security reconnaissance framework (~3000-4000 lines, 20+ files).
**Current state:** 4 providers (Google 22 checks, Azure 5, OpenAI 9, AWS 9), sync `requests`-based, console/JSON/HTML reports.
**Target state:** 14 providers, async `aiohttp`-based, severity ratings, 5 report formats (console/JSON/HTML/CSV/SARIF), plugin auto-discovery, key auto-detection, CI/CD ready.
---
## Architectural Decisions (LOCKED — do not reverse)
1. **asyncio + aiohttp** for all HTTP-based scanners
2. **boto3 wrapped in `asyncio.to_thread()`** for AWS (boto3 is sync-only)
3. **CLI redesigned with subcommands**: `scan`, `extract`, `list-checks`
4. **Plugin auto-discovery** — scanners loaded dynamically from `scanners/` dir
5. **Severity rating system** (Critical/High/Medium/Low) per finding
6. **Exit codes** for CI/CD: 0=clean, 1=vulnerable found, 2=scan error
7. **Key auto-detection** via regex per provider
8. **Backward compatibility**: NOT required — CLI redesign allowed
---
## Target Directory Structure
apiKeyScan/
├── apiKeyScan.py              # async entry point with subcommands
├── pyproject.toml             # PyPI packaging + ruff/mypy config
├── config.example.yaml        # config preset example
├── Dockerfile
├── docker-compose.yml
├── .gitignore                 # updated
├── requirements.txt           # updated with aiohttp, pyyaml, etc.
├── core/
│   ├── init.py
│   ├── base_scanner.py        # async BaseScanner + aiohttp session + severity + concurrency
│   ├── report_engine.py       # console + JSON + HTML + CSV + SARIF
│   ├── key_detector.py        # regex-based provider auto-detection
│   ├── notifier.py            # Slack/Discord webhooks
│   └── plugin_loader.py       # dynamic scanner discovery
├── scanners/
│   ├── init.py            # auto-discovery, no manual imports
│   ├── google_scanner.py      # async, 22+ checks
│   ├── azure_scanner.py       # async, 5+ checks
│   ├── openai_scanner.py      # async, 9+ checks
│   ├── aws_scanner.py         # boto3 via to_thread, 9+ checks
│   ├── github_scanner.py      # NEW
│   ├── anthropic_scanner.py   # NEW
│   ├── huggingface_scanner.py # NEW
│   ├── stripe_scanner.py      # NEW
│   ├── twilio_scanner.py      # NEW
│   ├── slack_scanner.py       # NEW
│   ├── discord_scanner.py     # NEW
│   ├── sendgrid_scanner.py    # NEW
│   ├── gitlab_scanner.py      # NEW
│   └── digitalocean_scanner.py# NEW
├── tests/
│   ├── init.py
│   ├── conftest.py            # fixtures for mock aiohttp responses
│   ├── test_base_scanner.py
│   ├── test_key_detector.py
│   ├── test_report_engine.py
│   ├── test_google_scanner.py
│   ├── test_azure_scanner.py
│   ├── test_openai_scanner.py
│   ├── test_aws_scanner.py
│   ├── test_github_scanner.py
│   └── ... (one per scanner)
└── .github/
    └── workflows/
        └── ci.yml             # lint → typecheck → test → build
---
## Phase 1 — Foundation & Robustness
### 1.1 Refactor `core/base_scanner.py` to async
**Current:** sync `requests`-based, `_safe_get`/`_safe_post` only in GoogleScanner.
**Target:** async `aiohttp`-based, all helpers in BaseScanner.
```python
# core/base_scanner.py — target structure
import asyncio
import aiohttp
from enum import Enum
from colorama import Fore, Style
class Severity(Enum):
    CRITICAL = ("CRITICAL", Fore.RED + Style.BRIGHT)
    HIGH = ("HIGH", Fore.RED)
    MEDIUM = ("MEDIUM", Fore.YELLOW)
    LOW = ("LOW", Fore.CYAN)
    INFO = ("INFO", Fore.BLUE)
class BaseScanner:
    def __init__(self, api_key, timeout=20, max_retries=3, rate_limit=None):
        self.api_key = api_key
        self.results = []
        self.raw_data = []
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.rate_limit = rate_limit  # requests per second
        self._semaphore = None
    async def _safe_get(self, service_name, url, headers=None, **kwargs):
        """Async GET with retry, timeout, rate limiting, error handling."""
        ...
    async def _safe_post(self, service_name, url, headers=None, json=None, **kwargs):
        """Async POST with retry, timeout, rate limiting, error handling."""
        ...
    async def _request_with_retry(self, method, url, **kwargs):
        """Retry with exponential backoff for 429/503."""
        for attempt in range(self.max_retries):
            try:
                async with self._session.request(method, url, timeout=self.timeout, **kwargs) as resp:
                    if resp.status in (429, 503) and attempt < self.max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return resp
            except aiohttp.ClientError as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
        ...
    def log_result(self, service_name, status_code, response_obj, severity=None):
        """Log result with auto-severity detection if not specified."""
        # Severity auto-detection logic:
        #   200 + VULNERABLE → CRITICAL or HIGH (scanner can override)
        #   403/401 → INFO (key invalid/restricted)
        #   404 → LOW
        #   400 → MEDIUM
        ...
    def log_error(self, service_name, error):
        """Log connection/network error."""
        ...
    async def scan(self):
        """Override in subclasses. Use self._session (aiohttp.ClientSession)."""
        raise NotImplementedError
    async def run(self):
        """Entry point: creates aiohttp session, calls scan(), handles cleanup."""
        async with aiohttp.ClientSession() as session:
            self._session = session
            await self.scan()
Key changes:
- _safe_get/_safe_post moved here, made async with aiohttp
- REQUEST_TIMEOUT → instance variable with aiohttp.ClientTimeout
- Bare except: → except (aiohttp.ClientError, asyncio.TimeoutError)
- Severity enum added
- log_result accepts optional severity param, auto-detects if None
- New run() method wraps scan() with session lifecycle
- Retry with exponential backoff for 429/503
1.2 Refactor all existing scanners to async
scanners/google_scanner.py:
- Remove _safe_get/_safe_post (now inherited)
- Change scan() to async def scan()
- All self._safe_get(...) → await self._safe_get(...)
- All self._safe_post(...) → await self._safe_post(...)
- Add severity hints: Identity Toolkit signUp = CRITICAL, GCS/Firestore/Secrets = HIGH, Maps = MEDIUM
scanners/azure_scanner.py:
- Add async def scan()
- Wrap all requests.get/post → await self._safe_get/_safe_post
- Add timeout (was missing entirely)
- Add severity hints
scanners/openai_scanner.py:
- Add async def scan()
- Wrap all requests.get/post → await self._safe_get/_safe_post
- Add timeout (was missing entirely)
- Add severity hints: Chat/Files/FineTuning = HIGH, Moderations = LOW
scanners/aws_scanner.py:
- Keep boto3 (sync) but wrap calls in asyncio.to_thread()
- async def scan() with await asyncio.to_thread(self._scan_sync)
- Add severity hints: STS/S3/IAM = CRITICAL, SES/SNS/SQS = HIGH
1.3 Update apiKeyScan.py entry point
import asyncio
# ... existing imports ...
async def run_scan(provider, api_key, **kwargs):
    scanner = get_scanner(provider, api_key, **kwargs)
    await scanner.run()
    return scanner
def main():
    # parse args
    scanner = asyncio.run(run_scan(...))
    ReportEngine.display_console_summary(scanner, provider)
    # reports...
    # exit code:
    vulnerable_count = sum(1 for r in scanner.results if "VULNERABLE" in r["status_text"])
    sys.exit(1 if vulnerable_count > 0 else 0)
1.4 Fix docs & gitignore
- Update README: "22 Checks" for Google (was 21/17)
- Update interactive wizard: "22 checks" (was 17)
- .gitignore: add pentest_*_report.json, pentest_*_report.html, pentest_*_report.csv, pentest_*_report.sarif, __pycache__/, *.zip, .codeartsdoer/
- Untrack scanners.zip: git rm --cached scanners.zip
---
Phase 2 — Performance & Reliability
2.1 Concurrency (parallel checks within a scanner)
In BaseScanner, add a check-runner pattern:
async def _run_checks(self, checks):
    """Run a list of check coroutines concurrently with optional rate limiting."""
    if self.rate_limit:
        self._semaphore = asyncio.Semaphore(self.rate_limit)
    tasks = [asyncio.create_task(self._run_one_check(check)) for check in checks]
    return await asyncio.gather(*tasks, return_exceptions=True)
async def _run_one_check(self, check_coro):
    if self._semaphore:
        async with self._semaphore:
            return await check_coro
    return await check_coro
Each scanner builds a list of check coroutines and calls await self._run_checks(checks).
2.2 Key format auto-detection (core/key_detector.py)
import re
KEY_PATTERNS = {
    "google": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
    "openai": re.compile(r"^sk-[a-zA-Z0-9]{20,}$"),
    "aws": re.compile(r"^AKIA[0-9A-Z]{16}$"),
    "azure": re.compile(r"^[a-f0-9]{32}$"),  # Azure subscription key
    "github": re.compile(r"^gh[pousr]_[A-Za-z0-9]{36}$"),
    "anthropic": re.compile(r"^sk-ant-[A-Za-z0-9_-]{95}$"),
    "huggingface": re.compile(r"^hf_[A-Za-z0-9]{34}$"),
    "stripe": re.compile(r"^sk_(live|test)_[a-zA-Z0-9]{24,}$"),
    "twilio": re.compile(r"^SK[a-fA-F0-9]{32}$"),
    "slack": re.compile(r"^xox[baprs]-[A-Za-z0-9-]+$"),
    "discord": re.compile(r"^[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,}$"),
    "sendgrid": re.compile(r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$"),
    "gitlab": re.compile(r"^glpat-[A-Za-z0-9_-]{20}$"),
    "digitalocean": re.compile(r"^dop_v1_[a-f0-9]{64}$"),
}
def detect_provider(key):
    """Return provider name or None."""
    for provider, pattern in KEY_PATTERNS.items():
        if pattern.match(key):
            return provider
    return None
2.3 Rate limiting
- --rate-limit N flag (requests per second)
- Implemented via asyncio.Semaphore in _run_checks
2.4 Exit codes
- 0 = no vulnerabilities found
- 1 = at least one VULNERABLE finding
- 2 = scan error (invalid key, connection failure, etc.)
---
Phase 3 — CLI/UX & Reporting
3.1 CLI redesign with subcommands
# apiKeyScan.py — new CLI structure
import argparse
def build_parser():
    parser = argparse.ArgumentParser(prog="apiKeyScan", description="Universal API Security Recon")
    subparsers = parser.add_subparsers(dest="command")
    # scan subcommand
    scan = subparsers.add_parser("scan", help="Scan an API key")
    scan.add_argument("-p", "--provider", help="Cloud provider (auto-detect if omitted)")
    scan.add_argument("-k", "--key", help="API key or access key ID")
    scan.add_argument("--secret", help="AWS secret access key")
    scan.add_argument("--keyfile", help="File containing keys (one per line)")
    scan.add_argument("--project-id", help="GCP project ID")
    scan.add_argument("--referer", help="HTTP Referer header")
    scan.add_argument("--collection", default="users", help="Firestore collection")
    scan.add_argument("--bucket", help="GCS bucket name")
    scan.add_argument("--region", default="us-east-1", help="AWS region")
    scan.add_argument("--timeout", type=int, default=20, help="Request timeout (seconds)")
    scan.add_argument("--rate-limit", type=int, help="Max requests per second")
    scan.add_argument("--proxy", help="HTTP proxy URL")
    scan.add_argument("--user-agent", help="Custom User-Agent")
    scan.add_argument("--severity-filter", choices=["critical","high","medium","low"], help="Min severity to report")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan.add_argument("-o", "--output", help="Output file prefix (default: pentest_<provider>)")
    scan.add_argument("--json", action="store_true", help="JSON report")
    scan.add_argument("--html", action="store_true", help="HTML report")
    scan.add_argument("--csv", action="store_true", help="CSV report")
    scan.add_argument("--sarif", action="store_true", help="SARIF report")
    scan.add_argument("--all-formats", action="store_true", help="All report formats")
    scan.add_argument("--notify-slack", help="Slack webhook URL")
    scan.add_argument("--notify-discord", help="Discord webhook URL")
    scan.add_argument("--config", help="YAML config file path")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    # extract subcommand
    extract = subparsers.add_parser("extract", help="Extract & scan keys from a codebase")
    extract.add_argument("path", help="Directory to scan for leaked keys")
    extract.add_argument("--scan", action="store_true", help="Auto-scan found keys")
    extract.add_argument("--output", help="Output file for found keys")
    # list-checks subcommand
    list_checks = subparsers.add_parser("list-checks", help="List available checks")
    list_checks.add_argument("-p", "--provider", help="Filter by provider")
    return parser
Usage examples:
# Auto-detect provider from key format
python apiKeyScan.py scan -k AIzaSy...
# Explicit provider with all formats
python apiKeyScan.py scan -p github -k ghp_xxxx --all-formats
# Batch from file
python apiKeyScan.py scan --keyfile keys.txt --html --sarif
# Extract keys from codebase then scan
python apiKeyScan.py extract ./repo/ --scan
# List checks
python apiKeyScan.py list-checks --provider google
# Config preset
python apiKeyScan.py scan --config preset.yaml
# With notifications
python apiKeyScan.py scan -p stripe -k sk_live_... --notify-slack $URL
3.2 SARIF report (ReportEngine.generate_sarif_report)
@staticmethod
def generate_sarif_report(scanner, provider_name, filename=None):
    """Generate SARIF 2.1.0 report for GitHub Code Scanning integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "apiKeyScan", "version": "2.0.0"}},
            "results": [
                {
                    "ruleId": r["service"],
                    "level": "error" if "VULNERABLE" in r["status_text"] else "note",
                    "message": {"text": r["status_text"]},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["url"]}}}]
                }
                for r in scanner.raw_data
            ]
        }]
    }
    # write to file
3.3 CSV report (ReportEngine.generate_csv_report)
Columns: service, status_text, status_code, severity, url, timestamp
3.4 HTML report upgrade
Add at top of HTML:
- Summary dashboard: total checks, vulnerable count, restricted count, error count
- Severity breakdown bar chart (CSS-based, no JS dependency)
- Color-coded severity badges per row
- Filter buttons (All / Vulnerable / Restricted / Errors)
3.5 Batch scanning (--keyfile)
async def scan_batch(keyfile, **kwargs):
    """Read keys from file, auto-detect provider, scan each."""
    with open(keyfile) as f:
        keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    results = {}
    for key in keys:
        provider = detect_provider(key) or kwargs.get("provider")
        if not provider:
            print(f"[!] Could not detect provider for key: {key[:10]}...")
            continue
        scanner = get_scanner(provider, key, **kwargs)
        await scanner.run()
        results[key] = scanner
    return results
3.6 --list-checks command
Each scanner class defines a CHECKS class attribute (list of check names/descriptions). list-checks enumerates these.
---
Phase 4 — New Providers
All new scanners follow this pattern:
from core.base_scanner import BaseScanner, Severity
from colorama import Fore, Style
class GitHubScanner(BaseScanner):
    PROVIDER_NAME = "github"
    CHECKS = [
        "User Profile (/user)",
        "Repos List (/user/repos)",
        "Orgs List (/user/orgs)",
        "Gists List (/gists)",
        "SSH Keys (/user/keys)",
        "Actions Secrets (/user/actions/secrets)",
        "Packages (/user/packages)",
        "Starred Repos (/user/starred)",
        "Notifications (/notifications)",
        "Tokens Scopes (X-OAuth-Scopes header)",
    ]
    async def scan(self):
        print(f"\n{Fore.CYAN}=== GITHUB API RECON ==={Style.RESET_ALL}\n")
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/vnd.github+json"}
        # 1. User Profile (auth validation + scope detection)
        ok, resp = await self._safe_get("GitHub User Profile", "https://api.github.com/user", headers=headers)
        if ok:
            # Check X-OAuth-Scopes header for permission info
            scopes = resp.headers.get("X-OAuth-Scopes", "none")
            self.log_result(f"GitHub User Profile (scopes: {scopes})", resp.status, resp, severity=Severity.LOW)
        # ... continue for all checks
4.1 GitHub Scanner (scanners/github_scanner.py)
- Endpoint base: https://api.github.com
- Auth: Authorization: Bearer <token> or token <token>
- Checks:
  1. User Profile (GET /user) — auth validation + scope detection via X-OAuth-Scopes header
  2. Repos List (GET /user/repos?per_page=100) — repo access
  3. Organizations (GET /user/orgs) — org access
  4. Gists (GET /gists) — code snippet exfiltration
  5. SSH Keys (GET /user/keys) — SSH key exposure
  6. Actions Secrets (GET /repos/{owner}/{repo}/actions/secrets) — CI/CD secret exposure (needs a repo)
  7. Packages (GET /user/packages) — package registry access
  8. Starred Repos (GET /user/starred) — activity intel
  9. Notifications (GET /notifications) — account activity
  10. Rate Limit (GET /rate_limit) — confirms valid token
4.2 Anthropic Scanner (scanners/anthropic_scanner.py)
- Endpoint base: https://api.anthropic.com
- Auth: x-api-key: <key>
- Checks:
  1. Messages API (POST /v1/messages) — auth validation + quota
  2. Models List (GET /v1/models) — available models
  3. Count Tokens (POST /v1/messages/count_tokens) — token counting
4.3 HuggingFace Scanner (scanners/huggingface_scanner.py)
- Endpoint base: https://huggingface.co/api
- Auth: Authorization: Bearer <token>
- Checks:
  1. Whoami (GET /whoami-v2) — auth validation + user info
  2. Models List (GET /models) — model access
  3. Datasets List (GET /datasets) — dataset access
  4. Spaces List (GET /spaces) — deployed apps
  5. Inference Endpoints (GET /inference-endpoints) — compute resources
4.4 Stripe Scanner (scanners/stripe_scanner.py)
- Endpoint base: https://api.stripe.com/v1
- Auth: Authorization: Bearer <key> (sk_live_/sk_test_)
- Checks:
  1. Balance (GET /balance) — auth validation + financial exposure
  2. Charges List (GET /charges?limit=1) — payment history
  3. Customers List (GET /customers?limit=1) — PII exposure
  4. Payouts List (GET /payouts?limit=1) — bank transfer access
  5. Refunds List (GET /refunds?limit=1) — refund ability
  6. Products List (GET /products?limit=1) — catalog access
  7. Webhooks List (GET /webhook_endpoints) — webhook interception
4.5 Twilio Scanner (scanners/twilio_scanner.py)
- Endpoint base: https://api.twilio.com/2010-04-01
- Auth: HTTP Basic (Account SID as username, auth token as password) OR API Key (SK... as username, secret as password)
- Note: Twilio needs Account SID + Auth Token (two values). Accept as key:secret or separate flags.
- Checks:
  1. Account (GET /Accounts/{sid}.json) — auth validation
  2. Messages List (GET /Accounts/{sid}/Messages.json?PageSize=1) — SMS history
  3. Calls List (GET /Accounts/{sid}/Calls.json?PageSize=1) — call history
  4. Phone Numbers (GET /Accounts/{sid}/IncomingPhoneNumbers.json) — phone number inventory
  5. Usage (GET /Accounts/{sid}/Usage/Records.json) — billing usage
4.6 Slack Scanner (scanners/slack_scanner.py)
- Endpoint base: https://slack.com/api
- Auth: Authorization: Bearer <token>
- Checks:
  1. Auth Test (GET /auth.test) — auth validation + workspace info
  2. Channels List (GET /conversations.list) — channel access
  3. Users List (GET /users.list) — member enumeration
  4. Team Info (GET /team.info) — workspace details
  5. Files List (GET /files.list) — file access
4.7 Discord Scanner (scanners/discord_scanner.py)
- Endpoint base: https://discord.com/api/v10
- Auth: Authorization: Bot <token>
- Checks:
  1. Get User (GET /users/@me) — auth validation + bot info
  2. Get Guilds (GET /users/@me/guilds) — server access
  3. Get Application (GET /oauth2/applications/@me) — app info + scopes
4.8 SendGrid Scanner (scanners/sendgrid_scanner.py)
- Endpoint base: https://api.sendgrid.com/v3
- Auth: Authorization: Bearer <key>
- Checks:
  1. API Keys List (GET /api_keys) — auth validation + key enumeration
  2. Mail Send (POST /mail/send) — DO NOT actually send, just check auth via a dry-run or invalid payload
  3. Suppressions (GET /suppressions/bounces) — bounce list access
  4. Templates (GET /templates) — email template access
  5. Stats (GET /stats) — sending statistics
4.9 GitLab Scanner (scanners/gitlab_scanner.py)
- Endpoint base: https://gitlab.com/api/v4
- Auth: PRIVATE-TOKEN: <token>
- Checks:
  1. User (GET /user) — auth validation
  2. Projects (GET /projects?membership=true) — project access
  3. Groups (GET /groups) — group access
  4. SSH Keys (GET /user/keys) — SSH key exposure
  5. CI/CD Variables — needs a project ID, check if available via projects list
  6. Personal Access Tokens (GET /personal_access_tokens) — token enumeration
4.10 DigitalOcean Scanner (scanners/digitalocean_scanner.py)
- Endpoint base: https://api.digitalocean.com/v2
- Auth: Authorization: Bearer <token>
- Checks:
  1. Account (GET /account) — auth validation
  2. Droplets (GET /droplets) — VPS instances
  3. Spaces Keys (GET /spaces/keys) — S3-compatible storage keys
  4. SSH Keys (GET /account/keys) — SSH key exposure
  5. Databases (GET /databases) — managed DB access
  6. Kubernetes Clusters (GET /kubernetes/clusters) — DOKS clusters
  7. Firewalls (GET /firewalls) — firewall rules
---
Phase 5 — Advanced Architecture
5.1 Plugin auto-discovery (core/plugin_loader.py)
import importlib
import pkgutil
from pathlib import Path
def load_scanners():
    """Dynamically discover and load all scanner classes from scanners/ dir."""
    scanners = {}
    scanners_dir = Path(__file__).parent.parent / "scanners"
    for finder, name, _ in pkgutil.iter_modules([str(scanners_dir)]):
        if name.endswith("_scanner"):
            module = importlib.import_module(f"scanners.{name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and attr.__name__.endswith("Scanner") and attr.__name__ != "BaseScanner":
                    provider = getattr(attr, "PROVIDER_NAME", attr.__name__.replace("Scanner", "").lower())
                    scanners[provider] = attr
    return scanners
def get_scanner(provider, api_key, **kwargs):
    scanners = load_scanners()
    scanner_class = scanners.get(provider)
    if not scanner_class:
        raise ValueError(f"Unknown provider: {provider}. Available: {list(scanners.keys())}")
    return scanner_class(api_key, **kwargs)
scanners/__init__.py becomes empty (or just a docstring) — no manual imports needed.
5.2 Config file support (--config)
# config.example.yaml
provider: google
key: AIzaSy...
project_id: my-project-123
output: my_scan_report
formats:
  - json
  - html
  - sarif
timeout: 30
rate_limit: 10
notify_slack: https://hooks.slack.com/...
Load with pyyaml, merge with CLI args (CLI takes precedence).
5.3 Key extraction mode (extract subcommand)
# core/key_detector.py — add extraction function
import os
from pathlib import Path
EXTRACT_PATTERNS = {
    "google": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "openai": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "aws": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    # ... (same as KEY_PATTERNS but without ^ and $ anchors)
}
def extract_keys_from_directory(path):
    """Scan all files in a directory for potential API keys."""
    found = []
    for root, dirs, files in os.walk(path):
        # Skip .git, node_modules, __pycache__, etc.
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for file in files:
            filepath = Path(root) / file
            try:
                content = filepath.read_text(errors="ignore")
                for provider, pattern in EXTRACT_PATTERNS.items():
                    for match in pattern.finditer(content):
                        found.append({
                            "provider": provider,
                            "key": match.group(),
                            "file": str(filepath),
                            "line": content[:match.start()].count("\n") + 1,
                        })
            except Exception:
                continue
    return found
5.4 Webhook notifications (core/notifier.py)
import aiohttp
import json
async def notify_slack(webhook_url, scanner, provider):
    """Send scan summary to Slack webhook."""
    vulnerable = sum(1 for r in scanner.results if "VULNERABLE" in r["status_text"])
    total = len(scanner.results)
    payload = {
        "text": f"apiKeyScan Results for {provider.upper()}",
        "attachments": [{
            "color": "danger" if vulnerable > 0 else "good",
            "fields": [
                {"title": "Total Checks", "value": str(total), "short": True},
                {"title": "Vulnerable", "value": str(vulnerable), "short": True},
            ]
        }]
    }
    async with aiohttp.ClientSession() as session:
        await session.post(webhook_url, json=payload)
async def notify_discord(webhook_url, scanner, provider):
    """Send scan summary to Discord webhook."""
    # Similar structure, Discord webhook format
    ...
5.5 Docker support
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "apiKeyScan.py"]
# docker-compose.yml
version: "3.8"
services:
  apikeyscan:
    build: .
    volumes:
      - ./reports:/app/reports
    # Usage: docker-compose run apikeyscan scan -p google -k AIzaSy...
5.6 PyPI packaging (pyproject.toml)
[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"
[project]
name = "apikeyscan"
version = "2.0.0"
description = "Universal API Security Reconnaissance Tool"
readme = "README.md"
license = {file = "LICENSE"}
requires-python = ">=3.8"
dependencies = [
    "aiohttp>=3.9.0",
    "colorama>=0.4.6",
    "pyyaml>=6.0",
    "boto3>=1.34.0",
]
[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-asyncio>=0.21", "ruff>=0.1", "mypy>=1.5", "aioresponses>=0.7"]
[project.scripts]
apikeyscan = "apiKeyScan:main"
[tool.ruff]
line-length = 120
target-version = "py38"
[tool.mypy]
python_version = "3.8"
ignore_missing_imports = true
[tool.pytest.ini_options]
asyncio_mode = "auto"
---
Phase 6 — Testing & CI
6.1 Test structure
# tests/conftest.py
import pytest
from aioresponses import aioresponses
@pytest.fixture
def mock_aiohttp():
    with aioresponses() as m:
        yield m
# tests/test_google_scanner.py
import pytest
from scanners.google_scanner import GoogleScanner
@pytest.mark.asyncio
async def test_google_scanner_maps(mock_aiohttp):
    mock_aiohttp.get(
        "https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=07&size=400x400&key=test_key",
        status=200,
        body=b"image_data",
    )
    scanner = GoogleScanner("test_key")
    await scanner.scan()
    assert any("Maps" in r["service"] for r in scanner.results)
6.2 Test coverage targets
- core/base_scanner.py: 90%+ (severity detection, error handling, retry logic)
- core/key_detector.py: 95%+ (all provider patterns, extraction)
- core/report_engine.py: 85%+ (all 5 formats)
- Each scanner: 80%+ (mock all endpoints, test status classification)
6.3 GitHub Actions CI (.github/workflows/ci.yml)
name: CI
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.8", "3.9", "3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: mypy core/ scanners/ apiKeyScan.py
      - run: pytest --cov=core --cov=scanners --cov-report=term-missing
---
Updated requirements.txt
aiohttp>=3.9.0
colorama>=0.4.6
pyyaml>=6.0
boto3>=1.34.0
Dev dependencies (in pyproject.toml [project.optional-dependencies]):
pytest>=7.0
pytest-asyncio>=0.21
pytest-cov>=4.0
aioresponses>=0.7
ruff>=0.1
mypy>=1.5
---
Implementation Order (Sequential)
Step	Phase	Description
1	1.1	Async BaseScanner with severity, retry, timeout
2	1.2	Refactor 4 existing scanners to async
3	1.3	Update entry point with asyncio.run + exit codes
4	1.4	Fix docs, gitignore, untrack scanners.zip
5	2.1	Concurrency in BaseScanner (_run_checks)
6	2.2	Key detector module
7	2.3-2.4	Rate limiting + exit codes
8	3.1	CLI redesign with subcommands
9	3.2-3.3	SARIF + CSV reports
10	3.4	HTML report dashboard upgrade
11	3.5-3.6	Batch scanning + list-checks
12	4.1-4.10	10 new provider scanners
13	5.1	Plugin auto-discovery
14	5.2	Config file support
15	5.3	Key extraction mode
16	5.4	Webhook notifiers
17	5.5-5.6	Docker + PyPI packaging
18	6.1-6.2	Unit tests
19	6.3	GitHub Actions CI
Total	 	 
---
Key Reminders for Implementation
1. All HTTP scanners MUST use await self._safe_get() / await self._safe_post() — never raw aiohttp calls
2. AWS scanner uses asyncio.to_thread() to wrap sync boto3 calls — do NOT rewrite boto3 to async
3. Every scanner class MUST define PROVIDER_NAME and CHECKS class attributes for plugin discovery and list-checks
4. Severity should be explicitly set for each check — don't rely solely on auto-detection
5. Never actually send emails/messages in SendGrid/Twilio/Slack scanners — use read-only endpoints or invalid payloads that test auth without side effects
6. Add --no-color support — check a global flag before applying colorama colors
7. Rate limit default: None (unlimited) — only apply if --rate-limit is specified
8. Proxy support: pass to aiohttp.ClientSession(connector=aiohttp.TCPConnector(...), proxy=...) or via trust_env=True

Addition 1: Auto-Detect Key (User Doesn't Know the Provider)
Scenario
User has a key but doesn't know which provider it belongs to. The current key_detector.py only does regex matching, which fails when:
- The key format is unknown/non-standard
- The key matches multiple providers (ambiguous)
- The key is a custom format
Solution: Multi-Strategy Auto-Detection (core/key_detector.py)
# core/key_detector.py — enhanced with 4 strategies
import re
import asyncio
from enum import Enum
from typing import Optional, List
class DetectionConfidence(Enum):
    HIGH = "high"       # Regex match (exact format)
    MEDIUM = "medium"   # Probe confirmed (network validated)
    LOW = "low"         # Fallback guess
    UNKNOWN = "unknown" # No match at all
# --- Strategy 1: Regex Pattern Matching (fast, no network) ---
KEY_PATTERNS = {
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
def detect_by_regex(key: str) -> List[dict]:
    """Strategy 1: Match key against known regex patterns.
    Returns list of candidates (may be multiple for ambiguous keys).
    """
    candidates = []
    for provider, info in KEY_PATTERNS.items():
        if info["pattern"].match(key):
            candidates.append({
                "provider": provider,
                "confidence": DetectionConfidence.HIGH,
                "method": "regex",
                "description": info["description"],
            })
    return candidates
# --- Strategy 2: Probe-Based Detection (network, definitive) ---
# Each provider has a lightweight, read-only auth-validation endpoint
PROBE_ENDPOINTS = {
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
    # AWS and Twilio need two-part auth — skip in probe, rely on regex
}
async def detect_by_probe(key: str, candidates: List[str] = None, timeout: int = 10) -> Optional[dict]:
    """Strategy 2: Send lightweight probe to each candidate provider.
    Only call this for providers where regex was ambiguous or failed.
    """
    import aiohttp
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
            except Exception:
                continue
    return None
# --- Strategy 3: Interactive Confirmation ---
def interactive_confirm(key: str, candidates: List[dict]) -> dict:
    """When multiple providers match or detection is uncertain,
    show candidates and let user choose.
    """
    from colorama import Fore, Style
    print(f"\n{Fore.YELLOW}[?] Multiple possible providers detected for key: {key[:8]}...{key[-4:]}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Detected candidates:{Style.RESET_ALL}")
    for i, c in enumerate(candidates, 1):
        print(f"  {i}) {c['provider'].upper()} — {c['description']} (confidence: {c['confidence'].value})")
    print(f"  0) Try all providers (probe)")
    choice = input(f"\nSelect provider (0-{len(candidates)}) [default: 1]: ").strip() or "1"
    idx = int(choice)
    if idx == 0:
        return {"provider": None, "action": "probe_all"}
    return candidates[idx - 1]
# --- Master Detection Function ---
async def auto_detect_provider(key: str, interactive: bool = True) -> dict:
    """Full auto-detection pipeline:
    1. Try regex (fast)
    2. If exactly 1 match → return it
    3. If multiple matches → interactive confirm or probe all
    4. If 0 matches → probe all providers (brute-force)
    5. If still nothing → return unknown
    """
    # Step 1: Regex
    candidates = detect_by_regex(key)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        # Ambiguous — multiple regex matches
        if interactive:
            return interactive_confirm(key, candidates)
        # Non-interactive: probe all candidates to find the real one
        result = await detect_by_probe(key, [c["provider"] for c in candidates])
        if result:
            return result
        return candidates[0]  # Fallback to first regex match
    # Step 4: No regex match — brute-force probe all providers
    result = await detect_by_probe(key)
    if result:
        return result
    # Step 5: Complete unknown
    if interactive:
        return interactive_confirm(key, [{
            "provider": "unknown",
            "confidence": DetectionConfidence.UNKNOWN,
            "method": "failed",
            "description": "Could not detect provider",
        }])
    return {
        "provider": "unknown",
        "confidence": DetectionConfidence.UNKNOWN,
        "method": "failed",
        "description": "Could not detect provider",
    }
CLI Integration
# User has a key, doesn't know what it is — just pass the key, omit --provider
python apiKeyScan.py scan -k "some_unknown_key_here"
# → Tool auto-detects via regex → if ambiguous, probes → if still unknown, asks user
# User has a key file with mixed unknown keys
python apiKeyScan.py scan --keyfile keys.txt
# → Each key auto-detected independently, results labeled by detected provider
# Force probe-based detection (skip regex, useful for non-standard key formats)
python apiKeyScan.py scan -k "some_key" --force-probe
# Non-interactive mode (for CI/CD) — auto-detect without prompts
python apiKeyScan.py scan -k "some_key" --no-interactive
# → If ambiguous, probes all candidates automatically
# → If still unknown, tries all providers and reports whatever responds
Detection Flow Diagram
User provides key (no --provider)
         │
         ▼
   ┌─ Regex Match ─┐
   │                │
   ▼                ▼
 1 match         N matches        0 matches
   │                │                │
   ▼                ▼                ▼
 DONE      Interactive?      Brute-force
           │                 probe ALL
     Yes → Ask user          providers
     No  → Probe all              │
           candidates             ▼
           │                  1 responds?
           ▼                  Yes → DONE
      1 responds?             No  → UNKNOWN
      Yes → DONE
      No  → Use first
           regex match
---
Addition 2: Professional Code Consistency Skill
Add this as a new section in the plan document:
## Code Quality Standards (MANDATORY for all implementation)
The following standards MUST be enforced across all code. The build model
should treat these as hard rules, not suggestions.
### 1. Formatting & Linting (enforced via ruff)
```toml
# pyproject.toml [tool.ruff] section
[tool.ruff]
line-length = 120
target-version = "py38"
[tool.ruff.lint]
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort (import ordering)
    "B",    # flake8-bugbear (common bugs)
    "C4",   # flake8-comprehensions
    "UP",   # pyupgrade (modernize syntax)
    "N",    # pep8-naming
    "SIM",  # flake8-simplify
    "RUF",  # ruff-specific rules
]
ignore = ["E501"]  # line length handled by formatter
[tool.ruff.format]
quote-style = "double"
indent-style = "space"
Rules:
- Run ruff check . — must pass with zero errors
- Run ruff format --check . — must be pre-formatted
- No bare except: — use except Exception: or specific types
- No mutable default arguments (def f(x=[]) → def f(x=None))
- No unused imports/variables
- Import order: stdlib → third-party → local (enforced by isort rule)
2. Type Hints (enforced via mypy)
# pyproject.toml [tool.mypy] section
[tool.mypy]
python_version = "3.8"
strict = true
ignore_missing_imports = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
Rules:
- ALL public functions/methods MUST have type hints on parameters and return type
- Private helpers (_prefix) SHOULD have type hints
- Use Optional[X] for nullable, List[X]/Dict[str, X] for collections
- async def functions must have -> X or -> None return annotation
Example:
# GOOD
async def _safe_get(
    self,
    service_name: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> tuple[bool, Optional[aiohttp.ClientResponse]]:
    ...
# BAD — no type hints, bare except
def _safe_get(self, service_name, url, headers=None):
    try:
        ...
    except:
        ...
3. Naming Conventions
Element	Convention
Class	PascalCase
Method/Function	snake_case
Private method	_snake_case
Constant	UPPER_SNAKE
Module	snake_case
Enum	PascalCase class, UPPER values
Type alias	PascalCase
4. Architecture Conventions
DRY (Don't Repeat Yourself):
- All HTTP logic lives in BaseScanner — scanners NEVER call aiohttp directly
- All report formatting lives in ReportEngine — scanners never format output
- All key detection lives in key_detector — scanners never detect key types
Single Responsibility:
- BaseScanner → HTTP lifecycle, error handling, result storage
- ReportEngine → output formatting (console, JSON, HTML, CSV, SARIF)
- KeyDetector → key format detection and provider identification
- PluginLoader → scanner discovery and instantiation
- Notifier → webhook notifications
- Each *_scanner.py → provider-specific check logic ONLY
Dependency Injection:
- Scanners receive config via constructor, never read global state
- BaseScanner.__init__ accepts timeout, max_retries, rate_limit as params
- No module-level mutable state (no globals except constants)
Interface Segregation:
- BaseScanner defines: scan(), log_result(), log_error(), run()
- Scanners ONLY override scan() — never override log_result or run
- PROVIDER_NAME and CHECKS are class attributes on every scanner
5. Docstring Standard (Google style)
async def _safe_get(
    self,
    service_name: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> tuple[bool, Optional[aiohttp.ClientResponse]]:
    """Perform an async GET request with retry, timeout, and error handling.
    Args:
        service_name: Human-readable name of the service being checked.
            Used for logging and result labeling.
        url: The full URL to request.
        headers: Optional HTTP headers. Falls back to self.headers if None.
    Returns:
        A tuple of (success, response). If the request succeeded, success is
        True and response is the aiohttp ClientResponse. On failure, success
        is False and response is None (error is logged internally).
    Raises:
        Never raises — all exceptions are caught and logged via log_error().
    """
    ...
Rules:
- ALL public methods MUST have docstrings (Args, Returns, Raises)
- Private methods SHOULD have docstrings (at minimum a one-line summary)
- Modules MUST have a module-level docstring
- Comments in code ONLY for "why" (business reasoning), NEVER for "what" (code does what it says)
6. Error Handling Rules
# GOOD — specific exceptions, graceful degradation
try:
    resp = await session.get(url)
except aiohttp.ClientConnectorError as e:
    self.log_error(service_name, f"Connection refused: {e}")
    return False, None
except asyncio.TimeoutError:
    self.log_error(service_name, "Request timed out")
    return False, None
except aiohttp.ClientError as e:
    self.log_error(service_name, str(e))
    return False, None
# BAD — bare except, swallows everything
try:
    resp = await session.get(url)
except:
    pass
Rules:
- NEVER use bare except: or except Exception: pass
- Catch specific exception types
- Every caught exception MUST be logged (via log_error or logging)
- One check failure MUST NOT crash the entire scan
- Network errors → log_error(), continue to next check
- Invalid key → log once, skip remaining checks for that provider
7. Security Practices
# GOOD — key masking in logs/reports
masked_key = f"{key[:5]}...{key[-4:]}" if len(key) > 10 else "***"
# BAD — full key in logs
print(f"Scanning with key: {api_key}")
Rules:
- NEVER log/print full API keys — always mask (key[:5]...key[-4:])
- NEVER hardcode secrets, tokens, or credentials in source code
- NEVER commit .env files, report outputs, or __pycache__
- Validate all user inputs (file paths, URLs, key formats)
- Use pathlib.Path for file operations (prevents path traversal)
- Reports written to current dir only — no arbitrary paths from user without validation
8. Testing Standards
# GOOD — descriptive name, one concept, mocked external call
@pytest.mark.asyncio
async def test_google_scanner_returns_vulnerable_when_gcs_returns_200(mock_aiohttp):
    """GCS bucket list returning 200 should be classified as VULNERABLE."""
    mock_aiohttp.get(
        "https://storage.googleapis.com/storage/v1/b/test-bucket/o?key=test_key",
        status=200,
        payload={"items": []},
    )
    scanner = GoogleScanner("test_key", project_id="test-bucket")
    await scanner.scan()
    gcs_result = next(r for r in scanner.results if "GCS" in r["service"])
    assert "VULNERABLE" in gcs_result["status_text"]
    assert gcs_result["severity"] == Severity.HIGH
# BAD — vague name, real network call, no assertions
@pytest.mark.asyncio
async def test_google():
    scanner = GoogleScanner("real_key_here")
    await scanner.scan()
Rules:
- Test naming: test_<unit>_<scenario>_<expected_result>
- One logical assertion concept per test (multiple asserts OK if testing same concept)
- ALL external calls MUST be mocked (aioresponses for aiohttp, moto for boto3)
- NEVER use real API keys in tests — use fake keys like "test_key", "ghp_fake"
- NEVER make real network calls in tests
- Test files: one per scanner module (test_google_scanner.py for google_scanner.py)
- Coverage target: 80%+ per module, 90%+ for core/
9. Import Conventions
# GOOD — ordered: stdlib → third-party → local
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
import aiohttp
from colorama import Fore, Style
from core.base_scanner import BaseScanner, Severity
# BAD — unordered, mixed
from core.base_scanner import BaseScanner
import json
import aiohttp
from colorama import Fore
from typing import Optional
10. File/Module Structure Template
Every scanner file MUST follow this structure:
"""Module docstring: what provider this scanner covers and what it checks."""
import asyncio  # if needed
from typing import Optional
import aiohttp  # only if direct aiohttp usage needed (rare)
from colorama import Fore, Style
from core.base_scanner import BaseScanner, Severity
class GitHubScanner(BaseScanner):
    """Scanner for GitHub PAT and fine-grained tokens.
    Checks repo access, org access, gists, SSH keys, Actions secrets,
    and token scope enumeration.
    """
    PROVIDER_NAME = "github"
    CHECKS = [
        "User Profile (/user)",
        "Repos List (/user/repos)",
        # ...
    ]
    def __init__(self, api_key: str, **kwargs) -> None:
        super().__init__(api_key, **kwargs)
    async def scan(self) -> None:
        """Run all GitHub API reconnaissance checks concurrently."""
        print(f"\n{Fore.CYAN}=== GITHUB API RECON ==={Style.RESET_ALL}\n")
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/vnd.github+json"}
        checks = [
            self._check_user_profile(headers),
            self._check_repos(headers),
            # ...
        ]
        await self._run_checks(checks)
    async def _check_user_profile(self, headers: dict) -> None:
        """Check user profile endpoint for auth validation and scope detection."""
        ok, resp = await self._safe_get("GitHub User Profile", "https://api.github.com/user", headers=headers)
        if ok and resp:
            scopes = resp.headers.get("X-OAuth-Scopes", "none")
            self.log_result(f"GitHub User (scopes: {scopes})", resp.status, resp, severity=Severity.LOW)
Structure order:
1. Module docstring
2. Imports (ordered)
3. Class definition with docstring
4. Class attributes (PROVIDER_NAME, CHECKS)
5. __init__ (if custom params needed)
6. scan() method (public, async)
7. Private check methods (_check_*, one per check)