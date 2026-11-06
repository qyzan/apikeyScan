# apiKeyScan — Universal API Security Recon

**apiKeyScan** is a comprehensive, async, multi-provider API key security reconnaissance tool. It checks if exposed API keys can be used to exfiltrate data, consume billing quotas, manipulate authentication services, or move laterally through cloud infrastructure.

---

## Features

- **14 Providers**: Google Cloud, Azure, OpenAI, AWS, GitHub, Anthropic, HuggingFace, Stripe, Twilio, Slack, Discord, SendGrid, GitLab, DigitalOcean
- **Async + Concurrent**: All HTTP checks run concurrently via `asyncio` + `aiohttp`
- **Severity Ratings**: CRITICAL / ERROR / HIGH / MEDIUM / LOW / INFO per finding
- **5 Report Formats**: Console, JSON, HTML (with dashboard), CSV, SARIF 2.1.0
- **Key Auto-Detection**: Regex-based provider identification (probe-based detection disabled for safety)
- **Plugin Auto-Discovery**: Scanners loaded dynamically — just drop in a new file
- **CI/CD Ready**: Exit codes (0=clean, 1=accessible, 2=error), SARIF for GitHub Code Scanning
- **Batch Scanning**: Scan multiple keys from a file
- **Key Extraction**: Scan codebases for leaked keys
- **Notifications**: Slack & Discord webhook alerts

> **Breaking change (B04, Nov 2026):** `status_text` values changed: `"VULNERABLE"` → `"ACCESSIBLE"`, network error severity `CRITICAL` → `ERROR`. Reports/notifiers now use the `outcome` field as machine contract. Active checks run by default; use `--no-active-checks` to disable.

---

## Installation

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt
```

Or install as a package:
```bash
pip install -e .
```

---

## Usage

### Credential masking and optional encrypted vault
> **Kapan:** sebelum scan yang sudah diotorisasi · **Siapa:** operator.

Logger/report mask API keys and tokens of at least 16 characters as their first
8 characters followed by `....`; shorter values, passwords and Basic credentials
are hidden completely. No suffix is shown. Metadata stays readable. Recognized
auth cookie names and known credential reflections are masked; unknown cookie
names are unclassified, not guaranteed safe. This is not a PII filter.

The sanitizer parses mappings/lists, bounded JSON/Python literal representations,
query parameters and cookies. It never uses eval. Limits are 65,536 characters
for structured text, 4,096 for regex fallback and 24 levels for tree traversal;
over-limit evidence gets an explicit omission marker. Unknown aliases, arbitrary
encodings and binary secrets are not comprehensively detected.

Vault mode is opt-in: add `--vault-dir <existing-parent-directory>` to an
authorized `scan` invocation. It creates one private run subdirectory and one
`.akv` file for single or batch input. This option does not make provider checks
non-mutating: B02 safety work is separate. This section does not instruct anyone
to run a scan merely to test the vault.

> **Kapan:** otomatis sebelum deteksi/probe/scan dalam mode vault · **Siapa:** runtime.

A random per-run password appears once on the controlling terminal, never via
stdout/stderr. Save it in a separate password manager and enter `SAVED`. Without
a controlling terminal or verifiable operator-only ACL, vault mode fails closed.
CI/non-interactive vault use is unsupported. Credential checkpoints are encrypted
before disk writes and persisted before processing each input; failure stops the
remaining run. After the first checkpoint succeeds, the controlling terminal
shows the absolute vault path and Scan ID. Reports contain both opaque
`vault_run` and `vault_record` references (CSV adds columns); locate the file
named `<vault_run>.akv` in the selected vault parent.

Format v1: fixed magic/version, random 16-byte salt and 12-byte nonce; scrypt
N=131072/r=8/p=1 derives a 32-byte key; AES-256-GCM authenticates the header and
payload. Maximum vault size is 16 MiB. No plaintext temporary export is created.

### Open a vault locally
> **Kapan:** saat operator perlu membuka hasil tersimpan · **Siapa:** operator.

Run `python apiKeyScan.py vault-open <vault.akv>`. Password input has no echo;
decrypted credential output goes only to the controlling terminal, not a file or
redirected stdout/stderr. Opening a vault does not contact any provider.

Keep encrypted backups and passwords separately; choose retention manually and
delete vaults when no longer needed. A lost password cannot be recovered.
Terminal recordings, scrollback, screenshots and a compromised host remain risks.
No SSD secure-deletion or Python memory-zeroization guarantee is made. After
interruption the last completed atomic checkpoint remains available; an abrupt
kill may leave ciphertext-only temporary files, and data still in memory may be
lost. Power-loss durability beyond filesystem guarantees is not promised.

### Scan a single key (auto-detect provider)
```bash
python apiKeyScan.py scan -k AIzaSy...
```

### Scan with explicit provider and all report formats
```bash
python apiKeyScan.py scan -p github -k ghp_xxxx --all-formats
```

### Batch scan from file
```bash
python apiKeyScan.py scan --keyfile keys.txt --html --sarif
```

### AWS credentials (requires secret key)
```bash
python apiKeyScan.py scan -p aws -k AKIAXXXXXX --secret YYYYYYYY --all-formats
```

### Extract keys from a codebase
```bash
python apiKeyScan.py extract ./repo/
```

### List available checks
```bash
python apiKeyScan.py list-checks --provider google
```

### With notifications
```bash
python apiKeyScan.py scan -p stripe -k sk_live_... --notify-slack $URL
```

### Config preset
```bash
python apiKeyScan.py scan --config preset.yaml
```

### Active checks and safety
> **Kapan:** sebelum scan dengan credential · **Siapa:** operator.

Active checks (HTTP calls that may read or mutate provider resources) run by
default when credentials are provided. Use `--no-active-checks` to disable all
active checks and record them as SKIPPED with an explicit reason. The legacy
`--active-checks` flag is accepted as a no-op for backward compatibility.

`--force-probe` is **deprecated and rejected** with exit code 2. Probe-based
provider detection is disabled for safety. Specify the provider explicitly with
`-p` instead.

### CLI options reference
> **Kapan:** saat konfigurasi scan · **Siapa:** operator.

| Option | Description |
|--------|-------------|
| `--no-active-checks` | Disable active checks; record as SKIPPED with reason |
| `--no-color` | Disable colored output |
| `--quiet` | Suppress routine output (errors still printed) |
| `--verbose` | Show URL and reason in scan results |
| `--severity-filter ERROR` | Display only findings at or above severity |
| `--overwrite` | Overwrite existing report files |
| `--concurrency N` | Max concurrent checks (default: 10) |
| `--connect-timeout S` | Connection timeout in seconds |
| `--read-timeout S` | Read timeout in seconds |
| `--account-sid SID` | Twilio account SID (required for Twilio) |
| `--config FILE` | Load config preset from YAML |
| `--vault-dir DIR` | Enable encrypted credential vault |

### Docker
> **Kapan:** saat eksekusi terisolasi via container · **Siapa:** operator.
> **Status:** Dockerfile dan Compose disediakan; build/runtime belum dieksekusi dalam sesi ini (acceptance criterion 5 belum terpenuhi).

```bash
docker-compose run apikeyscan scan -p google -k AIzaSy...
```

The image uses `python:3.10-slim`, runs as a non-root user (UID 1000), and
installs from the project wheel. Reports are written to a named persistent
volume (`apikeyscan-reports`). The root filesystem is read-only with a tmpfs
for `/tmp`.

---

## Exit Codes (CI/CD)

| Code | scan subcommand | extract subcommand |
|------|----------------|-------------------|
| 0    | No accessible findings, no errors | No candidate keys found |
| 1    | At least one ACCESSIBLE finding | Candidate keys found |
| 2    | Error (input, scan failure, all-unauthorized) | Inspection failure or `--scan` rejected |

---

## Architecture

```text
apiKeyScan/
├── apiKeyScan.py              # Async entry point with subcommands
├── core/
│   ├── base_scanner.py        # Async BaseScanner + aiohttp + severity
│   ├── config.py              # YAML config loading + CLI merge (B08)
│   ├── key_detector.py        # Regex auto-detection + key extraction (B03/B12)
│   ├── notifier.py            # Slack/Discord webhooks (B14)
│   ├── plugin_loader.py       # Dynamic scanner discovery (B14)
│   ├── redaction.py           # Credential masking/sanitization (B01)
│   ├── report_engine.py       # Console + JSON + HTML + CSV + SARIF
│   ├── transport.py           # Rate limiting + retry/backoff (B10)
│   └── vault.py               # Encrypted credential vault (B01V)
└── scanners/
    ├── google_scanner.py      # 24 checks
    ├── azure_scanner.py       # 5 checks
    ├── openai_scanner.py      # 9 checks
    ├── aws_scanner.py         # 9 checks (boto3 via to_thread)
    ├── github_scanner.py      # 9 checks
    ├── anthropic_scanner.py   # 3 checks
    ├── huggingface_scanner.py # 5 checks
    ├── stripe_scanner.py      # 7 checks
    ├── twilio_scanner.py      # 5 checks
    ├── slack_scanner.py       # 5 checks
    ├── discord_scanner.py     # 3 checks
    ├── sendgrid_scanner.py    # 5 checks
    ├── gitlab_scanner.py      # 5 checks
    └── digitalocean_scanner.py# 7 checks
```

To add a new scanner, create a `scanners/<provider>_scanner.py` file with a class inheriting from `BaseScanner`. Define `PROVIDER_NAME` and `CHECKS` class attributes, implement `async def scan()`. The plugin loader discovers it automatically.

---

## Disclaimer

**Educational and Authorized Security Use Only.**
