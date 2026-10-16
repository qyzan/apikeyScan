# apiKeyScan — Universal API Security Recon

**apiKeyScan** is a comprehensive, async, multi-provider API key security reconnaissance tool. It checks if exposed API keys can be used to exfiltrate data, consume billing quotas, manipulate authentication services, or move laterally through cloud infrastructure.

---

## Features

- **14 Providers**: Google Cloud, Azure, OpenAI, AWS, GitHub, Anthropic, HuggingFace, Stripe, Twilio, Slack, Discord, SendGrid, GitLab, DigitalOcean
- **Async + Concurrent**: All HTTP checks run concurrently via `asyncio` + `aiohttp`
- **Severity Ratings**: CRITICAL / HIGH / MEDIUM / LOW / INFO per finding
- **5 Report Formats**: Console, JSON, HTML (with dashboard), CSV, SARIF 2.1.0
- **Key Auto-Detection**: Regex + network probe-based provider identification
- **Plugin Auto-Discovery**: Scanners loaded dynamically — just drop in a new file
- **CI/CD Ready**: Exit codes (0=clean, 1=vulnerable, 2=error), SARIF for GitHub Code Scanning
- **Batch Scanning**: Scan multiple keys from a file
- **Key Extraction**: Scan codebases for leaked keys
- **Notifications**: Slack & Discord webhook alerts

---

## Installation

Requires **Python 3.8+**.

```bash
pip install -r requirements.txt
```

Or install as a package:
```bash
pip install -e .
```

---

## Usage

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
python apiKeyScan.py extract ./repo/ --scan
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

### Docker
```bash
docker-compose run apikeyscan scan -p google -k AIzaSy...
```

---

## Exit Codes (CI/CD)

| Code | Meaning |
|------|---------|
| 0    | No vulnerabilities found |
| 1    | At least one VULNERABLE finding |
| 2    | Scan error (invalid key, connection failure) |

---

## Architecture

```text
apiKeyScan/
├── apiKeyScan.py              # Async entry point with subcommands
├── core/
│   ├── base_scanner.py        # Async BaseScanner + aiohttp + severity
│   ├── report_engine.py       # Console + JSON + HTML + CSV + SARIF
│   ├── key_detector.py        # Regex + probe auto-detection
│   ├── notifier.py            # Slack/Discord webhooks
│   └── plugin_loader.py       # Dynamic scanner discovery
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
