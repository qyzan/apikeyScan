# APIKey Security Recon (apiKeyScan)

**apiKeyScan** is an extremely lightweight, highly modular API Security Reconnaissance tool designed to quickly analyze the risk impact of leaked API Keys, access tokens, and cloud credentials. 

Instead of bloated frameworks, apiKeyScan focuses purely on critical endpoint validation across major cloud providers (Google Cloud, Azure, AWS, and OpenAI). It checks if an exposed key can be used to exfiltrate data, consume massive billing quotas, manipulate authentication services, or even move laterally through obscure CI/CD infrastructure.

---

## 🚀 Features
- **Extensive Service Coverage**:
  - **Google Workspace & GCP (21 Checks)**: Covers critical infrastructure like GCS Buckets, Firebase Realtime DB, Firestore, Identity Toolkit, Maps Suite, and modern FCM HTTP v1. **Also hunts obscure services** like Google Secret Manager, Cloud KMS, Cloud Build, and Cloud SQL.
  - **Azure Cognitive & Cloud**: Validates Bing Search, Text Analytics, Face API, Translator, and Maps.
  - **AWS (Boto3 integration)**: Confirms administrative privileges via `GetCallerIdentity`, `ListBuckets`, `GetUser`, and `DescribeInstances`. **Also hunts lateral movement** via SES (Email Spamming), SNS, SQS, and Route53 (DNS Hijacking).
  - **OpenAI**: Verifies models and chat completions for quota exhaustion testing on leaked ChatGPT keys.

---

## 🛠 Installation

Requires **Python 3.8+**.

1. Clone the repository:
   ```bash
   git clone https://github.com/qyzan/apiKeyScan.git
   cd apiKeyScan
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

*(Note: `boto3` is officially required for AWS scanning. If you do not plan to scan AWS, the tool will gracefully skip the import crash).*

---

## 💻 Usage

### Interactive Mode (Recommended)
Simply execute the script without any arguments to trigger the automated wizard:
```bash
python apiKeyScan.py
```

### CLI Automation Mode
Ideal for CI/CD pipelines, bash loops, or mass-scanning tasks. If any dependent variable is missing, the script will interactively ask for it.

**1. Google API Scan with HTML Report**
```bash
python apiKeyScan.py --provider google --key AIzaSyABCD1234EFGH5678IJKL --html
```

**2. OpenAI Quota Check with JSON logging**
```bash
python apiKeyScan.py -p openai -k sk-proj-1234abcd5678efgh --json
```

**3. AWS Credential Check (Requires Secret Key)**
```bash
python apiKeyScan.py -p aws -k AKIAXXXXXX --secret YYYYYYYYYYYYYYYY --html
```

### Advanced Flags
- `--project-id [ID]` : Specify GCP Project ID (enhances Firebase/Firestore/Secrets checking).
- `--referer [URL]` : Spoof the HTTP Referer header to bypass poorly configured restrictions.
- `--collection [NAME]` : Specify custom Firestore collection name to query (default: `users`).
- `--bucket [NAME]` : Specify a target GCS Bucket (default falls back to project-id).

---

## 📁 Architecture / Writing Plugins

The system is highly modularized via an OOP `BaseScanner` interface.

```text
apiKeyScan/
├── apiKeyScan.py                 # The lightweight entry router
├── core/
│   ├── base_scanner.py        # Abstract Inheritance Class & HTTP Classifiers
│   └── report_engine.py       # Handles console coloring, JSON, and HTML exports
└── scanners/
    ├── google_scanner.py      # Google Cloud & Workspace Logic
    ├── azure_scanner.py       
    ├── openai_scanner.py      
    └── aws_scanner.py         
```

To create a new scanner (e.g., `github_scanner.py`), simply inherit from `BaseScanner`, construct your queries, and call `self.log_result("Service Name", response.status_code, response)`. The core engine handles colorization, false-positives, and JSON/HTML extraction automatically.

---

## ⚠️ Disclaimer

**Educational and Authorized Security Use Only.**
The author(s) of this project are not responsible for any misuse or damage caused by this tool. Never use this tool against infrastructure you do not have explicit, documented permission to test. Always adhere to responsible disclosure guidelines when dealing with compromised credentials.

