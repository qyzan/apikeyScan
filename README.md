# Universal API Security Recon (apiScan)

**apiScan** is an extremely lightweight, highly modular API Security Reconnaissance tool designed to quickly analyze the risk impact of leaked API Keys, access tokens, and cloud credentials. 

Instead of bloated frameworks, apiScan focuses purely on critical endpoint validation across major cloud providers (Google Cloud, Azure, AWS, and OpenAI). It checks if an exposed key can be used to exfiltrate data, consume massive billing quotas, or manipulate authentication services.

---

## 🚀 Features

- **Interactive Wizard Mode**: Don't want to type arguments? Just run `python apiScan.py` and let the aesthetic CLI guide you.
- **Advanced Modular OOP Architecture**: Easily write plugins for new services by dumping a file into the `scanners/` directory. No spaghetti code.
- **Aesthetic Reporting Engine**: Generate gorgeous offline HTML Dashboards and pristine JSON datasets to attach to your Bug Bounty/VAPT reports automatically.
- **Extensive Service Coverage**:
  - **Google Workspace & GCP**: Checks 17 highly-critical endpoints including GCS Buckets, Firebase, Firestore, Custom Search, Identity Toolkit, Maps Suite, and FCM.
  - **Azure Cognitive & Cloud**: Validates Bing Search, Text Analytics, Face API, Translator, and Maps.
  - **AWS (Boto3 integration)**: Confirms `GetCallerIdentity`, `ListBuckets`, `DescribeInstances`, `GetUser`, and `ListFunctions`.
  - **OpenAI**: Verifies models and chat completions for quota exhaustion testing.

---

## 🛠 Installation

Requires **Python 3.8+**.

1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/apiGoogleScan.git
   cd apiGoogleScan
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

*(Note: `boto3` is required for AWS scanning. If you do not plan to scan AWS, the tool will gracefully skip it without crashing).*

---

## 💻 Usage

### Interactive Mode (Recommended)
Simply execute the script without any arguments to trigger the automated wizard:
```bash
python apiScan.py
```

### CLI Automation Mode
Ideal for CI/CD pipelines, bash loops, or mass-scanning tasks.

**1. Google API Scan with HTML Report**
```bash
python apiScan.py --provider google --key AIzaSyABCD1234EFGH5678IJKL --html
```

**2. OpenAI Quota Check with JSON logging**
```bash
python apiScan.py -p openai -k sk-proj-1234abcd5678efgh --json
```

**3. AWS Credential Check (Requires Secret Key)**
```bash
python apiScan.py -p aws -k AKIAXXXXXX --secret YYYYYYYYYYYYYYYY --html
```

### Advanced Flags
- `--project-id [ID]` : Specify GCP Project ID (enhances Firebase/Firestore checking).
- `--referer [URL]` : Spoof the HTTP Referer header to bypass poorly configured restrictions.
- `--collection [NAME]` : Specify custom Firestore collection name to query (default: `users`).
- `--bucket [NAME]` : Specify a target GCS Bucket (default falls back to project-id).

---

## 📁 Architecture / Writing Plugins

The system is highly modularized via an OOP `BaseScanner` interface.

```
apiScan/
├── apiScan.py                 # The lightweight entry router
├── core/
│   ├── base_scanner.py        # Abstract Inheritance Class
│   └── report_engine.py       # Handles console coloring, JSON, and HTML exports
└── scanners/
    ├── google_scanner.py      # Module specific logic
    ├── azure_scanner.py       
    ├── openai_scanner.py      
    └── aws_scanner.py         
```

To create a new scanner (e.g., `github_scanner.py`), simply inherit from `BaseScanner`, wrap your requests, and call `self.log_result("Service Name", response.status_code, response)`. The core engine handles the rest seamlessly.

---

## ⚠️ Disclaimer

**Educational and Authorized Security Use Only.**
The author(s) of this project are not responsible for any misuse or damage caused by this tool. Never use this tool against infrastructure you do not have explicit, documented permission to test. Always adhere to responsible disclosure guidelines when dealing with compromised credentials.
