#!/usr/bin/env python3
"""apiKeyScan — Universal API Security Reconnaissance Tool.

Async, multi-provider API key scanner with 14+ provider support,
severity ratings, 5 report formats (console/JSON/HTML/CSV/SARIF),
plugin auto-discovery, key auto-detection, and CI/CD exit codes.

Usage:
    python apiKeyScan.py scan -k AIzaSy...           # auto-detect provider
    python apiKeyScan.py scan -p github -k ghp_...   # explicit provider
    python apiKeyScan.py scan --keyfile keys.txt      # batch scan
    python apiKeyScan.py extract ./repo/ --scan       # extract & scan
    python apiKeyScan.py list-checks --provider google
"""

import argparse
import asyncio
import sys
from typing import Any, Dict, List, Optional

from colorama import Fore, Style, init

from core.key_detector import auto_detect_provider, extract_keys_from_directory
from core.notifier import send_notifications
from core.plugin_loader import get_scanner, list_checks, list_providers
from core.report_engine import ReportEngine

init(autoreset=True)

VERSION = "2.0.0"


def print_banner() -> None:
    """Print the apiKeyScan banner."""
    banner = f"""
{Fore.MAGENTA}   ___  ____ ___  ____                  {Style.RESET_ALL}
{Fore.MAGENTA}  / _ \\|  _ \\_ _|/ ___|  ___ __ _ _ __  {Style.RESET_ALL}
{Fore.MAGENTA} | |_| | |_) | | \\___ \\ / __/ _` | '_ \\ {Style.RESET_ALL}
{Fore.MAGENTA} |  _  |  __/| |  ___) | (_| (_| | | | |{Style.RESET_ALL}
{Fore.MAGENTA} |_| |_|_|  |___||____/ \\___\\__,_|_| |_|{Style.RESET_ALL}
{Fore.CYAN}        Universal API Security Recon v{VERSION}    {Style.RESET_ALL}
    """
    print(banner)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI parser with subcommands.

    Returns:
        Configured ArgumentParser with scan, extract, and list-checks subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="apiKeyScan",
        description="Universal API Security Reconnaissance Tool",
    )
    subparsers = parser.add_subparsers(dest="command")

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
    scan.add_argument("--severity-filter", choices=["critical", "high", "medium", "low"], help="Min severity to report")
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
    scan.add_argument("--force-probe", action="store_true", help="Force probe-based detection")
    scan.add_argument("--no-interactive", action="store_true", help="Non-interactive mode (CI/CD)")
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan.add_argument("-q", "--quiet", action="store_true", help="Quiet output")

    extract = subparsers.add_parser("extract", help="Extract & scan keys from a codebase")
    extract.add_argument("path", help="Directory to scan for leaked keys")
    extract.add_argument("--scan", action="store_true", help="Auto-scan found keys")
    extract.add_argument("--output", help="Output file for found keys")
    extract.add_argument("--no-color", action="store_true", help="Disable colored output")

    list_checks_cmd = subparsers.add_parser("list-checks", help="List available checks")
    list_checks_cmd.add_argument("-p", "--provider", help="Filter by provider")
    list_checks_cmd.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser


def load_config(config_path: str) -> Dict[str, Any]:
    """Load a YAML config file.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Dict of configuration values.
    """
    try:
        import yaml

        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        print(f"{Fore.RED}[!] PyYAML is required for config files. Install: pip install pyyaml{Style.RESET_ALL}")
        return {}
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Config file not found: {config_path}{Style.RESET_ALL}")
        return {}


def build_scanner_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    """Build scanner constructor kwargs from CLI args.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dict of kwargs for scanner construction.
    """
    kwargs: Dict[str, Any] = {
        "timeout": args.timeout,
        "no_color": args.no_color,
    }
    if args.rate_limit:
        kwargs["rate_limit"] = args.rate_limit
    if args.proxy:
        kwargs["proxy"] = args.proxy
    if args.user_agent:
        kwargs["user_agent"] = args.user_agent
    if args.project_id:
        kwargs["project_id"] = args.project_id
    if args.referer:
        kwargs["referer"] = args.referer
    if args.collection:
        kwargs["collection_name"] = args.collection
    if args.bucket:
        kwargs["bucket_name"] = args.bucket
    if args.secret:
        kwargs["aws_secret"] = args.secret
    if args.region:
        kwargs["region"] = args.region
    return kwargs


async def run_single_scan(
    provider: str,
    api_key: str,
    kwargs: Dict[str, Any],
    args: argparse.Namespace,
) -> Optional[Any]:
    """Run a single provider scan and generate reports.

    Args:
        provider: The provider name.
        api_key: The API key to scan.
        kwargs: Scanner constructor kwargs.
        args: Parsed CLI arguments for report flags.

    Returns:
        The scanner instance if successful, None on error.
    """
    try:
        scanner = get_scanner(provider, api_key, **kwargs)
        await scanner.run()

        ReportEngine.display_console_summary(scanner, provider)

        output_prefix = args.output or f"pentest_{provider}_report"

        if args.all_formats or (not args.json and not args.html and not args.csv and not args.sarif):
            ReportEngine.generate_all_reports(scanner, provider, output_prefix)
        else:
            if args.json:
                ReportEngine.generate_json_report(scanner, provider, f"{output_prefix}.json")
            if args.html:
                ReportEngine.generate_html_report(scanner, provider, f"{output_prefix}.html")
            if args.csv:
                ReportEngine.generate_csv_report(scanner, provider, f"{output_prefix}.csv")
            if args.sarif:
                ReportEngine.generate_sarif_report(scanner, provider, f"{output_prefix}.sarif")

        if args.notify_slack or args.notify_discord:
            await send_notifications(scanner, provider, args.notify_slack, args.notify_discord)

        return scanner
    except ValueError as e:
        print(f"{Fore.RED}[!] {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")
        return None


async def run_scan_command(args: argparse.Namespace) -> int:
    """Execute the scan subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0=clean, 1=vulnerable found, 2=error.
    """
    config_data: Dict[str, Any] = {}
    if args.config:
        config_data = load_config(args.config)

    provider = args.provider or config_data.get("provider")
    api_key = args.key or config_data.get("key")
    keyfile = args.keyfile or config_data.get("keyfile")

    if not api_key and not keyfile:
        print(f"{Fore.RED}[!] Please specify --key or --keyfile.{Style.RESET_ALL}")
        return 2

    kwargs = build_scanner_kwargs(args)

    scanners: List[Any] = []
    has_error = False

    if keyfile:
        try:
            with open(keyfile, encoding="utf-8") as f:
                keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Keyfile not found: {keyfile}{Style.RESET_ALL}")
            return 2

        for key in keys:
            key_provider = provider
            if not key_provider:
                detection = await auto_detect_provider(
                    key,
                    interactive=not args.no_interactive,
                    force_probe=args.force_probe,
                )
                key_provider = detection.get("provider")
                if not key_provider or key_provider == "unknown":
                    print(f"{Fore.YELLOW}[!] Could not detect provider for key: {key[:10]}...{Style.RESET_ALL}")
                    continue

            print(f"\n{Fore.GREEN}[*] Scanning {key_provider.upper()} key: {key[:8]}...{Style.RESET_ALL}")
            result = await run_single_scan(key_provider, key, kwargs, args)
            if result:
                scanners.append(result)
            else:
                has_error = True
    else:
        if not provider:
            detection = await auto_detect_provider(
                api_key,
                interactive=not args.no_interactive,
                force_probe=args.force_probe,
            )
            provider = detection.get("provider")
            if not provider or provider == "unknown":
                print(f"{Fore.RED}[!] Could not detect provider for the given key.{Style.RESET_ALL}")
                return 2
            print(f"{Fore.GREEN}[*] Auto-detected provider: {provider.upper()}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}[*] Initializing {provider.upper()} scanner...{Style.RESET_ALL}")
        result = await run_single_scan(provider, api_key, kwargs, args)
        if result:
            scanners.append(result)
        else:
            has_error = True

    if has_error and not scanners:
        return 2

    vulnerable_count = sum(1 for s in scanners for r in s.results if "VULNERABLE" in r["status_text"])
    return 1 if vulnerable_count > 0 else 0


def run_extract_command(args: argparse.Namespace) -> int:
    """Execute the extract subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0=success, 2=error.
    """
    print_banner()
    print(f"\n{Fore.CYAN}=== KEY EXTRACTION MODE ==={Style.RESET_ALL}\n")

    found = extract_keys_from_directory(args.path)

    if not found:
        print(f"{Fore.GREEN}[+] No API keys found in {args.path}{Style.RESET_ALL}")
        return 0

    print(f"{Fore.YELLOW}[!] Found {len(found)} potential API key(s):{Style.RESET_ALL}\n")
    for item in found:
        masked = f"{item['key'][:8]}...{item['key'][-4:]}" if len(item["key"]) > 12 else item["key"]
        print(f"  {Fore.RED}[{item['provider'].upper()}]{Style.RESET_ALL} {masked}")
        print(f"    File: {item['file']}:{item['line']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for item in found:
                f.write(f"{item['provider']}:{item['key']} # {item['file']}:{item['line']}\n")
        print(f"\n{Fore.BLUE}[INFO] Keys saved to: {args.output}{Style.RESET_ALL}")

    if args.scan:
        print(f"\n{Fore.CYAN}[*] Scanning found keys...{Style.RESET_ALL}")
        for item in found:
            print(
                f"\n{Fore.GREEN}[*] Scanning {item['provider'].upper()} key from {item['file']}:{item['line']}{Style.RESET_ALL}"
            )

    return 1 if found else 0


def run_list_checks_command(args: argparse.Namespace) -> int:
    """Execute the list-checks subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0=success.
    """
    print_banner()
    checks = list_checks(args.provider)

    if args.provider:
        checks_list = checks.get(args.provider, [])
        print(f"\n{Fore.CYAN}=== {args.provider.upper()} Checks ({len(checks_list)}) ==={Style.RESET_ALL}\n")
        for i, check in enumerate(checks_list, 1):
            print(f"  {i:3d}. {check}")
    else:
        providers = list_providers()
        print(f"\n{Fore.CYAN}=== Available Providers ({len(providers)}) ==={Style.RESET_ALL}\n")
        for p in providers:
            count = len(checks.get(p, []))
            print(f"  {Fore.GREEN}{p:<20}{Style.RESET_ALL} ({count} checks)")
            for check in checks.get(p, []):
                print(f"    - {check}")
            print()

    return 0


def main() -> None:
    """Main entry point — parse args and dispatch to subcommand handlers."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        if not args.no_color:
            print_banner()
        exit_code = asyncio.run(run_scan_command(args))
        sys.exit(exit_code)
    elif args.command == "extract":
        exit_code = run_extract_command(args)
        sys.exit(exit_code)
    elif args.command == "list-checks":
        exit_code = run_list_checks_command(args)
        sys.exit(exit_code)
    else:
        print_banner()
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
