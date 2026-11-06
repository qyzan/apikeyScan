#!/usr/bin/env python3
"""apiKeyScan — Universal API Security Reconnaissance Tool.

Async, multi-provider API key scanner with 14+ provider support,
severity ratings, 5 report formats (console/JSON/HTML/CSV/SARIF),
plugin auto-discovery, key auto-detection, and CI/CD exit codes.

Usage:
    python apiKeyScan.py scan -k AIzaSy...           # auto-detect provider
    python apiKeyScan.py scan -p github -k ghp_...   # explicit provider
    python apiKeyScan.py scan --keyfile keys.txt      # batch scan
    python apiKeyScan.py extract ./repo/             # extract keys from codebase
    python apiKeyScan.py list-checks --provider google
"""

import argparse
import asyncio
import re
import sys
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init

from core.base_scanner import CheckOutcome, ExecutionStatus
from core.config import ConfigError, load_config, merge_config_into_args
from core.key_detector import auto_detect_provider, extract_keys_from_directory
from core.notifier import send_notifications
from core.plugin_loader import get_scanner, list_checks, list_providers
from core.redaction import Sanitizer, mask
from core.report_engine import ReportEngine

init(autoreset=True)

VERSION = "2.0.0"

_SECRET_IN_FILENAME = re.compile(
    r"(ghp_|gho_|ghu_|ghs_|ghr_|"
    r"sk-|"
    r"AIza[0-9A-Za-z_-]{10,}|"
    r"AKIA[0-9A-Z]{12,}|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|"
    r"[0-9a-f]{40,})"
)

_FRAGMENT_MIN_LEN = 8

_EXTRACT_FORMAT_RE = re.compile(r"^\w+:.+\s+#\s+.+:\d+$")


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
    scan.add_argument("--account-sid", help="Twilio Account SID (AC... format)")
    scan.add_argument("--timeout", type=int, default=20, help="Overall request timeout (seconds)")
    scan.add_argument("--connect-timeout", type=int, default=10, help="Connection establishment timeout (seconds)")
    scan.add_argument("--read-timeout", type=int, default=10, help="Socket read timeout (seconds)")
    scan.add_argument("--rate-limit", type=int, help="Max requests per second (token bucket)")
    scan.add_argument("--concurrency", type=int, default=5, help="Max concurrent in-flight requests")
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
    scan.add_argument("--overwrite", action="store_true", help="Overwrite existing report files")
    scan.add_argument("--notify-slack", help="Slack webhook URL")
    scan.add_argument("--notify-discord", help="Discord webhook URL")
    scan.add_argument("--config", help="YAML config file path")
    scan.add_argument(
        "--force-probe",
        action="store_true",
        help="Deprecated: rejected with error (probe-based detection is disabled for safety)",
    )
    scan.add_argument("--no-interactive", action="store_true", help="Non-interactive mode (CI/CD)")
    scan.add_argument(
        "--no-active-checks",
        action="store_true",
        help="Disable mutating/billable checks (enabled by default)",
    )
    scan.add_argument(
        "--active-checks",
        action="store_true",
        help="No-op compatibility alias (active checks are enabled by default)",
    )
    scan.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    scan.add_argument("--vault-dir", help="Existing parent directory for an encrypted per-run vault (interactive only)")

    vault_open = subparsers.add_parser("vault-open", help="Open a local credential vault on the controlling terminal")
    vault_open.add_argument("path")

    extract = subparsers.add_parser("extract", help="Extract keys from a codebase")
    extract.add_argument("path", help="Directory to scan for leaked keys")
    extract.add_argument("--scan", action="store_true", help="Not yet supported — use 'scan' subcommand instead")
    extract.add_argument("--output", help="Output file for found keys")
    extract.add_argument("--no-color", action="store_true", help="Disable colored output")

    list_checks_cmd = subparsers.add_parser("list-checks", help="List available checks")
    list_checks_cmd.add_argument("-p", "--provider", help="Filter by provider")
    list_checks_cmd.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser


def build_scanner_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Build scanner constructor kwargs from CLI args.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dict of kwargs for scanner construction.
    """
    kwargs: dict[str, Any] = {
        "timeout": args.timeout,
        "no_color": args.no_color,
        "quiet": getattr(args, "quiet", False),
        "active_checks": not getattr(args, "no_active_checks", False),
        "concurrency": getattr(args, "concurrency", 5),
        "connect_timeout": getattr(args, "connect_timeout", 10),
        "read_timeout": getattr(args, "read_timeout", 10),
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
        kwargs["api_secret"] = args.secret
    if args.region:
        kwargs["region"] = args.region
    if getattr(args, "account_sid", None):
        kwargs["account_sid"] = args.account_sid
    return kwargs


async def run_single_scan(
    provider: str,
    api_key: str,
    kwargs: dict[str, Any],
    args: argparse.Namespace,
) -> Any | None:
    """Run a single provider scan (scan-only, no report writing).

    Args:
        provider: The provider name.
        api_key: The API key to scan.
        kwargs: Scanner constructor kwargs.
        args: Parsed CLI arguments for scanner flags.

    Returns:
        The scanner instance if successful, None on error.
    """
    try:
        scanner = get_scanner(provider, api_key, **kwargs)
        scanner.vault_ref = getattr(args, "vault_ref", None)
        scanner.vault_run = getattr(args, "vault_run", None)
        await scanner.run()

        if not getattr(args, "quiet", False):
            ReportEngine.display_console_summary(
                scanner,
                provider,
                severity_filter=getattr(args, "severity_filter", None),
                verbose=getattr(args, "verbose", False),
            )

        return scanner
    except ValueError as e:
        safe = Sanitizer(kwargs, secrets=(api_key,)).text(str(e))
        print(f"{Fore.RED}[!] {safe}{Style.RESET_ALL}")
        return None
    except Exception as e:
        safe = Sanitizer(kwargs, secrets=(api_key,)).text(str(e))
        print(f"{Fore.RED}[!] Scan error: {safe}{Style.RESET_ALL}")
        return None


def _make_input_entry(scanner: Any, provider: str, key: str) -> dict[str, Any]:
    """Create a manifest input entry from a completed scanner.

    Args:
        scanner: The scanner instance with scan_results.
        provider: The provider name.
        key: The raw API key (will be masked).

    Returns:
        Dict with key_masked, provider, status, and check counts.
    """
    return {
        "key_masked": mask(key),
        "provider": provider,
        "status": "completed",
        "checks_total": len(scanner.scan_results),
        "checks_accessible": sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.ACCESSIBLE),
        "checks_restricted": sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.RESTRICTED),
        "checks_skipped": sum(1 for r in scanner.scan_results if r.outcome == CheckOutcome.SKIPPED),
        "checks_error": sum(1 for r in scanner.scan_results if r.execution_status == ExecutionStatus.ERROR),
    }


def _determine_report_formats(args: argparse.Namespace) -> list[str]:
    """Determine which report formats to write based on CLI args.

    Args:
        args: Parsed CLI arguments.

    Returns:
        List of format names (json, html, csv, sarif).
    """
    if args.all_formats or (not args.json and not args.html and not args.csv and not args.sarif):
        return ["json", "html", "csv", "sarif"]
    formats: list[str] = []
    if args.json:
        formats.append("json")
    if args.html:
        formats.append("html")
    if args.csv:
        formats.append("csv")
    if args.sarif:
        formats.append("sarif")
    return formats


def _write_report_bundle(
    args: argparse.Namespace,
    scanners: list[tuple[Any, str]],
    inputs: list[dict[str, Any]],
    scanned_keys: list[str] | None = None,
) -> bool:
    """Write report bundle (reports + manifest).

    Args:
        args: Parsed CLI arguments.
        scanners: List of (scanner, provider) tuples.
        inputs: List of manifest input entries.
        scanned_keys: List of raw API keys being scanned, for credential-in-filename check.

    Returns:
        True if any write failed (including overwrite conflict), False on success.
    """
    if args.output:
        for key in scanned_keys or []:
            if not key:
                continue
            if len(key) < _FRAGMENT_MIN_LEN:
                if key in args.output:
                    print(
                        f"{Fore.RED}[!] Output prefix contains a scanned credential. "
                        f"Refusing to use secret in filename.{Style.RESET_ALL}"
                    )
                    return True
            else:
                for i in range(len(key) - _FRAGMENT_MIN_LEN + 1):
                    if key[i : i + _FRAGMENT_MIN_LEN] in args.output:
                        print(
                            f"{Fore.RED}[!] Output prefix contains a scanned credential fragment. "
                            f"Refusing to use secret in filename.{Style.RESET_ALL}"
                        )
                        return True
        if _SECRET_IN_FILENAME.search(args.output):
            print(
                f"{Fore.RED}[!] Output prefix contains a secret-like pattern. "
                f"Refusing to use potential secret in filename.{Style.RESET_ALL}"
            )
            return True

    is_batch = len(scanners) > 1
    if args.output:
        output_prefix = args.output
    elif is_batch:
        output_prefix = "pentest_report"
    elif scanners:
        output_prefix = f"pentest_{scanners[0][1]}_report"
    else:
        output_prefix = "pentest_report"

    formats = _determine_report_formats(args)
    manifest_filename = f"{output_prefix}_manifest.json"

    target_files = [f"{output_prefix}.{fmt}" for fmt in formats] if scanners else []

    if not getattr(args, "overwrite", False):
        for filepath in [*target_files, manifest_filename]:
            if Path(filepath).exists():
                print(
                    f"{Fore.RED}[!] Output file already exists: {filepath}. "
                    f"Use --overwrite to replace.{Style.RESET_ALL}"
                )
                return True

    report_results: list[dict[str, Any]] = []
    write_failed = False

    for fmt, filepath in zip(formats, target_files, strict=False):
        try:
            if is_batch:
                if fmt == "json":
                    ReportEngine.generate_json_batch_report(scanners, filepath)
                elif fmt == "html":
                    ReportEngine.generate_html_batch_report(scanners, filepath)
                elif fmt == "csv":
                    ReportEngine.generate_csv_batch_report(scanners, filepath)
                elif fmt == "sarif":
                    ReportEngine.generate_sarif_batch_report(scanners, filepath)
            else:
                scanner, provider = scanners[0]
                if fmt == "json":
                    ReportEngine.generate_json_report(scanner, provider, filepath)
                elif fmt == "html":
                    ReportEngine.generate_html_report(scanner, provider, filepath)
                elif fmt == "csv":
                    ReportEngine.generate_csv_report(scanner, provider, filepath)
                elif fmt == "sarif":
                    ReportEngine.generate_sarif_report(scanner, provider, filepath)
            report_results.append({"filename": filepath, "format": fmt, "write_status": "written"})
        except OSError as e:
            write_failed = True
            print(f"{Fore.RED}[!] Failed to write {fmt} report: {e}{Style.RESET_ALL}")
            report_results.append(
                {"filename": filepath, "format": fmt, "write_status": "write_failed", "error": str(e)}
            )

    bundle_status = "partial" if write_failed else "complete"
    try:
        ReportEngine.generate_manifest(inputs, report_results, manifest_filename, bundle_status)
    except OSError as e:
        write_failed = True
        print(f"{Fore.RED}[!] Failed to write manifest: {e}{Style.RESET_ALL}")

    return write_failed


async def run_scan_command(args: argparse.Namespace) -> int:
    """Execute the scan subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0=clean scan (no accessible findings, no errors, not all-unauthorized),
                   1=accessible finding detected (scan completed without errors),
                   2=error (input error, scan failure, no scanners ran,
                           zero check results, any check with execution_status=ERROR,
                           all checks UNAUTHORIZED (credential invalid), or partial failure).
    """
    config_data: dict[str, Any] = {}
    if args.config:
        try:
            config_data = load_config(args.config)
        except ConfigError as e:
            print(f"{Fore.RED}[!] Config error: {e}{Style.RESET_ALL}")
            return 2
        merge_config_into_args(args, config_data)

    provider = args.provider
    api_key = args.key
    keyfile = args.keyfile

    if not api_key and not keyfile:
        print(f"{Fore.RED}[!] Please specify --key or --keyfile.{Style.RESET_ALL}")
        return 2

    if getattr(args, "force_probe", False):
        print(
            f"{Fore.RED}[!] Probe-based detection is disabled: it sends credentials to "
            f"provider endpoints. Specify the provider with -p instead.{Style.RESET_ALL}"
        )
        return 2

    if getattr(args, "active_checks", False):
        print(
            f"{Fore.YELLOW}[i] --active-checks is a no-op: active checks are now enabled "
            f"by default. Use --no-active-checks to disable them.{Style.RESET_ALL}"
        )

    kwargs = build_scanner_kwargs(args)

    vault = None
    if getattr(args, "vault_dir", None):
        from core.vault import start_vault

        try:
            if args.no_interactive:
                raise ValueError("Interactive vault required")
            vault = start_vault(Path(args.vault_dir))
            args.vault_run = vault.path.stem
        except (OSError, ValueError):
            print("[!] Vault initialization failed; scan cancelled.")
            return 2

    def checkpoint(key: str) -> bool:
        if vault is None:
            return True
        try:
            credential = {"api_key": key}
            if args.secret:
                credential["aws_secret"] = args.secret
            args.vault_ref = vault.add(credential, provider or "undetected")
            return True
        except (OSError, ValueError):
            print("[!] Vault persistence failed; scan cancelled.")
            return False

    scanners: list[tuple[Any, str]] = []
    inputs: list[dict[str, Any]] = []
    scanned_keys: list[str] = []
    has_error = False

    if keyfile:
        try:
            with open(keyfile, encoding="utf-8") as f:
                keys: list[str] = []
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _EXTRACT_FORMAT_RE.match(stripped):
                        print(
                            f"{Fore.RED}[!] Keyfile rejected: line {len(keys) + 1} "
                            f"matches extract output format (provider:key # file:line). "
                            f"Use extract output as input to 'apiKeyScan scan -k <key>', "
                            f"not as a keyfile.{Style.RESET_ALL}"
                        )
                        return 2
                    keys.append(stripped)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Keyfile not found: {keyfile}{Style.RESET_ALL}")
            return 2

        for key in keys:
            scanned_keys.append(key)
            if not checkpoint(key):
                return 2
            key_provider = provider
            if not key_provider:
                detection = await auto_detect_provider(
                    key,
                    interactive=not args.no_interactive,
                    force_probe=args.force_probe,
                )
                key_provider = detection.get("provider")
                if not key_provider or key_provider == "unknown":
                    print(f"{Fore.YELLOW}[!] Could not detect provider for key: {mask(key)}{Style.RESET_ALL}")
                    inputs.append(
                        {
                            "key_masked": mask(key),
                            "provider": "unknown",
                            "status": "skipped",
                            "reason": "provider not detected",
                        }
                    )
                    continue

            print(f"\n{Fore.GREEN}[*] Scanning {key_provider.upper()} key: {mask(key)}{Style.RESET_ALL}")
            result = await run_single_scan(key_provider, key, kwargs, args)
            if result:
                scanners.append((result, key_provider))
                inputs.append(_make_input_entry(result, key_provider, key))
            else:
                has_error = True
                inputs.append({"key_masked": mask(key), "provider": key_provider, "status": "failed"})
    else:
        assert api_key is not None
        scanned_keys.append(api_key)
        if not checkpoint(api_key):
            return 2
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
            scanners.append((result, provider))
            inputs.append(_make_input_entry(result, provider, api_key))
        else:
            has_error = True
            inputs.append({"key_masked": mask(api_key), "provider": provider, "status": "failed"})

    write_failed = _write_report_bundle(args, scanners, inputs, scanned_keys=scanned_keys)

    if args.notify_slack or args.notify_discord:
        for scanner, prov in scanners:
            await send_notifications(scanner, prov, args.notify_slack, args.notify_discord)

    if has_error or write_failed:
        return 2

    if not scanners:
        return 2

    all_results = [r for s, _ in scanners for r in s.scan_results]
    if not all_results:
        return 2

    has_execution_error = any(r.execution_status == ExecutionStatus.ERROR for r in all_results)
    if has_execution_error:
        return 2

    if all(r.outcome == CheckOutcome.UNAUTHORIZED for r in all_results):
        return 2

    vulnerable_count = sum(1 for r in all_results if r.outcome == CheckOutcome.ACCESSIBLE)
    return 1 if vulnerable_count > 0 else 0


def run_extract_command(args: argparse.Namespace) -> int:
    """Execute the extract subcommand.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0=no candidates found, 1=candidates found,
                  2=inspection failure or --scan rejected.
    """
    if args.scan:
        print(
            f"{Fore.RED}[!] --scan is not yet supported. "
            f"Use 'apiKeyScan scan -k <key>' to scan individual keys.{Style.RESET_ALL}"
        )
        return 2

    path = Path(args.path)
    if not path.exists():
        print(f"{Fore.RED}[!] Path not found: {args.path}{Style.RESET_ALL}")
        return 2
    if not path.is_dir():
        print(f"{Fore.RED}[!] Not a directory: {args.path}{Style.RESET_ALL}")
        return 2

    print_banner()
    print(f"\n{Fore.CYAN}=== KEY EXTRACTION MODE ==={Style.RESET_ALL}\n")

    result = extract_keys_from_directory(args.path)

    if result.skipped:
        print(f"{Fore.YELLOW}[i] {len(result.skipped)} file(s) skipped:{Style.RESET_ALL}")
        for s in result.skipped:
            print(f"    {s.path} — {s.reason}")
        print()

    print(f"{Fore.CYAN}[i] Scanned {result.files_scanned}/{result.files_total} file(s).{Style.RESET_ALL}\n")

    if not result.found:
        not_inspected = len(result.skipped)
        scanned = result.files_scanned
        print(
            f"{Fore.GREEN}[+] No candidates found — {scanned} file(s) inspected, "
            f"{not_inspected} file(s) not inspected.{Style.RESET_ALL}"
        )
        return 0

    print(f"{Fore.YELLOW}[!] Found {len(result.found)} potential API key candidate(s):{Style.RESET_ALL}\n")
    for item in result.found:
        masked = f"{item.key[:8]}...{item.key[-4:]}" if len(item.key) > 12 else item.key
        conf_color = Fore.RED if item.confidence == "high" else Fore.YELLOW
        print(f"  {conf_color}[{item.provider.upper()}]{Style.RESET_ALL} {masked} (confidence: {item.confidence})")
        print(f"    Reason: {item.reason}")
        for fpath, line in item.locations:
            print(f"    Location: {fpath}:{line}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("# apiKeyScan extract output — format: provider:key # file:line\n")
                f.write("# NOTE: keys are written raw per operator decision (B09).\n")
                for item in result.found:
                    for fpath, line in item.locations:
                        f.write(f"{item.provider}:{item.key} # {fpath}:{line}\n")
            print(f"\n{Fore.BLUE}[INFO] Keys saved to: {args.output}{Style.RESET_ALL}")
        except OSError as e:
            print(f"{Fore.RED}[!] Failed to write output file: {e}{Style.RESET_ALL}")
            return 2

    return 1


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

    if getattr(args, "no_color", False):
        init(autoreset=True, strip=True)

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "vault-open":
        from core.vault import open_local

        try:
            open_local(Path(args.path))
        except (OSError, ValueError):
            print("[!] Cannot open vault or incorrect password.")
            sys.exit(2)
    elif args.command == "scan":
        if not getattr(args, "quiet", False):
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
