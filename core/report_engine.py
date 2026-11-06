"""Report engine for generating scan results in multiple formats.

Supports console summary, JSON, HTML (with dashboard), CSV, and SARIF 2.1.0
reports. All report methods are static and accept a scanner instance.
"""

import csv
import html as html_lib
import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from colorama import Fore, Style

from core.redaction import mask, scanner_sanitizer


class ReportEngine:
    """Static report generation engine for all output formats."""

    @staticmethod
    def _safe_snapshot(scanner: Any) -> Any:
        """Sanitize even externally populated results without changing the scanner."""
        sanitizer = scanner_sanitizer(scanner, scanner.results, scanner.raw_data)
        return SimpleNamespace(
            api_key=ReportEngine._mask_key(scanner.api_key),
            results=sanitizer.clean(scanner.results),
            raw_data=sanitizer.clean(scanner.raw_data),
            vault_ref=getattr(scanner, "vault_ref", None),
            vault_run=getattr(scanner, "vault_run", None),
        )

    @staticmethod
    def _mask_key(api_key: str) -> str:
        """Mask an API key for safe display in reports.

        Args:
            api_key: The API key to mask.

        Returns:
            Prefix-only token mask, or a full redaction marker for short inputs.
        """
        return mask(api_key)

    _SEVERITY_FILTER_MAP: dict[str, int] = {
        "critical": 0,
        "high": 2,
        "medium": 3,
        "low": 4,
    }

    @staticmethod
    def display_console_summary(
        scanner: Any,
        provider_name: str,
        severity_filter: str | None = None,
        verbose: bool = False,
    ) -> None:
        """Print a colorized console summary table of all scan results.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for the summary header.
            severity_filter: Optional minimum severity to display (critical/high/medium/low).
                Results below this severity are hidden from display but still stored.
            verbose: If True, show URL and reason for each result.
        """
        no_color = getattr(scanner, "no_color", False)
        cyan = "" if no_color else Fore.CYAN
        reset = "" if no_color else Style.RESET_ALL

        scanner = ReportEngine._safe_snapshot(scanner)
        all_results = scanner.results
        all_raw = scanner.raw_data

        max_order = ReportEngine._SEVERITY_FILTER_MAP.get(severity_filter or "", 99)
        severity_order = {"CRITICAL": 0, "ERROR": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

        visible = []
        hidden_count = 0
        for i, res in enumerate(all_results):
            sev = res.get("severity", "INFO")
            if severity_order.get(sev, 5) <= max_order:
                visible.append((res, all_raw[i] if i < len(all_raw) else {}))
            else:
                hidden_count += 1

        print(f"\n{cyan}{'=' * 70}")
        print(f"{'SERVICE':<45} | {'RESULT':<25}")
        print(f"{'=' * 70}{reset}")
        for res, raw in visible:
            color = "" if no_color else res.get("color", "")
            status = res["status_text"]
            service = res["service"]
            severity = res.get("severity", "INFO")
            print(f"{color}{service:<45} | {status:<25}{reset} [{severity}]")
            if verbose:
                url = raw.get("url", "N/A")
                reason = raw.get("reason", "")
                print(f"  URL: {url}")
                if reason:
                    print(f"  Reason: {reason}")
        print(f"{cyan}{'=' * 70}{reset}")

        if hidden_count > 0:
            total = len(all_results)
            print(f"  {hidden_count} result(s) hidden by severity filter ({total} total)\n")
        else:
            print()

    @staticmethod
    def generate_json_report(scanner: Any, provider_name: str, filename: str | None = None) -> str:
        """Generate a JSON report file with scan metadata and raw responses.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for metadata.
            filename: Optional custom filename. Defaults to pentest_<provider>_report.json.

        Returns:
            The filename of the generated report.
        """
        scanner = ReportEngine._safe_snapshot(scanner)
        if not filename:
            filename = f"pentest_{provider_name}_report.json"

        masked_key = ReportEngine._mask_key(scanner.api_key)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "scan_metadata": {
                        "provider": provider_name,
                        "vault_record": scanner.vault_ref,
                        "vault_run": scanner.vault_run,
                        "timestamp": datetime.now().isoformat(),
                        "api_key_scanned": masked_key,
                        "total_checks": len(scanner.results),
                        "vulnerable_count": sum(1 for r in scanner.results if r.get("outcome") == "accessible"),
                    },
                    "results": scanner.results,
                    "raw_responses": scanner.raw_data,
                },
                f,
                indent=4,
                default=str,
            )
        print(f"{Fore.BLUE}[INFO] JSON Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_csv_report(scanner: Any, provider_name: str, filename: str | None = None) -> str:
        """Generate a CSV report file with one row per check.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for metadata.
            filename: Optional custom filename. Defaults to pentest_<provider>_report.csv.

        Returns:
            The filename of the generated report.
        """
        scanner = ReportEngine._safe_snapshot(scanner)
        if not filename:
            filename = f"pentest_{provider_name}_report.csv"

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["service", "status_text", "status_code", "severity", "url", "timestamp", "vault_record", "vault_run"]
            )
            timestamp = datetime.now().isoformat()
            for i, res in enumerate(scanner.results):
                raw = scanner.raw_data[i] if i < len(scanner.raw_data) else {}
                writer.writerow(
                    [
                        res["service"],
                        res["status_text"],
                        res.get("status_code", ""),
                        res.get("severity", "INFO"),
                        raw.get("url", "N/A"),
                        timestamp,
                        scanner.vault_ref,
                        scanner.vault_run,
                    ]
                )
        print(f"{Fore.BLUE}[INFO] CSV Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_sarif_report(scanner: Any, provider_name: str, filename: str | None = None) -> str:
        """Generate a SARIF 2.1.0 report for GitHub Code Scanning integration.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for the tool driver.
            filename: Optional custom filename. Defaults to pentest_<provider>_report.sarif.

        Returns:
            The filename of the generated report.
        """
        scanner = ReportEngine._safe_snapshot(scanner)
        if not filename:
            filename = f"pentest_{provider_name}_report.sarif"

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "apiKeyScan", "version": "2.0.0"}},
                    "properties": {"vault_record": scanner.vault_ref, "vault_run": scanner.vault_run},
                    "results": [
                        {
                            "ruleId": res["service"],
                            "level": "error" if res.get("outcome") == "accessible" else "note",
                            "message": {"text": res["status_text"]},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": raw.get("url", "N/A")},
                                    }
                                }
                            ],
                        }
                        for res, raw in zip(scanner.results, scanner.raw_data, strict=False)
                    ],
                }
            ],
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=4, default=str)
        print(f"{Fore.BLUE}[INFO] SARIF Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_html_report(scanner: Any, provider_name: str, filename: str | None = None) -> str:
        """Generate an HTML report with summary dashboard and severity badges.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for the report header.
            filename: Optional custom filename. Defaults to pentest_<provider>_report.html.

        Returns:
            The filename of the generated report.
        """
        scanner = ReportEngine._safe_snapshot(scanner)
        if not filename:
            filename = f"pentest_{provider_name}_report.html"

        total = len(scanner.results)
        vulnerable = sum(1 for r in scanner.results if r.get("outcome") == "accessible")
        restricted = sum(1 for r in scanner.results if r.get("outcome") == "restricted")
        errors = sum(1 for r in scanner.results if r.get("outcome") == "error")
        sum(1 for r in scanner.results if r.get("outcome") == "unauthorized")

        sev_counts: dict[str, int] = {"CRITICAL": 0, "ERROR": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in scanner.results:
            sev = r.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_colors = {
            "CRITICAL": "#ff4444",
            "ERROR": "#ff44ff",
            "HIGH": "#ff8800",
            "MEDIUM": "#ffdd44",
            "LOW": "#44ddff",
            "INFO": "#4488ff",
        }

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>apiKeyScan Report - {provider_name.upper()}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2f; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #27293d; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ border-bottom: 2px solid #e14eca; padding-bottom: 10px; color: #ffffff; }}
        h2 {{ color: #ffeb3b; margin-top: 30px; }}
        .dashboard {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .card {{ background: #1e1e2f; padding: 15px 25px; border-radius: 8px; text-align: center; min-width: 120px; }}
        .card .num {{ font-size: 28px; font-weight: bold; display: block; }}
        .card .label {{ font-size: 12px; color: #aaa; text-transform: uppercase; }}
        .card.vulnerable .num {{ color: #00f2fe; }}
        .card.restricted .num {{ color: #fd5d93; }}
        .card.errors .num {{ color: #ff4444; }}
        .card.total .num {{ color: #ffeb3b; }}
        .sev-bar {{ display: flex; height: 30px; border-radius: 5px; overflow: hidden; margin: 10px 0; }}
        .sev-segment {{ display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: bold; color: #fff; transition: width 0.3s; }}
        .sev-legend {{ display: flex; gap: 15px; margin: 10px 0; flex-wrap: wrap; }}
        .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: #fff; }}
        .filters {{ margin: 15px 0; }}
        .filter-btn {{ background: #1f8ef1; color: #fff; border: none; padding: 8px 16px; cursor: pointer; border-radius: 4px; margin-right: 5px; }}
        .filter-btn:hover {{ background: #007bff; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }}
        th, td {{ border: 1px solid #333; padding: 12px; text-align: left; word-wrap: break-word; overflow-wrap: break-word; }}
        th {{ background-color: #1e1e2f; color: #ffeb3b; }}
        tr:nth-child(even) {{ background-color: #2b2b40; }}
        .vulnerable {{ color: #00f2fe; font-weight: bold; }}
        .restricted {{ color: #fd5d93; font-weight: bold; }}
        .unauthorized {{ color: #fd5d93; font-weight: bold; }}
        .other {{ color: #ffeb3b; }}
        .details-btn {{ background-color: #1f8ef1; color: #ffffff; border: none; padding: 8px 12px; cursor: pointer; border-radius: 4px; font-weight: bold; transition: 0.2s; }}
        .details-btn:hover {{ background-color: #007bff; }}
        .details-row {{ display: none; background-color: #1e1e2f; }}
        pre {{ background: #121212; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; word-break: break-all; font-size: 13px; color: #00f2fe; border: 1px solid #333; }}
        .header-info {{ margin-bottom: 20px; font-size: 16px; }}
        .header-info strong {{ color: #ffeb3b; }}
    </style>
    <script>
        function toggleDetails(id) {{
            var el = document.getElementById(id);
            el.style.display = el.style.display === 'table-row' ? 'none' : 'table-row';
        }}
        function filterRows(filter) {{
            var rows = document.querySelectorAll('tr[data-status]');
            rows.forEach(function(row) {{
                if (filter === 'all' || row.dataset.status === filter) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>apiKeyScan Security Reconnaissance Report</h1>
        <div class="header-info">
            <p><strong>Provider:</strong> {provider_name.upper()}</p>
            <p><strong>Vault record:</strong> {html_lib.escape(scanner.vault_ref or '')}</p>
            <p><strong>Vault run:</strong> {html_lib.escape(scanner.vault_run or '')}</p>
            <p><strong>Date Scanned:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <h2>Summary Dashboard</h2>
        <div class="dashboard">
            <div class="card total"><span class="num">{total}</span><span class="label">Total Checks</span></div>
            <div class="card vulnerable"><span class="num">{vulnerable}</span><span class="label">Vulnerable</span></div>
            <div class="card restricted"><span class="num">{restricted}</span><span class="label">Restricted</span></div>
            <div class="card errors"><span class="num">{errors}</span><span class="label">Errors</span></div>
        </div>

        <h2>Severity Breakdown</h2>
        <div class="sev-bar">
"""
        for sev, count in sev_counts.items():
            if total > 0 and count > 0:
                pct = (count / total) * 100
                html_content += f'            <div class="sev-segment" style="width: {pct}%; background: {sev_colors.get(sev, "#888")};">{sev}: {count}</div>\n'

        html_content += """        </div>
        <div class="sev-legend">
"""
        for sev, count in sev_counts.items():
            html_content += f'            <span class="sev-badge" style="background: {sev_colors.get(sev, "#888")};">{sev}: {count}</span>\n'

        html_content += """        </div>

        <div class="filters">
            <button class="filter-btn" onclick="filterRows('all')">All</button>
            <button class="filter-btn" onclick="filterRows('vulnerable')">Vulnerable</button>
            <button class="filter-btn" onclick="filterRows('restricted')">Restricted</button>
            <button class="filter-btn" onclick="filterRows('error')">Errors</button>
        </div>

        <table>
            <tr>
                <th>Service Name</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Endpoint URL</th>
                <th>Action</th>
            </tr>
"""
        for i, raw in enumerate(scanner.raw_data):
            res = scanner.results[i]
            outcome_val = res.get("outcome", "")
            if outcome_val == "accessible":
                status_class = "vulnerable"
                data_status = "vulnerable"
            elif outcome_val == "restricted":
                status_class = "restricted"
                data_status = "restricted"
            elif outcome_val == "unauthorized":
                status_class = "unauthorized"
                data_status = "restricted"
            elif outcome_val == "error":
                status_class = "other"
                data_status = "error"
            else:
                status_class = "other"
                data_status = "other"

            url_short = raw["url"][:60] + "..." if len(raw["url"]) > 60 else raw["url"]
            raw_body = raw["response_body"]
            if isinstance(raw_body, str) and raw_body.startswith("data:image/"):
                body_pretty = f'<br/><img src="{raw_body}" alt="API Image Response" style="max-width: 100%; border: 1px solid #444; border-radius: 5px;" />'
            else:
                body_str = (
                    json.dumps(raw_body, indent=2, default=str) if isinstance(raw_body, dict | list) else str(raw_body)
                )
                body_pretty = f"<pre>{html_lib.escape(body_str)}</pre>"

            sev = res.get("severity", "INFO")
            sev_badge = f'<span class="sev-badge" style="background: {sev_colors.get(sev, "#888")};">{sev}</span>'

            html_content += f"""
            <tr data-status="{data_status}">
                <td>{html_lib.escape(res["service"])}</td>
                <td class="{status_class}">{html_lib.escape(res["status_text"])}</td>
                <td>{sev_badge}</td>
                <td><a href="{html_lib.escape(str(raw["url"]))}" style="color: #1f8ef1; text-decoration: none;" target="_blank">{html_lib.escape(url_short)}</a></td>
                <td><button class="details-btn" onclick="toggleDetails('detail-{i}')">View Response</button></td>
            </tr>
            <tr id="detail-{i}" class="details-row">
                <td colspan="5">
                    <strong>Status Code:</strong> {raw.get("status_code", "N/A")}<br/><br/>
                    <strong>Response Body:</strong>
                    {body_pretty}
                </td>
            </tr>"""

        html_content += """
        </table>
    </div>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"{Fore.BLUE}[INFO] HTML Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_all_reports(scanner: Any, provider_name: str, output_prefix: str | None = None) -> list[str]:
        """Generate reports in all available formats.

        Args:
            scanner: The scanner instance with results and raw_data.
            provider_name: The provider name for filenames.
            output_prefix: Optional custom prefix for filenames.

        Returns:
            List of generated filenames.
        """
        prefix = output_prefix or f"pentest_{provider_name}_report"
        files: list[str] = []
        files.append(ReportEngine.generate_json_report(scanner, provider_name, f"{prefix}.json"))
        files.append(ReportEngine.generate_html_report(scanner, provider_name, f"{prefix}.html"))
        files.append(ReportEngine.generate_csv_report(scanner, provider_name, f"{prefix}.csv"))
        files.append(ReportEngine.generate_sarif_report(scanner, provider_name, f"{prefix}.sarif"))
        return files

    @staticmethod
    def generate_json_batch_report(scanners_with_providers: list[tuple[Any, str]], filename: str) -> str:
        """Generate a batch JSON report with all scanners' results.

        Args:
            scanners_with_providers: List of (scanner, provider_name) tuples.
            filename: Output filename.

        Returns:
            The filename of the generated report.
        """
        timestamp = datetime.now().isoformat()
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scans: list[dict[str, Any]] = []
        for scanner, provider_name in scanners_with_providers:
            snap = ReportEngine._safe_snapshot(scanner)
            scans.append(
                {
                    "provider": provider_name,
                    "api_key_scanned": snap.api_key,
                    "vault_record": snap.vault_ref,
                    "vault_run": snap.vault_run,
                    "results": snap.results,
                    "raw_responses": snap.raw_data,
                }
            )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "scan_metadata": {
                        "batch_id": batch_id,
                        "timestamp": timestamp,
                        "inputs_total": len(scanners_with_providers),
                        "scanners_completed": len(scanners_with_providers),
                    },
                    "scans": scans,
                },
                f,
                indent=4,
                default=str,
            )
        print(f"{Fore.BLUE}[INFO] JSON Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_csv_batch_report(scanners_with_providers: list[tuple[Any, str]], filename: str) -> str:
        """Generate a batch CSV report with provider and masked key columns.

        Args:
            scanners_with_providers: List of (scanner, provider_name) tuples.
            filename: Output filename.

        Returns:
            The filename of the generated report.
        """
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["provider", "api_key", "service", "status_text", "status_code", "severity", "url", "timestamp"]
            )
            timestamp = datetime.now().isoformat()
            for scanner, provider_name in scanners_with_providers:
                snap = ReportEngine._safe_snapshot(scanner)
                for i, res in enumerate(snap.results):
                    raw = snap.raw_data[i] if i < len(snap.raw_data) else {}
                    writer.writerow(
                        [
                            provider_name,
                            snap.api_key,
                            res["service"],
                            res["status_text"],
                            res.get("status_code", ""),
                            res.get("severity", "INFO"),
                            raw.get("url", "N/A"),
                            timestamp,
                        ]
                    )
        print(f"{Fore.BLUE}[INFO] CSV Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_sarif_batch_report(scanners_with_providers: list[tuple[Any, str]], filename: str) -> str:
        """Generate a batch SARIF 2.1.0 report with all scanners' results.

        Args:
            scanners_with_providers: List of (scanner, provider_name) tuples.
            filename: Output filename.

        Returns:
            The filename of the generated report.
        """
        all_results: list[dict[str, Any]] = []
        for scanner, provider_name in scanners_with_providers:
            snap = ReportEngine._safe_snapshot(scanner)
            for res, raw in zip(snap.results, snap.raw_data, strict=False):
                all_results.append(
                    {
                        "ruleId": res["service"],
                        "level": "error" if res.get("outcome") == "accessible" else "note",
                        "message": {"text": res["status_text"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": raw.get("url", "N/A")},
                                }
                            }
                        ],
                        "properties": {"provider": provider_name, "api_key": snap.api_key},
                    }
                )

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "apiKeyScan", "version": "2.0.0"}},
                    "results": all_results,
                }
            ],
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=4, default=str)
        print(f"{Fore.BLUE}[INFO] SARIF Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_html_batch_report(scanners_with_providers: list[tuple[Any, str]], filename: str) -> str:
        """Generate a batch HTML report with sections per provider/key.

        Args:
            scanners_with_providers: List of (scanner, provider_name) tuples.
            filename: Output filename.

        Returns:
            The filename of the generated report.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_parts = [
            f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>apiKeyScan Batch Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background-color: #1e1e2f; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #27293d; padding: 20px; border-radius: 8px; }}
        h1 {{ border-bottom: 2px solid #e14eca; padding-bottom: 10px; color: #ffffff; }}
        h2 {{ color: #ffeb3b; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
        th {{ background-color: #1e1e2f; color: #ffeb3b; }}
        .vulnerable {{ color: #00f2fe; font-weight: bold; }}
        .restricted {{ color: #fd5d93; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>apiKeyScan Batch Report</h1>
        <p><strong>Date Scanned:</strong> {timestamp}</p>
        <p><strong>Inputs:</strong> {len(scanners_with_providers)}</p>
"""
        ]

        for idx, (scanner, provider_name) in enumerate(scanners_with_providers):
            snap = ReportEngine._safe_snapshot(scanner)
            html_parts.append(
                f"""
        <h2>Scan {idx + 1}: {html_lib.escape(provider_name.upper())} &mdash; {html_lib.escape(str(snap.api_key))}</h2>
        <table>
            <tr><th>Service</th><th>Status</th><th>Severity</th><th>Outcome</th></tr>
"""
            )
            for res in snap.results:
                outcome = res.get("outcome", "")
                cls = "vulnerable" if outcome == "accessible" else "restricted" if outcome == "restricted" else ""
                html_parts.append(
                    f"            <tr><td>{html_lib.escape(res['service'])}</td>"
                    f'<td class="{cls}">{html_lib.escape(res["status_text"])}</td>'
                    f"<td>{html_lib.escape(str(res.get('severity', 'INFO')))}</td>"
                    f"<td>{html_lib.escape(outcome)}</td></tr>\n"
                )
            html_parts.append("        </table>\n")

        html_parts.append(
            """    </div>
</body>
</html>"""
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write("".join(html_parts))
        print(f"{Fore.BLUE}[INFO] HTML Report saved to: {filename}{Style.RESET_ALL}")
        return filename

    @staticmethod
    def generate_manifest(
        inputs: list[dict[str, Any]],
        report_files: list[dict[str, Any]],
        filename: str,
        bundle_status: str,
    ) -> str:
        """Generate a manifest file for the report bundle.

        Args:
            inputs: List of input entries (key_masked, provider, status, check counts).
            report_files: List of report file entries (filename, format, write_status).
            filename: Output filename for the manifest.
            bundle_status: Overall bundle status ("complete" or "partial").

        Returns:
            The filename of the generated manifest.
        """
        completed = sum(1 for i in inputs if i.get("status") == "completed")
        failed = sum(1 for i in inputs if i.get("status") == "failed")
        skipped = sum(1 for i in inputs if i.get("status") == "skipped")
        terminal_statuses = {"completed", "failed", "skipped"}
        outcomes_recorded = sum(1 for i in inputs if i.get("status") in terminal_statuses)

        manifest = {
            "scan_id": f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "inputs": inputs,
            "reconciliation": {
                "inputs_total": len(inputs),
                "outcomes_recorded": outcomes_recorded,
                "scanners_completed": completed,
                "scanners_failed": failed,
                "scanners_skipped": skipped,
            },
            "reports": report_files,
            "bundle_status": bundle_status,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4, default=str)
        print(f"{Fore.BLUE}[INFO] Manifest saved to: {filename}{Style.RESET_ALL}")
        return filename
