import json
from datetime import datetime
from colorama import Fore, Style

class ReportEngine:
    @staticmethod
    def display_console_summary(scanner, provider_name):
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{'SERVICE':<40} | {'RESULT'}")
        print(f"{'='*65}{Style.RESET_ALL}")
        for res in scanner.results:
            color = res["color"]
            status = res["status_text"]
            service = res["service"]
            print(f"{color}{service:<40} | {status}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

    @staticmethod
    def generate_json_report(scanner, provider_name, filename=None):
        if not filename:
            filename = f"pentest_{provider_name}_report.json"
        
        masked_key = scanner.api_key[:5] + "..." + scanner.api_key[-5:] if len(scanner.api_key) > 10 else "***"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_metadata": {
                    "provider": provider_name,
                    "timestamp": datetime.now().isoformat(),
                    "api_key_scanned": masked_key
                },
                "raw_responses": scanner.raw_data
            }, f, indent=4)
        print(f"{Fore.BLUE}[INFO] JSON Report saved to: {filename}{Style.RESET_ALL}")

    @staticmethod
    def generate_html_report(scanner, provider_name, filename=None):
        if not filename:
            filename = f"pentest_{provider_name}_report.html"
            
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Pentest Report - {provider_name.upper()}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2f; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #27293d; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ border-bottom: 2px solid #e14eca; padding-bottom: 10px; color: #ffffff; }}
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
            if(el.style.display === 'table-row') {{
                el.style.display = 'none';
            }} else {{
                el.style.display = 'table-row';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <h1>API Security Reconnaissance Report</h1>
        <div class="header-info">
            <p><strong>Provider:</strong> {provider_name.upper()}</p>
            <p><strong>Date SCANNED:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <table>
            <tr>
                <th>Service Name</th>
                <th>Status</th>
                <th>Endpoint URL</th>
                <th>Action</th>
            </tr>
"""
        for i, raw in enumerate(scanner.raw_data):
            res = scanner.results[i]
            status_class = res["status_text"].lower()
            if "vulnerable" in status_class: status_class = "vulnerable"
            elif "restricted" in status_class: status_class = "restricted"
            elif "unauthorized" in status_class: status_class = "unauthorized"
            else: status_class = "other"
            
            url_short = raw["url"][:60] + "..." if len(raw["url"]) > 60 else raw["url"]
            raw_body = raw["response_body"]
            if isinstance(raw_body, str) and raw_body.startswith("data:image/"):
                body_pretty = f'<br/><img src="{raw_body}" alt="API Image Response" style="max-width: 100%; border: 1px solid #444; border-radius: 5px;" />'
            else:
                body_str = json.dumps(raw_body, indent=2) if isinstance(raw_body, dict) else str(raw_body)
                import html
                body_pretty = f"<pre>{html.escape(body_str)}</pre>"
            
            html_content += f"""
            <tr>
                <td>{res['service']}</td>
                <td class="{status_class}">{res['status_text']}</td>
                <td><a href="{raw['url']}" style="color: #1f8ef1; text-decoration: none;" target="_blank">{url_short}</a></td>
                <td><button class="details-btn" onclick="toggleDetails('detail-{i}')">View Response Content</button></td>
            </tr>
            <tr id="detail-{i}" class="details-row">
                <td colspan="4">
                    <strong>Status Code:</strong> {raw['status_code']}<br/><br/>
                    <strong>Response body (raw payload):</strong>
                    {body_pretty}
                </td>
            </tr>"""
            
        html_content += """
        </table>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{Fore.BLUE}[INFO] HTML Report saved to: {filename}{Style.RESET_ALL}")
