import argparse
import sys
from colorama import Fore, Style, init
from core.report_engine import ReportEngine
from scanners import GoogleScanner, AzureScanner, OpenAIScanner, AWSScanner

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.MAGENTA}  ___  ____ ___  ____                  {Style.RESET_ALL}
{Fore.MAGENTA} / _ \\|  _ \\_ _|/ ___|  ___ __ _ _ __  {Style.RESET_ALL}
{Fore.MAGENTA}| |_| | |_) | | \\___ \\ / __/ _` | '_ \\ {Style.RESET_ALL}
{Fore.MAGENTA}|  _  |  __/| |  ___) | (_| (_| | | | |{Style.RESET_ALL}
{Fore.MAGENTA}|_| |_|_|  |___||____/ \\___\\__,_|_| |_|{Style.RESET_ALL}
{Fore.CYAN}       Universal API Security Recon     {Style.RESET_ALL}
    """
    print(banner)

def interactive_mode():
    print_banner()
    print(f"\n{Fore.CYAN}=== Interactive Wizard ==={Style.RESET_ALL}")
    print("1) Google Cloud / Workspace API (17 checks)")
    print("2) Azure Cognitive / Cloud API")
    print("3) OpenAI API Check")
    print("4) AWS Credentials Scan")
    
    choice = input("Select Provider (1-4) [default 1]: ").strip() or "1"
    
    aws_secret = None
    if choice == "4":
        provider = "aws"
        api_key = input("Enter AWS Access Key ID: ").strip()
        aws_secret = input("Enter AWS Secret Access Key: ").strip()
    elif choice == "3":
        provider = "openai"
        api_key = input(f"Enter {provider.upper()} API Key: ").strip()
    elif choice == "2":
        provider = "azure"
        api_key = input(f"Enter {provider.upper()} API Key: ").strip()
    else:
        provider = "google"
        api_key = input(f"Enter {provider.upper()} API Key: ").strip()
    
    if not api_key:
        print(f"{Fore.RED}[!] API/Access Key is strictly required.{Style.RESET_ALL}")
        sys.exit(1)

    project_id, referer, collection, bucket = None, None, "users", None
    if provider == "google":
        project_id = input("Enter Project ID (Optional, press Enter to skip): ").strip() or None
        referer = input("Enter Referer (Optional, press Enter to skip): ").strip() or None
        collection = input("Enter Firestore Collection to check [default: users]: ").strip() or "users"
        bucket = input("Enter GCS Bucket Name [default: Project ID]: ").strip() or None

    print("\nSelect Export Format:")
    print("1) Console Table Only")
    print("2) Console + JSON Report")
    print("3) Console + HTML Report")
    print("4) Console + JSON + HTML (All)")
    
    fmt = input("Choose export (1-4) [default 4]: ").strip() or "4"
    
    return {
        "provider": provider,
        "api_key": api_key,
        "aws_secret": aws_secret,
        "project_id": project_id,
        "referer": referer,
        "collection": collection,
        "bucket": bucket,
        "export_fmt": fmt
    }

def main():
    parser = argparse.ArgumentParser(description="APIScan - Universal API Security Recon (Google, Azure, OpenAI, AWS)")
    parser.add_argument("-p", "--provider", choices=["google", "azure", "openai", "aws"], help="Cloud Provider to scan")
    parser.add_argument("-k", "--key", help="API Key or AWS Access Key ID")
    parser.add_argument("--secret", help="AWS Secret Access Key (Only for AWS provider)")
    parser.add_argument("--project-id", help="Project ID (Google only)")
    parser.add_argument("--referer", help="Bypass referer restriction header")
    parser.add_argument("--collection", default="users", help="Firestore Collection (Google only)")
    parser.add_argument("--bucket", help="GCS Bucket Name (Google only)")
    parser.add_argument("--json", action="store_true", help="Generate JSON format log")
    parser.add_argument("--html", action="store_true", help="Generate HTML report page")

    if len(sys.argv) == 1:
        # CLI empty, load interactive UI wizard
        args = interactive_mode()
        provider = args["provider"]
        api_key = args["api_key"]
        aws_secret = args["aws_secret"]
        project_id = args["project_id"]
        referer = args["referer"]
        collection = args["collection"]
        bucket = args["bucket"]
        
        json_opt = args["export_fmt"] in ["2", "4"]
        html_opt = args["export_fmt"] in ["3", "4"]
    else:
        # CLI Mode arguments parsing
        print_banner()
        parsed_args = parser.parse_args()
        if not parsed_args.provider or not parsed_args.key:
            print(f"{Fore.RED}[!] Please specify --provider and --key when running in CLI mode.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Example: python apiScan.py -p google -k AIzaSy... --html{Style.RESET_ALL}")
            sys.exit(1)
            
        provider = parsed_args.provider
        api_key = parsed_args.key
        aws_secret = parsed_args.secret
        project_id = parsed_args.project_id
        referer = parsed_args.referer
        collection = parsed_args.collection
        bucket = parsed_args.bucket

        # Prompt for missing config even in CLI mode
        if provider == "aws" and not aws_secret:
            aws_secret = input(f"{Fore.YELLOW}Enter AWS Secret Access Key:{Style.RESET_ALL} ").strip()
        
        if provider == "google":
            if not project_id:
                project_id = input(f"{Fore.YELLOW}Enter Project ID (Optional, press Enter to skip):{Style.RESET_ALL} ").strip() or None
            if not referer:
                referer = input(f"{Fore.YELLOW}Enter Referer (Optional, press Enter to skip):{Style.RESET_ALL} ").strip() or None
            if collection == "users":
                col_input = input(f"{Fore.YELLOW}Enter Firestore Collection to check [default: users]:{Style.RESET_ALL} ").strip()
                if col_input: collection = col_input
            if not bucket:
                bucket = input(f"{Fore.YELLOW}Enter GCS Bucket Name [default: Project ID]:{Style.RESET_ALL} ").strip() or None
        
        json_opt = parsed_args.json
        html_opt = parsed_args.html
        
        if not json_opt and not html_opt:
            json_opt = True
            html_opt = True

    print(f"\n{Fore.GREEN}[*] Initializing {provider.upper()} API scanner module...{Style.RESET_ALL}")

    if provider == "google":
        scanner = GoogleScanner(api_key, project_id=project_id, referer=referer)
        scanner.scan(collection_name=collection, bucket_name=bucket)
    elif provider == "azure":
        scanner = AzureScanner(api_key)
        scanner.scan()
    elif provider == "openai":
        scanner = OpenAIScanner(api_key)
        scanner.scan()
    elif provider == "aws":
        scanner = AWSScanner(api_key, aws_secret)
        scanner.scan()

    ReportEngine.display_console_summary(scanner, provider)
    
    if json_opt:
        ReportEngine.generate_json_report(scanner, provider)
        
    if html_opt:
        ReportEngine.generate_html_report(scanner, provider)

if __name__ == "__main__":
    main()