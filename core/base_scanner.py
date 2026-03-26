from colorama import Fore, Style

class BaseScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.results = []
        self.raw_data = []

    def log_result(self, service_name, status_code, response_obj):
        try:
            full_body = response_obj.json()
        except:
            if "image/" in response_obj.headers.get("Content-Type", ""):
                import base64
                b64_str = base64.b64encode(response_obj.content).decode('utf-8')
                ctype = response_obj.headers["Content-Type"]
                full_body = f"data:{ctype};base64,{b64_str}"
            else:
                full_body = response_obj.text

        if status_code == 200:
            status_text = "VULNERABLE"
            color = Fore.GREEN
            # False-positive check for Google APIs that return 200 OK but deny within the body
            if isinstance(full_body, dict):
                if full_body.get("status") == "REQUEST_DENIED" or "error_message" in full_body or "error" in full_body:
                    status_text = "RESTRICTED (API DENIED)"
                    color = Fore.RED
        elif status_code == 403:
            status_text = "RESTRICTED (DENIED BY POLICY)"
            color = Fore.RED
        elif status_code == 401:
            status_text = "UNAUTHORIZED (INVALID/REVOKED KEY)"
            color = Fore.RED
        elif status_code == 404:
            status_text = "NOT FOUND (TARGET MISSING/DELETED)"
            color = Fore.YELLOW
        elif status_code == 400:
            if isinstance(full_body, dict) and 'error' in full_body and isinstance(full_body['error'], dict) and full_body['error'].get('status') == 'API_KEY_INVALID':
                 status_text = "UNAUTHORIZED (INVALID/REVOKED KEY)"
                 color = Fore.RED
            else:
                 status_text = "BAD REQUEST (INVALID ARGS/PAYLOAD)"
                 color = Fore.YELLOW
        else:
            status_text = f"STATUS {status_code}"
            color = Fore.YELLOW
        
        print(f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name}...")

        self.results.append({
            "service": service_name,
            "status_text": status_text,
            "status_code": status_code,
            "color": color
        })
        
        self.raw_data.append({
            "service": service_name,
            "url": response_obj.url,
            "status_code": status_code,
            "headers": dict(response_obj.headers),
            "response_body": full_body
        })

    def scan(self):
        raise NotImplementedError("Subclasses must implement scan()")
