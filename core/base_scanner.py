from colorama import Fore, Style

class BaseScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.results = []
        self.raw_data = []

    def log_result(self, service_name, status_code, response_obj):
        if status_code == 200:
            status_text = "VULNERABLE"
            color = Fore.GREEN
        elif status_code == 403:
            status_text = "RESTRICTED"
            color = Fore.RED
        elif status_code == 401:
            status_text = "UNAUTHORIZED"
            color = Fore.RED
        else:
            status_text = f"STATUS {status_code}"
            color = Fore.YELLOW
        
        print(f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name}...")
        
        try:
            full_body = response_obj.json()
        except:
            full_body = response_obj.text

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
