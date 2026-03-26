import requests
from colorama import Fore, Style
from core.base_scanner import BaseScanner

class OpenAIScanner(BaseScanner):
    def __init__(self, api_key):
        super().__init__(api_key)

    def scan(self):
        print(f"\n{Fore.CYAN}=== OPENAI API RECON ==={Style.RESET_ALL}\n")
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        
        resp = requests.get("https://api.openai.com/v1/models", headers=headers)
        self.log_result("OpenAI Models (Auth Validation)", resp.status_code, resp)
        
        payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 5}
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        self.log_result("OpenAI Chat Completions", resp.status_code, resp)
