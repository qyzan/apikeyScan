import requests
from colorama import Fore, Style
from core.base_scanner import BaseScanner

class OpenAIScanner(BaseScanner):
    def __init__(self, api_key):
        super().__init__(api_key)

    def scan(self):
        print(f"\n{Fore.CYAN}=== OPENAI API RECON ==={Style.RESET_ALL}\n")
        
        # Standard API Headers
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Beta Headers required for Assistants & Vector Stores
        beta_headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "OpenAI-Beta": "assistants=v2"
        }

        # 1. Models List (Basic Auth Validation)
        resp = requests.get("https://api.openai.com/v1/models", headers=headers)
        self.log_result("OpenAI Models (Auth Validation)", resp.status_code, resp)

        # 2. Chat Completions (GPT-3.5/GPT-4 Generation)
        payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 5}
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        self.log_result("OpenAI Chat Generative", resp.status_code, resp)

        # 3. DALL-E Image Generation
        img_payload = {"model": "dall-e-2", "prompt": "a white siamese cat", "n": 1, "size": "256x256"}
        resp = requests.post("https://api.openai.com/v1/images/generations", headers=headers, json=img_payload)
        self.log_result("OpenAI DALL-E Images", resp.status_code, resp)

        # 4. Uploaded Files (Data Exfiltration Risk)
        resp = requests.get("https://api.openai.com/v1/files", headers=headers)
        self.log_result("OpenAI Uploaded Files", resp.status_code, resp)

        # 5. Fine-Tuning Jobs (Intellectual Property Risk)
        resp = requests.get("https://api.openai.com/v1/fine_tuning/jobs", headers=headers)
        self.log_result("OpenAI Fine-Tuning Jobs", resp.status_code, resp)

        # 6. Assistants API (Custom GPTs / Logic Exposure)
        resp = requests.get("https://api.openai.com/v1/assistants", headers=beta_headers)
        self.log_result("OpenAI Assistants", resp.status_code, resp)

        # 7. Vector Stores (RAG Knowledge Base Exposure)
        resp = requests.get("https://api.openai.com/v1/vector_stores", headers=beta_headers)
        self.log_result("OpenAI Vector Stores", resp.status_code, resp)

        # 8. Batches API
        resp = requests.get("https://api.openai.com/v1/batches", headers=headers)
        self.log_result("OpenAI Batches", resp.status_code, resp)

        # 9. Moderations API
        mod_payload = {"input": "I want to kill them."}
        resp = requests.post("https://api.openai.com/v1/moderations", headers=headers, json=mod_payload)
        self.log_result("OpenAI Moderations", resp.status_code, resp)
