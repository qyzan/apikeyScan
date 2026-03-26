import requests
from colorama import Fore, Style
from core.base_scanner import BaseScanner

class AzureScanner(BaseScanner):
    def __init__(self, api_key):
        super().__init__(api_key)

    def scan(self):
        print(f"\n{Fore.CYAN}=== AZURE API RECON ==={Style.RESET_ALL}\n")
        
        # Azure Maps API
        maps_url = f"https://atlas.microsoft.com/search/address/json?api-version=1.0&query=1%20microsoft%20way&subscription-key={self.api_key}"
        resp = requests.get(maps_url)
        self.log_result("Azure Maps API", resp.status_code, resp)

        # Azure Translator Text API
        translator_url = "https://api.cognitive.microsofttranslator.com/translate?api-version=3.0&to=es"
        headers_trans = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload = [{"Text": "Hello API test"}]
        resp = requests.post(translator_url, headers=headers_trans, json=payload)
        self.log_result("Azure Translator API", resp.status_code, resp)

        # Azure Bing Search API
        bing_url = "https://api.bing.microsoft.com/v7.0/search?q=microsoft"
        headers_bing = {"Ocp-Apim-Subscription-Key": self.api_key}
        resp = requests.get(bing_url, headers=headers_bing)
        self.log_result("Azure Bing Search API", resp.status_code, resp)

        # Azure Face API (West US default test region)
        face_url = "https://westus.api.cognitive.microsoft.com/face/v1.0/detect"
        headers_face = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload_face = {"url": "https://raw.githubusercontent.com/Azure-Samples/cognitive-services-sample-data-files/master/Face/images/Family1-Dad1.jpg"}
        resp = requests.post(face_url, headers=headers_face, json=payload_face)
        self.log_result("Azure Face API (WestUS Region)", resp.status_code, resp)

        # Azure Text Analytics API (West US)
        text_url = "https://westus.api.cognitive.microsoft.com/text/analytics/v3.0/languages"
        headers_text = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload_text = {"documents": [{"id": "1", "text": "Hello world"}]}
        resp = requests.post(text_url, headers=headers_text, json=payload_text)
        self.log_result("Azure Text Analytics API (WestUS)", resp.status_code, resp)
