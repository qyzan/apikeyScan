"""Azure Cognitive Services & Cloud API scanner with async checks.

Validates Azure Maps, Translator, Bing Search, Face API, and Text Analytics
using subscription-key based authentication.
"""

from typing import Any

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class AzureScanner(BaseScanner):
    """Scanner for Azure Cognitive Services and Cloud API keys.

    Checks Azure Maps, Translator, Bing Search, Face API, and Text Analytics
    using Ocp-Apim-Subscription-Key authentication.
    """

    PROVIDER_NAME = "azure"
    CHECKS = [
        "Azure Maps API",
        "Azure Translator API",
        "Azure Bing Search API",
        "Azure Face API (WestUS Region)",
        "Azure Text Analytics API (WestUS)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the Azure scanner.

        Args:
            api_key: The Azure subscription key to test.
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all Azure API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== AZURE API RECON ==={Style.RESET_ALL}\n")

        checks = [
            self._check_maps(),
            self._check_translator(),
            self._check_bing(),
            self._check_face(),
            self._check_text_analytics(),
        ]
        await self._run_checks(checks)

    async def _check_maps(self) -> None:
        """Check Azure Maps address search API access."""
        svc = "Azure Maps API"
        url = f"https://atlas.microsoft.com/search/address/json?api-version=1.0&query=1%20microsoft%20way&subscription-key={self.api_key}"
        ok, resp = await self._safe_get(svc, url)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_translator(self) -> None:
        """Check Azure Translator Text API access."""
        svc = "Azure Translator API"
        url = "https://api.cognitive.microsofttranslator.com/translate?api-version=3.0&to=es"
        headers: dict[str, str] = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload = [{"Text": "Hello API test"}]
        ok, resp = await self._safe_post(svc, url, headers=headers, json_body=payload)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_bing(self) -> None:
        """Check Azure Bing Search API access."""
        svc = "Azure Bing Search API"
        url = "https://api.bing.microsoft.com/v7.0/search?q=microsoft"
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}
        ok, resp = await self._safe_get(svc, url, headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_face(self) -> None:
        """Check Azure Face API (WestUS region) access."""
        svc = "Azure Face API (WestUS Region)"
        url = "https://westus.api.cognitive.microsoft.com/face/v1.0/detect"
        headers = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload = {
            "url": "https://raw.githubusercontent.com/Azure-Samples/cognitive-services-sample-data-files/master/Face/images/Family1-Dad1.jpg"
        }
        ok, resp = await self._safe_post(svc, url, headers=headers, json_body=payload)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_text_analytics(self) -> None:
        """Check Azure Text Analytics API (WestUS region) access."""
        svc = "Azure Text Analytics API (WestUS)"
        url = "https://westus.api.cognitive.microsoft.com/text/analytics/v3.0/languages"
        headers = {"Ocp-Apim-Subscription-Key": self.api_key, "Content-Type": "application/json"}
        payload = {"documents": [{"id": "1", "text": "Hello world"}]}
        ok, resp = await self._safe_post(svc, url, headers=headers, json_body=payload)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
