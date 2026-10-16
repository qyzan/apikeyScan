"""HuggingFace Hub API scanner with async checks.

Validates whoami, models, datasets, spaces, and inference endpoints
using Bearer token authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class HuggingFaceScanner(BaseScanner):
    """Scanner for HuggingFace Hub API tokens.

    Checks whoami, models, datasets, spaces, and inference endpoints.
    """

    PROVIDER_NAME = "huggingface"
    CHECKS = [
        "Whoami (GET /api/whoami-v2)",
        "Models List (GET /api/models)",
        "Datasets List (GET /api/datasets)",
        "Spaces List (GET /api/spaces)",
        "Inference Endpoints (GET /api/inference-endpoints)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the HuggingFace scanner.

        Args:
            api_key: The HuggingFace token (hf_... format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all HuggingFace API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== HUGGINGFACE API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"Authorization": f"Bearer {self.api_key}"}

        checks = [
            self._check_whoami(headers),
            self._check_models(headers),
            self._check_datasets(headers),
            self._check_spaces(headers),
            self._check_inference_endpoints(headers),
        ]
        await self._run_checks(checks)

    async def _check_whoami(self, headers: Dict[str, str]) -> None:
        """Check whoami endpoint — auth validation and user info."""
        svc = "HuggingFace Whoami"
        ok, resp = await self._safe_get(svc, "https://huggingface.co/api/whoami-v2", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_models(self, headers: Dict[str, str]) -> None:
        """Check models listing — model access."""
        svc = "HuggingFace Models List"
        ok, resp = await self._safe_get(svc, "https://huggingface.co/api/models", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_datasets(self, headers: Dict[str, str]) -> None:
        """Check datasets listing — dataset access."""
        svc = "HuggingFace Datasets List"
        ok, resp = await self._safe_get(svc, "https://huggingface.co/api/datasets", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_spaces(self, headers: Dict[str, str]) -> None:
        """Check spaces listing — deployed app access."""
        svc = "HuggingFace Spaces List"
        ok, resp = await self._safe_get(svc, "https://huggingface.co/api/spaces", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_inference_endpoints(self, headers: Dict[str, str]) -> None:
        """Check inference endpoints — compute resource access."""
        svc = "HuggingFace Inference Endpoints"
        ok, resp = await self._safe_get(svc, "https://huggingface.co/api/inference-endpoints", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)
