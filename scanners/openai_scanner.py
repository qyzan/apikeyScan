"""OpenAI API scanner with async checks for quota and data exposure.

Validates Models, Chat Completions, DALL-E, Files, Fine-Tuning, Assistants,
Vector Stores, Batches, and Moderations endpoints.
"""

from typing import Any

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class OpenAIScanner(BaseScanner):
    """Scanner for OpenAI API keys.

    Checks model access, chat completions, image generation, file listing,
    fine-tuning jobs, assistants, vector stores, batches, and moderations.
    """

    PROVIDER_NAME = "openai"
    CHECKS = [
        "OpenAI Models (Auth Validation)",
        "OpenAI Chat Generative",
        "OpenAI DALL-E Images",
        "OpenAI Uploaded Files",
        "OpenAI Fine-Tuning Jobs",
        "OpenAI Assistants",
        "OpenAI Vector Stores",
        "OpenAI Batches",
        "OpenAI Moderations",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the OpenAI scanner.

        Args:
            api_key: The OpenAI API key to test (sk-... format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all OpenAI API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== OPENAI API RECON ==={Style.RESET_ALL}\n")

        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        beta_headers: dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "OpenAI-Beta": "assistants=v2",
        }

        checks = [
            self._check_models(headers),
            self._check_chat(headers),
            self._check_dalle(headers),
            self._check_files(headers),
            self._check_fine_tuning(headers),
            self._check_assistants(beta_headers),
            self._check_vector_stores(beta_headers),
            self._check_batches(headers),
            self._check_moderations(headers),
        ]
        await self._run_checks(checks)

    async def _check_models(self, headers: dict[str, str]) -> None:
        """Check OpenAI Models list — basic auth validation."""
        svc = "OpenAI Models (Auth Validation)"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/models", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_chat(self, headers: dict[str, str]) -> None:
        """Check OpenAI Chat Completions — generative quota access."""
        svc = "OpenAI Chat Generative"
        payload = {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 5}
        ok, resp = await self._safe_post(
            svc, "https://api.openai.com/v1/chat/completions", headers=headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_dalle(self, headers: dict[str, str]) -> None:
        """Check OpenAI DALL-E image generation access."""
        svc = "OpenAI DALL-E Images"
        payload = {"model": "dall-e-2", "prompt": "a white siamese cat", "n": 1, "size": "256x256"}
        ok, resp = await self._safe_post(
            svc, "https://api.openai.com/v1/images/generations", headers=headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_files(self, headers: dict[str, str]) -> None:
        """Check OpenAI uploaded files listing — data exfiltration risk."""
        svc = "OpenAI Uploaded Files"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/files", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_fine_tuning(self, headers: dict[str, str]) -> None:
        """Check OpenAI fine-tuning jobs — intellectual property risk."""
        svc = "OpenAI Fine-Tuning Jobs"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/fine_tuning/jobs", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_assistants(self, headers: dict[str, str]) -> None:
        """Check OpenAI Assistants API — custom GPT logic exposure."""
        svc = "OpenAI Assistants"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/assistants", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_vector_stores(self, headers: dict[str, str]) -> None:
        """Check OpenAI Vector Stores — RAG knowledge base exposure."""
        svc = "OpenAI Vector Stores"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/vector_stores", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_batches(self, headers: dict[str, str]) -> None:
        """Check OpenAI Batches API access."""
        svc = "OpenAI Batches"
        ok, resp = await self._safe_get(svc, "https://api.openai.com/v1/batches", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)

    async def _check_moderations(self, headers: dict[str, str]) -> None:
        """Check OpenAI Moderations API access."""
        svc = "OpenAI Moderations"
        payload = {"input": "I want to kill them."}
        ok, resp = await self._safe_post(
            svc, "https://api.openai.com/v1/moderations", headers=headers, json_body=payload
        )
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)
