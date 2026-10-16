"""DigitalOcean API scanner with async checks for cloud resource access.

Validates account, droplets, spaces keys, SSH keys, databases,
Kubernetes clusters, and firewalls using Bearer token authentication.
"""

from typing import Any, Dict

from colorama import Fore, Style

from core.base_scanner import BaseScanner, Severity


class DigitalOceanScanner(BaseScanner):
    """Scanner for DigitalOcean Personal Access Tokens.

    Checks account, droplets, spaces keys, SSH keys, databases,
    Kubernetes clusters, and firewalls.
    """

    PROVIDER_NAME = "digitalocean"
    CHECKS = [
        "Account (GET /v2/account)",
        "Droplets (GET /v2/droplets)",
        "Spaces Keys (GET /v2/spaces/keys)",
        "SSH Keys (GET /v2/account/keys)",
        "Databases (GET /v2/databases)",
        "Kubernetes Clusters (GET /v2/kubernetes/clusters)",
        "Firewalls (GET /v2/firewalls)",
    ]

    def __init__(self, api_key: str, **kwargs: Any) -> None:
        """Initialize the DigitalOcean scanner.

        Args:
            api_key: The DigitalOcean PAT (dop_v1_... format).
            **kwargs: Additional BaseScanner options.
        """
        super().__init__(api_key, **kwargs)

    async def scan(self) -> None:
        """Run all DigitalOcean API reconnaissance checks concurrently."""
        print(f"\n{self._c(Fore.CYAN)}=== DIGITALOCEAN API RECON ==={Style.RESET_ALL}\n")

        headers: Dict[str, str] = {"Authorization": f"Bearer {self.api_key}"}

        checks = [
            self._check_account(headers),
            self._check_droplets(headers),
            self._check_spaces_keys(headers),
            self._check_ssh_keys(headers),
            self._check_databases(headers),
            self._check_k8s_clusters(headers),
            self._check_firewalls(headers),
        ]
        await self._run_checks(checks)

    async def _check_account(self, headers: Dict[str, str]) -> None:
        """Check account endpoint — auth validation."""
        svc = "DigitalOcean Account"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/account", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.LOW)

    async def _check_droplets(self, headers: Dict[str, str]) -> None:
        """Check droplets listing — VPS instance access."""
        svc = "DigitalOcean Droplets"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/droplets", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_spaces_keys(self, headers: Dict[str, str]) -> None:
        """Check spaces keys — S3-compatible storage key access."""
        svc = "DigitalOcean Spaces Keys"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/spaces/keys", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_ssh_keys(self, headers: Dict[str, str]) -> None:
        """Check SSH keys — key exposure risk."""
        svc = "DigitalOcean SSH Keys"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/account/keys", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_databases(self, headers: Dict[str, str]) -> None:
        """Check databases — managed database access."""
        svc = "DigitalOcean Databases"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/databases", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_k8s_clusters(self, headers: Dict[str, str]) -> None:
        """Check Kubernetes clusters — DOKS cluster access."""
        svc = "DigitalOcean Kubernetes Clusters"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/kubernetes/clusters", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.HIGH)

    async def _check_firewalls(self, headers: Dict[str, str]) -> None:
        """Check firewalls — firewall rule access."""
        svc = "DigitalOcean Firewalls"
        ok, resp = await self._safe_get(svc, "https://api.digitalocean.com/v2/firewalls", headers=headers)
        if ok and resp:
            self.log_result(svc, resp.status, resp, severity=Severity.MEDIUM)
