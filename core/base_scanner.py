"""Base scanner module providing async HTTP infrastructure for all provider scanners.

This module defines the BaseScanner class with aiohttp-based async HTTP helpers,
severity rating system, retry with exponential backoff, rate limiting, and
concurrent check execution. All provider scanners inherit from BaseScanner.
"""

import asyncio
import base64
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Tuple

import aiohttp
from colorama import Fore, Style


class Severity(Enum):
    """Severity levels for scan findings, ordered from most to least critical."""

    CRITICAL = ("CRITICAL", Fore.RED + Style.BRIGHT)
    HIGH = ("HIGH", Fore.RED)
    MEDIUM = ("MEDIUM", Fore.YELLOW)
    LOW = ("LOW", Fore.CYAN)
    INFO = ("INFO", Fore.BLUE)

    @property
    def label(self) -> str:
        """Return the human-readable label for this severity."""
        return self.value[0]

    @property
    def color(self) -> str:
        """Return the colorama color string for this severity."""
        return self.value[1]


SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class ResponseData:
    """Immutable container for HTTP response data captured from aiohttp.

    Since aiohttp responses are released when their context manager exits,
    we capture all needed data upfront and expose it through a response-like
    interface that log_result() can consume synchronously.
    """

    status: int
    headers: Dict[str, str]
    url: str
    _body_bytes: bytes
    _content_type: str = ""

    def json(self) -> Any:
        """Parse the response body as JSON.

        Returns:
            Parsed JSON content (dict, list, etc.).

        Raises:
            json.JSONDecodeError: If the body is not valid JSON.
        """
        return json.loads(self._body_bytes)

    @property
    def text(self) -> str:
        """Return the response body decoded as UTF-8."""
        return self._body_bytes.decode("utf-8", errors="replace")

    @property
    def content(self) -> bytes:
        """Return the raw response body bytes."""
        return self._body_bytes


class BaseScanner:
    """Abstract base class for all async API key scanners.

    Provides aiohttp-based HTTP helpers with retry, timeout, rate limiting,
    severity-aware result logging, and concurrent check execution.

    Subclasses must override the scan() method and define PROVIDER_NAME
    and CHECKS class attributes.
    """

    PROVIDER_NAME: str = "base"
    CHECKS: ClassVar[List[str]] = []

    def __init__(
        self,
        api_key: str,
        timeout: int = 20,
        max_retries: int = 3,
        rate_limit: Optional[int] = None,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        no_color: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initialize the base scanner.

        Args:
            api_key: The API key or access token to test.
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts for 429/503 responses.
            rate_limit: Optional max requests per second (None = unlimited).
            proxy: Optional HTTP proxy URL.
            user_agent: Optional custom User-Agent header.
            no_color: If True, disable colored output.
            **kwargs: Additional provider-specific options.
        """
        self.api_key = api_key
        self.results: List[Dict[str, Any]] = []
        self.raw_data: List[Dict[str, Any]] = []
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.user_agent = user_agent
        self.no_color = no_color
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._extra: Dict[str, Any] = kwargs

    def _c(self, color: str) -> str:
        """Return color code or empty string if --no-color is set.

        Args:
            color: The colorama color string.

        Returns:
            The color string, or empty string if no_color is True.
        """
        return "" if self.no_color else color

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Optional[ResponseData]:
        """Execute an HTTP request with retry and exponential backoff.

        Retries on 429 (Too Many Requests) and 503 (Service Unavailable)
        responses, as well as transient aiohttp ClientErrors.

        Args:
            method: HTTP method ("GET" or "POST").
            url: The full URL to request.
            headers: Optional HTTP headers.
            json_body: Optional JSON body for POST requests.
            params: Optional query string parameters.

        Returns:
            ResponseData if the request succeeded, None on failure.

        Raises:
            Never raises — all exceptions are caught and logged via log_error().
        """
        if self._session is None:
            raise RuntimeError("No active aiohttp session. Call run() first.")

        kwargs: Dict[str, Any] = {"timeout": self.timeout}
        if headers:
            kwargs["headers"] = headers
        if json_body is not None:
            kwargs["json"] = json_body
        if params:
            kwargs["params"] = params
        if self.proxy:
            kwargs["proxy"] = self.proxy

        for attempt in range(self.max_retries):
            try:
                async with self._session.request(method, url, **kwargs) as resp:
                    if resp.status in (429, 503) and attempt < self.max_retries - 1:
                        await asyncio.sleep(2**attempt)
                        continue

                    body = await resp.read()
                    return ResponseData(
                        status=resp.status,
                        headers=dict(resp.headers),
                        url=str(resp.url),
                        _body_bytes=body,
                        _content_type=resp.headers.get("Content-Type", ""),
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
                    continue
                raise
        return None

    async def _safe_get(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, Optional[ResponseData]]:
        """Perform an async GET request with retry, timeout, and error handling.

        Args:
            service_name: Human-readable name of the service being checked.
            url: The full URL to request.
            headers: Optional HTTP headers.
            params: Optional query string parameters.

        Returns:
            A tuple of (success, response). On failure, success is False and
            response is None (error is logged internally).
        """
        try:
            resp = await self._request_with_retry("GET", url, headers=headers, params=params)
            if resp is not None:
                return True, resp
            self.log_error(service_name, "Request returned no response after retries")
            return False, None
        except aiohttp.ClientConnectorError as e:
            self.log_error(service_name, f"Connection refused: {e}")
            return False, None
        except asyncio.TimeoutError:
            self.log_error(service_name, "Request timed out")
            return False, None
        except aiohttp.ClientError as e:
            self.log_error(service_name, str(e))
            return False, None

    async def _safe_post(
        self,
        service_name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, Optional[ResponseData]]:
        """Perform an async POST request with retry, timeout, and error handling.

        Args:
            service_name: Human-readable name of the service being checked.
            url: The full URL to request.
            headers: Optional HTTP headers.
            json_body: Optional JSON body for the POST request.
            params: Optional query string parameters.

        Returns:
            A tuple of (success, response). On failure, success is False and
            response is None (error is logged internally).
        """
        try:
            resp = await self._request_with_retry("POST", url, headers=headers, json_body=json_body, params=params)
            if resp is not None:
                return True, resp
            self.log_error(service_name, "Request returned no response after retries")
            return False, None
        except aiohttp.ClientConnectorError as e:
            self.log_error(service_name, f"Connection refused: {e}")
            return False, None
        except asyncio.TimeoutError:
            self.log_error(service_name, "Request timed out")
            return False, None
        except aiohttp.ClientError as e:
            self.log_error(service_name, str(e))
            return False, None

    def _auto_detect_severity(self, status_code: int, full_body: Any) -> Severity:
        """Auto-detect severity from HTTP status code and response body.

        Args:
            status_code: The HTTP status code.
            full_body: The parsed response body (dict, str, etc.).

        Returns:
            The detected Severity level.
        """
        if status_code == 200:
            if isinstance(full_body, dict) and (
                full_body.get("status") == "REQUEST_DENIED" or "error_message" in full_body
            ):
                return Severity.MEDIUM
            return Severity.HIGH
        elif status_code in (403, 401):
            return Severity.INFO
        elif status_code == 404:
            return Severity.LOW
        elif status_code == 400:
            return Severity.MEDIUM
        return Severity.LOW

    def _classify_status(self, status_code: int, full_body: Any) -> Tuple[str, str]:
        """Classify an HTTP status code into a human-readable status text and color.

        Args:
            status_code: The HTTP status code.
            full_body: The parsed response body for false-positive detection.

        Returns:
            A tuple of (status_text, color_string).
        """
        if status_code == 200:
            status_text = "VULNERABLE"
            color = self._c(Fore.GREEN)
            if isinstance(full_body, dict) and (
                full_body.get("status") == "REQUEST_DENIED" or "error_message" in full_body or "error" in full_body
            ):
                status_text = "RESTRICTED (API DENIED)"
                color = self._c(Fore.RED)
        elif status_code == 403:
            status_text = "RESTRICTED (DENIED BY POLICY)"
            color = self._c(Fore.RED)
        elif status_code == 401:
            status_text = "UNAUTHORIZED (INVALID/REVOKED KEY)"
            color = self._c(Fore.RED)
        elif status_code == 404:
            status_text = "NOT FOUND (TARGET MISSING/DELETED)"
            color = self._c(Fore.YELLOW)
        elif status_code == 400:
            if (
                isinstance(full_body, dict)
                and "error" in full_body
                and isinstance(full_body["error"], dict)
                and full_body["error"].get("status") == "API_KEY_INVALID"
            ):
                status_text = "UNAUTHORIZED (INVALID/REVOKED KEY)"
                color = self._c(Fore.RED)
            else:
                status_text = "BAD REQUEST (INVALID ARGS/PAYLOAD)"
                color = self._c(Fore.YELLOW)
        else:
            status_text = f"STATUS {status_code}"
            color = self._c(Fore.YELLOW)
        return status_text, color

    def _parse_body(self, response_obj: ResponseData) -> Any:
        """Parse the response body, handling JSON, images, and text.

        Args:
            response_obj: The ResponseData object to parse.

        Returns:
            Parsed body: dict for JSON, base64 data URI for images, str otherwise.
        """
        content_type = response_obj._content_type
        if "image/" in content_type:
            b64_str = base64.b64encode(response_obj._body_bytes).decode("utf-8")
            return f"data:{content_type};base64,{b64_str}"
        try:
            return response_obj.json()
        except (json.JSONDecodeError, ValueError):
            return response_obj.text

    def log_result(
        self,
        service_name: str,
        status_code: int,
        response_obj: ResponseData,
        severity: Optional[Severity] = None,
    ) -> None:
        """Log a scan result with auto-severity detection if not specified.

        Args:
            service_name: Human-readable name of the service checked.
            status_code: The HTTP status code received.
            response_obj: The ResponseData object with full response info.
            severity: Optional explicit severity. If None, auto-detected.
        """
        full_body = self._parse_body(response_obj)
        status_text, color = self._classify_status(status_code, full_body)

        if severity is None:
            severity = self._auto_detect_severity(status_code, full_body)

        print(
            f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name}... [{self._c(severity.color)}{severity.label}{Style.RESET_ALL}]"
        )

        self.results.append(
            {
                "service": service_name,
                "status_text": status_text,
                "status_code": status_code,
                "color": color,
                "severity": severity.label,
            }
        )

        self.raw_data.append(
            {
                "service": service_name,
                "url": response_obj.url,
                "status_code": status_code,
                "headers": response_obj.headers,
                "response_body": full_body,
                "severity": severity.label,
            }
        )

    def log_error(self, service_name: str, error: Any) -> None:
        """Log a connection/network error for a service without crashing the scan.

        Args:
            service_name: Human-readable name of the service that failed.
            error: The error message or exception object.
        """
        status_text = "CONNECTION ERROR"
        color = self._c(Fore.RED)
        error_msg = str(error)
        if len(error_msg) > 120:
            error_msg = error_msg[:120] + "..."

        print(f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name}... ({error_msg})")

        self.results.append(
            {
                "service": service_name,
                "status_text": status_text,
                "status_code": None,
                "color": color,
                "severity": Severity.CRITICAL.label,
            }
        )

        self.raw_data.append(
            {
                "service": service_name,
                "url": "N/A",
                "status_code": None,
                "headers": {},
                "response_body": f"Connection Error: {error}",
                "severity": Severity.CRITICAL.label,
            }
        )

    def log_custom_result(
        self,
        service_name: str,
        status_text: str,
        status_code: Optional[int],
        response_body: Any,
        url: str = "N/A",
        severity: Severity = Severity.INFO,
        color: Optional[str] = None,
    ) -> None:
        """Log a custom result (e.g., for boto3-based scanners that don't use HTTP).

        Args:
            service_name: Human-readable name of the service checked.
            status_text: The status text to display (e.g., "VULNERABLE (ACCESS)").
            status_code: The status code (200 for success, 403 for denied).
            response_body: The response body data to store.
            url: The endpoint URL or pseudo-URL.
            severity: The severity level for this finding.
            color: Optional custom color. Defaults to severity color.
        """
        if color is None:
            color = self._c(severity.color)

        print(
            f"{color}[{status_text}]{Style.RESET_ALL} Checking {service_name}... [{self._c(severity.color)}{severity.label}{Style.RESET_ALL}]"
        )

        self.results.append(
            {
                "service": service_name,
                "status_text": status_text,
                "status_code": status_code,
                "color": color,
                "severity": severity.label,
            }
        )

        self.raw_data.append(
            {
                "service": service_name,
                "url": url,
                "status_code": status_code,
                "headers": {},
                "response_body": response_body,
                "severity": severity.label,
            }
        )

    async def _run_one_check(self, check_coro: Any) -> Any:
        """Run a single check coroutine with optional rate limiting.

        Args:
            check_coro: The check coroutine to execute.

        Returns:
            The result of the coroutine.
        """
        if self._semaphore:
            async with self._semaphore:
                return await check_coro
        return await check_coro

    async def _run_checks(self, checks: List[Any]) -> List[Any]:
        """Run a list of check coroutines concurrently with optional rate limiting.

        Args:
            checks: List of check coroutines to execute.

        Returns:
            List of results (exceptions are returned as values, not raised).
        """
        if self.rate_limit:
            self._semaphore = asyncio.Semaphore(self.rate_limit)
        tasks = [asyncio.create_task(self._run_one_check(check)) for check in checks]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def scan(self) -> None:
        """Run all provider-specific checks. Override in subclasses.

        Raises:
            NotImplementedError: Always, if not overridden in a subclass.
        """
        raise NotImplementedError("Subclasses must implement scan()")

    async def run(self) -> None:
        """Entry point: creates aiohttp session, calls scan(), handles cleanup.

        This method manages the aiohttp.ClientSession lifecycle. Subclasses
        override scan(), not run().
        """
        connector_kwargs: Dict[str, Any] = {}
        headers: Dict[str, str] = {}
        if self.user_agent:
            headers["User-Agent"] = self.user_agent

        async with aiohttp.ClientSession(
            timeout=self.timeout,
            headers=headers,
            trust_env=True,
            **connector_kwargs,
        ) as session:
            self._session = session
            await self.scan()
