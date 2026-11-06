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
from typing import Any, ClassVar

import aiohttp
from colorama import Fore, Style

from core.redaction import scanner_sanitizer
from core.transport import RateLimiter, RetryConfig, compute_backoff, parse_retry_after


class Severity(Enum):
    """Severity levels for scan findings, ordered from most to least critical."""

    CRITICAL = ("CRITICAL", Fore.RED + Style.BRIGHT)
    ERROR = ("ERROR", Fore.MAGENTA + Style.BRIGHT)
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
        return str(self.value[1])


SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "ERROR": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
}


class ExecutionStatus(Enum):
    """Execution status of a check — whether it ran, errored, or was skipped."""

    COMPLETED = "completed"
    ERROR = "error"
    SKIPPED = "skipped"


class CheckOutcome(Enum):
    """Outcome of a check — what was learned about the credential.

    This is the machine contract; status_text is a derived display string.
    """

    ACCESSIBLE = "accessible"
    RESTRICTED = "restricted"
    UNAUTHORIZED = "unauthorized"
    NOT_FOUND = "not_found"
    BAD_REQUEST = "bad_request"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ResponseData:
    """Immutable container for HTTP response data captured from aiohttp.

    Since aiohttp responses are released when their context manager exits,
    we capture all needed data upfront and expose it through a response-like
    interface that log_result() can consume synchronously.
    """

    status: int
    headers: dict[str, str]
    url: str
    _body_bytes: bytes
    _content_type: str = ""
    truncated: bool = False

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


def _is_empty_body(body: Any) -> bool:
    """Check if a parsed response body is effectively empty.

    )Args:
         body: The parsed response body.

     Returns:
         True if the body is None, empty dict, empty list, or blank string.
    """
    if body is None:
        return True
    if isinstance(body, dict) and len(body) == 0:
        return True
    if isinstance(body, list) and len(body) == 0:
        return True
    return bool(isinstance(body, str) and body.strip() == "")


_OUTCOME_DISPLAY: dict[CheckOutcome, str] = {
    CheckOutcome.ACCESSIBLE: "ACCESSIBLE",
    CheckOutcome.RESTRICTED: "RESTRICTED",
    CheckOutcome.UNAUTHORIZED: "UNAUTHORIZED",
    CheckOutcome.NOT_FOUND: "NOT FOUND",
    CheckOutcome.BAD_REQUEST: "BAD REQUEST",
    CheckOutcome.INCONCLUSIVE: "INCONCLUSIVE",
    CheckOutcome.ERROR: "CONNECTION ERROR",
    CheckOutcome.SKIPPED: "SKIPPED",
}


@dataclass
class ScanResult:
    """Unified result object for a single check.

    Links check identity, execution status, outcome, reason, and sanitized
    evidence into one object. Replaces the parallel results/raw_data lists.
    """

    check_id: str
    service_name: str
    provider: str
    execution_status: ExecutionStatus
    outcome: CheckOutcome
    reason: str
    status_code: int | None
    url: str
    headers: dict[str, str]
    response_body: Any
    error_message: str | None = None
    auto_severity: Severity = Severity.INFO
    reviewer_severity: Severity | None = None
    custom_color: str | None = None
    custom_status_text: str | None = None
    truncated: bool = False

    @property
    def effective_severity(self) -> Severity:
        """Return reviewer severity if set, otherwise auto severity."""
        return self.reviewer_severity or self.auto_severity

    @property
    def color(self) -> str:
        """Return custom color if set, otherwise severity-derived color."""
        if self.custom_color is not None:
            return self.custom_color
        return self.effective_severity.color

    @property
    def status_text(self) -> str:
        """Return display string: custom override or derived from outcome."""
        if self.custom_status_text is not None:
            return self.custom_status_text
        return _OUTCOME_DISPLAY.get(self.outcome, "UNKNOWN")


class BaseScanner:
    """Abstract base class for all async API key scanners.

    Provides aiohttp-based HTTP helpers with retry, timeout, rate limiting,
    severity-aware result logging, and concurrent check execution.

    Subclasses must override the scan() method and define PROVIDER_NAME
    and CHECKS class attributes.
    """

    PROVIDER_NAME: str = "base"
    CHECKS: ClassVar[list[str]] = []
    SUPPORTS_HTTP_TRANSPORT: ClassVar[bool] = True

    def __init__(
        self,
        api_key: str,
        timeout: int = 20,
        max_retries: int = 3,
        rate_limit: int | None = None,
        proxy: str | None = None,
        user_agent: str | None = None,
        no_color: bool = False,
        active_checks: bool = True,
        quiet: bool = False,
        concurrency: int = 5,
        connect_timeout: int = 10,
        read_timeout: int = 10,
        max_response_size: int = 10 * 1024 * 1024,
        **kwargs: Any,
    ) -> None:
        """Initialize the base scanner.

        Args:
            api_key: The API key or access token to test.
            timeout: Overall request timeout in seconds.
            max_retries: Maximum retry attempts for 429/503 responses.
            rate_limit: Optional max requests per second (None = unlimited).
            proxy: Optional HTTP proxy URL.
            user_agent: Optional custom User-Agent header.
            no_color: If True, disable colored output.
            active_checks: If True (default), run mutating/billable checks. Use
                --no-active-checks to disable them.
            concurrency: Max concurrent in-flight requests (semaphore).
            connect_timeout: Connection establishment timeout in seconds.
            read_timeout: Socket read timeout in seconds.
            max_response_size: Maximum response body size in bytes.
            **kwargs: Additional provider-specific options.
        """
        self.api_key = api_key
        self.vault_ref: str | None = None
        self.vault_run: str | None = None
        self.scan_results: list[ScanResult] = []
        self.planned_checks: int = 0

        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        if connect_timeout <= 0:
            raise ValueError(f"connect_timeout must be positive, got {connect_timeout}")
        if read_timeout <= 0:
            raise ValueError(f"read_timeout must be positive, got {read_timeout}")
        if max_retries <= 0:
            raise ValueError(f"max_retries must be positive, got {max_retries}")
        if concurrency <= 0:
            raise ValueError(f"concurrency must be positive, got {concurrency}")
        if max_response_size <= 0:
            raise ValueError(f"max_response_size must be positive, got {max_response_size}")
        if rate_limit is not None and rate_limit <= 0:
            raise ValueError(f"rate_limit must be positive when set, got {rate_limit}")

        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=connect_timeout, sock_read=read_timeout)
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.user_agent = user_agent
        self.no_color = no_color
        self.active_checks = active_checks
        self.quiet = quiet
        self.concurrency = concurrency
        self.max_response_size = max_response_size
        self._retry_config = RetryConfig(max_retries=max_retries)
        self._session: aiohttp.ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._rate_limiter: RateLimiter | None = None
        self._extra: dict[str, Any] = kwargs

        if not self.SUPPORTS_HTTP_TRANSPORT:
            self._warn_unsupported_transport(
                timeout=timeout,
                rate_limit=rate_limit,
                concurrency=concurrency,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                max_response_size=max_response_size,
                proxy=proxy,
                user_agent=user_agent,
            )

        if self._extra:
            self._warn_unrecognized_params()

    def _warn_unrecognized_params(self) -> None:
        """Warn about parameters in _extra that this scanner does not recognize.

        These are provider-specific options passed to the wrong scanner (e.g.,
        --secret to GitHub) or typos in config. They are silently stored in
        _extra without effect — this warning makes that visible.
        """
        color = self._c(Fore.YELLOW)
        params = ", ".join(sorted(self._extra.keys()))
        print(
            f"{color}[!] Warning: {self.PROVIDER_NAME} scanner does not recognize "
            f"parameter(s): {params}. These will be ignored.{self._c(Style.RESET_ALL)}"
        )

    def _warn_unsupported_transport(self, **params: Any) -> None:
        """Warn about transport parameters that this scanner does not support.

        Only warns when the user explicitly set non-default values, so default
        construction does not produce noise.

        Args:
            **params: Transport parameter name→value pairs to check.
        """
        defaults = {
            "timeout": 20,
            "rate_limit": None,
            "concurrency": 5,
            "connect_timeout": 10,
            "read_timeout": 10,
            "max_response_size": 10 * 1024 * 1024,
            "proxy": None,
            "user_agent": None,
        }
        unsupported = [name for name, value in params.items() if value != defaults.get(name)]
        if unsupported:
            color = self._c(Fore.YELLOW)
            print(
                f"{color}[!] Warning: {self.PROVIDER_NAME} scanner does not support "
                f"HTTP transport options ({', '.join(sorted(unsupported))}). "
                f"These settings have no effect on this scanner type.{self._c(Style.RESET_ALL)}"
            )

    @property
    def results(self) -> list[dict[str, Any]]:
        """Derived compatibility view of scan_results for report adapters."""
        return [
            {
                "service": r.service_name,
                "status_text": r.status_text,
                "status_code": r.status_code,
                "color": r.color,
                "severity": r.effective_severity.label,
                "outcome": r.outcome.value,
                "truncated": r.truncated,
            }
            for r in self.scan_results
        ]

    @property
    def raw_data(self) -> list[dict[str, Any]]:
        """Derived compatibility view of scan_results for report adapters."""
        return [
            {
                "service": r.service_name,
                "url": r.url,
                "status_code": r.status_code,
                "headers": r.headers,
                "response_body": r.response_body,
                "severity": r.effective_severity.label,
                "outcome": r.outcome.value,
                "truncated": r.truncated,
                "reason": r.reason,
            }
            for r in self.scan_results
        ]

    @property
    def check_accounting(self) -> dict[str, int]:
        """Reconcile planned vs completed/failed/skipped checks.

        Returns:
            Dict with keys: planned, completed, failed, skipped, missing.
            missing = planned - (completed + failed + skipped); should be 0
            for a completed scan.
        """
        completed = sum(1 for r in self.scan_results if r.execution_status == ExecutionStatus.COMPLETED)
        failed = sum(1 for r in self.scan_results if r.execution_status == ExecutionStatus.ERROR)
        skipped = sum(1 for r in self.scan_results if r.execution_status == ExecutionStatus.SKIPPED)
        return {
            "planned": self.planned_checks,
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "missing": self.planned_checks - (completed + failed + skipped),
        }

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
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        params: dict[str, str] | None = None,
        idempotent: bool = True,
    ) -> ResponseData | None:
        """Execute an HTTP request with retry and exponential backoff.

        Retries on 429 (Too Many Requests) and 503 (Service Unavailable)
        responses, as well as transient aiohttp ClientErrors. Non-idempotent
        operations (POST) are not retried on timeout to avoid ambiguous results.

        Args:
            method: HTTP method ("GET" or "POST").
            url: The full URL to request.
            headers: Optional HTTP headers.
            json_body: Optional JSON body for POST requests.
            params: Optional query string parameters.
            idempotent: If True, retry on transient errors. If False, do not
                retry on timeout/ambiguous results.

        Returns:
            ResponseData if the request succeeded, None on failure.

        Raises:
            aiohttp.ClientError or asyncio.TimeoutError on final attempt failure.
        """
        if self._session is None:
            raise RuntimeError("No active aiohttp session. Call run() first.")

        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if headers:
            kwargs["headers"] = headers
        if json_body is not None:
            kwargs["json"] = json_body
        if params:
            kwargs["params"] = params
        if self.proxy:
            kwargs["proxy"] = self.proxy

        for attempt in range(self._retry_config.max_retries):
            if self._rate_limiter:
                await self._rate_limiter.acquire()
            try:
                async with self._session.request(method, url, **kwargs) as resp:
                    if resp.status in (429, 503) and attempt < self._retry_config.max_retries - 1:
                        retry_after = parse_retry_after(resp.headers.get("Retry-After", ""))
                        wait = compute_backoff(attempt, self._retry_config, retry_after)
                        await asyncio.sleep(wait)
                        continue

                    body = await resp.read()
                    truncated = False
                    if len(body) > self.max_response_size:
                        body = body[: self.max_response_size]
                        truncated = True
                    return ResponseData(
                        status=resp.status,
                        headers=dict(resp.headers),
                        url=str(resp.url),
                        _body_bytes=body,
                        _content_type=resp.headers.get("Content-Type", ""),
                        truncated=truncated,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if not idempotent:
                    raise
                if attempt < self._retry_config.max_retries - 1:
                    wait = compute_backoff(attempt, self._retry_config)
                    await asyncio.sleep(wait)
                    continue
                raise
        return None

    async def _safe_get(
        self,
        service_name: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> tuple[bool, ResponseData | None]:
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
            resp = await self._request_with_retry("GET", url, headers=headers, params=params, idempotent=True)
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
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
        params: dict[str, str] | None = None,
    ) -> tuple[bool, ResponseData | None]:
        """Perform an async POST request with retry, timeout, and error handling.

        POST is non-idempotent: transient errors are not retried to avoid
        ambiguous results (the operation may have succeeded on the server).

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
            resp = await self._request_with_retry(
                "POST", url, headers=headers, json_body=json_body, params=params, idempotent=False
            )
            if resp is not None:
                return True, resp
            self.log_error(service_name, "Request returned no response after retries")
            return False, None
        except aiohttp.ClientConnectorError as e:
            self.log_error(service_name, f"Connection refused: {e}")
            return False, None
        except asyncio.TimeoutError:
            self.log_error(service_name, "Request timed out — operation may have succeeded; result is ambiguous")
            return False, None
        except aiohttp.ClientError as e:
            self.log_error(service_name, str(e))
            return False, None

    def _classify_outcome(self, status_code: int, full_body: Any, is_malformed: bool) -> CheckOutcome:
        """Classify an HTTP response into a check outcome.

        Args:
            status_code: The HTTP status code.
            full_body: The parsed response body.
            is_malformed: Whether the body failed JSON parsing.

        Returns:
            The CheckOutcome for this response.
        """
        if status_code == 200:
            if isinstance(full_body, dict) and (
                full_body.get("status") == "REQUEST_DENIED" or "error_message" in full_body or "error" in full_body
            ):
                return CheckOutcome.RESTRICTED
            if _is_empty_body(full_body) or is_malformed:
                return CheckOutcome.INCONCLUSIVE
            return CheckOutcome.ACCESSIBLE
        elif status_code == 403:
            return CheckOutcome.RESTRICTED
        elif status_code == 401:
            return CheckOutcome.UNAUTHORIZED
        elif status_code == 404:
            return CheckOutcome.NOT_FOUND
        elif status_code == 400:
            if (
                isinstance(full_body, dict)
                and "error" in full_body
                and isinstance(full_body["error"], dict)
                and full_body["error"].get("status") == "API_KEY_INVALID"
            ):
                return CheckOutcome.UNAUTHORIZED
            return CheckOutcome.BAD_REQUEST
        return CheckOutcome.INCONCLUSIVE

    def _auto_detect_severity(self, outcome: CheckOutcome, status_code: int) -> Severity:
        """Auto-detect severity from outcome and status code.

        Args:
            outcome: The classified check outcome.
            status_code: The HTTP status code.

        Returns:
            The detected Severity level.
        """
        if outcome == CheckOutcome.ACCESSIBLE:
            return Severity.HIGH
        elif outcome == CheckOutcome.RESTRICTED:
            return Severity.MEDIUM if status_code == 200 else Severity.INFO
        elif outcome == CheckOutcome.UNAUTHORIZED:
            return Severity.INFO
        elif outcome == CheckOutcome.NOT_FOUND:
            return Severity.LOW
        elif outcome == CheckOutcome.BAD_REQUEST:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _outcome_reason(outcome: CheckOutcome, status_code: int, is_malformed: bool) -> str:
        """Build a traceable reason string for an outcome.

        Args:
            outcome: The classified check outcome.
            status_code: The HTTP status code.
            is_malformed: Whether the body failed JSON parsing.

        Returns:
            A human-readable reason string.
        """
        if outcome == CheckOutcome.ACCESSIBLE:
            return f"HTTP {status_code} with valid response data"
        elif outcome == CheckOutcome.RESTRICTED:
            return f"HTTP {status_code} — access denied by policy or API"
        elif outcome == CheckOutcome.UNAUTHORIZED:
            return f"HTTP {status_code} — key invalid or revoked"
        elif outcome == CheckOutcome.NOT_FOUND:
            return f"HTTP {status_code} — target missing or deleted"
        elif outcome == CheckOutcome.BAD_REQUEST:
            return f"HTTP {status_code} — invalid arguments or payload"
        elif outcome == CheckOutcome.INCONCLUSIVE:
            if is_malformed:
                return f"HTTP {status_code} with malformed (non-JSON) body"
            return f"HTTP {status_code} with empty or inconclusive body"
        return f"HTTP {status_code}"

    def _parse_body(self, response_obj: ResponseData) -> tuple[Any, bool]:
        """Parse the response body, handling JSON, images, and text.

        Args:
            response_obj: The ResponseData object to parse.

        Returns:
            A tuple of (parsed_body, is_malformed). parsed_body is dict for JSON,
            data URI string for images, str otherwise. is_malformed is True if
            JSON parsing failed on a non-image response.
        """
        content_type = response_obj._content_type
        if "image/" in content_type:
            b64_str = base64.b64encode(response_obj._body_bytes).decode("utf-8")
            return f"data:{content_type};base64,{b64_str}", False
        try:
            return response_obj.json(), False
        except (json.JSONDecodeError, ValueError):
            return response_obj.text, True

    def log_result(
        self,
        service_name: str,
        status_code: int,
        response_obj: ResponseData,
        severity: Severity | None = None,
    ) -> None:
        """Log a scan result with auto-outcome and auto-severity detection.

        Args:
            service_name: Human-readable name of the service checked.
            status_code: The HTTP status code received.
            response_obj: The ResponseData object with full response info.
            severity: Optional explicit severity override. If None, auto-detected.
        """
        full_body, is_malformed = self._parse_body(response_obj)
        outcome = self._classify_outcome(status_code, full_body, is_malformed)

        if severity is None:
            severity = self._auto_detect_severity(outcome, status_code)

        reason = self._outcome_reason(outcome, status_code, is_malformed)
        if response_obj.truncated:
            reason += " [response truncated — evidence incomplete]"

        sanitizer = scanner_sanitizer(self, full_body, response_obj.headers, response_obj.url)
        clean_service = sanitizer.text(service_name)
        clean_body = sanitizer.clean(full_body)
        clean_url = sanitizer.text(response_obj.url)
        clean_headers = sanitizer.clean(response_obj.headers)

        status_text = ScanResult(
            check_id="",
            service_name=clean_service,
            provider=self.PROVIDER_NAME,
            execution_status=ExecutionStatus.COMPLETED,
            outcome=outcome,
            reason=reason,
            status_code=status_code,
            url=clean_url,
            headers=clean_headers,
            response_body=clean_body,
            auto_severity=severity,
        ).status_text

        color = self._c(severity.color)
        if not self.quiet:
            print(
                f"{color}[{status_text}]{self._c(Style.RESET_ALL)} Checking {clean_service}... "
                f"[{self._c(severity.color)}{severity.label}{self._c(Style.RESET_ALL)}]"
            )

        self.scan_results.append(
            ScanResult(
                check_id="",
                service_name=clean_service,
                provider=self.PROVIDER_NAME,
                execution_status=ExecutionStatus.COMPLETED,
                outcome=outcome,
                reason=reason,
                status_code=status_code,
                url=clean_url,
                headers=clean_headers,
                response_body=clean_body,
                auto_severity=severity,
                truncated=response_obj.truncated,
            )
        )

    def log_error(self, service_name: str, error: Any) -> None:
        """Log a connection/network error for a service without crashing the scan.

        Network errors are severity ERROR, not CRITICAL — a connection failure
        is an execution problem, not a confirmed vulnerability.

        Args:
            service_name: Human-readable name of the service that failed.
            error: The error message or exception object.
        """
        sanitizer = scanner_sanitizer(self, str(error))
        clean_service = sanitizer.text(service_name)
        safe_error = sanitizer.text(str(error))
        error_msg = safe_error
        if len(error_msg) > 120:
            error_msg = error_msg[:120] + "..."

        color = self._c(Severity.ERROR.color)
        status_text = "CONNECTION ERROR"
        print(f"{color}[{status_text}]{self._c(Style.RESET_ALL)} Checking {clean_service}... ({error_msg})")

        self.scan_results.append(
            ScanResult(
                check_id="",
                service_name=clean_service,
                provider=self.PROVIDER_NAME,
                execution_status=ExecutionStatus.ERROR,
                outcome=CheckOutcome.ERROR,
                reason=f"Network error: {safe_error}",
                status_code=None,
                url="N/A",
                headers={},
                response_body=f"Connection Error: {safe_error}",
                error_message=safe_error,
                auto_severity=Severity.ERROR,
            )
        )

    def log_custom_result(
        self,
        service_name: str,
        status_text: str,
        status_code: int | None,
        response_body: Any,
        url: str = "N/A",
        severity: Severity = Severity.INFO,
        color: str | None = None,
        outcome: CheckOutcome | None = None,
        execution_status: ExecutionStatus = ExecutionStatus.COMPLETED,
    ) -> None:
        """Log a custom result (e.g., for boto3-based scanners that don't use HTTP).

        Args:
            service_name: Human-readable name of the service checked.
            status_text: The status text to display (e.g., "ACCESSIBLE (ACCESS)").
            status_code: The status code (200 for success, 403 for denied).
            response_body: The response body data to store.
            url: The endpoint URL or pseudo-URL.
            severity: The severity level for this finding.
            color: Optional custom color. Defaults to severity color.
            outcome: Optional explicit outcome. If None, inferred from status_code.
            execution_status: Execution status of this check.
        """
        if color is None:
            color = self._c(severity.color)
        if outcome is None:
            outcome = self._infer_outcome_from_status(status_code, status_text)

        sanitizer = scanner_sanitizer(self, response_body, status_text, url)
        clean_service = sanitizer.text(service_name)
        clean_status_text = sanitizer.text(status_text)
        clean_body = sanitizer.clean(response_body)
        clean_url = sanitizer.text(url)

        if not self.quiet:
            print(
                f"{color}[{clean_status_text}]{self._c(Style.RESET_ALL)} Checking {clean_service}... "
                f"[{self._c(severity.color)}{severity.label}{self._c(Style.RESET_ALL)}]"
            )

        self.scan_results.append(
            ScanResult(
                check_id="",
                service_name=clean_service,
                provider=self.PROVIDER_NAME,
                execution_status=execution_status,
                outcome=outcome,
                reason=clean_status_text,
                status_code=status_code,
                url=clean_url,
                headers={},
                response_body=clean_body,
                auto_severity=severity,
                custom_color=color,
                custom_status_text=clean_status_text,
            )
        )

    @staticmethod
    def _infer_outcome_from_status(status_code: int | None, status_text: str) -> CheckOutcome:
        """Infer a CheckOutcome from status_code and status_text for custom results.

        Args:
            status_code: The HTTP status code (may be None).
            status_text: The display status text.

        Returns:
            The inferred CheckOutcome.
        """
        text_upper = status_text.upper()
        if "SKIPPED" in text_upper:
            return CheckOutcome.SKIPPED
        if "ERROR" in text_upper:
            return CheckOutcome.ERROR
        if status_code == 200:
            if "RESTRICTED" in text_upper or "DENIED" in text_upper:
                return CheckOutcome.RESTRICTED
            return CheckOutcome.ACCESSIBLE
        if status_code == 403:
            return CheckOutcome.RESTRICTED
        if status_code == 401:
            return CheckOutcome.UNAUTHORIZED
        if status_code == 404:
            return CheckOutcome.NOT_FOUND
        if status_code == 400:
            return CheckOutcome.BAD_REQUEST
        if "RESTRICTED" in text_upper or "DENIED" in text_upper:
            return CheckOutcome.RESTRICTED
        if "UNAUTHORIZED" in text_upper:
            return CheckOutcome.UNAUTHORIZED
        return CheckOutcome.INCONCLUSIVE

    async def _skip_check(self, service_name: str, reason: str, category: str = "ACTIVE CHECK") -> None:
        """Record that a check was skipped with an explicit reason.

        Args:
            service_name: Human-readable name of the skipped check.
            reason: Why this check is skipped (used when --no-active-checks is set
                or when a required parameter is missing).
            category: Skip category for display — "ACTIVE CHECK" for disabled
                mutating checks, "MISSING PARAMETER" for missing prerequisites.
        """
        self.log_custom_result(
            service_name=service_name,
            status_text=f"SKIPPED ({category})",
            status_code=None,
            response_body=f"Skipped ({category}): {reason}.",
            url="N/A",
            severity=Severity.INFO,
            outcome=CheckOutcome.SKIPPED,
            execution_status=ExecutionStatus.SKIPPED,
        )

    async def _run_one_check(self, check_coro: Any) -> Any:
        """Run a single check coroutine with optional concurrency limiting.

        Rate limiting is applied per HTTP request inside _request_with_retry,
        not here, so retries are also rate-limited.

        Args:
            check_coro: The check coroutine to execute.

        Returns:
            The result of the coroutine.
        """
        if self._semaphore:
            async with self._semaphore:
                return await check_coro
        return await check_coro

    async def _run_checks(self, checks: list[tuple[str, Any]]) -> list[Any]:
        """Run a list of (check_name, coroutine) pairs concurrently with rate limiting.

        Exceptions are caught and recorded as ScanResult with ERROR outcome.
        CancelledError is recorded as an interruption, not a clean exit.
        Check names are paired at construction time, not inferred from CHECKS index.

        Concurrency is limited by a semaphore (``concurrency`` parameter).
        Rate is limited by a token bucket (``rate_limit`` parameter, RPS).

        Args:
            checks: List of (check_name, coroutine) tuples to execute.

        Returns:
            List of results (exceptions are returned as values, not raised).
        """
        self.planned_checks = len(checks)
        self._semaphore = asyncio.Semaphore(self.concurrency)
        if self.rate_limit:
            self._rate_limiter = RateLimiter(float(self.rate_limit))
        tasks = [asyncio.create_task(self._run_one_check(coro)) for _, coro in checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                check_name = checks[i][0]
                if isinstance(result, asyncio.CancelledError):
                    self._log_check_exception(check_name, "Check cancelled or interrupted")
                else:
                    self._log_check_exception(check_name, str(result))

        return results

    def _log_check_exception(self, check_name: str, error_msg: str) -> None:
        """Record a check that failed with an exception.

        Args:
            check_name: Human-readable name of the failed check.
            error_msg: The error message (will be sanitized).
        """
        sanitizer = scanner_sanitizer(self, error_msg)
        clean_name = sanitizer.text(check_name)
        safe_error = sanitizer.text(error_msg)
        if len(safe_error) > 120:
            safe_error = safe_error[:120] + "..."

        color = self._c(Severity.ERROR.color)
        print(f"{color}[CONNECTION ERROR]{self._c(Style.RESET_ALL)} Checking {clean_name}... " f"({safe_error})")

        self.scan_results.append(
            ScanResult(
                check_id=clean_name,
                service_name=clean_name,
                provider=self.PROVIDER_NAME,
                execution_status=ExecutionStatus.ERROR,
                outcome=CheckOutcome.ERROR,
                reason=f"Check raised exception: {safe_error}",
                status_code=None,
                url="N/A",
                headers={},
                response_body=f"Check Error: {safe_error}",
                error_message=safe_error,
                auto_severity=Severity.ERROR,
            )
        )

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
        connector_kwargs: dict[str, Any] = {}
        headers: dict[str, str] = {}
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
