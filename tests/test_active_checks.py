"""Offline regressions for B02 (revised): mutating/generation checks run by default.

Tests prove that active checks (sign-up, message send, email send, billable
generation) ARE scheduled by default, and that --no-active-checks disables
them with an explicit skip reason instead of vanishing from coverage.
The legacy --active-checks flag is a no-op compatibility alias. All tests
use fake transports; no real network.
"""

from unittest.mock import AsyncMock

import pytest

from apiKeyScan import build_parser, build_scanner_kwargs
from core.base_scanner import ResponseData
from scanners.anthropic_scanner import AnthropicScanner
from scanners.google_scanner import GoogleScanner
from scanners.openai_scanner import OpenAIScanner
from scanners.sendgrid_scanner import SendGridScanner


def _mock_response(status: int = 200, body: bytes = b'{"data": []}') -> ResponseData:
    return ResponseData(
        status=status,
        headers={"Content-Type": "application/json"},
        url="https://example.com/test",
        _body_bytes=body,
        _content_type="application/json",
    )


def _post_urls(scanner: object) -> list[str]:
    return [call.args[1] for call in scanner._safe_post.call_args_list]


def _skipped(scanner: object) -> list[dict]:
    return [r for r in scanner.results if "SKIPPED" in r.get("status_text", "")]


# --- OpenAI ---


@pytest.mark.asyncio
async def test_openai_active_checks_enabled_by_default():
    scanner = OpenAIScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert any("chat/completions" in u for u in urls), "chat generation should run by default"
    assert any("images/generations" in u for u in urls), "DALL-E generation should run by default"
    assert any("moderations" in u for u in urls), "moderations (non-active) should still run"
    assert len(_skipped(scanner)) == 0


@pytest.mark.asyncio
async def test_openai_active_checks_disabled_with_no_active_checks():
    scanner = OpenAIScanner("test_key", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert not any("chat/completions" in u for u in urls), "chat generation ran despite --no-active-checks"
    assert not any("images/generations" in u for u in urls), "DALL-E generation ran despite --no-active-checks"
    assert any("moderations" in u for u in urls), "moderations (non-active) should still run"
    skipped = _skipped(scanner)
    assert len(skipped) == 2, f"expected 2 skips, got {len(skipped)}"
    reasons = " ".join(str(r.get("service", "")) for r in skipped)
    assert "Chat" in reasons and "DALL-E" in reasons


# --- Anthropic ---


@pytest.mark.asyncio
async def test_anthropic_active_checks_enabled_by_default():
    scanner = AnthropicScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert any(u.rstrip("/").endswith("/v1/messages") for u in urls), "messages generation should run by default"
    assert any("count_tokens" in u for u in urls), "count_tokens (non-active) should still run"
    assert len(_skipped(scanner)) == 0


@pytest.mark.asyncio
async def test_anthropic_active_checks_disabled_with_no_active_checks():
    scanner = AnthropicScanner("test_key", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert not any(
        u.rstrip("/").endswith("/v1/messages") for u in urls
    ), "messages generation ran despite --no-active-checks"
    assert any("count_tokens" in u for u in urls), "count_tokens (non-active) should still run"
    skipped = _skipped(scanner)
    assert len(skipped) == 1
    assert "Messages" in str(skipped[0].get("service", ""))


# --- SendGrid ---


@pytest.mark.asyncio
async def test_sendgrid_active_checks_enabled_by_default():
    scanner = SendGridScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert any("mail/send" in u for u in urls), "mail send should run by default"
    get_urls = [call.args[1] for call in scanner._safe_get.call_args_list]
    assert any("api_keys" in u for u in get_urls), "api_keys listing (non-active) should still run"
    assert len(_skipped(scanner)) == 0


@pytest.mark.asyncio
async def test_sendgrid_active_checks_disabled_with_no_active_checks():
    scanner = SendGridScanner("test_key", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert not any("mail/send" in u for u in urls), "mail send ran despite --no-active-checks"
    skipped = _skipped(scanner)
    assert len(skipped) == 1
    assert "Mail Send" in str(skipped[0].get("service", ""))


# --- Google ---


@pytest.mark.asyncio
async def test_google_identity_toolkit_enabled_by_default():
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert any("signUp" in u for u in urls), "identity toolkit signUp should run by default"
    assert any("images:annotate" in u for u in urls), "vision (non-active) should still run"
    assert any("threatMatches" in u for u in urls), "safe browsing (non-active) should still run"
    skipped = _skipped(scanner)
    assert len(skipped) == 10, f"expected 10 skips (missing project_id), got {len(skipped)}"


@pytest.mark.asyncio
async def test_google_fcm_disabled_with_no_active_checks_and_project_id():
    scanner = GoogleScanner("test_key", project_id="my-project", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert not any("signUp" in u for u in urls), "signUp ran despite --no-active-checks"
    assert not any("messages:send" in u for u in urls), "FCM send ran despite --no-active-checks"
    skipped = _skipped(scanner)
    assert len(skipped) == 2, f"expected 2 skips (signUp + FCM), got {len(skipped)}"
    services = " ".join(str(r.get("service", "")) for r in skipped)
    assert "Identity Toolkit" in services
    assert "FCM" in services


@pytest.mark.asyncio
async def test_google_active_checks_enabled_with_project_id():
    scanner = GoogleScanner("test_key", project_id="my-project", no_color=True, active_checks=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert any("signUp" in u for u in urls), "signUp should run with active_checks=True"
    assert any("messages:send" in u for u in urls), "FCM send should run with active_checks=True"
    assert len(_skipped(scanner)) == 0


# --- Skip record content ---


@pytest.mark.asyncio
async def test_skip_record_has_explicit_reason_and_no_secret():
    scanner = OpenAIScanner("test_key", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response()))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response()))
    await scanner.scan()
    for skip in _skipped(scanner):
        assert skip["status_code"] is None
        assert "SKIPPED" in skip["status_text"]
    raw_skips = [
        r
        for r in scanner.raw_data
        if "SKIPPED" in r.get("service", "") or "Disabled" in str(r.get("response_body", ""))
    ]
    for entry in raw_skips:
        body = str(entry.get("response_body", ""))
        assert "Skipped" in body or "Disabled" in body, "skip reason must be explicit"
        assert "test_key" not in body, "skip record must not leak the API key"


# --- CLI passthrough ---


def test_cli_no_active_checks_flag_default_false():
    args = build_parser().parse_args(["scan", "-k", "dummy"])
    assert args.no_active_checks is False


def test_cli_no_active_checks_flag_set_true():
    args = build_parser().parse_args(["scan", "-k", "dummy", "--no-active-checks"])
    assert args.no_active_checks is True


def test_cli_legacy_active_checks_flag_accepted():
    args = build_parser().parse_args(["scan", "-k", "dummy", "--active-checks"])
    assert args.active_checks is True


def test_build_scanner_kwargs_default_active_checks_true():
    args = build_parser().parse_args(["scan", "-k", "dummy"])
    kwargs = build_scanner_kwargs(args)
    assert kwargs["active_checks"] is True


def test_build_scanner_kwargs_no_active_checks_false():
    args = build_parser().parse_args(["scan", "-k", "dummy", "--no-active-checks"])
    kwargs = build_scanner_kwargs(args)
    assert kwargs["active_checks"] is False


def test_build_scanner_kwargs_legacy_active_checks_still_true():
    args = build_parser().parse_args(["scan", "-k", "dummy", "--active-checks"])
    kwargs = build_scanner_kwargs(args)
    assert kwargs["active_checks"] is True


# --- No fallback from safe to mutating ---


@pytest.mark.asyncio
async def test_no_fallback_to_mutating_on_denied_access():
    scanner = OpenAIScanner("test_key", no_color=True, active_checks=False)
    scanner._safe_get = AsyncMock(return_value=(False, None))
    scanner._safe_post = AsyncMock(return_value=(True, _mock_response(403, b'{"error": "forbidden"}')))
    await scanner.scan()
    urls = _post_urls(scanner)
    assert not any("chat/completions" in u for u in urls), "denied safe check must not trigger chat generation"
    assert not any("images/generations" in u for u in urls), "denied safe check must not trigger DALL-E"
