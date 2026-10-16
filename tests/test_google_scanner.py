"""Tests for scanners/google_scanner.py — async check execution with mocks."""

from unittest.mock import AsyncMock

import pytest

from core.base_scanner import ResponseData
from scanners.google_scanner import GoogleScanner


def _mock_response(
    status: int = 200, body: bytes = b'{"data": []}', content_type: str = "application/json"
) -> ResponseData:
    """Create a mock ResponseData for testing.

    Args:
        status: HTTP status code.
        body: Response body bytes.
        content_type: Content-Type header.

    Returns:
        A ResponseData instance.
    """
    return ResponseData(
        status=status,
        headers={"Content-Type": content_type},
        url="https://example.com/test",
        _body_bytes=body,
        _content_type=content_type,
    )


@pytest.mark.asyncio
async def test_google_scanner_maps_check():
    """Google Maps static map check should record a result."""
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b"image", "image/png")))
    await scanner._check_maps_static()
    assert any("Maps" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_google_scanner_gemini_check():
    """Google Gemini API check should record a result."""
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b'{"models": []}')))
    await scanner._check_gemini()
    assert any("Gemini" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_google_scanner_translate_check():
    """Google Translation API check should record a restricted result."""
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(403, b'{"error": "forbidden"}')))
    await scanner._check_translate()
    assert any("Translation" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_google_scanner_youtube_check():
    """YouTube Data API check should record a result."""
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b'{"items": []}')))
    await scanner._check_youtube()
    assert any("YouTube" in r["service"] for r in scanner.results)


@pytest.mark.asyncio
async def test_google_scanner_maps_vulnerable_severity():
    """Maps check returning 200 should have MEDIUM severity."""
    scanner = GoogleScanner("test_key", no_color=True)
    scanner._safe_get = AsyncMock(return_value=(True, _mock_response(200, b"image", "image/png")))
    await scanner._check_maps_static()
    assert scanner.results[0]["severity"] == "MEDIUM"


def test_google_scanner_checks_attribute():
    """GoogleScanner should define CHECKS with 20+ entries."""
    assert len(GoogleScanner.CHECKS) >= 20


def test_google_scanner_provider_name():
    """GoogleScanner should have correct PROVIDER_NAME."""
    assert GoogleScanner.PROVIDER_NAME == "google"
