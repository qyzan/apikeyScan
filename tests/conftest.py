"""Pytest fixtures and configuration for apiKeyScan tests."""

import asyncio

import pytest

try:
    from aioresponses import aioresponses

    AIORESPONSES_AVAILABLE = True
except ImportError:
    AIORESPONSES_AVAILABLE = False


def _asyncio_available() -> bool:
    """Check if asyncio event loop can be created in this environment.

    Returns:
        True if an event loop can be created, False otherwise.
    """
    try:
        loop = asyncio.new_event_loop()
        loop.close()
        return True
    except OSError:
        return False


ASYNCIO_AVAILABLE = _asyncio_available()


@pytest.fixture
def mock_aiohttp():
    """Mock aiohttp HTTP requests for testing.

    Yields:
        An aioresponses context manager for mocking HTTP responses.
        None if aioresponses is not available.
    """
    if not AIORESPONSES_AVAILABLE:
        yield None
        return
    with aioresponses() as m:
        yield m


def pytest_collection_modifyitems(config, items):
    """Skip async tests if asyncio event loop is not available."""
    if ASYNCIO_AVAILABLE:
        return
    skip_marker = pytest.mark.skip(reason="Asyncio event loop not available in this sandbox environment")
    for item in items:
        if "asyncio" in item.keywords:
            item.add_marker(skip_marker)
