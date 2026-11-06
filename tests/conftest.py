"""Pytest fixtures and configuration for apiKeyScan tests."""

import asyncio
import socket
from functools import wraps
from typing import Any

import pytest


def _install_network_guard():
    """Guard Python socket calls before collection, including fixture setup.

    Only exact loopback literals needed by Windows asyncio/local test servers
    are allowed. This is not an OS sandbox: subprocesses, native networking,
    saved pre-import callables and deliberate monkeypatching are not isolated.
    """
    patch = pytest.MonkeyPatch()

    def guarded_connect(original):
        @wraps(original)
        def connect(sock, address):
            if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
                raise RuntimeError("B00 network guard: non-loopback connection denied; use a fake transport")
            return original(sock, address)

        return connect

    for name in ("connect", "connect_ex"):
        patch.setattr(socket.socket, name, guarded_connect(getattr(socket.socket, name)))

    def guarded_async_connect(original):
        @wraps(original)
        async def connect(loop, sock, address):
            if not isinstance(address, tuple) or address[0] not in ("127.0.0.1", "::1"):
                raise RuntimeError("B00 network guard: non-loopback connection denied; use a fake transport")
            return await original(loop, sock, address)

        return connect

    loop_types: list[Any] = [asyncio.SelectorEventLoop]
    if hasattr(asyncio, "ProactorEventLoop"):
        loop_types.append(asyncio.ProactorEventLoop)
    for loop_type in loop_types:
        patch.setattr(loop_type, "sock_connect", guarded_async_connect(loop_type.sock_connect))

    def guarded_resolver(original, numeric=False):
        @wraps(original)
        def resolve(*args, **kwargs):
            if numeric:
                host = args[0] if args else kwargs.get("host")
                if host in ("127.0.0.1", "::1", b"127.0.0.1", b"::1"):
                    # Numeric literals only: never delegate a hostname to DNS.
                    kwargs["flags"] = kwargs.get("flags", 0) | socket.AI_NUMERICHOST
                    if len(args) > 5:
                        args = (*args[:5], args[5] | socket.AI_NUMERICHOST, *args[6:])
                        kwargs.pop("flags")
                    return original(*args, **kwargs)
            raise RuntimeError("B00 network guard: DNS resolution denied; use a fake transport")

        return resolve

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        patch.setattr(socket, name, guarded_resolver(getattr(socket, name), numeric=name == "getaddrinfo"))
    return patch


_NETWORK_PATCH = _install_network_guard()


def pytest_unconfigure(config):
    """Restore only when pytest has finished, never via a test opt-out."""
    _NETWORK_PATCH.undo()


try:
    from aioresponses import aioresponses

    AIORESPONSES_AVAILABLE = True
except ImportError:
    AIORESPONSES_AVAILABLE = False


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
