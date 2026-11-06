"""Network guard regressions; rejected operations never reach a real socket."""

import asyncio
import runpy
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest


@pytest.fixture
def guarded_socket(monkeypatch):
    """Load the real suite configuration over sentinel-only socket boundaries."""
    native = {name: Mock(return_value=0) for name in ("connect", "connect_ex")}
    fake_type = type("SentinelSocket", (), native)
    resolvers = {
        name: Mock(return_value=[])
        for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo")
    }
    fake = SimpleNamespace(socket=fake_type, AI_NUMERICHOST=socket.AI_NUMERICHOST, **resolvers)
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "socket", fake)
        config = runpy.run_path(str(Path(__file__).with_name("conftest.py")))
    try:
        yield fake, native
    finally:
        config["_NETWORK_PATCH"].undo()


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
@pytest.mark.parametrize(
    "host",
    [
        "192.0.2.1",
        "10.0.0.1",
        "2001:db8::1",
        "provider.invalid",
        "localhost",
        "127.0.0.2",
        "::ffff:127.0.0.1",
        "0.0.0.0",
    ],
)
def test_connect_denied_before_native_call(guarded_socket, method, host):
    fake, native = guarded_socket
    with pytest.raises(RuntimeError, match="B00 network guard: non-loopback connection denied"):
        getattr(fake.socket(), method)((host, 443))
    native[method].assert_not_called()


@pytest.mark.parametrize("method", ["connect", "connect_ex"])
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_only_exact_loopback_delegates(guarded_socket, method, host):
    fake, native = guarded_socket
    sock = fake.socket()
    assert getattr(sock, method)((host, 12345)) == 0
    native[method].assert_called_once_with(sock, (host, 12345))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("positional", [False, True])
def test_loopback_resolution_is_numeric_only(guarded_socket, host, positional):
    fake, _ = guarded_socket
    if positional:
        fake.getaddrinfo(host, 12345, 0, 0, 0, 0)
    else:
        fake.getaddrinfo(host=host, port=12345)
    args, kwargs = fake.getaddrinfo.__wrapped__.call_args
    flags = args[5] if positional else kwargs["flags"]
    assert flags & socket.AI_NUMERICHOST


@pytest.mark.parametrize("host", ["provider.invalid", "localhost", "10.0.0.1", "127.0.0.2"])
def test_dns_keyword_arguments_cannot_bypass_guard(guarded_socket, host):
    fake, _ = guarded_socket
    with pytest.raises(RuntimeError, match="B00 network guard: DNS resolution denied"):
        fake.getaddrinfo(host=host, port=443)
    fake.getaddrinfo.__wrapped__.assert_not_called()


@pytest.mark.parametrize(
    "resolver,args",
    [
        ("getaddrinfo", ("provider.invalid", 443)),
        ("gethostbyname", ("provider.invalid",)),
        ("gethostbyname_ex", ("provider.invalid",)),
        ("gethostbyaddr", ("192.0.2.1",)),
        ("getnameinfo", (("192.0.2.1", 443), 0)),
    ],
)
def test_dns_denied_before_system_resolver(guarded_socket, resolver, args):
    fake, _ = guarded_socket
    with pytest.raises(RuntimeError, match="B00 network guard: DNS resolution denied"):
        getattr(fake, resolver)(*args)
    getattr(fake, resolver).__wrapped__.assert_not_called()


def test_guard_does_not_hide_async_failures():
    config = runpy.run_path(str(Path(__file__).with_name("conftest.py")))
    try:
        assert "pytest_collection_modifyitems" not in config, "Guard must not turn broken event loops into skips"
    finally:
        if "_NETWORK_PATCH" in config:
            config["_NETWORK_PATCH"].undo()


def test_event_loop_lifecycle():
    async def local():
        await asyncio.sleep(0)
        return "local-only"

    loop = asyncio.new_event_loop()
    try:
        assert loop.run_until_complete(local()) == "local-only"
    finally:
        loop.close()
    assert loop.is_closed()


def test_automatic_guard_is_active_without_opt_in_fixture():
    for operation in (socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo):
        assert Path(operation.__code__.co_filename).name == "conftest.py"


@pytest.mark.asyncio
async def test_provider_and_webhooks_use_fake_transport(monkeypatch):
    from core.base_scanner import BaseScanner
    from core.notifier import notify_discord, notify_slack

    response = MagicMock(status=200, headers={"Content-Type": "application/json"}, url="https://provider.invalid")
    response.read = AsyncMock(return_value=b'{"ok": true}')
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=False)
    session = MagicMock()
    session.request.return_value = context
    session.post.return_value = context
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    factory = Mock(return_value=session)
    monkeypatch.setattr("aiohttp.ClientSession", factory)

    scanner = BaseScanner("b00-dummy", max_retries=1)
    scanner._session = session
    result = await scanner._request_with_retry("GET", "https://provider.invalid")
    assert result is not None and result.status == 200
    assert await notify_slack("https://webhook.invalid/slack", scanner, "test")
    assert await notify_discord("https://webhook.invalid/discord", scanner, "test")
    session.request.assert_called_once()
    assert session.post.call_count == 2
    assert factory.call_count == 2


@pytest.mark.parametrize(
    "loop_type",
    [asyncio.SelectorEventLoop, *([asyncio.ProactorEventLoop] if hasattr(asyncio, "ProactorEventLoop") else [])],
)
def test_async_connect_denied_before_native_call(monkeypatch, loop_type):
    native = AsyncMock()
    with monkeypatch.context() as patch:
        patch.setattr(loop_type, "sock_connect", native)
        config = runpy.run_path(str(Path(__file__).with_name("conftest.py")))
        try:

            async def attempt():
                with pytest.raises(RuntimeError, match="B00 network guard: non-loopback connection denied"):
                    await loop_type.sock_connect(None, None, ("192.0.2.1", 443))

            asyncio.run(attempt())
            native.assert_not_called()
        finally:
            config["_NETWORK_PATCH"].undo()
