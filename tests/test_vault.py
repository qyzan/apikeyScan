"""Offline vault acceptance tests; no real terminal or credentials."""

import pytest


def test_vault_authenticated_roundtrip():
    from core.vault import decrypt, encrypt

    password = "dummy-password-not-real"
    payload = {"records": [{"id": "opaque", "credential": "DUMMY_VAULT_SECRET"}]}
    blob = encrypt(payload, password)
    assert b"DUMMY_VAULT_SECRET" not in blob
    assert password.encode() not in blob
    assert decrypt(blob, password) == payload
    assert encrypt(payload, password) != blob
    for damaged in (blob[:-1], bytes([blob[0] ^ 1]) + blob[1:], blob[:-1] + bytes([blob[-1] ^ 1])):
        with pytest.raises(ValueError):
            decrypt(damaged, password)
    with pytest.raises(ValueError):
        decrypt(blob, "incorrect-password")


def test_checkpoint_failure_keeps_previous_vault(tmp_path, monkeypatch):
    from core import vault

    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    ref = store.add({"api_key": "DUMMY_FIRST_CREDENTIAL"}, "test")
    assert vault.read_vault(store.path, "dummy-password")["records"][0]["id"] == ref
    before = store.path.read_bytes()

    def failed(*args):
        raise OSError("dummy write failure")

    monkeypatch.setattr(vault.os, "replace", failed)
    with pytest.raises(OSError):
        store.add({"api_key": "DUMMY_SECOND_CREDENTIAL"}, "test")
    assert store.path.read_bytes() == before
    assert len(vault.read_vault(store.path, "dummy-password")["records"]) == 1
    assert not list(store.path.parent.glob("*.tmp"))


def test_terminal_unavailable_never_falls_back_to_stdout(monkeypatch, capsys):
    from core import vault

    def unavailable(*args, **kwargs):
        raise OSError("no terminal")

    monkeypatch.setattr("builtins.open", unavailable)
    with pytest.raises(OSError), vault.Terminal():
        pass
    assert capsys.readouterr() == ("", "")


@pytest.mark.asyncio
async def test_cli_checkpoints_before_scan_and_stops_on_write_failure(tmp_path, monkeypatch):
    import importlib
    from unittest.mock import AsyncMock, Mock

    from core import vault

    cli = importlib.import_module("apiKeyScan")
    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    monkeypatch.setattr(vault, "start_vault", Mock(return_value=store))
    dispatch = AsyncMock(return_value=None)
    monkeypatch.setattr(cli, "run_single_scan", dispatch)
    args = cli.build_parser().parse_args(
        ["scan", "-p", "github", "-k", "DUMMY_CLI_CREDENTIAL", "--vault-dir", str(tmp_path)]
    )
    await cli.run_scan_command(args)
    assert len(vault.read_vault(store.path, "dummy-password")["records"]) == 1
    dispatch.assert_awaited_once()
    dispatch.reset_mock()
    monkeypatch.setattr(store, "add", Mock(side_effect=OSError("dummy failure")))
    assert await cli.run_scan_command(args) == 2
    dispatch.assert_not_called()


def test_password_only_uses_dedicated_terminal(tmp_path, monkeypatch, capsys):
    import io

    from core import vault

    class FakeTerminal:
        reader = io.StringIO("SAVED\n")
        output = ""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def write(self, text):
            self.output += text

    terminal = FakeTerminal()
    monkeypatch.setattr(vault, "Terminal", lambda: terminal)
    monkeypatch.setattr(vault.secrets, "token_urlsafe", lambda n: "DUMMY_TERMINAL_PASSWORD")
    store = vault.start_vault(tmp_path)
    assert str(store.path.resolve()) in terminal.output
    assert store.path.stem in terminal.output
    assert terminal.output.count("DUMMY_TERMINAL_PASSWORD") == 1
    assert capsys.readouterr() == ("", "")
    assert vault.read_vault(store.path, "DUMMY_TERMINAL_PASSWORD")["records"] == []
    for path in store.path.parent.iterdir():
        assert b"DUMMY_TERMINAL_PASSWORD" not in path.read_bytes()


def test_open_local_only_writes_to_terminal(tmp_path, monkeypatch, capsys):
    from core import vault

    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    store.add({"api_key": "DUMMY_OPEN_CREDENTIAL"}, "test")
    output = []

    class FakeTerminal:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def password(self):
            return "dummy-password"

        def write(self, text):
            output.append(text)

    monkeypatch.setattr(vault, "Terminal", FakeTerminal)
    vault.open_local(store.path)
    assert "DUMMY_OPEN_CREDENTIAL" in output[0]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("format_name", ["json", "html", "csv", "sarif"])
def test_vault_reference_survives_all_reports(tmp_path, format_name):
    from core.base_scanner import BaseScanner
    from core.report_engine import ReportEngine

    scanner = BaseScanner("DUMMY_INPUT_CREDENTIAL")
    scanner.vault_ref = "opaque-record-reference"
    scanner.vault_run = "opaque-vault-run"
    scanner.log_custom_result("Inventory", "RESTRICTED", 403, {"count": 1})
    path = tmp_path / ("report." + format_name)
    getattr(ReportEngine, "generate_" + format_name + "_report")(scanner, "test", str(path))
    content = path.read_text(encoding="utf-8")
    assert scanner.vault_ref in content
    assert scanner.vault_run in content
    assert "DUMMY_INPUT_CREDENTIAL" not in content


@pytest.mark.asyncio
async def test_batch_uses_one_vault_before_each_dispatch(tmp_path, monkeypatch):
    import importlib
    from unittest.mock import Mock

    from core import vault

    cli = importlib.import_module("apiKeyScan")
    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    starter = Mock(return_value=store)
    monkeypatch.setattr(vault, "start_vault", starter)
    keys = ["DUMMY_BATCH_FIRST_CREDENTIAL", "DUMMY_BATCH_SECOND_CREDENTIAL"]
    keyfile = tmp_path / "dummy-keys.txt"
    keyfile.write_text("\n".join(keys))
    calls = []

    async def dispatch(provider, key, kwargs, args):
        records = vault.read_vault(store.path, "dummy-password")["records"]
        assert records[-1]["credentials"]["api_key"] == key
        assert records[-1]["id"] == args.vault_ref
        calls.append(key)

    monkeypatch.setattr(cli, "run_single_scan", dispatch)
    args = cli.build_parser().parse_args(
        ["scan", "-p", "github", "--keyfile", str(keyfile), "--vault-dir", str(tmp_path)]
    )
    await cli.run_scan_command(args)
    assert calls == keys
    starter.assert_called_once()
    assert len(list(store.path.parent.glob("*.akv"))) == 1


def test_interruption_keeps_last_checkpoint(tmp_path, monkeypatch):
    from core import vault

    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    store.add({"api_key": "DUMMY_PERSISTED"}, "test")
    before = store.path.read_bytes()

    def interrupt(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(vault.os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt):
        store.add({"api_key": "DUMMY_INTERRUPTED"}, "test")
    assert store.path.read_bytes() == before
    assert not list(store.path.parent.glob("*.tmp"))


def test_rejects_oversized_vault_before_kdf(monkeypatch):
    from core import vault

    def forbidden(*args):
        pytest.fail("KDF must not run for invalid bounds")

    monkeypatch.setattr(vault, "_key", forbidden)
    with pytest.raises(ValueError):
        vault.decrypt(vault.MAGIC + b"x" * vault.MAX_SIZE, "dummy")


def test_ciphertext_file_inherits_operator_acl(tmp_path):
    import os
    import subprocess

    from core import vault

    store = vault.Vault.create(tmp_path / "private", "dummy-password")
    if os.name == "nt":
        listing = subprocess.check_output(["icacls", str(store.path)], text=True)
        assert "(I)(F)" in listing
        assert "Everyone" not in listing and "BUILTIN" not in listing
        # One explicit operator ACE only; file inheritance from protected parent.
        assert len([line for line in listing.splitlines() if "(F)" in line]) == 1
    else:
        assert store.path.stat().st_mode & 0o777 == 0o600


def test_acl_failure_prevents_password_generation(tmp_path, monkeypatch):
    import io
    from unittest.mock import Mock

    from core import vault

    class FakeTerminal:
        reader = io.StringIO("SAVED\n")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def write(self, text):
            pytest.fail("Password must not be displayed before ACL verification")

    monkeypatch.setattr(vault, "Terminal", FakeTerminal)
    generator = Mock()
    monkeypatch.setattr(vault.secrets, "token_urlsafe", generator)
    monkeypatch.setattr(vault, "private_directory", Mock(side_effect=OSError("dummy ACL failure")))
    with pytest.raises(OSError):
        vault.start_vault(tmp_path)
    generator.assert_not_called()


@pytest.mark.asyncio
async def test_noninteractive_vault_stops_before_detection(tmp_path, monkeypatch):
    import importlib
    from unittest.mock import AsyncMock, Mock

    from core import vault

    cli = importlib.import_module("apiKeyScan")
    starter = Mock()
    detection = AsyncMock()
    dispatch = AsyncMock()
    monkeypatch.setattr(vault, "start_vault", starter)
    monkeypatch.setattr(cli, "auto_detect_provider", detection)
    monkeypatch.setattr(cli, "run_single_scan", dispatch)
    args = cli.build_parser().parse_args(
        ["scan", "-k", "DUMMY_NONINTERACTIVE", "--vault-dir", str(tmp_path), "--no-interactive"]
    )
    assert await cli.run_scan_command(args) == 2
    starter.assert_not_called()
    detection.assert_not_called()
    dispatch.assert_not_called()


def test_windows_password_reads_without_echo(monkeypatch):
    import io
    import os

    from core import vault

    if os.name != "nt":
        pytest.skip("Windows console input boundary")
    import msvcrt

    terminal = vault.Terminal()
    terminal.writer = io.StringIO()
    chars = iter("\ndummy-passworx\bd\r")
    monkeypatch.setattr(msvcrt, "getwch", lambda: next(chars))
    assert terminal.password() == "dummy-password"
    assert "dummy-password" not in terminal.writer.getvalue()


@pytest.mark.asyncio
async def test_cli_errors_and_short_batch_key_are_masked(tmp_path, monkeypatch, capsys):
    import importlib
    from unittest.mock import AsyncMock, Mock

    cli = importlib.import_module("apiKeyScan")
    key = "SHORT_CANARY"
    args = cli.build_parser().parse_args(["scan", "-p", "github", "-k", key])
    monkeypatch.setattr(cli, "get_scanner", Mock(side_effect=ValueError("invalid credential " + key)))
    await cli.run_single_scan("github", key, {}, args)
    assert key not in capsys.readouterr().out
    keyfile = tmp_path / "dummy-keys.txt"
    keyfile.write_text(key)
    args = cli.build_parser().parse_args(["scan", "-p", "github", "--keyfile", str(keyfile)])
    monkeypatch.setattr(cli, "run_single_scan", AsyncMock(return_value=None))
    await cli.run_scan_command(args)
    assert key not in capsys.readouterr().out
