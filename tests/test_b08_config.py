"""B08 acceptance tests: schema config dan precedence.

Tests prove:
- Criterion 1: default → config → CLI explicit precedence; argparse defaults
  do not silently override config.
- Criterion 2: All advertised config fields are applied or rejected with reason;
  safety options are not silently ignored.
- Criterion 3: YAML scalar/list/malformed, wrong type, unknown field, missing
  file → structured error without secret.
- Criterion 4: timeout/rate_limit/output/formats/project_id from config are
  traceable to dispatch fake and report.
"""

import importlib
import sys
from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.base_scanner import (
    BaseScanner,
    CheckOutcome,
    ExecutionStatus,
    ScanResult,
    Severity,
)
from core.config import ConfigError, load_config, merge_config_into_args


def _make_scanner(
    api_key: str = "test_key_12345",
    outcomes: list[tuple[CheckOutcome, ExecutionStatus]] | None = None,
) -> BaseScanner:
    """Create a scanner with scan_results."""
    if outcomes is None:
        outcomes = [(CheckOutcome.RESTRICTED, ExecutionStatus.COMPLETED)]
    scanner = BaseScanner(api_key, no_color=True)
    scanner.scan_results = [
        ScanResult(
            check_id=f"check-{i}",
            service_name=f"Check-{i}",
            provider="test",
            execution_status=es,
            outcome=oc,
            reason="test",
            status_code=200 if oc == CheckOutcome.ACCESSIBLE else None,
            url="https://example.com/test",
            headers={},
            response_body={},
            auto_severity=Severity.HIGH if oc == CheckOutcome.ACCESSIBLE else Severity.INFO,
        )
        for i, (oc, es) in enumerate(outcomes)
    ]
    return scanner


def _run_cli(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    scanners: list[BaseScanner | None] | None = None,
    auto_providers: list[str] | None = None,
) -> int:
    """Run CLI main() and return exit code via SystemExit."""
    cli = importlib.import_module("apiKeyScan")
    monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", *argv])

    run_cm = (
        patch.object(cli, "run_single_scan", AsyncMock(side_effect=scanners)) if scanners is not None else nullcontext()
    )
    auto_cm = (
        patch.object(
            cli,
            "auto_detect_provider",
            AsyncMock(side_effect=[{"provider": p} for p in auto_providers]),
        )
        if auto_providers is not None
        else nullcontext()
    )

    with run_cm, auto_cm, pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code


def _run_cli_with_capture(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    scanner: BaseScanner,
) -> tuple[int, AsyncMock]:
    """Run CLI and capture the run_single_scan mock for kwargs inspection."""
    cli = importlib.import_module("apiKeyScan")
    monkeypatch.setattr(sys, "argv", ["apiKeyScan.py", *argv])

    mock = AsyncMock(return_value=scanner)
    with patch.object(cli, "run_single_scan", mock), pytest.raises(SystemExit) as excinfo:
        cli.main()
    return excinfo.value.code, mock


class TestConfigValidation:
    """Criterion 3: YAML validation — structured errors without secret."""

    def test_valid_config_loaded(self, tmp_path):
        """Valid YAML with known fields → returns dict."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\ntimeout: 30\n", encoding="utf-8")
        data = load_config(str(cfg))
        assert data["provider"] == "github"
        assert data["timeout"] == 30

    def test_unknown_field_rejected(self, tmp_path):
        """Unknown field → ConfigError listing valid fields."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nbogus_field: true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="Unknown config field: 'bogus_field'"):
            load_config(str(cfg))

    def test_type_mismatch_rejected(self, tmp_path):
        """String where int expected → ConfigError."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("timeout: not_a_number\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be int"):
            load_config(str(cfg))

    def test_malformed_yaml_rejected(self, tmp_path):
        """Malformed YAML → ConfigError."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\n  - bad: indent\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="Malformed YAML"):
            load_config(str(cfg))

    def test_missing_file_rejected(self, tmp_path):
        """Missing file → ConfigError."""
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_invalid_format_rejected(self, tmp_path):
        """Unknown format name → ConfigError."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("formats: [json, xml]\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="Unknown format in 'formats' field"):
            load_config(str(cfg))

    def test_invalid_severity_filter_rejected(self, tmp_path):
        """Invalid severity_filter → ConfigError."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("severity_filter: extreme\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="Invalid value in 'severity_filter' field"):
            load_config(str(cfg))

    def test_non_dict_top_level_rejected(self, tmp_path):
        """YAML list at top level → ConfigError."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            load_config(str(cfg))

    def test_empty_config_returns_empty_dict(self, tmp_path):
        """Empty YAML file → empty dict (not error)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("", encoding="utf-8")
        data = load_config(str(cfg))
        assert data == {}

    def test_error_message_no_secret(self, tmp_path):
        """Error message must not contain secret values from config."""
        secret_key = "AIzaSySuperSecret123456789"
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"key: {secret_key}\nbogus: true\n", encoding="utf-8")
        with pytest.raises(ConfigError) as excinfo:
            load_config(str(cfg))
        assert secret_key not in str(excinfo.value)


class TestConfigMerge:
    """Criterion 1: Precedence — default → config → CLI explicit."""

    def test_config_applied_when_cli_not_explicit(self):
        """Config timeout=30, no CLI flag → args.timeout=30."""
        args = Namespace(timeout=20, provider=None)
        config = {"timeout": 30}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key"])
        assert args.timeout == 30

    def test_cli_overrides_config(self):
        """Config timeout=30, CLI --timeout 10 → args.timeout=10."""
        args = Namespace(timeout=10, provider=None)
        config = {"timeout": 30}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key", "--timeout", "10"])
        assert args.timeout == 10

    def test_no_config_no_change(self):
        """Empty config → args unchanged."""
        args = Namespace(timeout=20, provider=None)
        merge_config_into_args(args, {}, argv=["apiKeyScan.py", "scan"])
        assert args.timeout == 20

    def test_formats_from_config(self):
        """Config formats=[json,html] → args.json=True, args.html=True."""
        args = Namespace(json=False, html=False, csv=False, sarif=False, all_formats=False)
        config = {"formats": ["json", "html"]}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key"])
        assert args.json is True
        assert args.html is True
        assert args.csv is False
        assert args.sarif is False

    def test_cli_format_overrides_config_formats(self):
        """CLI --csv explicit → config formats ignored."""
        args = Namespace(json=False, html=False, csv=True, sarif=False, all_formats=False)
        config = {"formats": ["json", "html"]}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key", "--csv"])
        assert args.json is False
        assert args.html is False
        assert args.csv is True

    def test_store_true_from_config(self):
        """Config no_color=true, no CLI → args.no_color=True."""
        args = Namespace(no_color=False)
        config = {"no_color": True}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key"])
        assert args.no_color is True

    def test_cli_store_true_overrides_config_false(self):
        """Config no_color=false, CLI --no-color → args.no_color=True."""
        args = Namespace(no_color=True)
        config = {"no_color": False}
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan", "-k", "key", "--no-color"])
        assert args.no_color is True

    def test_all_fields_merge(self):
        """Every schema field can be merged into args."""
        args = Namespace(
            provider=None,
            key=None,
            keyfile=None,
            secret=None,
            project_id=None,
            referer=None,
            collection="users",
            bucket=None,
            region="us-east-1",
            timeout=20,
            rate_limit=None,
            proxy=None,
            user_agent=None,
            severity_filter=None,
            no_color=False,
            output=None,
            json=False,
            html=False,
            csv=False,
            sarif=False,
            all_formats=False,
            notify_slack=None,
            notify_discord=None,
            force_probe=False,
            no_interactive=False,
            no_active_checks=False,
            verbose=False,
            quiet=False,
            vault_dir=None,
            overwrite=False,
        )
        config = {
            "provider": "github",
            "key": "ghp_test",
            "keyfile": None,
            "secret": "wJalrXUt",
            "project_id": "proj-123",
            "referer": "http://ref",
            "collection": "mycoll",
            "bucket": "mybucket",
            "region": "eu-west-1",
            "timeout": 45,
            "rate_limit": 5,
            "proxy": "http://proxy:8080",
            "user_agent": "MyAgent",
            "severity_filter": "high",
            "no_color": True,
            "output": "report",
            "formats": ["json"],
            "notify_slack": "http://slack",
            "notify_discord": "http://discord",
            "force_probe": False,
            "no_interactive": True,
            "no_active_checks": True,
            "verbose": True,
            "quiet": False,
            "vault_dir": "/tmp/vault",
            "overwrite": True,
        }
        merge_config_into_args(args, config, argv=["apiKeyScan.py", "scan"])
        assert args.provider == "github"
        assert args.timeout == 45
        assert args.collection == "mycoll"
        assert args.region == "eu-west-1"
        assert args.no_color is True
        assert args.json is True
        assert args.overwrite is True


class TestConfigPrecedenceCLI:
    """Criterion 1: Precedence via CLI integration."""

    def test_config_timeout_reaches_scanner(self, monkeypatch, tmp_path):
        """Config timeout=30, no CLI → scanner kwargs timeout=30."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\ntimeout: 30\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["timeout"] == 30

    def test_cli_timeout_overrides_config(self, monkeypatch, tmp_path):
        """Config timeout=30, CLI --timeout 10 → scanner kwargs timeout=10."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\ntimeout: 30\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--timeout",
                "10",
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["timeout"] == 10

    def test_config_project_id_reaches_scanner(self, monkeypatch, tmp_path):
        """Config project_id → scanner kwargs project_id."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nproject_id: my-proj-123\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["project_id"] == "my-proj-123"

    def test_config_rate_limit_reaches_scanner(self, monkeypatch, tmp_path):
        """Config rate_limit → scanner kwargs rate_limit."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nrate_limit: 5\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["rate_limit"] == 5

    def test_config_output_reaches_report(self, monkeypatch, tmp_path):
        """Config output → report file created at that prefix."""
        out_prefix = str(tmp_path / "from_config_report")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"provider: github\noutput: {out_prefix}\nformats: [json]\n", encoding="utf-8")
        scanner = _make_scanner()
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test123456789", "--config", str(cfg), "--no-color"],
            scanners=[scanner],
        )
        assert code == 0
        assert Path(f"{out_prefix}.json").exists()

    def test_config_formats_generate_reports(self, monkeypatch, tmp_path):
        """Config formats=[json,html] → both report files created."""
        out_prefix = str(tmp_path / "fmt_report")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"provider: github\noutput: {out_prefix}\nformats: [json, html]\n", encoding="utf-8")
        scanner = _make_scanner()
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test123456789", "--config", str(cfg), "--no-color"],
            scanners=[scanner],
        )
        assert code == 0
        assert Path(f"{out_prefix}.json").exists()
        assert Path(f"{out_prefix}.html").exists()

    def test_cli_format_overrides_config_formats(self, monkeypatch, tmp_path):
        """Config formats=[json,html], CLI --csv → only csv created."""
        out_prefix = str(tmp_path / "override_report")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"provider: github\noutput: {out_prefix}\nformats: [json, html]\n", encoding="utf-8")
        scanner = _make_scanner()
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test123456789", "--config", str(cfg), "--no-color", "--csv"],
            scanners=[scanner],
        )
        assert code == 0
        assert Path(f"{out_prefix}.csv").exists()
        assert not Path(f"{out_prefix}.json").exists()
        assert not Path(f"{out_prefix}.html").exists()

    def test_config_provider_used(self, monkeypatch, tmp_path):
        """Config provider → used without CLI -p."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        provider_arg = mock.call_args[0][0]
        assert provider_arg == "github"

    def test_cli_provider_overrides_config(self, monkeypatch, tmp_path):
        """Config provider=github, CLI -p gitlab → provider=gitlab."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "-p",
                "gitlab",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        provider_arg = mock.call_args[0][0]
        assert provider_arg == "gitlab"


class TestConfigErrorHandling:
    """Criterion 3: Error handling via CLI."""

    def test_unknown_field_exit_2(self, monkeypatch, tmp_path):
        """Unknown field in config → exit 2."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nbogus: true\n", encoding="utf-8")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "key", "--config", str(cfg), "--no-color"],
            scanners=[_make_scanner()],
        )
        assert code == 2

    def test_type_mismatch_exit_2(self, monkeypatch, tmp_path):
        """Type mismatch in config → exit 2."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("timeout: not_a_number\n", encoding="utf-8")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "key", "--config", str(cfg), "--no-color"],
            scanners=[_make_scanner()],
        )
        assert code == 2

    def test_malformed_yaml_exit_2(self, monkeypatch, tmp_path):
        """Malformed YAML → exit 2."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\n  - bad: indent\n", encoding="utf-8")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "key", "--config", str(cfg), "--no-color"],
            scanners=[_make_scanner()],
        )
        assert code == 2

    def test_missing_config_file_exit_2(self, monkeypatch, tmp_path):
        """Missing config file → exit 2."""
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "key", "--config", str(tmp_path / "nope.yaml"), "--no-color"],
            scanners=[_make_scanner()],
        )
        assert code == 2

    def test_safety_option_no_active_checks_from_config(self, monkeypatch, tmp_path):
        """Config no_active_checks=true → scanner kwargs active_checks=False."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nno_active_checks: true\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["active_checks"] is False

    def test_force_probe_from_config_rejected(self, monkeypatch, tmp_path):
        """Config force_probe=true → exit 2 (not silently ignored)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\nforce_probe: true\n", encoding="utf-8")
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "key", "--config", str(cfg), "--no-color"],
            scanners=[_make_scanner()],
        )
        assert code == 2


class TestArgvEqualsSyntax:
    """Fix 1: --flag=value and -fvalue must be detected as explicit CLI."""

    def test_output_equals_syntax_overrides_config(self, monkeypatch, tmp_path):
        """--output=FROM_CLI overrides config output."""
        cfg_out = str(tmp_path / "config_out")
        cli_out = str(tmp_path / "cli_out")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"provider: github\noutput: {cfg_out}\nformats: [json]\n", encoding="utf-8")
        scanner = _make_scanner()
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test123456789", "--config", str(cfg), "--no-color", f"--output={cli_out}"],
            scanners=[scanner],
        )
        assert code == 0
        assert Path(f"{cli_out}.json").exists()
        assert not Path(f"{cfg_out}.json").exists()

    def test_short_flag_attached_overrides_config(self, monkeypatch, tmp_path):
        """-oFROM_CLI overrides config output."""
        cfg_out = str(tmp_path / "config_out")
        cli_out = str(tmp_path / "cli_out")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"provider: github\noutput: {cfg_out}\nformats: [json]\n", encoding="utf-8")
        scanner = _make_scanner()
        code = _run_cli(
            monkeypatch,
            ["scan", "-k", "ghp_test123456789", "--config", str(cfg), "--no-color", f"-o{cli_out}"],
            scanners=[scanner],
        )
        assert code == 0
        assert Path(f"{cli_out}.json").exists()
        assert not Path(f"{cfg_out}.json").exists()

    def test_timeout_equals_syntax_overrides_config(self, monkeypatch, tmp_path):
        """--timeout=10 overrides config timeout=30."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("provider: github\ntimeout: 30\n", encoding="utf-8")
        scanner = _make_scanner()
        code, mock = _run_cli_with_capture(
            monkeypatch,
            [
                "scan",
                "-k",
                "ghp_test123456789",
                "--config",
                str(cfg),
                "--no-color",
                "--json",
                "-o",
                str(tmp_path / "out"),
                "--timeout=10",
            ],
            scanner,
        )
        assert code == 0
        call_kwargs = mock.call_args[0][2]
        assert call_kwargs["timeout"] == 10


class TestNoSecretInErrors:
    """Fix 2: Error messages must not echo raw values (secret leakage)."""

    def test_secret_in_formats_not_echoed(self, tmp_path):
        """Secret placed in formats → error message does not contain it."""
        secret = "ghp_supersecret123456789"
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"formats: [json, {secret}]\n", encoding="utf-8")
        with pytest.raises(ConfigError) as excinfo:
            load_config(str(cfg))
        assert secret not in str(excinfo.value)

    def test_secret_in_severity_not_echoed(self, tmp_path):
        """Secret placed in severity_filter → error message does not contain it."""
        secret = "ghp_supersecret123456789"
        cfg = tmp_path / "config.yaml"
        cfg.write_text(f"severity_filter: {secret}\n", encoding="utf-8")
        with pytest.raises(ConfigError) as excinfo:
            load_config(str(cfg))
        assert secret not in str(excinfo.value)


class TestBoolAsIntRejected:
    """Fix 3: bool must not be accepted as int (bool subclass of int)."""

    def test_timeout_true_rejected(self, tmp_path):
        """timeout: true → ConfigError (bool is not int)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("timeout: true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be int, got bool"):
            load_config(str(cfg))

    def test_rate_limit_false_rejected(self, tmp_path):
        """rate_limit: false → ConfigError (bool is not int)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("rate_limit: false\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must be int, got bool"):
            load_config(str(cfg))

    def test_timeout_zero_rejected_positive(self, tmp_path):
        """timeout: 0 → rejected (must be positive)."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("timeout: 0\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="positive"):
            load_config(str(cfg))
