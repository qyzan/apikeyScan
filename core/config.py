"""Config schema, validation, and CLI merge for apiKeyScan.

Precedence: argparse default < config file < explicit CLI flag.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, cast


class ConfigError(Exception):
    """Structured config error — message must not contain secrets."""


_CONFIG_SCHEMA: dict[str, type] = {
    "provider": str,
    "key": str,
    "keyfile": str,
    "secret": str,
    "project_id": str,
    "referer": str,
    "collection": str,
    "bucket": str,
    "region": str,
    "account_sid": str,
    "api_secret": str,
    "timeout": int,
    "rate_limit": int,
    "concurrency": int,
    "connect_timeout": int,
    "read_timeout": int,
    "proxy": str,
    "user_agent": str,
    "severity_filter": str,
    "no_color": bool,
    "output": str,
    "formats": list,
    "notify_slack": str,
    "notify_discord": str,
    "force_probe": bool,
    "no_interactive": bool,
    "no_active_checks": bool,
    "verbose": bool,
    "quiet": bool,
    "vault_dir": str,
    "overwrite": bool,
}

_CONFIG_TO_CLI: dict[str, set[str]] = {
    "provider": {"-p", "--provider"},
    "key": {"-k", "--key"},
    "keyfile": {"--keyfile"},
    "secret": {"--secret"},
    "project_id": {"--project-id"},
    "referer": {"--referer"},
    "collection": {"--collection"},
    "bucket": {"--bucket"},
    "region": {"--region"},
    "account_sid": {"--account-sid"},
    "api_secret": {"--secret"},
    "timeout": {"--timeout"},
    "rate_limit": {"--rate-limit"},
    "concurrency": {"--concurrency"},
    "connect_timeout": {"--connect-timeout"},
    "read_timeout": {"--read-timeout"},
    "proxy": {"--proxy"},
    "user_agent": {"--user-agent"},
    "severity_filter": {"--severity-filter"},
    "no_color": {"--no-color"},
    "output": {"-o", "--output"},
    "notify_slack": {"--notify-slack"},
    "notify_discord": {"--notify-discord"},
    "force_probe": {"--force-probe"},
    "no_interactive": {"--no-interactive"},
    "no_active_checks": {"--no-active-checks"},
    "verbose": {"-v", "--verbose"},
    "quiet": {"-q", "--quiet"},
    "vault_dir": {"--vault-dir"},
    "overwrite": {"--overwrite"},
}

_FORMAT_FLAGS: set[str] = {"--json", "--html", "--csv", "--sarif", "--all-formats"}
_VALID_FORMATS: set[str] = {"json", "html", "csv", "sarif"}
_VALID_SEVERITY: set[str] = {"critical", "high", "medium", "low"}


def _normalize_argv(argv: list[str]) -> set[str]:
    """Extract flag names from argv, handling --flag=value and -fvalue syntax.

    Args:
        argv: Command-line argument list.

    Returns:
        Set of flag tokens (e.g. {"--output", "-o", "--timeout"}).
    """
    flags: set[str] = set()
    for token in argv:
        if token.startswith("--"):
            flags.add(token.split("=")[0])
        elif token.startswith("-") and len(token) > 1:
            flags.add(token[:2])
    return flags


def load_config(config_path: str) -> dict[str, Any]:
    """Load and validate a YAML config file.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Dict of validated configuration values.

    Raises:
        ConfigError: If PyYAML is missing, file is not found, YAML is
            malformed, or schema validation fails.
    """
    try:
        import yaml
    except ImportError:
        raise ConfigError("PyYAML is required for config files. Install: pip install pyyaml") from None

    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Malformed YAML in config file: {e}") from e

    if not isinstance(data, dict):
        raise ConfigError(f"Config must be a YAML mapping at top level, got {type(data).__name__}")

    _validate_config(data)
    return data


def _validate_config(data: dict[str, Any]) -> None:
    """Validate config data against schema.

    Args:
        data: Raw config dict from YAML.

    Raises:
        ConfigError: On unknown field, type mismatch, or invalid value.
    """
    valid_fields = set(_CONFIG_SCHEMA)
    for key, value in data.items():
        if key not in valid_fields:
            raise ConfigError(f"Unknown config field: '{key}'. Valid fields: {sorted(valid_fields)}")
        expected_type = _CONFIG_SCHEMA[key]
        if expected_type is int and isinstance(value, bool):
            raise ConfigError(f"Config field '{key}' must be int, got bool")
        if not isinstance(value, expected_type):
            raise ConfigError(f"Config field '{key}' must be {expected_type.__name__}, " f"got {type(value).__name__}")
        if key == "formats":
            for item in cast(list[Any], value):
                if not isinstance(item, str) or item not in _VALID_FORMATS:
                    raise ConfigError(f"Unknown format in 'formats' field. Valid formats: {sorted(_VALID_FORMATS)}")
        if key == "severity_filter" and value not in _VALID_SEVERITY:
            raise ConfigError(f"Invalid value in 'severity_filter' field. Valid: {sorted(_VALID_SEVERITY)}")
        if (
            key in ("timeout", "rate_limit", "concurrency", "connect_timeout", "read_timeout")
            and isinstance(value, int)
            and value <= 0
        ):
            raise ConfigError(f"Config field '{key}' must be positive, got {value}")


def merge_config_into_args(
    args: argparse.Namespace,
    config: dict[str, Any],
    argv: list[str] | None = None,
) -> None:
    """Apply config values to args namespace with correct precedence.

    Precedence: argparse default < config < explicit CLI flag.
    A config field is applied only if the corresponding CLI flag was
    NOT explicitly present in argv.

    Args:
        args: Parsed argparse namespace (mutated in place).
        config: Validated config dict.
        argv: Command-line args list (defaults to sys.argv).
    """
    if argv is None:
        argv = sys.argv
    argv_set = _normalize_argv(argv)

    for field, value in config.items():
        if field == "formats":
            if not (_FORMAT_FLAGS & argv_set):
                for fmt in value:
                    setattr(args, fmt, True)
            continue

        cli_flags = _CONFIG_TO_CLI.get(field, set())
        if cli_flags & argv_set:
            continue

        setattr(args, field, value)
