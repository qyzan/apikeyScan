"""Plugin auto-discovery module for dynamic scanner loading.

Discovers and loads all scanner classes from the scanners/ directory
without requiring manual imports in __init__.py.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from core.base_scanner import BaseScanner


def load_scanners() -> Dict[str, Type[BaseScanner]]:
    """Dynamically discover and load all scanner classes from scanners/ dir.

    Returns:
        Dict mapping provider names to scanner classes.
    """
    scanners: Dict[str, Type[BaseScanner]] = {}
    scanners_dir = Path(__file__).parent.parent / "scanners"

    for _finder, name, _ in pkgutil.iter_modules([str(scanners_dir)]):
        if not name.endswith("_scanner"):
            continue
        try:
            module = importlib.import_module(f"scanners.{name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseScanner) and attr.__name__ != "BaseScanner":
                    provider = getattr(attr, "PROVIDER_NAME", attr.__name__.replace("Scanner", "").lower())
                    scanners[provider] = attr
        except ImportError:
            continue
    return scanners


def get_scanner_class(provider: str) -> Type[BaseScanner]:
    """Get a scanner class by provider name.

    Args:
        provider: The provider name (e.g., 'google', 'github').

    Returns:
        The scanner class for the given provider.

    Raises:
        ValueError: If the provider is not found.
    """
    scanners = load_scanners()
    scanner_class = scanners.get(provider)
    if not scanner_class:
        raise ValueError(f"Unknown provider: {provider}. Available: {list(scanners.keys())}")
    return scanner_class


def get_scanner(provider: str, api_key: str, **kwargs: Any) -> BaseScanner:
    """Instantiate a scanner for the given provider.

    Args:
        provider: The provider name.
        api_key: The API key to scan.
        **kwargs: Additional scanner constructor arguments.

    Returns:
        An instantiated scanner object.

    Raises:
        ValueError: If the provider is not found.
    """
    scanner_class = get_scanner_class(provider)
    return scanner_class(api_key, **kwargs)


def list_providers() -> List[str]:
    """List all available provider names.

    Returns:
        Sorted list of provider name strings.
    """
    return sorted(load_scanners().keys())


def list_checks(provider: Optional[str] = None) -> Dict[str, List[str]]:
    """List available checks for one or all providers.

    Args:
        provider: Optional provider name to filter by. If None, lists all.

    Returns:
        Dict mapping provider names to lists of check descriptions.
    """
    scanners = load_scanners()
    if provider:
        cls = scanners.get(provider)
        if cls:
            return {provider: getattr(cls, "CHECKS", [])}
        return {}
    return {p: getattr(cls, "CHECKS", []) for p, cls in sorted(scanners.items())}
