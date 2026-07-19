"""
Plugin interface + auto-discovery.

Every scanner is a plugin. Dropping a new file into
bsen/scanners/windows/ or bsen/scanners/linux/ (or bsen/scanners/common/)
that defines a class inheriting ScannerPlugin is enough - no core
code needs to change. This satisfies the "plugins are automatically
discovered at startup, no core modification needed" requirement.
"""
from __future__ import annotations

import importlib
import pkgutil
import platform
import traceback
from abc import ABC, abstractmethod
from typing import Iterable

from bsen.core.models import ScanResult, now


class ScannerPlugin(ABC):
    """Base interface every scanner must implement."""

    #: Human-readable plugin name
    name: str = "unnamed"
    #: One of "system", "network", "security", "forensics", "threat_hunting", "hardening"
    category: str = "general"
    #: "windows", "linux", or "any"
    platform_supported: str = "any"
    #: MVP priority tag purely informational (1, 2, 3)
    priority: int = 1

    def supported_here(self) -> bool:
        current = "windows" if platform.system().lower().startswith("win") else "linux"
        return self.platform_supported in ("any", current)

    @abstractmethod
    def scan(self) -> ScanResult:
        """Run the scan and return a populated ScanResult. Must be read-only."""
        raise NotImplementedError

    def safe_scan(self) -> ScanResult:
        started = now()
        try:
            result = self.scan()
            return result
        except Exception as exc:  # noqa: BLE001 - plugins must never crash the whole run
            return ScanResult(
                plugin_name=self.name,
                category=self.category,
                platform=self.platform_supported,
                started_at=started,
                finished_at=now(),
                error=f"{exc}\n{traceback.format_exc(limit=3)}",
            )


def discover_plugins(packages: Iterable[str]) -> list[ScannerPlugin]:
    """Import every module under the given packages and instantiate any
    ScannerPlugin subclasses found. This is the auto-discovery mechanism."""
    plugins: list[ScannerPlugin] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            continue
        if not hasattr(pkg, "__path__"):
            continue
        for _, mod_name, is_pkg in pkgutil.iter_modules(pkg.__path__, prefix=pkg_name + "."):
            if is_pkg:
                continue
            try:
                mod = importlib.import_module(mod_name)
            except Exception:
                continue
            for attr in vars(mod).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, ScannerPlugin)
                    and attr is not ScannerPlugin
                ):
                    try:
                        instance = attr()
                    except Exception:
                        continue
                    if instance.supported_here():
                        plugins.append(instance)
    # de-duplicate by class identity in case of double-import
    seen = set()
    unique = []
    for p in plugins:
        key = (p.__class__.__module__, p.__class__.__name__)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique
