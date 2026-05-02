"""Plugin registry — discovers and loads scanner/analyzer/reporter extensions.

Public scanners ship as entry points under depfence.scanners / depfence.analyzers /
depfence.reporters. Additional plugins are discovered from:
  1. Entry points (pip-installed packages)
  2. DEPFENCE_PLUGIN_PATH directories (colon-separated)
  3. ~/.depfence/plugins/ directory

This is the standard extensibility mechanism. Third-party and internal
extensions use the same interface.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import sys
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from depfence.core.models import Finding, PackageId, PackageMeta, ScanResult


@runtime_checkable
class Scanner(Protocol):
    name: str
    ecosystems: list[str]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]: ...


@runtime_checkable
class Analyzer(Protocol):
    name: str

    async def analyze(self, package: PackageMeta, source_path: Path | None) -> list[Finding]: ...


@runtime_checkable
class Reporter(Protocol):
    name: str
    format: str

    def render(self, result: ScanResult) -> str: ...


class PluginRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}
        self._analyzers: dict[str, Analyzer] = {}
        self._reporters: dict[str, Reporter] = {}
        self._hooks: dict[str, list[Any]] = {}

    def discover(self) -> None:
        self._load_entry_points()
        self._load_path_plugins()
        self._load_user_plugins()

    def _load_entry_points(self) -> None:
        for group, store in [
            ("depfence.scanners", self._scanners),
            ("depfence.analyzers", self._analyzers),
            ("depfence.reporters", self._reporters),
        ]:
            try:
                eps = importlib.metadata.entry_points(group=group)
            except TypeError:
                eps = importlib.metadata.entry_points().get(group, [])
            for ep in eps:
                try:
                    cls = ep.load()
                    instance = cls()
                    store[ep.name] = instance
                except Exception:
                    pass

    def _load_path_plugins(self) -> None:
        plugin_path = os.environ.get("DEPFENCE_PLUGIN_PATH", "")
        if not plugin_path:
            return
        for directory in plugin_path.split(":"):
            self._load_plugins_from_dir(Path(directory))

    def _load_user_plugins(self) -> None:
        user_dir = Path.home() / ".depfence" / "plugins"
        if user_dir.exists():
            self._load_plugins_from_dir(user_dir)

    def _load_plugins_from_dir(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
        for py_file in directory.glob("*.py"):
            module_name = f"depfence_plugin_{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    self._register_from_module(mod)
            except Exception:
                pass

    def _register_from_module(self, mod: Any) -> None:
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, type):
                try:
                    instance = obj()
                except Exception:
                    continue
                if isinstance(instance, Scanner):
                    self._scanners[instance.name] = instance
                elif isinstance(instance, Analyzer):
                    self._analyzers[instance.name] = instance
                elif isinstance(instance, Reporter):
                    self._reporters[instance.name] = instance

    def register_hook(self, event: str, callback: Any) -> None:
        self._hooks.setdefault(event, []).append(callback)

    async def fire_hook(self, event: str, **kwargs: Any) -> None:
        for cb in self._hooks.get(event, []):
            try:
                result = cb(**kwargs)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                pass

    @property
    def scanners(self) -> dict[str, Scanner]:
        return dict(self._scanners)

    @property
    def analyzers(self) -> dict[str, Analyzer]:
        return dict(self._analyzers)

    @property
    def reporters(self) -> dict[str, Reporter]:
        return dict(self._reporters)


_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        _registry.discover()
    return _registry
