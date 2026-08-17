"""Contract tests for the canonical shipped-scanner catalog."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from depfence.core import registry as registry_module
from depfence.core.engine import _merge_scanner_coverage
from depfence.core.fetcher import set_fetch_enabled
from depfence.core.models import Finding, ScanState
from depfence.core.registry import (
    SCANNER_PROFILES,
    SHIPPED_SCANNERS,
    PluginRegistry,
    ShippedScannerSpec,
    run_shipped_project_scanners,
)
from depfence.core.scan_scope import ScanScope


class GoodProjectScanner:
    async def scan_project(self, _scope: ScanScope) -> list[Finding]:
        return []


class BrokenProjectScanner:
    async def scan_project(self, _scope: ScanScope) -> list[Finding]:
        raise RuntimeError("fixture failure")


class HangingProjectScanner:
    async def scan_project(self, _scope: ScanScope) -> list[Finding]:
        await asyncio.sleep(1)
        return []


def test_catalog_declares_every_project_capability_truthfully() -> None:
    names = [spec.name for spec in SHIPPED_SCANNERS]
    assert len(names) == len(set(names))
    assert "agent_skill" in names

    for spec in SHIPPED_SCANNERS:
        scanner = spec.load()
        assert spec.project is hasattr(scanner, "scan_project"), spec.name
        if spec.package:
            assert hasattr(scanner, "scan"), spec.name

    advisory_names = {spec.name for spec in SHIPPED_SCANNERS if spec.advisory}
    assert advisory_names == {"npm_advisory", "pypi_advisory", "osv"}


def test_named_profiles_are_catalog_subsets_with_expected_boundaries() -> None:
    catalog = {spec.name for spec in SHIPPED_SCANNERS}
    assert SCANNER_PROFILES["full"] == catalog
    assert set(SCANNER_PROFILES) == {"full", "advisory", "ai", "mcp", "ci", "model"}
    assert all(names <= catalog for names in SCANNER_PROFILES.values())
    assert SCANNER_PROFILES["mcp"] == {"agent_skill", "mcp_fingerprint", "mcp_scanner"}
    assert "prompt_injection" in SCANNER_PROFILES["ai"]
    assert "gha_workflow" in SCANNER_PROFILES["ci"]


def test_packaged_scanner_entry_points_match_runtime_catalog() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    section = pyproject.split('[project.entry-points."depfence.scanners"]', 1)[1]
    section = section.split("\n[", 1)[0]
    packaged = {
        name.strip(): target.strip().strip('"')
        for line in section.splitlines()
        if "=" in line
        for name, target in [line.split("=", 1)]
    }
    runtime = {spec.name: spec.target for spec in SHIPPED_SCANNERS}
    assert packaged == runtime


def test_incomplete_lane_cannot_be_overwritten_by_later_pass() -> None:
    coverage = {"mixed": ScanState.INDETERMINATE}
    _merge_scanner_coverage(coverage, {"mixed": ScanState.PASS})
    assert coverage["mixed"] == ScanState.INDETERMINATE


@pytest.mark.asyncio
async def test_project_runner_names_failures_and_continues(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    specs = (
        ShippedScannerSpec(
            "good", f"{__name__}:GoodProjectScanner", package=False, project=True
        ),
        ShippedScannerSpec(
            "broken", f"{__name__}:BrokenProjectScanner", package=False, project=True
        ),
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", specs)
    registry = PluginRegistry()
    registry._scanners = {  # noqa: SLF001
        "good": GoodProjectScanner(),
        "broken": BrokenProjectScanner(),
    }

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert {run.name for run in runs} == {"good", "broken"}
    assert next(run for run in runs if run.name == "good").status == ScanState.PASS
    broken = next(run for run in runs if run.name == "broken")
    assert broken.status == ScanState.INDETERMINATE
    assert "fixture failure" in (broken.error or "")


@pytest.mark.asyncio
async def test_network_required_project_scanner_is_indeterminate_offline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class MustNotRun:
        async def scan_project(self, _root: Path) -> list[Finding]:
            raise AssertionError("offline runner executed a network-only scanner")

    spec = ShippedScannerSpec(
        "remote",
        "unused:MustNotRun",
        package=False,
        project=True,
        requires_network=True,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"remote": MustNotRun()}  # noqa: SLF001
    set_fetch_enabled(False)
    try:
        runs = await run_shipped_project_scanners(registry, tmp_path)
    finally:
        set_fetch_enabled(True)

    assert runs[0].status == ScanState.INDETERMINATE
    assert "offline policy" in (runs[0].error or "")


@pytest.mark.asyncio
async def test_project_runner_honors_advisory_exclusion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class MustNotRun:
        async def scan_project(self, _root: Path) -> list[Finding]:
            raise AssertionError("excluded advisory scanner ran")

    spec = ShippedScannerSpec(
        "osv",
        "unused:MustNotRun",
        package=False,
        project=True,
        advisory=True,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"osv": MustNotRun()}  # noqa: SLF001

    assert await run_shipped_project_scanners(
        registry,
        tmp_path,
        skip_advisory=True,
    ) == []


@pytest.mark.asyncio
async def test_project_runner_bounds_scanner_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    spec = ShippedScannerSpec(
        "hanging",
        f"{__name__}:HangingProjectScanner",
        package=False,
        project=True,
        timeout_seconds=0.5,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"hanging": HangingProjectScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.INDETERMINATE
    assert "TimeoutError" in (runs[0].error or "")


@pytest.mark.asyncio
async def test_hook_failure_is_returned_instead_of_silently_dropped() -> None:
    registry = PluginRegistry()

    def broken_hook(**_kwargs: object) -> None:
        raise ValueError("hook failure")

    registry.register_hook("post_scan", broken_hook)
    errors = await registry.fire_hook("post_scan", findings=[])

    assert len(errors) == 1
    assert "post_scan" in errors[0]
    assert "hook failure" in errors[0]
