"""Firing tests for scanner/plugin trust boundaries."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from depfence.core import registry as registry_module
from depfence.core.models import Finding, FindingType, ScanState, Severity
from depfence.core.registry import (
    PluginRegistry,
    ShippedScannerSpec,
    plugin_fingerprint,
    run_shipped_project_scanners,
)
from depfence.core.scan_scope import ScanScope


class BlockingScanner:
    async def scan_project(self, scope: ScanScope) -> list[Finding]:
        (scope.root / "worker.pid").write_text(str(os.getpid()))
        while True:
            time.sleep(1)


class ScopeAwareScanner:
    async def scan_project(self, scope: ScanScope) -> list[Finding]:
        if not isinstance(scope, ScanScope):
            raise TypeError("runner did not provide ScanScope")
        (scope.root / "scope-root").write_text(str(scope.root))
        return []


class LegacyPathScanner:
    async def scan_project(self, project_dir: object) -> list[Finding]:
        root = project_dir.resolve()  # type: ignore[attr-defined]
        if root != project_dir.root:  # type: ignore[attr-defined]
            raise TypeError("legacy path resolution changed")
        return []


class ResourceScanner:
    async def scan_project(self, _scope: ScanScope) -> list[Finding]:
        return [
            Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package="project:workflow.yml",
                title="project resource finding",
                detail="test",
            )
        ]


class SlowScanner:
    async def scan_project(self, _scope: ScanScope) -> list[Finding]:
        time.sleep(0.6)
        return []


class ExclusiveScanner:
    async def scan_project(self, scope: ScanScope) -> list[Finding]:
        marker = scope.root / "active-worker"
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            time.sleep(0.05)
        finally:
            os.close(descriptor)
            marker.unlink()
        return []


class BoundedReaderScanner:
    async def scan_project(self, scope: ScanScope) -> list[Finding]:
        scope.read_bytes("candidate.dat", max_bytes=64)
        return []


def _write_sentinel_plugin(directory: Path, sentinel: Path) -> Path:
    plugin = directory / "sentinel_plugin.py"
    plugin.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('FIRED')\n"
        "class SentinelScanner:\n"
        "    name = 'sentinel'\n"
        "    ecosystems = []\n"
        "    async def scan(self, packages): return []\n"
    )
    return plugin


def test_path_plugin_sentinel_does_not_fire_during_default_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = tmp_path / "sentinel-fired"
    _write_sentinel_plugin(tmp_path, sentinel)
    monkeypatch.setenv("DEPFENCE_PLUGIN_PATH", str(tmp_path))

    PluginRegistry().discover()

    assert not sentinel.exists()


def test_path_plugin_requires_opt_in_and_matching_fingerprint(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel-fired"
    plugin = _write_sentinel_plugin(tmp_path, sentinel)

    untrusted = PluginRegistry(enable_third_party=True, plugin_paths=[tmp_path])
    untrusted.discover()
    assert not sentinel.exists()
    assert any("fingerprint is not approved" in issue.error for issue in untrusted.issues)

    trusted = PluginRegistry(
        enable_third_party=True,
        plugin_paths=[tmp_path],
        trusted_plugin_fingerprints={plugin_fingerprint(plugin)},
    )
    trusted.discover()
    assert sentinel.read_text() == "FIRED"
    assert "sentinel" in trusted.scanners


def test_stopped_worker_releases_parent_process_resources() -> None:
    context = registry_module.multiprocessing.get_context("spawn")
    process = context.Process(target=time.sleep, args=(0,))
    process.start()
    process.join()

    registry_module._stop_worker(process)  # noqa: SLF001
    registry_module._stop_worker(process)  # noqa: SLF001

    with pytest.raises(ValueError, match="closed"):
        process.is_alive()


@pytest.mark.asyncio
async def test_mcp_symlink_escape_is_named_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-mcp.json"
    outside.write_text('{"mcpServers": {}}')
    try:
        (tmp_path / ".mcp.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    spec = ShippedScannerSpec(
        "mcp_scanner",
        "depfence.scanners.mcp_scanner:McpScanner",
        package=False,
        project=True,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._load_shipped_scanners()  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.INDETERMINATE
    assert "escapes project root" in (runs[0].error or "")


@pytest.mark.asyncio
async def test_malformed_mcp_config_is_named_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".mcp.json").write_text("{ definitely not JSON")
    spec = ShippedScannerSpec(
        "mcp_scanner",
        "depfence.scanners.mcp_scanner:McpScanner",
        package=False,
        project=True,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._load_shipped_scanners()  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.INDETERMINATE
    assert "malformed JSON" in (runs[0].error or "")


@pytest.mark.asyncio
async def test_blocking_project_scanner_process_is_killed_and_reaped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid_file = tmp_path / "worker.pid"

    spec = ShippedScannerSpec(
        "blocking",
        f"{__name__}:BlockingScanner",
        package=False,
        project=True,
        timeout_seconds=0.5,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"blocking": BlockingScanner()}  # noqa: SLF001

    started = time.monotonic()
    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert time.monotonic() - started < 2.0
    assert runs[0].status is ScanState.INDETERMINATE
    assert "timed out" in (runs[0].error or "")
    worker_pid = int(pid_file.read_text())
    assert all(child.pid != worker_pid for child in registry_module.multiprocessing.active_children())


@pytest.mark.asyncio
async def test_project_runner_passes_mandatory_scan_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "scope-root"
    spec = ShippedScannerSpec(
        "scoped", f"{__name__}:ScopeAwareScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"scoped": ScopeAwareScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.PASS
    assert marker.read_text() == str(tmp_path.resolve())


@pytest.mark.asyncio
async def test_scan_scope_preserves_legacy_path_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = ShippedScannerSpec(
        "legacy", f"{__name__}:LegacyPathScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"legacy": LegacyPathScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.PASS


@pytest.mark.asyncio
async def test_worker_preserves_project_resource_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = ShippedScannerSpec(
        "resource", f"{__name__}:ResourceScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"resource": ResourceScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.PASS
    assert runs[0].findings[0].package == "project:workflow.yml"


@pytest.mark.asyncio
async def test_inapplicable_scanner_is_skipped_before_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Inapplicable:
        def is_applicable(self, _scope: object) -> bool:
            return False

        async def scan_project(self, _scope: object) -> list[Finding]:
            raise AssertionError("inapplicable scanner worker was created")

    spec = ShippedScannerSpec(
        "inapplicable",
        "unused:Inapplicable",
        package=False,
        project=True,
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"inapplicable": Inapplicable()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.PASS
    assert runs[0].duration_ms < 20


@pytest.mark.asyncio
async def test_non_importable_scanner_is_named_unproven_without_process_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LocalScanner:
        async def scan_project(self, _scope: object) -> list[Finding]:
            return []

    spec = ShippedScannerSpec(
        "local", "missing_test_module:LocalScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"local": LocalScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.UNPROVEN
    assert "not importable" in (runs[0].error or "")


@pytest.mark.asyncio
async def test_fork_only_runtime_is_named_unproven_instead_of_used(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = ShippedScannerSpec(
        "scoped", f"{__name__}:ScopeAwareScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    monkeypatch.setattr(
        registry_module.multiprocessing,
        "get_all_start_methods",
        lambda: ["fork"],
    )
    registry = PluginRegistry()
    registry._scanners = {"scoped": ScopeAwareScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.UNPROVEN
    assert "no safe multiprocessing start method" in (runs[0].error or "")
    assert not (tmp_path / "scope-root").exists()


@pytest.mark.asyncio
async def test_project_runner_uses_one_aggregate_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = (
        ShippedScannerSpec(
            "slow-one",
            f"{__name__}:SlowScanner",
            package=False,
            project=True,
            timeout_seconds=2,
        ),
        ShippedScannerSpec(
            "slow-two",
            f"{__name__}:SlowScanner",
            package=False,
            project=True,
            timeout_seconds=2,
        ),
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", specs)
    registry = PluginRegistry()
    registry._scanners = {  # noqa: SLF001
        "slow-one": SlowScanner(),
        "slow-two": SlowScanner(),
    }

    started = time.monotonic()
    runs = await run_shipped_project_scanners(
        registry,
        tmp_path,
        max_workers=1,
        deadline_seconds=1.0,
    )

    assert time.monotonic() - started < 1.5
    assert runs[0].status is ScanState.PASS
    assert runs[1].status is ScanState.INDETERMINATE
    assert "timed out" in (runs[1].error or "")


@pytest.mark.asyncio
async def test_project_runner_never_exceeds_worker_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    specs = tuple(
        ShippedScannerSpec(
            name, f"{__name__}:ExclusiveScanner", package=False, project=True
        )
        for name in ("observed-one", "observed-two", "observed-three")
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", specs)
    registry = PluginRegistry()
    registry._scanners = {  # noqa: SLF001
        spec.name: ExclusiveScanner() for spec in specs
    }

    runs = await run_shipped_project_scanners(registry, tmp_path, max_workers=1)

    assert all(run.status is ScanState.PASS for run in runs)
    assert not (tmp_path / "active-worker").exists()


@pytest.mark.asyncio
async def test_oversized_scanner_input_is_named_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "candidate.dat").write_bytes(b"x" * 65)
    spec = ShippedScannerSpec(
        "bounded", f"{__name__}:BoundedReaderScanner", package=False, project=True
    )
    monkeypatch.setattr(registry_module, "SHIPPED_SCANNERS", (spec,))
    registry = PluginRegistry()
    registry._scanners = {"bounded": BoundedReaderScanner()}  # noqa: SLF001

    runs = await run_shipped_project_scanners(registry, tmp_path)

    assert runs[0].status is ScanState.INDETERMINATE
    assert "exceeds 64 byte limit" in (runs[0].error or "")
