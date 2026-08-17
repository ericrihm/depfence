"""Snapshot-driven Rich dashboard with an embeddable runtime seam."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from depfence.core.snapshot import (
    DepFenceSnapshot,
    JsonSnapshotStore,
    SnapshotVerdict,
    snapshot_from_result,
)


class SnapshotSource(Protocol):
    """Minimal refresh interface a future Tartifacts source can implement."""

    def refresh(self, previous: DepFenceSnapshot | None = None) -> DepFenceSnapshot: ...


class SnapshotRenderer(Protocol):
    """Renderer interface independent of the refresh/runtime implementation."""

    def render(self, snapshot: DepFenceSnapshot) -> RenderableType: ...


@dataclass
class ScanSnapshotSource:
    target: Path
    offline: bool = False

    def refresh(self, previous: DepFenceSnapshot | None = None) -> DepFenceSnapshot:
        from depfence.core.engine import scan_directory

        result = asyncio.run(
            scan_directory(
                self.target,
                fetch_metadata=not self.offline,
                enrich=not self.offline,
                project_scanners=True,
            )
        )
        return snapshot_from_result(result, offline=self.offline, previous=previous)


class RichSnapshotRenderer:
    _STATUS_STYLES = {
        SnapshotVerdict.PASS: "bold green",
        SnapshotVerdict.FAIL: "bold red",
        SnapshotVerdict.INDETERMINATE: "bold magenta",
        SnapshotVerdict.UNPROVEN: "bold yellow",
    }

    def render(self, snapshot: DepFenceSnapshot) -> RenderableType:
        status = Text(snapshot.status.value, style=self._STATUS_STYLES[snapshot.status])
        header = Table.grid(expand=True)
        header.add_column()
        header.add_column(justify="right")
        header.add_row(status, f"DepFence {snapshot.depfence_version} · {snapshot.mode}")
        header.add_row(snapshot.reason, snapshot.created_at)

        summary = Table(box=None, expand=True)
        summary.add_column("Packages", justify="right")
        for severity in ("critical", "high", "medium", "low", "info"):
            summary.add_column(severity.title(), justify="right")
        summary.add_row(
            str(snapshot.packages_scanned),
            *(str(snapshot.severity_counts.get(severity, 0)) for severity in ("critical", "high", "medium", "low", "info")),
        )

        findings = Table(expand=True)
        findings.add_column("Severity", width=10)
        findings.add_column("Package", ratio=1)
        findings.add_column("Finding", ratio=2)
        if snapshot.findings:
            for finding in snapshot.findings[:12]:
                findings.add_row(finding.severity.upper(), finding.package, finding.title)
        else:
            findings.add_row("—", "—", "No findings in the evaluated corpus")

        coverage = Text()
        if snapshot.coverage.errors:
            coverage.append(f"Incomplete: {len(snapshot.coverage.errors)} error(s)", style="magenta")
        elif snapshot.coverage.skipped:
            coverage.append(f"Incomplete: {len(snapshot.coverage.skipped)} stage(s) skipped", style="yellow")
        else:
            coverage.append("Coverage complete for declared scan stages", style="green")
        coverage.append(
            f" · new {len(snapshot.delta.new_finding_ids)} · resolved {len(snapshot.delta.resolved_finding_ids)}"
        )

        return Group(
            Panel(header, title="DepFence dashboard", subtitle=snapshot.target),
            Panel(summary, title="Current posture"),
            Panel(findings, title="Prioritized findings"),
            Panel(coverage, title="Coverage and delta"),
        )


@dataclass
class DashboardRuntime:
    """Small orchestration seam usable directly or replaceable by Tartifacts."""

    source: SnapshotSource
    store: JsonSnapshotStore
    renderer: SnapshotRenderer
    console: Console

    def refresh(self) -> DepFenceSnapshot:
        try:
            previous = self.store.read()
        except (OSError, ValueError, json.JSONDecodeError):
            previous = None
        snapshot = self.source.refresh(previous)
        self.store.write(snapshot)
        return snapshot

    def render_once(self) -> DepFenceSnapshot:
        snapshot = self.refresh()
        self.console.print(self.renderer.render(snapshot))
        return snapshot

    def render_json(self) -> DepFenceSnapshot:
        snapshot = self.refresh()
        self.console.print_json(snapshot.to_json())
        return snapshot

    def run(self, *, interval: float = 30.0) -> None:
        snapshot = self.refresh()
        with Live(
            self.renderer.render(snapshot),
            console=self.console,
            refresh_per_second=4,
            screen=False,
        ) as live:
            while True:
                time.sleep(interval)
                snapshot = self.refresh()
                live.update(self.renderer.render(snapshot), refresh=True)


@dataclass
class SharedDashboardRuntime:
    """Product-native wrapper around the optional shared artifact runtime."""

    runtime: Any
    console: Console

    def render_once(self) -> DepFenceSnapshot:
        self.runtime.refresh_now()
        output = self.runtime.render_once()
        self.console.file.write(output)
        self.console.file.flush()
        payload = self.runtime.render_json()
        return DepFenceSnapshot.from_dict(payload)

    def render_json(self) -> DepFenceSnapshot:
        self.runtime.refresh_now()
        payload = self.runtime.render_json()
        self.console.print_json(data=payload)
        return DepFenceSnapshot.from_dict(payload)

    def run(self, *, interval: float = 30.0) -> None:
        del interval  # configured in the immutable shared runtime specification
        self.runtime.run()


def build_dashboard_runtime(
    *,
    source: SnapshotSource,
    store: JsonSnapshotStore,
    renderer: SnapshotRenderer,
    console: Console,
    interval: float,
) -> DashboardRuntime | SharedDashboardRuntime:
    """Use the shared lifecycle when installed, with a standalone fallback."""

    try:
        from tartifacts import ArtifactRuntime, ArtifactSpec, RefreshPolicy
        from tartifacts import JsonSnapshotStore as SharedSnapshotStore
    except ImportError:
        return DashboardRuntime(source=source, store=store, renderer=renderer, console=console)

    shared_store = SharedSnapshotStore(store.path, schema_version="depfence.snapshot/v1")

    def refresh() -> dict[str, object]:
        try:
            previous = store.read()
        except (OSError, ValueError, json.JSONDecodeError):
            previous = None
        snapshot = source.refresh(previous)
        payload = snapshot.to_dict()
        shared_store.write(payload)
        return payload

    def render(state: dict[str, object], _console: Console) -> RenderableType:
        payload = state.get("snapshot")
        if not isinstance(payload, dict):
            return Panel("No snapshot is available yet", title="DepFence dashboard")
        return renderer.render(DepFenceSnapshot.from_dict(payload))

    spec = ArtifactSpec(
        title="DepFence project security",
        snapshot_source=shared_store,
        refresh=refresh,
        refresh_policy=RefreshPolicy(interval=interval, refresh_on_start=True),
        render=render,
        summary=lambda state: state.get("snapshot"),
    )
    return SharedDashboardRuntime(runtime=ArtifactRuntime(spec), console=console)
