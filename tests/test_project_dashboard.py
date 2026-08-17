"""Dashboard runtime and CLI tests."""

from __future__ import annotations

import json

from click.testing import CliRunner
from rich.console import Console

from depfence.cli.main import cli
from depfence.core.models import ScanResult
from depfence.core.project_dashboard import DashboardRuntime, RichSnapshotRenderer
from depfence.core.snapshot import JsonSnapshotStore, snapshot_from_result


class StaticSource:
    def __init__(self, result: ScanResult) -> None:
        self.result = result

    def refresh(self, previous=None):
        return snapshot_from_result(self.result, previous=previous)


def test_runtime_renders_once_and_persists_snapshot(tmp_path) -> None:
    result = ScanResult(target=str(tmp_path), ecosystem="pypi", packages_scanned=2)
    console = Console(record=True, width=100)
    runtime = DashboardRuntime(
        source=StaticSource(result),
        store=JsonSnapshotStore(tmp_path / "snapshot.json"),
        renderer=RichSnapshotRenderer(),
        console=console,
    )
    snapshot = runtime.render_once()
    output = console.export_text()
    assert snapshot.status.value == "PASS"
    assert "DepFence dashboard" in output
    assert "PASS" in output
    assert (tmp_path / "snapshot.json").exists()


def test_dashboard_json_cli_is_one_shot(monkeypatch, tmp_path) -> None:
    async def fake_scan_directory(*args, **kwargs):
        return ScanResult(target=str(tmp_path), ecosystem="pypi", packages_scanned=3)

    monkeypatch.setattr("depfence.core.engine.scan_directory", fake_scan_directory)
    snapshot_path = tmp_path / "out.json"
    result = CliRunner().invoke(
        cli,
        ["dashboard", str(tmp_path), "--json", "--offline", "--snapshot", str(snapshot_path)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "depfence.snapshot/v1"
    assert payload["status"] == "PASS"
    assert payload["mode"] == "offline"
    assert json.loads(snapshot_path.read_text())["scan_id"] == payload["scan_id"]


def test_dashboard_help_exposes_product_command_not_tart() -> None:
    result = CliRunner().invoke(cli, ["dashboard", "--help"])
    assert result.exit_code == 0
    assert "DepFence project security dashboard" in result.output
    assert "tart" not in result.output.lower()
