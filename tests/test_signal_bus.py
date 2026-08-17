from __future__ import annotations

import json
import stat
from pathlib import Path

from depfence.core import signal_bus


def _use_queue(monkeypatch, tmp_path: Path) -> Path:
    queue = tmp_path / "private" / "signals" / "pending.jsonl"
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", str(queue))
    monkeypatch.chdir(tmp_path / "project")
    Path.cwd().mkdir(exist_ok=True)
    return queue


def test_signal_is_private_and_does_not_persist_path(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    queue = tmp_path / "private" / "signals" / "pending.jsonl"
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", str(queue))
    monkeypatch.chdir(project)
    sensitive = str(project / "customer-secret" / "workflow.yml")

    error = signal_bus.emit_signal(
        name="test",
        value={"count": 1},
        source="test",
        file_path=sensitive,
    )

    assert error is None
    raw = queue.read_text()
    assert sensitive not in raw
    assert "customer-secret" not in raw
    record = json.loads(raw)
    assert record["schema"] == "depfence.signal/v1"
    assert record["value"]["file_id"].startswith("path-hmac-sha256:")
    assert stat.S_IMODE(queue.stat().st_mode) == 0o600
    assert stat.S_IMODE(queue.parent.stat().st_mode) == 0o700


def test_relative_override_is_named_unproven(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", "pending.jsonl")

    error = signal_bus.emit_signal(name="test", value={}, source="test")

    assert error is not None
    assert "UNPROVEN" in error
    assert not (tmp_path / "pending.jsonl").exists()


def test_worktree_override_is_named_unproven(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", str(project / "pending.jsonl"))

    error = signal_bus.emit_signal(name="test", value={}, source="test")

    assert error is not None
    assert "UNPROVEN" in error
    assert not (project / "pending.jsonl").exists()


def test_queue_retention_is_bounded(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    queue = tmp_path / "private" / "pending.jsonl"
    monkeypatch.chdir(project)
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", str(queue))
    monkeypatch.setattr(signal_bus, "MAX_QUEUE_BYTES", 700)

    for index in range(20):
        assert signal_bus.emit_signal(
            name="test", value={"index": index, "padding": "x" * 50}, source="test"
        ) is None

    assert queue.stat().st_size <= 700
    records = [json.loads(line) for line in queue.read_text().splitlines()]
    assert records[-1]["value"]["index"] == 19


def test_nonfinite_signal_is_named_unproven(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    queue = tmp_path / "private" / "pending.jsonl"
    monkeypatch.chdir(project)
    monkeypatch.setenv("DEPFENCE_SIGNAL_BUS", str(queue))

    error = signal_bus.emit_signal(name="test", value={"bad": float("nan")}, source="test")

    assert error is not None
    assert "UNPROVEN" in error
    assert not queue.exists()
