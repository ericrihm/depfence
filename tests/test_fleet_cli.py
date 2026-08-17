from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from depfence.cli.fleet_commands import fleet


def test_empty_fleet_is_unproven_exit_two_and_schema_valid(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "fleet"
    root.mkdir()

    result = CliRunner().invoke(fleet, ["inventory", str(root)])

    assert result.exit_code == 2
    document = json.loads(result.output)
    assert document["schema_version"] == "depfence.fleet/v1"
    assert document["status"] == "UNPROVEN"
    assert str(root) not in result.output


def test_output_is_atomic_owner_only_and_does_not_follow_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "fleet"
    root.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("preserve me", encoding="utf-8")
    output = tmp_path / "fleet.json"
    try:
        output.symlink_to(victim)
    except OSError:
        return

    result = CliRunner().invoke(fleet, ["inventory", str(root), "-o", str(output)])

    assert result.exit_code == 2
    assert victim.read_text(encoding="utf-8") == "preserve me"
    assert not output.is_symlink()
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "UNPROVEN"
    assert output.stat().st_mode & 0o777 == 0o600
    assert not any(path.name.startswith(".fleet.json.") for path in tmp_path.iterdir())
