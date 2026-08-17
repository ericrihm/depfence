from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from depfence.core.local_state import PrivateState, PrivateStateError


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_private_state_refuses_worktree_destination(tmp_path: Path):
    project = tmp_path / "repo"
    project.mkdir()
    with pytest.raises(PrivateStateError, match="outside the project worktree"):
        PrivateState.open(project_root=project, root=project / ".depfence" / "private")


def test_private_state_refuses_symlink_escape(tmp_path: Path):
    project = tmp_path / "repo"
    project.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(PrivateStateError, match="symlink"):
        PrivateState.open(project_root=project, root=link / "private")


def test_private_state_hardens_modes_and_writes_atomically(tmp_path: Path):
    project = tmp_path / "repo"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    path = state.write_text("evidence/fleet-audit/run/projects/result.json", "{}\n")
    assert path.read_text() == "{}\n"
    assert _mode(state.root) == 0o700
    current = state.root
    for part in path.parent.relative_to(state.root).parts:
        current /= part
        assert _mode(current) == 0o700
    assert _mode(path) == 0o600
    assert not list(path.parent.glob(f".{path.name}.*"))


def test_project_identifier_is_stable_opaque_and_key_is_private(tmp_path: Path):
    project = tmp_path / "customer-secret-repo"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    first = state.project_id(project)
    second = state.project_id(project)
    assert first == second
    assert str(project) not in first
    assert first.startswith("project-hmac-sha256:")
    assert _mode(state.path("install.key")) == 0o600
    assert str(project).encode() not in state.path("install.key").read_bytes()


def test_private_state_repairs_broad_existing_modes(tmp_path: Path):
    project = tmp_path / "repo"
    project.mkdir()
    root = tmp_path / "state"
    root.mkdir(mode=0o777)
    os.chmod(root, 0o777)  # noqa: S103 - deliberately simulate an unsafe pre-existing mode
    state = PrivateState.open(project_root=project, root=root)
    state.write_text("existing", "secret")
    os.chmod(state.path("existing"), 0o644)
    state.write_text("existing", "replacement")
    assert _mode(root) == 0o700
    assert _mode(state.path("existing")) == 0o600


def test_private_state_rejects_parent_traversal(tmp_path: Path):
    state = PrivateState.open(project_root=tmp_path / "repo", root=tmp_path / "state")
    with pytest.raises(PrivateStateError, match="relative"):
        state.write_text("../escape", "no")
