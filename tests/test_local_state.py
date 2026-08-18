"""Tests for private, machine-local state with explicit privacy boundary."""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from depfence.core.local_state import PrivateState, PrivateStateError


@contextmanager
def _resolved_tmpdir() -> Iterator[Path]:
    """Yield a resolved temp dir to avoid macOS /var → /private/var symlink."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d).resolve()


# -- Construction --


def test_open_creates_root_directory() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        root = Path(state) / "depfence-test-state"
        ps = PrivateState.open(project_root=project, root=root)
        assert ps.root.is_dir()
        assert oct(os.stat(ps.root).st_mode & 0o777) == "0o700"


def test_open_rejects_state_inside_project() -> None:
    with _resolved_tmpdir() as project:
        with pytest.raises(PrivateStateError, match="outside the project"):
            PrivateState.open(
                project_root=project,
                root=Path(project) / ".depfence",
            )


def test_open_rejects_symlink_in_path() -> None:
    with _resolved_tmpdir() as d:
        real = Path(d) / "real"
        real.mkdir()
        link = Path(d) / "link"
        link.symlink_to(real)
        with _resolved_tmpdir() as project:
            with pytest.raises(PrivateStateError, match="symlink"):
                PrivateState.open(project_root=project, root=link / "state")


# -- path() --


def test_path_returns_resolved_within_root() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        result: Path = ps.path("sub/file.txt")
        assert str(result).startswith(str(ps.root))


def test_path_rejects_absolute() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        with pytest.raises(PrivateStateError, match="relative"):
            ps.path("/etc/passwd")


def test_path_rejects_dotdot() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        with pytest.raises(PrivateStateError, match="relative"):
            ps.path("../escape")


# -- write/read --


def test_write_and_read_text() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        dest = ps.write_text("notes/memo.txt", "hello private world")
        assert dest.read_text() == "hello private world"
        assert oct(os.stat(dest).st_mode & 0o777) == "0o600"


def test_write_bytes_atomic() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        dest = ps.write_bytes("data.bin", b"\x00\x01\x02")
        assert dest.read_bytes() == b"\x00\x01\x02"


def test_write_refuses_symlink_target() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        # Create a symlink where the file would go
        target = ps.path("trap.txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        real = Path(state) / "real.txt"
        real.write_text("real")
        target.symlink_to(real)
        with pytest.raises(PrivateStateError, match="symlink"):
            ps.write_text("trap.txt", "should not work")


# -- opaque_id --


def test_opaque_id_is_stable() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        id1 = ps.opaque_id("test", "value")
        id2 = ps.opaque_id("test", "value")
        assert id1 == id2
        assert id1.startswith("test-hmac-sha256:")


def test_project_id_uses_project_namespace() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        pid: str = ps.project_id(project)
        assert pid.startswith("project-hmac-sha256:")


def test_opaque_id_rejects_invalid_namespace() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        with pytest.raises(PrivateStateError, match="namespace"):
            ps.opaque_id("INVALID", "value")


def test_opaque_id_different_values_produce_different_ids() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        id1 = ps.opaque_id("ns", "value1")
        id2 = ps.opaque_id("ns", "value2")
        assert id1 != id2


# -- install key --


def test_install_key_is_created_and_reused() -> None:
    with _resolved_tmpdir() as project, _resolved_tmpdir() as state:
        ps = PrivateState.open(project_root=project, root=state)
        # First call creates the key
        id1 = ps.opaque_id("test", "value")
        # Second call reuses it (stable)
        id2 = ps.opaque_id("test", "value")
        assert id1 == id2
        # Key file exists and is 32 bytes
        key_path = ps.path("install.key")
        assert key_path.exists()
        assert len(key_path.read_bytes()) == 32
        assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"
