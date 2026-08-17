from __future__ import annotations

import os
import stat

import pytest

from depfence.core.fingerprint_store import FingerprintStore, FingerprintStoreError


def test_default_store_is_private_and_project_scoped(tmp_path) -> None:
    project_a = tmp_path / "a"
    project_b = tmp_path / "b"
    private = tmp_path / "private"
    project_a.mkdir()
    project_b.mkdir()
    store_a = FingerprintStore.open(project_root=project_a, private_root=private)
    store_b = FingerprintStore.open(project_root=project_b, private_root=private)
    subject = store_a.subject_id(kind="mcp_schema", source=".mcp.json", name="same")

    store_a.observe(
        kind="mcp_schema",
        project_id=store_a.project_id(project_a),
        subject_id=subject,
        digest="a" * 64,
        snapshot={"tools": []},
    )
    store_b.observe(
        kind="mcp_schema",
        project_id=store_b.project_id(project_b),
        subject_id=subject,
        digest="b" * 64,
        snapshot={"tools": []},
    )

    database = private / "fingerprints" / "fingerprints.sqlite3"
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
    assert store_a.statuses(
        kind="mcp_schema", project_id=store_a.project_id(project_a)
    )[0].observed_digest == "a" * 64
    assert store_b.statuses(
        kind="mcp_schema", project_id=store_b.project_id(project_b)
    )[0].observed_digest == "b" * 64


def test_symlink_database_is_refused(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    target = tmp_path / "target.sqlite3"
    target.write_text("")
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(FingerprintStoreError, match="symlink"):
        FingerprintStore.open(project_root=project, database_path=link)


def test_nonfinite_or_oversized_snapshot_is_refused(tmp_path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    store = FingerprintStore.open(
        project_root=project, private_root=tmp_path / "private"
    )
    identity = store.project_id(project)

    with pytest.raises(FingerprintStoreError, match="record fingerprint"):
        store.observe(
            kind="mcp_schema",
            project_id=identity,
            subject_id="subject",
            digest="a" * 64,
            snapshot={"bad": float("nan")},
        )
    with pytest.raises(FingerprintStoreError, match="size limit"):
        store.observe(
            kind="mcp_schema",
            project_id=identity,
            subject_id="subject",
            digest="a" * 64,
            snapshot={"large": "x" * (257 * 1024)},
        )


def test_database_permissions_are_repaired(tmp_path) -> None:
    project = tmp_path / "project"
    private = tmp_path / "private"
    project.mkdir()
    FingerprintStore.open(project_root=project, private_root=private)
    database = private / "fingerprints" / "fingerprints.sqlite3"
    os.chmod(database, 0o644)

    FingerprintStore.open(project_root=project, private_root=private)

    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_explicit_database_cannot_escape_private_state(tmp_path) -> None:
    project = tmp_path / "project"
    private = tmp_path / "private"
    project.mkdir()

    with pytest.raises(FingerprintStoreError, match="inside PrivateState"):
        FingerprintStore.open(
            project_root=project,
            private_root=private,
            database_path=tmp_path / "outside.sqlite3",
        )
