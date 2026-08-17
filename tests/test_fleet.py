from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path

from depfence.core.fleet import audit_fleet, discover_worktrees, inventory_fleet
from depfence.core.local_state import PrivateState
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, ScanState, Severity
from depfence.schemas import validate_document


def _repo(path: Path, *, remote: str | None = None) -> Path:
    path.mkdir(parents=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "init", "--quiet", str(path)],
        check=True,
        env={
            **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )
    if remote:
        subprocess.run(
            ["git", "-C", str(path), "config", "--local", "remote.origin.url", remote],
            check=True,
            env={
                **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
        )
    return path


def test_inventory_is_private_schema_valid_and_does_not_emit_paths(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    repo = _repo(root / "secret-project", remote="https://github.com/example/project.git")
    (repo / "package-lock.json").write_text("{}")
    (repo / ".env.local").write_text("TOKEN=not-read-by-inventory")
    executable = repo / "tool.sh"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    document = inventory_fleet(root, state=state).to_dict()

    validate_document(document)
    rendered = str(document)
    assert "secret-project" not in rendered
    assert str(tmp_path) not in rendered
    assert "not-read-by-inventory" not in rendered
    assert document["summary"]["projects"] == 1
    assert document["projects"][0]["counts"]["lockfiles"] == 1


def test_discovery_budget_is_named_incomplete(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    _repo(root / "one")
    _repo(root / "two")
    projects, errors = discover_worktrees(root, max_projects=1)
    assert len(projects) == 1
    assert errors == ["fleet discovery reached the 1-project budget"]


def test_repository_without_origin_is_complete_negative_remote_evidence(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    _repo(root / "local-only")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    document = inventory_fleet(root, state=state).to_dict()

    assert document["status"] == "PASS"
    assert document["projects"][0]["remote"] == {"present": False, "host": None}
    assert document["projects"][0]["errors"] == []


def test_directory_symlinks_are_counted_but_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    project = _repo(root / "project")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".env.secret").write_text("not inspected")
    os.symlink(outside, project / "linked-directory")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    document = inventory_fleet(root, state=state).to_dict()
    counts = document["projects"][0]["counts"]

    assert counts["symlinks"] == 1
    assert counts["env_files"] == 0


def test_audit_is_per_project_and_timeout_is_not_pass(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    good = _repo(root / "good")
    slow = _repo(root / "slow")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    async def scanner(path: Path) -> ScanResult:
        if path == slow:
            await asyncio.sleep(0.1)
        finding = Finding(
            finding_type=FindingType.UNPINNED,
            severity=Severity.HIGH,
            package=PackageId("npm", "example", "1.0.0"),
            title="Mutable dependency",
            detail="test",
        )
        return ScanResult(
            target=str(path),
            ecosystem="npm",
            packages_scanned=1,
            findings=[finding] if path == good else [],
            scanner_coverage={"test": ScanState.FAIL if path == good else ScanState.PASS},
        )

    document = asyncio.run(
        audit_fleet(root, workers=2, project_deadline=0.01, state=state, scanner=scanner)
    ).to_dict()

    validate_document(document)
    assert document["status"] == "INDETERMINATE"
    assert sorted(project["status"] for project in document["projects"]) == ["FAIL", "INDETERMINATE"]
    assert str(root) not in str(document)


def test_worktree_discovery_does_not_follow_symlink(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    root.mkdir()
    outside = _repo(tmp_path / "outside")
    os.symlink(outside, root / "escape")
    projects, errors = discover_worktrees(root)
    assert projects == []
    assert errors == []


def test_inventory_rejects_marker_only_directory_before_other_git_queries(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "fleet"
    project = root / "partial-recovery"
    (project / ".git").mkdir(parents=True)
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    calls: list[tuple[str, ...]] = []

    def unavailable(_project: Path, *arguments: str, timeout: float = 5.0):
        del timeout
        calls.append(arguments)
        return None, "git evidence unavailable (exit 128)"

    monkeypatch.setattr("depfence.core.fleet._safe_git", unavailable)
    document = inventory_fleet(root, state=state).to_dict()

    assert calls == [("rev-parse", "--is-inside-work-tree")]
    assert document["projects"][0]["coverage"] == "INDETERMINATE"
    assert "partial-recovery" not in str(document)


def test_audit_does_not_scan_marker_only_git_candidate(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    marker_only = root / "recovered"
    (marker_only / ".git").mkdir(parents=True)
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    calls: list[Path] = []

    async def scanner(path: Path) -> ScanResult:
        calls.append(path)
        return ScanResult(target=str(path), ecosystem="multi", packages_scanned=1)

    document = asyncio.run(audit_fleet(root, state=state, scanner=scanner)).to_dict()

    assert calls == []
    assert document["status"] == "INDETERMINATE"
    assert document["projects"][0]["status"] == "INDETERMINATE"
    assert "recovered" not in str(document)


def test_audit_worker_exception_is_named_incomplete(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    _repo(root / "broken")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    async def scanner(_path: Path) -> ScanResult:
        raise ValueError("private attacker-controlled detail")

    document = asyncio.run(audit_fleet(root, state=state, scanner=scanner)).to_dict()
    assert document["status"] == "INDETERMINATE"
    assert "private attacker-controlled detail" not in str(document)


def test_cancelled_audit_retains_redacted_completed_checkpoint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fleet"
    fast = _repo(root / "confidential-fast-name")
    _repo(root / "confidential-slow-name")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    fast_returned = asyncio.Event()

    async def scanner(path: Path) -> ScanResult:
        if path == fast:
            fast_returned.set()
            return ScanResult(
                target=str(path),
                ecosystem="npm",
                packages_scanned=1,
                findings=[
                    Finding(
                        finding_type=FindingType.SECRET_EXPOSED,
                        severity=Severity.CRITICAL,
                        package="file:private.env",
                        title="private title",
                        detail="private finding detail",
                    )
                ],
                errors=[f"sensitive detail at {path}"],
                scanner_coverage={"test": ScanState.INDETERMINATE},
                scanner_errors={"test": f"secret detail at {path}"},
            )
        await asyncio.sleep(60)
        raise AssertionError("unreachable")

    async def exercise() -> None:
        task = asyncio.create_task(
            audit_fleet(root, workers=2, state=state, scanner=scanner)
        )
        await fast_returned.wait()
        latest = state.path("evidence/fleet-audit/latest.json")
        for _ in range(100):
            manifest = json.loads(latest.read_text(encoding="utf-8"))
            if manifest["completed"]:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("completed project was not checkpointed")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("audit cancellation did not propagate")

    asyncio.run(exercise())

    manifest_path = state.path("evidence/fleet-audit/latest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_document(manifest)
    assert manifest["lifecycle"] == "INTERRUPTED"
    assert len(manifest["completed"]) == 1
    assert len(manifest["unfinished"]) == 1
    assert manifest["unfinished"][0]["status"] == "INDETERMINATE"
    assert "interrupted" in manifest["unfinished"][0]["cause"]

    checkpoint_path = state.path(manifest["completed"][0]["checkpoint"])
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    validate_document(checkpoint)
    rendered = json.dumps({"manifest": manifest, "checkpoint": checkpoint})
    assert "confidential-fast-name" not in rendered
    assert "confidential-slow-name" not in rendered
    assert "sensitive detail" not in rendered
    assert "secret detail" not in rendered
    assert "private finding detail" not in rendered
    assert checkpoint["project"]["summary"]["rules"] == {"secret_exposed": 1}
    assert checkpoint["project"]["summary"]["rule_severity"] == {
        "secret_exposed": {"critical": 1}
    }
    assert str(tmp_path) not in rendered
    assert checkpoint_path.stat().st_mode & 0o777 == 0o600
    assert manifest_path.stat().st_mode & 0o777 == 0o600


def test_interrupted_audit_resumes_only_unfinished_projects(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    fast = _repo(root / "fast")
    slow = _repo(root / "slow")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    fast_returned = asyncio.Event()

    async def first_scanner(path: Path) -> ScanResult:
        if path == fast:
            fast_returned.set()
            return ScanResult(
                target=str(path),
                ecosystem="multi",
                packages_scanned=1,
                scanner_coverage={"local": ScanState.PASS},
            )
        await asyncio.sleep(60)
        raise AssertionError("unreachable")

    async def interrupt_first_run() -> None:
        task = asyncio.create_task(
            audit_fleet(root, workers=2, state=state, scanner=first_scanner)
        )
        await fast_returned.wait()
        latest = state.path("evidence/fleet-audit/latest.json")
        for _ in range(100):
            manifest = json.loads(latest.read_text(encoding="utf-8"))
            if manifest["completed"]:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(interrupt_first_run())
    first_manifest = json.loads(
        state.path("evidence/fleet-audit/latest.json").read_text(encoding="utf-8")
    )
    calls: list[Path] = []

    async def resumed_scanner(path: Path) -> ScanResult:
        calls.append(path)
        return ScanResult(
            target=str(path),
            ecosystem="multi",
            packages_scanned=1,
            scanner_coverage={"local": ScanState.PASS},
        )

    resumed = asyncio.run(
        audit_fleet(root, state=state, scanner=resumed_scanner, resume=True)
    ).to_dict()
    final_manifest = json.loads(
        state.path("evidence/fleet-audit/latest.json").read_text(encoding="utf-8")
    )

    assert calls == [slow]
    assert len(resumed["projects"]) == 2
    assert resumed["status"] == "PASS"
    assert final_manifest["audit_id"] == first_manifest["audit_id"]
    assert final_manifest["created_at"] == first_manifest["created_at"]
    assert final_manifest["lifecycle"] == "COMPLETE"
    assert len(final_manifest["completed"]) == 2
    assert final_manifest["unfinished"] == []


def test_resume_replaces_positive_checkpoint_without_rule_severity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fleet"
    _repo(root / "project")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    finding = Finding(
        finding_type=FindingType.SECRET_EXPOSED,
        severity=Severity.CRITICAL,
        package="file:secret",
        title="Secret",
        detail="redacted",
    )

    async def initial_scanner(path: Path) -> ScanResult:
        return ScanResult(
            target=str(path),
            ecosystem="multi",
            packages_scanned=1,
            findings=[finding],
            scanner_coverage={"local": ScanState.FAIL},
        )

    asyncio.run(audit_fleet(root, state=state, scanner=initial_scanner))
    manifest_path = state.path("evidence/fleet-audit/latest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checkpoint_path = state.path(manifest["completed"][0]["checkpoint"])
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    del checkpoint["project"]["summary"]["rule_severity"]
    state.write_text(
        manifest["completed"][0]["checkpoint"],
        json.dumps(checkpoint, sort_keys=True, indent=2) + "\n",
    )
    calls = 0

    async def interrupted_replacement(_path: Path) -> ScanResult:
        nonlocal calls
        calls += 1
        await asyncio.sleep(60)
        raise AssertionError("unreachable")

    document = asyncio.run(
        audit_fleet(
            root,
            state=state,
            scanner=interrupted_replacement,
            resume=True,
            fleet_deadline=0.05,
        )
    ).to_dict()
    updated = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert calls == 1
    assert document["status"] == "INDETERMINATE"
    assert updated["completed"] == []
    assert len(updated["unfinished"]) == 1


def test_explicit_project_selection_leaves_other_projects_named_unfinished(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fleet"
    selected = _repo(root / "selected")
    _repo(root / "not-selected")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")
    selected_id = state.project_id(selected)
    calls: list[Path] = []

    async def scanner(path: Path) -> ScanResult:
        calls.append(path)
        return ScanResult(
            target=str(path),
            ecosystem="multi",
            packages_scanned=1,
            scanner_coverage={"local": ScanState.PASS},
        )

    document = asyncio.run(
        audit_fleet(
            root,
            state=state,
            scanner=scanner,
            project_ids=frozenset({selected_id}),
        )
    ).to_dict()
    manifest = json.loads(
        state.path("evidence/fleet-audit/latest.json").read_text(encoding="utf-8")
    )

    assert calls == [selected]
    assert document["status"] == "INDETERMINATE"
    assert len(document["projects"]) == 2
    assert manifest["lifecycle"] == "INTERRUPTED"
    assert len(manifest["completed"]) == 1
    assert len(manifest["unfinished"]) == 1


def test_fleet_summary_distinguishes_timeout_and_offline_policy(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    _repo(root / "project")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    async def scanner(path: Path) -> ScanResult:
        return ScanResult(
            target=str(path),
            ecosystem="multi",
            packages_scanned=1,
            errors=["Scanner remote timed out"],
            scanner_coverage={
                "local": ScanState.PASS,
                "remote": ScanState.INDETERMINATE,
                "advisory": ScanState.INDETERMINATE,
            },
            scanner_errors={
                "remote": "TimeoutError: timed out after 1s",
                "advisory": "network-required scanner disabled by offline policy",
            },
        )

    document = asyncio.run(audit_fleet(root, state=state, scanner=scanner)).to_dict()
    coverage = document["projects"][0]["coverage"]

    assert coverage["reasons"] == {
        "advisory": "disabled_by_policy",
        "local": "evaluated",
        "remote": "timed_out",
    }
    assert coverage["reason_counts"] == {
        "disabled_by_policy": 1,
        "evaluated": 1,
        "timed_out": 1,
    }


def test_aggregate_deadline_returns_durable_partial_evidence(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    fast = _repo(root / "fast")
    _repo(root / "slow")
    state = PrivateState.open(project_root=root, root=tmp_path / "private")

    async def scanner(path: Path) -> ScanResult:
        if path != fast:
            await asyncio.sleep(60)
        return ScanResult(
            target=str(path),
            ecosystem="multi",
            packages_scanned=1,
            scanner_coverage={"local": ScanState.PASS},
        )

    document = asyncio.run(
        audit_fleet(
            root,
            workers=2,
            project_deadline=120,
            fleet_deadline=0.1,
            state=state,
            scanner=scanner,
        )
    ).to_dict()
    manifest = json.loads(
        state.path("evidence/fleet-audit/latest.json").read_text(encoding="utf-8")
    )

    assert document["status"] == "INDETERMINATE"
    assert document["coverage"]["errors"] == [
        "fleet audit reached its aggregate deadline"
    ]
    assert sorted(project["status"] for project in document["projects"]) == [
        "INDETERMINATE",
        "PASS",
    ]
    timed_out = next(
        project for project in document["projects"] if project["status"] == "INDETERMINATE"
    )
    assert timed_out["coverage"]["reasons"] == {"fleet": "timed_out"}
    assert manifest["lifecycle"] == "INTERRUPTED"
    assert len(manifest["completed"]) == 1
    assert len(manifest["unfinished"]) == 1
