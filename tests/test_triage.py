from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path

from click.testing import CliRunner

from depfence.cli.fleet_commands import fleet
from depfence.core.fleet import audit_fleet
from depfence.core.local_state import PrivateState
from depfence.core.models import (
    Finding,
    FindingType,
    PackageId,
    ScanResult,
    ScanState,
    Severity,
)
from depfence.core.triage import (
    append_triage,
    fleet_evidence,
    review_triage,
    triage_plan,
    triage_queue,
)
from depfence.schemas import validate_document


def _repo(path: Path) -> Path:
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
    return path


def _seed_finding_evidence(
    state: PrivateState, project_id: str, finding_id: str
) -> None:
    document = {
        "schema_version": "depfence.evidence/v1",
        "evidence_id": "evidence-1",
        "created_at": "2026-08-16T00:00:00+00:00",
        "project_id": project_id,
        "classification": "redacted-private",
        "status": "FAIL",
        "source_digest": "sha256:" + "1" * 64,
        "coverage": {"complete": True, "scanners": {}, "errors": [], "scanner_errors": {}},
        "findings": [{
            "id": finding_id,
            "rule": "secret_exposed",
            "severity": "critical",
            "title": "Secret exposed",
            "summary": "token=[REDACTED]",
            "snippet": "token=[REDACTED]",
            "snippet_status": "redacted",
            "snippet_digest": "sha256:" + "2" * 64,
            "metadata_digest": "sha256:" + "4" * 64,
            "evidence_digest": "sha256:" + "2" * 64,
            "location": {"kind": "file", "id": "location-hmac-sha256:" + "3" * 64},
            "confidence": 0.9,
            "evidence_class": "secret",
        }],
    }
    validate_document(document)
    state.write_text("evidence/documents/evidence-1.json", json.dumps(document))


def test_triage_journal_is_chained_redacted_and_owner_only(tmp_path: Path) -> None:
    project = tmp_path / "private-project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    project_id = state.project_id(project)

    first = append_triage(
        state,
        project_id=project_id,
        finding_id="df-0123456789abcdef0123",
        decision="confirmed",
        reason=f"token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 at {project / '.env'}",
        evidence_ids=("evidence-2", "evidence-1", "evidence-1"),
    )
    second = append_triage(
        state,
        project_id=project_id,
        decision="needs_context",
        reason="Awaiting offline reproduction",
    )

    validate_document(first)
    validate_document(second)
    assert second["sequence"] == 2
    assert second["previous_hmac"] == first["record_hmac"]
    assert first["evidence_ids"] == ["evidence-1", "evidence-2"]
    assert str(project) not in json.dumps(first)
    assert "ghp_" not in json.dumps(first)
    assert "[PATH]" in first["reason"]
    review = review_triage(state)
    assert review["status"] == "PASS"
    assert review["records"] == 2
    for path in state.path("triage/v1/records").glob("*.json"):
        assert path.stat().st_mode & 0o777 == 0o600


def test_tampered_triage_record_is_named_incomplete_without_detail(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    append_triage(
        state,
        project_id=state.project_id(project),
        decision="confirmed",
        reason="benign",
    )
    record_path = next(state.path("triage/v1/records").glob("*.json"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["reason"] = "attacker secret detail"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    review = review_triage(state)

    assert review["status"] == "INDETERMINATE"
    assert review["records"] == 0
    assert "attacker secret detail" not in json.dumps(review)


def test_fleet_evidence_digests_private_checkpoints_and_apply_is_explicit(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fleet"
    _repo(root / "secret-repository-name")
    state = PrivateState.open(project_root=root, root=tmp_path / "state")

    async def scanner(path: Path) -> ScanResult:
        return ScanResult(
            target=str(path), ecosystem="npm", packages_scanned=1,
            findings=[Finding(
                finding_type=FindingType.SECRET_EXPOSED,
                severity=Severity.CRITICAL,
                package=PackageId("file", "redacted"),
                title="Secret exposed",
                detail="token=[REDACTED]",
            )],
            scanner_coverage={"test": ScanState.PASS},
        )

    asyncio.run(audit_fleet(root, state=state, scanner=scanner))
    dry_run = fleet_evidence(state, apply=False)

    validate_document(dry_run)
    assert dry_run["status"] == "PASS"
    assert dry_run["mode"] == "dry-run"
    assert len(dry_run["projects"]) == 1
    assert "secret-repository-name" not in json.dumps(dry_run)
    assert not state.path("evidence/fleet-review").exists()

    applied = fleet_evidence(state, apply=True)
    assert applied["mode"] == "apply"
    written = list(state.path("evidence/fleet-review").glob("*.json"))
    assert len(written) == 1
    assert written[0].stat().st_mode & 0o777 == 0o600
    queue = triage_queue(state)
    assert queue["status"] == "PASS"
    assert len(queue["findings"]) == 1
    cli_queue = CliRunner().invoke(
        fleet, ["triage", str(root), "--state-root", str(state.root)]
    )
    assert cli_queue.exit_code == 0
    assert len(json.loads(cli_queue.output)["findings"]) == 1


def test_cli_review_is_dry_run_first_and_does_not_mutate_state(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state_root = tmp_path / "state"
    state = PrivateState.open(project_root=project, root=state_root)
    project_id = state.project_id(project)
    finding_id = "df-0123456789abcdef0123"
    _seed_finding_evidence(state, project_id, finding_id)
    before = {path.relative_to(state_root) for path in state_root.rglob("*")}

    result = CliRunner().invoke(
        fleet,
        [
            "review", finding_id, "--state-root", str(state_root),
            "--decision", "confirmed",
            "--reason", "review /private/secret token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        ],
    )

    assert result.exit_code == 0
    document = json.loads(result.output)
    validate_document(document)
    assert document["mode"] == "dry-run"
    assert document["would_append"] is True
    assert "[PATH]" in document["reason"]
    assert "ghp_" not in result.output
    assert before == {path.relative_to(state_root) for path in state_root.rglob("*")}

    applied = CliRunner().invoke(
        fleet,
        [
            "review", finding_id, "--state-root", str(state_root),
            "--decision", "confirmed", "--reason", "verified", "--apply",
        ],
    )
    assert applied.exit_code == 0
    assert json.loads(applied.output)["decision"] == "confirmed"
    assert review_triage(state)["records"] == 1


def test_cli_evidence_hides_snippet_unless_requested(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    finding_id = "df-0123456789abcdef0123"
    _seed_finding_evidence(state, state.project_id(project), finding_id)

    hidden = CliRunner().invoke(
        fleet, ["evidence", finding_id, "--state-root", str(state.root)]
    )
    shown = CliRunner().invoke(
        fleet, ["evidence", finding_id, "--state-root", str(state.root), "--show-snippet"]
    )

    assert hidden.exit_code == 0
    assert json.loads(hidden.output)["snippet"] is None
    assert json.loads(shown.output)["snippet"] == "token=[REDACTED]"


def test_cli_review_refuses_symlinked_private_state(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    root.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    linked = tmp_path / "linked-state"
    try:
        linked.symlink_to(victim, target_is_directory=True)
    except OSError:
        return

    result = CliRunner().invoke(
        fleet, [
            "evidence", "df-0123456789abcdef0123", "--state-root", str(linked)
        ]
    )

    assert result.exit_code == 2
    document = json.loads(result.output)
    assert document["status"] == "INDETERMINATE"
    assert str(victim) not in result.output


def test_cli_invalid_evidence_identifier_does_not_echo_raw_path(tmp_path: Path) -> None:
    root = tmp_path / "fleet"
    root.mkdir()
    raw = "/private/do-not-echo"
    result = CliRunner().invoke(
        fleet,
        [
            "evidence", raw,
        ],
    )

    assert result.exit_code != 0
    assert raw not in result.output


def test_triage_plan_rejects_malformed_public_identity() -> None:
    try:
        triage_plan(
            project_id="/raw/private/path",
            decision="accepted_risk",
            reason="benign",
            finding_id=None,
            evidence_ids=(),
        )
    except Exception:
        pass
    else:
        raise AssertionError("raw path project identity was accepted")


def test_triage_plan_rejects_path_as_evidence_identifier() -> None:
    project_id = "project-hmac-sha256:" + "b" * 64
    try:
        triage_plan(
            project_id=project_id,
            decision="confirmed",
            reason="benign",
            finding_id=None,
            evidence_ids=("/private/raw/path",),
        )
    except ValueError:
        pass
    else:
        raise AssertionError("raw path evidence identifier was accepted")
