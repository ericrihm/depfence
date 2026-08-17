from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from jsonschema import ValidationError

from depfence.core.advisory import (
    AdvisoryJournal,
    advisory_task,
    evidence_document,
    run_advisory,
)
from depfence.core.local_state import PrivateState
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, ScanState, Severity
from depfence.schemas import validate_document


class FakeAdapter:
    def submit(self, task: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "schema_version": "depfence.advisory-result/v1",
            "task_id": task["task_id"],
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "status": "INCOMPLETE",
            "claims": [],
            "citations": [],
            "uncertainties": ["No primary source was supplied."],
            "proposed_tests": ["Add a malicious firing fixture."],
            "remediation_options": [],
        }


def test_evidence_is_redacted_and_schema_valid(tmp_path: Path) -> None:
    project = tmp_path / "private-project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    result = ScanResult(
        target=str(project),
        ecosystem="file",
        findings=[
            Finding(
                finding_type=FindingType.SECRET_EXPOSED,
                severity=Severity.CRITICAL,
                package=PackageId("file", str(project / ".env")),
                title="Token at " + str(project / ".env"),
                detail="api_key=sk-abcdefghijklmnopqrstuvwxyz",
                confidence=0.73,
                metadata={"file": str(project / ".env"), "line": 7},
            )
        ],
        errors=["could not read " + str(project / "locked")],
        scanner_coverage={"secrets": ScanState.INDETERMINATE},
    )

    evidence = evidence_document(result, state=state, project_root=project)
    validate_document(evidence)
    rendered = str(evidence)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in rendered
    assert "api_key=[REDACTED]" in rendered
    assert evidence["status"] == "INDETERMINATE"
    assert str(project) not in rendered
    item = evidence["findings"][0]
    assert item["evidence_class"] == "secret"
    assert item["confidence"] == 0.73
    assert item["location"]["kind"] == "file"
    assert item["location"]["line"] == 7
    assert item["location"]["id"].startswith("location-hmac-sha256:")
    assert item["evidence_digest"].startswith("sha256:")
    assert item["snippet_digest"] == item["evidence_digest"]
    assert item["metadata_digest"].startswith("sha256:")
    assert item["snippet_status"] == "redacted"
    assert item["snippet"] == "api_key=[REDACTED]"


def test_advisory_is_audited_but_never_changes_assurance(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    task = advisory_task(
        role="adversarial_reviewer",
        risk="P0",
        objective="Challenge the suppression contract",
        evidence_ids=["run-1"],
    )

    result = run_advisory(task, adapter=FakeAdapter(), journal=AdvisoryJournal(state))

    assert result["status"] == "INCOMPLETE"
    assert state.path(f"advisory/tasks/{task['task_id']}.json").is_file()
    assert state.path(f"advisory/results/{task['task_id']}.json").is_file()
    assert state.path(f"advisory/tasks/{task['task_id']}.json").stat().st_mode & 0o077 == 0


def test_invalid_role_is_refused() -> None:
    with pytest.raises(ValueError, match="unsupported advisory role"):
        advisory_task(role="autonomous_fixer", risk="P0", objective="mutate", evidence_ids=[])


def test_evidence_v1_extension_remains_backward_compatible(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    result = ScanResult(
        target=str(project),
        ecosystem="file",
        findings=[
            Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.LOW,
                package=PackageId("file", "example"),
                title="Example",
                detail="Benign bounded evidence",
            )
        ],
    )
    evidence = evidence_document(result, state=state, project_root=project)
    for field in (
        "snippet", "snippet_status", "snippet_digest", "metadata_digest",
        "evidence_digest", "location", "confidence", "evidence_class"
    ):
        evidence["findings"][0].pop(field)

    validate_document(evidence)


def test_evidence_snippet_is_three_lines_and_320_utf8_bytes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    detail = "\n".join(["😀" * 100, "second", "third", "fourth"])
    result = ScanResult(
        target=str(project), ecosystem="file",
        findings=[Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.HIGH,
            package=PackageId("file", "example"),
            title="Bounded",
            detail=detail,
        )],
    )

    item = evidence_document(result, state=state, project_root=project)["findings"][0]

    assert len(item["snippet"].encode("utf-8")) <= 320
    assert len(item["snippet"].splitlines()) <= 3
    assert item["snippet_status"] == "truncated"
    assert item["snippet_digest"].startswith("sha256:")
    assert item["metadata_digest"].startswith("sha256:")


def test_malformed_private_adapter_response_is_refused(tmp_path: Path) -> None:
    class BadAdapter:
        def submit(self, task: Mapping[str, Any]) -> Mapping[str, Any]:
            return {"schema_version": "depfence.advisory-result/v1", "task_id": task["task_id"]}

    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "state")
    task = advisory_task(
        role="security_contracts", risk="P1", objective="review", evidence_ids=[]
    )
    with pytest.raises(ValidationError):
        run_advisory(task, adapter=BadAdapter(), journal=AdvisoryJournal(state))
