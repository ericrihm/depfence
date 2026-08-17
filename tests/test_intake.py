from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from depfence.core.intake import approve_intake, inspect_source
from depfence.core.local_state import PrivateState
from depfence.schemas import validate_document


def _source_repository(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
    (path / "README.md").write_text("safe fixture\n")
    (path / ".gitattributes").write_text("* -export-subst\n")
    subprocess.run(["git", "-C", str(path), "add", "README.md", ".gitattributes"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "fixture"], check=True)
    hooks = path / ".git" / "hooks"
    hook = hooks / "post-checkout"
    hook.write_text("#!/bin/sh\ntouch ../HOOK_RAN\n")
    hook.chmod(0o755)
    return path


def test_intake_does_not_checkout_or_run_hooks_and_is_schema_valid(tmp_path: Path) -> None:
    source = _source_repository(tmp_path / "source")
    state = PrivateState.open(project_root=source, root=tmp_path / "private")

    result = inspect_source(str(source), state=state)
    document = result.to_dict()

    validate_document(document)
    assert document["status"] == "PASS"
    assert not (source / "HOOK_RAN").exists()
    quarantine = state.path(f"intake/quarantine/{result.intake_id}")
    assert not (quarantine / "repository" / "README.md").exists()
    assert (quarantine / "tree" / "README.md").read_text() == "safe fixture\n"


def test_file_budget_is_unproven_and_cannot_be_approved(tmp_path: Path) -> None:
    source = _source_repository(tmp_path / "source")
    state = PrivateState.open(project_root=source, root=tmp_path / "private")
    result = inspect_source(str(source), state=state, file_budget=1)

    assert result.status.value == "UNPROVEN"
    assert any("file intake budget" in error for error in result.errors)
    record = state.path(f"intake/records/{result.intake_id}.json")
    assert json.loads(record.read_text())["status"] == "UNPROVEN"
    with pytest.raises(ValueError, match="only a complete"):
        approve_intake(result.intake_id, state=state, approved_by="operator", reason="reviewed")


def test_approval_records_decision_but_does_not_promote(tmp_path: Path) -> None:
    source = _source_repository(tmp_path / "source")
    state = PrivateState.open(project_root=source, root=tmp_path / "private")
    result = inspect_source(str(source), state=state)

    approval_path = approve_intake(
        result.intake_id, state=state, approved_by="operator", reason="reviewed fixtures"
    )
    approval = json.loads(approval_path.read_text())
    assert approval["promotes_automatically"] is False
    assert approval["commit"] == result.commit
    assert approval_path.stat().st_mode & 0o077 == 0
