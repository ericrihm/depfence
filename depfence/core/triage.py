"""Private, append-only fleet evidence and operator triage records."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from depfence.core.local_state import PrivateState, PrivateStateError
from depfence.core.snapshot import redact_text
from depfence.schemas import validate_document

TRIAGE_SCHEMA_VERSION = "depfence.triage/v1"
TRIAGE_PLAN_SCHEMA_VERSION = "depfence.triage-plan/v1"
TRIAGE_REVIEW_SCHEMA_VERSION = "depfence.triage-review/v1"
FLEET_EVIDENCE_SCHEMA_VERSION = "depfence.fleet-evidence/v1"
FINDING_EVIDENCE_SCHEMA_VERSION = "depfence.finding-evidence/v1"
TRIAGE_QUEUE_SCHEMA_VERSION = "depfence.triage-queue/v1"
DECISIONS = {
    "unreviewed", "confirmed", "likely", "false_positive", "accepted_risk",
    "needs_context",
}
_MAX_RECORDS = 10_000
_MAX_RECORD_BYTES = 32 * 1024


def _json(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _canonical(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _safe_reason(reason: str) -> str:
    text = re.sub(r"(?<![\w.])/(?:[^\s'\"/]+/)*[^\s'\"]+", "[PATH]", reason)
    text = re.sub(r"(?i)\b[A-Z]:\\(?:[^\s'\"\\]+\\)*[^\s'\"]+", "[PATH]", text)
    return redact_text(text, limit=240)


def _validate_finding_id(value: str) -> None:
    if re.fullmatch(r"df-[0-9a-f]{20}", value) is None:
        raise ValueError("finding identifier is invalid")


def _validate_project_id(value: str) -> None:
    if re.fullmatch(r"project-hmac-sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("project identifier is invalid")


def triage_plan(
    *, project_id: str, decision: str, reason: str, finding_id: str | None,
    evidence_ids: tuple[str, ...],
) -> dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError("unsupported triage decision")
    _validate_project_id(project_id)
    if finding_id is not None:
        _validate_finding_id(finding_id)
    if any(
        re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", evidence_id) is None
        for evidence_id in evidence_ids
    ):
        raise ValueError("triage evidence identifier is invalid")
    document = {
        "schema_version": TRIAGE_PLAN_SCHEMA_VERSION,
        "mode": "dry-run",
        "status": "PASS",
        "project_id": project_id,
        "decision": decision,
        "reason": _safe_reason(reason),
        "finding_id": finding_id,
        "evidence_ids": sorted(set(evidence_ids)),
        "would_append": True,
    }
    validate_document(document)
    return document


@contextmanager
def _journal_lock(state: PrivateState) -> Iterator[None]:
    lock = state.path("triage/v1/.lock")
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(lock.parent, 0o700)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock, flags, 0o600)
    except FileExistsError as exc:
        raise PrivateStateError("triage journal is locked or requires recovery") from exc
    try:
        os.fchmod(descriptor, 0o600)
        yield
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)


def _read_records(state: PrivateState) -> list[dict[str, Any]]:
    directory = state.path("triage/v1/records")
    if not directory.exists():
        return []
    records: list[dict[str, Any]] = []
    paths = sorted(directory.glob("*.json"))
    if len(paths) > _MAX_RECORDS:
        raise PrivateStateError("triage journal exceeds the record budget")
    previous: str | None = None
    for expected, path in enumerate(paths, 1):
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or path.is_symlink() or path.stat().st_size > _MAX_RECORD_BYTES:
            raise PrivateStateError("triage journal contains an unsafe record")
        record = json.loads(path.read_text(encoding="utf-8"))
        validate_document(record)
        supplied = str(record.pop("record_hmac"))
        expected_hmac = state.opaque_id("triage_record", _canonical(record))
        record["record_hmac"] = supplied
        if record["sequence"] != expected or record["previous_hmac"] != previous:
            raise PrivateStateError("triage journal sequence or chain is invalid")
        if supplied != expected_hmac:
            raise PrivateStateError("triage journal authentication failed")
        expected_name = f"{expected:08d}-{supplied.rsplit(':', 1)[-1]}.json"
        if path.name != expected_name:
            raise PrivateStateError("triage journal record name is invalid")
        previous = supplied
        records.append(record)
    return records


def append_triage(
    state: PrivateState, *, project_id: str, decision: str, reason: str,
    finding_id: str | None = None, evidence_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    plan = triage_plan(
        project_id=project_id, decision=decision, reason=reason,
        finding_id=finding_id, evidence_ids=evidence_ids,
    )
    with _journal_lock(state):
        records = _read_records(state)
        record: dict[str, Any] = {
            "schema_version": TRIAGE_SCHEMA_VERSION,
            "journal_id": state.opaque_id("triage_journal", "v1"),
            "sequence": len(records) + 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "project_id": plan["project_id"],
            "finding_id": plan["finding_id"],
            "decision": plan["decision"],
            "reason": plan["reason"],
            "evidence_ids": plan["evidence_ids"],
            "previous_hmac": records[-1]["record_hmac"] if records else None,
        }
        record["record_hmac"] = state.opaque_id("triage_record", _canonical(record))
        validate_document(record)
        name = f"{record['sequence']:08d}-{str(record['record_hmac']).rsplit(':', 1)[-1]}.json"
        destination = state.path(Path("triage/v1/records") / name)
        if destination.exists():
            raise PrivateStateError("triage journal record already exists")
        state.write_text(Path("triage/v1/records") / name, _json(record))
        return record


def review_triage(state: PrivateState) -> dict[str, Any]:
    try:
        records = _read_records(state)
        errors: list[str] = []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, PrivateStateError) as exc:
        records = []
        errors = [f"triage journal unavailable ({type(exc).__name__})"]
    counts: dict[str, int] = {}
    for record in records:
        decision = str(record["decision"])
        counts[decision] = counts.get(decision, 0) + 1
    document = {
        "schema_version": TRIAGE_REVIEW_SCHEMA_VERSION,
        "status": "INDETERMINATE" if errors else "PASS",
        "records": len(records),
        "decisions": dict(sorted(counts.items())),
        "latest_hmac": records[-1]["record_hmac"] if records else None,
        "errors": errors,
    }
    validate_document(document)
    return document


def fleet_evidence(state: PrivateState, *, apply: bool) -> dict[str, Any]:
    latest = state.path("evidence/fleet-audit/latest.json")
    errors: list[str] = []
    projects: list[dict[str, Any]] = []
    audit_id: str | None = None
    root_id: str | None = None
    try:
        manifest = json.loads(latest.read_text(encoding="utf-8"))
        validate_document(manifest)
        audit_id = str(manifest["audit_id"])
        root_id = str(manifest["root_id"])
        entries = cast(list[dict[str, Any]], manifest["completed"])
        if len(entries) > _MAX_RECORDS:
            raise ValueError("fleet evidence exceeds the project budget")
        for entry in entries:
            raw = state.path(str(entry["checkpoint"])).read_bytes()
            if len(raw) > _MAX_RECORD_BYTES:
                raise ValueError("fleet checkpoint exceeds the size budget")
            checkpoint = json.loads(raw)
            validate_document(checkpoint)
            project = cast(dict[str, Any], checkpoint["project"])
            projects.append({
                "project_id": project["project_id"],
                "status": project["status"],
                "checkpoint_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "finding_ids": project["finding_ids"],
            })
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, PrivateStateError) as exc:
        errors.append(f"fleet evidence unavailable ({type(exc).__name__})")
    document = {
        "schema_version": FLEET_EVIDENCE_SCHEMA_VERSION,
        "mode": "apply" if apply else "dry-run",
        "status": "INDETERMINATE" if errors else "PASS",
        "audit_id": audit_id,
        "root_id": root_id,
        "projects": sorted(projects, key=lambda item: str(item["project_id"])),
        "errors": errors,
    }
    validate_document(document)
    if apply and not errors and audit_id is not None:
        name = audit_id.rsplit(":", 1)[-1]
        state.write_text(f"evidence/fleet-review/{name}.json", _json(document))
    return document


def finding_evidence(
    state: PrivateState, finding_id: str, *, show_snippet: bool = False
) -> dict[str, Any]:
    """Find one bounded private evidence item without exposing its source path."""
    _validate_finding_id(finding_id)
    found: dict[str, Any] | None = None
    evidence_id: str | None = None
    project_id: str | None = None
    errors: list[str] = []
    try:
        directory = state.path("evidence/documents")
        paths = sorted(directory.glob("*.json")) if directory.exists() else []
        if len(paths) > _MAX_RECORDS:
            raise ValueError("private evidence exceeds the document budget")
        for path in paths:
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise PrivateStateError("private evidence contains an unsafe document")
            if path.stat().st_size > _MAX_RECORD_BYTES:
                raise ValueError("private evidence document exceeds the size budget")
            document = json.loads(path.read_text(encoding="utf-8"))
            validate_document(document)
            for item in cast(list[dict[str, Any]], document["findings"]):
                if item.get("id") == finding_id:
                    if found is not None:
                        raise ValueError("finding identifier is ambiguous across evidence")
                    found = item
                    evidence_id = state.opaque_id("evidence", str(document["evidence_id"]))
                    project_id = str(document["project_id"])
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, PrivateStateError) as exc:
        errors.append(f"finding evidence unavailable ({type(exc).__name__})")
    if found is None and not errors:
        errors.append("finding evidence is not present")
    required_detail = {
        "evidence_class", "confidence", "location", "snippet", "snippet_status",
        "snippet_digest", "metadata_digest",
    }
    if found is not None and not required_detail.issubset(found):
        errors.append("finding evidence lacks the enriched review fields")
    result = {
        "schema_version": FINDING_EVIDENCE_SCHEMA_VERSION,
        "status": "INDETERMINATE" if errors else "PASS",
        "finding_id": finding_id,
        "evidence_id": evidence_id,
        "project_id": project_id,
        "evidence_class": found.get("evidence_class") if found else None,
        "confidence": found.get("confidence") if found else None,
        "location": found.get("location") if found else None,
        "evidence_digest": found.get("evidence_digest") if found else None,
        "snippet_status": found.get("snippet_status") if found else None,
        "snippet_digest": found.get("snippet_digest") if found else None,
        "metadata_digest": found.get("metadata_digest") if found else None,
        "snippet": found.get("snippet") if found and show_snippet else None,
        "errors": errors,
    }
    validate_document(result)
    return result


def triage_queue(
    state: PrivateState, *, severity: str | None = None, rule: str | None = None
) -> dict[str, Any]:
    """Build a finding-ID queue from redacted fleet checkpoints."""
    if rule is not None and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", rule) is None:
        raise ValueError("triage rule filter is invalid")
    evidence = fleet_evidence(state, apply=False)
    projects = cast(list[dict[str, Any]], evidence["projects"])
    queued: list[dict[str, Any]] = []
    for project in projects:
        # Fleet checkpoint evidence intentionally omits finding detail. Filters
        # are therefore conservative: without matching detail, do not claim a
        # finding meets the requested filter.
        if severity is not None or rule is not None:
            continue
        queued.extend(
            {"project_id": project["project_id"], "finding_id": finding_id}
            for finding_id in cast(list[str], project["finding_ids"])
        )
    errors = list(cast(list[str], evidence["errors"]))
    if (severity is not None or rule is not None) and projects:
        errors.append("checkpoint detail is insufficient to evaluate the requested filter")
    document = {
        "schema_version": TRIAGE_QUEUE_SCHEMA_VERSION,
        "status": "INDETERMINATE" if errors else "PASS",
        "filters": {"severity": severity, "rule": rule},
        "findings": sorted(queued, key=lambda item: (item["project_id"], item["finding_id"])),
        "errors": errors,
    }
    validate_document(document)
    return document


__all__ = [
    "append_triage", "finding_evidence", "fleet_evidence", "review_triage",
    "triage_plan", "triage_queue",
]
