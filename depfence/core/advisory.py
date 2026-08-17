"""Provider-neutral advisory envelopes for private model orchestration."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from depfence.core.finding_identity import finding_id
from depfence.core.local_state import PrivateState
from depfence.core.models import ScanResult, ScanState
from depfence.core.snapshot import redact_text
from depfence.schemas import validate_document

EVIDENCE_SCHEMA_VERSION = "depfence.evidence/v1"
TASK_SCHEMA_VERSION = "depfence.advisory-task/v1"
RESULT_SCHEMA_VERSION = "depfence.advisory-result/v1"

ADVISORY_ROLES = {
    "security_contracts",
    "integration_planner",
    "mechanical_release",
    "adversarial_reviewer",
}
RISK_TIERS = {"P0", "P1", "P2", "P3"}
PROHIBITED_ACTIONS = (
    "declare_assurance",
    "modify_host",
    "modify_repository",
    "rotate_credentials",
    "delete_data",
    "publish",
)


def _scan_status(result: ScanResult) -> ScanState:
    if result.errors or any(
        state in {ScanState.INDETERMINATE, ScanState.UNPROVEN}
        for state in result.scanner_coverage.values()
    ):
        return ScanState.INDETERMINATE
    if result.findings:
        return ScanState.FAIL
    return ScanState.PASS if result.packages_scanned else ScanState.UNPROVEN


def _redacted_evidence_text(value: object, project_root: Path, *, limit: int) -> str:
    text = str(value)
    project = str(project_root.expanduser().resolve(strict=False))
    home = str(Path.home().resolve(strict=False))
    text = text.replace(project, "[PROJECT]")
    if home and home != project:
        text = text.replace(home, "[HOME]")
    text = re.sub(r"(?<![\w.])/(?:[^\s'\"/]+/)*[^\s'\"]+", "[PATH]", text)
    text = re.sub(r"(?i)\b[A-Z]:\\(?:[^\s'\"\\]+\\)*[^\s'\"]+", "[PATH]", text)
    return cast(str, redact_text(text, limit=limit))


def _evidence_snippet(value: object, project_root: Path) -> tuple[str, str]:
    raw = str(value)
    lines = raw.splitlines()
    selected = lines[:3]
    redacted_lines = [
        _redacted_evidence_text(line, project_root, limit=320) for line in selected
    ]
    candidate = "\n".join(redacted_lines)
    encoded = candidate.encode("utf-8")
    byte_truncated = len(encoded) > 320
    if byte_truncated:
        candidate = encoded[:320].decode("utf-8", errors="ignore")
    if not candidate:
        status = "unavailable"
    elif len(lines) > 3 or byte_truncated:
        status = "truncated"
    elif "[REDACTED]" in candidate:
        status = "redacted"
    else:
        status = "available"
    return candidate, status


def evidence_document(
    result: ScanResult,
    *,
    state: PrivateState,
    project_root: Path,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Normalize a scan into a bounded envelope safe for private routing."""

    evidence_id = run_id or str(uuid.uuid4())
    findings = []
    for finding in result.findings:
        snippet, snippet_status = _evidence_snippet(finding.detail, project_root)
        raw_location = next(
            (
                finding.metadata.get(key)
                for key in ("location", "file", "path")
                if finding.metadata.get(key) is not None
            ),
            None,
        )
        location: dict[str, Any] = {"kind": "unknown"}
        if raw_location is not None:
            location = {
                "kind": "file",
                "id": state.opaque_id("location", str(raw_location)),
            }
        line = finding.metadata.get("line")
        if isinstance(line, int) and line > 0:
            location["line"] = line
        evidence_class = (
            "secret"
            if finding.finding_type.value == "secret_exposed"
            else "provenance"
            if "provenance" in finding.finding_type.value
            else "supply_chain"
            if getattr(finding.package, "ecosystem", "unknown") not in {"file", "git", "config"}
            else "static_analysis"
        )
        confidence = float(finding.confidence)
        if not math.isfinite(confidence):
            confidence = 0.0
        snippet_digest = "sha256:" + hashlib.sha256(snippet.encode("utf-8")).hexdigest()
        metadata_payload = json.dumps(
            finding.metadata, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        findings.append({
            "id": finding_id(finding),
            "rule": finding.finding_type.value,
            "severity": finding.severity.value,
            "title": _redacted_evidence_text(finding.title, project_root, limit=160),
            "summary": _redacted_evidence_text(finding.detail, project_root, limit=240),
            "snippet": snippet,
            "snippet_status": snippet_status,
            "snippet_digest": snippet_digest,
            "metadata_digest": "sha256:" + hashlib.sha256(metadata_payload).hexdigest(),
            "evidence_digest": snippet_digest,
            "location": location,
            "confidence": max(0.0, min(1.0, confidence)),
            "evidence_class": evidence_class,
        })
    coverage = {
        "complete": _scan_status(result) not in {ScanState.INDETERMINATE, ScanState.UNPROVEN},
        "scanners": {
            name: scan_state.value for name, scan_state in sorted(result.scanner_coverage.items())
        },
        "errors": [
            _redacted_evidence_text(error, project_root, limit=240) for error in result.errors
        ],
        "scanner_errors": {
            name: _redacted_evidence_text(error, project_root, limit=240)
            for name, error in sorted(result.scanner_errors.items())
        },
    }
    digest_payload = json.dumps(
        {"findings": findings, "coverage": coverage}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_id": evidence_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "project_id": state.project_id(project_root),
        "classification": "redacted-private",
        "status": _scan_status(result).value,
        "source_digest": "sha256:" + hashlib.sha256(digest_payload).hexdigest(),
        "coverage": coverage,
        "findings": findings,
    }


def advisory_task(
    *,
    role: str,
    risk: str,
    objective: str,
    evidence_ids: Sequence[str],
    time_budget_seconds: int = 900,
    max_output_tokens: int = 8_000,
    task_id: str | None = None,
) -> dict[str, Any]:
    if role not in ADVISORY_ROLES:
        raise ValueError(f"unsupported advisory role: {role}")
    if risk not in RISK_TIERS:
        raise ValueError(f"unsupported risk tier: {risk}")
    task = {
        "schema_version": TASK_SCHEMA_VERSION,
        "task_id": task_id or str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "risk": risk,
        "classification": "redacted-private",
        "objective": redact_text(objective, limit=500),
        "evidence_ids": sorted(set(evidence_ids)),
        "budget": {
            "time_seconds": max(1, time_budget_seconds),
            "max_output_tokens": max(1, max_output_tokens),
        },
        "required_deliverables": [
            "claims",
            "primary_source_citations",
            "uncertainties",
            "proposed_tests",
            "remediation_options",
        ],
        "prohibited_actions": list(PROHIBITED_ACTIONS),
    }
    validate_document(task)
    return task


class AdvisoryAdapter(Protocol):
    """Private adapters implement one request/response operation."""

    def submit(self, task: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class AdvisoryJournal:
    state: PrivateState

    def record_task(self, task: Mapping[str, Any]) -> Path:
        validate_document(dict(task))
        task_id = str(task["task_id"])
        return cast(Path, self.state.write_text(
            Path("advisory") / "tasks" / f"{task_id}.json",
            json.dumps(task, sort_keys=True, indent=2, allow_nan=False) + "\n",
        ))

    def record_result(self, result: Mapping[str, Any]) -> Path:
        validate_document(dict(result))
        task_id = str(result["task_id"])
        return cast(Path, self.state.write_text(
            Path("advisory") / "results" / f"{task_id}.json",
            json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n",
        ))


def run_advisory(
    task: Mapping[str, Any],
    *,
    adapter: AdvisoryAdapter,
    journal: AdvisoryJournal,
) -> dict[str, Any]:
    """Run an advisory task without allowing its result to alter assurance."""

    validate_document(dict(task))
    journal.record_task(task)
    response = dict(adapter.submit(task))
    validate_document(response)
    if response.get("task_id") != task.get("task_id"):
        raise ValueError("advisory response task_id does not match the request")
    journal.record_result(response)
    return response


__all__ = [
    "ADVISORY_ROLES",
    "EVIDENCE_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "TASK_SCHEMA_VERSION",
    "AdvisoryAdapter",
    "AdvisoryJournal",
    "advisory_task",
    "evidence_document",
    "run_advisory",
]
