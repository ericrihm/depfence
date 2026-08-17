"""Versioned, secret-safe snapshots for DepFence consumers.

The snapshot is an interchange contract, not an attestation.  It records what a
local, user-owned scanner observed and uses the workspace's four-state verdict
vocabulary so an incomplete or empty scan can never be mistaken for a pass.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from depfence import __version__
from depfence.core.finding_identity import finding_id
from depfence.core.models import Finding, ScanResult, ScanState, Severity

SCHEMA_VERSION = "depfence.snapshot/v1"


class SnapshotVerdict(str, Enum):
    """Evidence-aware outcome for a completed snapshot."""

    PASS = "PASS"  # noqa: S105 - verdict vocabulary, not a credential
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    UNPROVEN = "UNPROVEN"


_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|password|secret)(\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def redact_text(value: object, *, limit: int = 240) -> str:
    """Return bounded display text with common credentials and controls removed."""

    text = _CONTROL_CHARS.sub("", str(value)).replace("\r", " ").replace("\n", " ")
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            text = pattern.sub(r"\1\2[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text[:limit]


@dataclass(frozen=True)
class SnapshotFinding:
    id: str
    finding_type: str
    severity: str
    package: str
    title: str
    cve: str | None = None
    fix_version: str | None = None

    @classmethod
    def from_finding(cls, finding: Finding) -> SnapshotFinding:
        return cls(
            id=finding_id(finding),
            finding_type=finding.finding_type.value,
            severity=finding.severity.value,
            package=redact_text(finding.package, limit=160),
            title=redact_text(finding.title),
            cve=redact_text(finding.cve, limit=80) if finding.cve else None,
            fix_version=redact_text(finding.fix_version, limit=80) if finding.fix_version else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "package": self.package,
            "title": self.title,
            "cve": self.cve,
            "fix_version": self.fix_version,
        }


@dataclass(frozen=True)
class SnapshotCoverage:
    completed: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed": list(self.completed),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
            "complete": not self.skipped and not self.errors,
        }


@dataclass(frozen=True)
class SnapshotDelta:
    new_finding_ids: tuple[str, ...] = ()
    resolved_finding_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_finding_ids": list(self.new_finding_ids),
            "resolved_finding_ids": list(self.resolved_finding_ids),
        }


@dataclass(frozen=True)
class DepFenceSnapshot:
    """The ``depfence.snapshot/v1`` local JSON contract."""

    scan_id: str
    created_at: str
    target: str
    depfence_version: str
    status: SnapshotVerdict
    mode: str
    packages_scanned: int
    severity_counts: Mapping[str, int]
    findings: tuple[SnapshotFinding, ...] = ()
    coverage: SnapshotCoverage = field(default_factory=SnapshotCoverage)
    delta: SnapshotDelta = field(default_factory=SnapshotDelta)
    reason: str = ""

    @property
    def safe(self) -> bool:
        """Legacy convenience value; only a proven PASS is safe."""

        return self.status is SnapshotVerdict.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "target": self.target,
            "depfence_version": self.depfence_version,
            "status": self.status.value,
            "reason": self.reason,
            "safe": self.safe,
            "mode": self.mode,
            "assurance": {
                "class": "local-scan/unauthenticated",
                "collector_runs_as": "invoking-user",
                "tamper_resistant": False,
            },
            "summary": {
                "packages_scanned": self.packages_scanned,
                "findings": len(self.findings),
                "severity": dict(self.severity_counts),
            },
            "coverage": self.coverage.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "delta": self.delta.to_dict(),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DepFenceSnapshot:
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported snapshot schema: {data.get('schema_version')!r}")
        summary = data.get("summary") or {}
        coverage = data.get("coverage") or {}
        delta = data.get("delta") or {}
        findings = tuple(
            SnapshotFinding(
                id=str(item["id"]),
                finding_type=str(item["finding_type"]),
                severity=str(item["severity"]),
                package=str(item["package"]),
                title=str(item["title"]),
                cve=item.get("cve"),
                fix_version=item.get("fix_version"),
            )
            for item in data.get("findings", ())
        )
        return cls(
            scan_id=str(data["scan_id"]),
            created_at=str(data["created_at"]),
            target=str(data["target"]),
            depfence_version=str(data.get("depfence_version", "unknown")),
            status=SnapshotVerdict(str(data["status"])),
            reason=str(data.get("reason", "")),
            mode=str(data.get("mode", "unknown")),
            packages_scanned=int(summary.get("packages_scanned", 0)),
            severity_counts={str(k): int(v) for k, v in (summary.get("severity") or {}).items()},
            findings=findings,
            coverage=SnapshotCoverage(
                completed=tuple(str(v) for v in coverage.get("completed", ())),
                skipped=tuple(str(v) for v in coverage.get("skipped", ())),
                errors=tuple(str(v) for v in coverage.get("errors", ())),
            ),
            delta=SnapshotDelta(
                new_finding_ids=tuple(str(v) for v in delta.get("new_finding_ids", ())),
                resolved_finding_ids=tuple(str(v) for v in delta.get("resolved_finding_ids", ())),
            ),
        )


def snapshot_from_result(
    result: ScanResult,
    *,
    offline: bool = False,
    previous: DepFenceSnapshot | None = None,
) -> DepFenceSnapshot:
    """Build a snapshot without treating errors or an empty corpus as clean."""

    findings = tuple(SnapshotFinding.from_finding(finding) for finding in result.findings)
    completed = tuple(sorted(
        name for name, state in result.scanner_coverage.items()
        if state in {ScanState.PASS, ScanState.FAIL}
    ))
    skipped = tuple(sorted(
        name for name, state in result.scanner_coverage.items()
        if state is ScanState.UNPROVEN
    ))
    incomplete = tuple(sorted(
        name for name, state in result.scanner_coverage.items()
        if state is ScanState.INDETERMINATE
    ))
    named_errors = [
        f"{redact_text(name, limit=100)}: {redact_text(message)}"
        for name, message in sorted(result.scanner_errors.items())
    ]
    errors = tuple(dict.fromkeys(
        [*(redact_text(error) for error in result.errors), *named_errors]
    ))
    if errors or incomplete or skipped:
        status = SnapshotVerdict.INDETERMINATE
        reason = "one or more scan stages could not be evaluated"
    elif findings:
        status = SnapshotVerdict.FAIL
        reason = "one or more security assertions did not hold"
    elif result.packages_scanned == 0:
        status = SnapshotVerdict.UNPROVEN
        reason = "the scan completed without an evaluated package corpus"
    else:
        status = SnapshotVerdict.PASS
        reason = "the evaluated assertions held for the scanned corpus"

    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    current_ids = {finding.id for finding in findings}
    previous_ids = {finding.id for finding in previous.findings} if previous else set()
    return DepFenceSnapshot(
        scan_id=str(uuid.uuid4()),
        created_at=(result.completed_at or datetime.now(timezone.utc)).isoformat(),
        target=str(Path(result.target).resolve()),
        depfence_version=__version__,
        status=status,
        reason=reason,
        mode="offline" if offline else "online",
        packages_scanned=result.packages_scanned,
        severity_counts=counts,
        findings=findings,
        coverage=SnapshotCoverage(
            completed=completed or (
                ("depfence-engine",)
                if not result.scanner_coverage and not errors
                else ()
            ),
            skipped=tuple(sorted((*skipped, *incomplete))),
            errors=errors,
        ),
        delta=SnapshotDelta(
            new_finding_ids=tuple(sorted(current_ids - previous_ids)),
            resolved_finding_ids=tuple(sorted(previous_ids - current_ids)),
        ),
    )


class JsonSnapshotStore:
    """Atomic local store; also serves as the future Tartifacts adapter boundary."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self) -> DepFenceSnapshot | None:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("snapshot root must be a JSON object")
        return DepFenceSnapshot.from_dict(data)

    def write(self, snapshot: DepFenceSnapshot) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(snapshot.to_json())
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
