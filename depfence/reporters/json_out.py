"""Versioned JSON scan reporters."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from depfence.core.finding_identity import finding_id
from depfence.core.models import Finding, ScanResult, ScanState, Severity
from depfence.core.scanner_outcome import materialize
from depfence.reporters.package_id import coerce_package_id

SCHEMA_VERSION = "depfence.scan/v1"


def _serialize(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):
        return obj.value  # type: ignore[union-attr]
    return str(obj)


def _finding(finding: Finding) -> dict[str, Any]:
    package = coerce_package_id(finding.package)
    return {
        "id": finding_id(finding),
        "finding_type": finding.finding_type.value,
        "severity": finding.severity.value,
        "package": {
            "ecosystem": package.ecosystem,
            "name": package.name,
            "version": package.version,
        },
        "title": finding.title,
        "detail": finding.detail,
        "cve": finding.cve,
        "cwe": finding.cwe,
        "fix_version": finding.fix_version,
        "references": list(finding.references),
        "confidence": finding.confidence,
        "metadata": finding.metadata,
    }


def scan_document(result: ScanResult) -> dict[str, Any]:
    """Return the stable ``depfence.scan/v1`` representation of *result*."""
    counts = {severity.value: 0 for severity in Severity}
    for finding in result.findings:
        counts[finding.severity.value] += 1

    outcomes = materialize(
        result.scanner_coverage,
        result.scanner_errors,
        result.scanner_outcomes,
    )
    coverage_states = dict(result.scanner_coverage)
    for name, outcome in outcomes.items():
        coverage_states[name] = outcome.state
    incomplete = bool(result.errors) or any(
        state in {ScanState.INDETERMINATE, ScanState.UNPROVEN}
        for state in coverage_states.values()
    )
    if incomplete:
        status = "INDETERMINATE"
    elif result.findings:
        status = "FAIL"
    elif result.packages_scanned == 0:
        status = "UNPROVEN"
    else:
        status = "PASS"

    return {
        "schema_version": SCHEMA_VERSION,
        "target": result.target,
        "ecosystem": result.ecosystem,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "status": status,
        "packages_scanned": result.packages_scanned,
        "summary": {
            "findings": len(result.findings),
            "suppressed_findings": len(result.suppressed_findings),
            "severity": counts,
        },
        "coverage": {
            "complete": not incomplete,
            "scanners": {
                name: state.value for name, state in sorted(coverage_states.items())
            },
            "errors": list(result.errors),
            "scanner_errors": dict(sorted(result.scanner_errors.items())),
            "outcomes": {
                name: outcome.to_dict() for name, outcome in sorted(outcomes.items())
            },
        },
        "findings": [_finding(finding) for finding in result.findings],
        "suppressed_findings": [_finding(finding) for finding in result.suppressed_findings],
    }


class JsonReporter:
    """Default versioned JSON reporter."""

    name = "json"
    format = "json"

    def render(self, result: ScanResult) -> str:
        return json.dumps(scan_document(result), indent=2, default=_serialize)


class LegacyJsonReporter:
    """Pre-v1 dataclass dump retained for compatibility migrations."""

    name = "json-legacy"
    format = "json-legacy"

    def render(self, result: ScanResult) -> str:
        document = asdict(result)
        # json-legacy is an exact compatibility surface; typed outcomes are
        # available in depfence.scan/v1 without changing its historical shape.
        document.pop("scanner_outcomes", None)
        return json.dumps(document, indent=2, default=_serialize)
