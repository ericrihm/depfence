"""Contract tests for depfence.snapshot/v1."""

from __future__ import annotations

import json

import pytest

from depfence.core.models import Finding, FindingType, PackageId, ScanResult, ScanState, Severity
from depfence.core.snapshot import (
    SCHEMA_VERSION,
    DepFenceSnapshot,
    JsonSnapshotStore,
    SnapshotVerdict,
    snapshot_from_result,
)


def _result(*, packages: int = 1, findings: list[Finding] | None = None, errors: list[str] | None = None) -> ScanResult:
    return ScanResult(
        target=".",
        ecosystem="pypi",
        packages_scanned=packages,
        findings=findings or [],
        errors=errors or [],
    )


def _finding(title: str = "Known issue") -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=Severity.HIGH,
        package=PackageId("pypi", "example", "1.0"),
        title=title,
        detail="raw context must not enter snapshots",
        cve="CVE-2026-0001",
    )


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_result(), SnapshotVerdict.PASS),
        (_result(findings=[_finding()]), SnapshotVerdict.FAIL),
        (_result(errors=["scanner unavailable"]), SnapshotVerdict.INDETERMINATE),
        (_result(packages=0), SnapshotVerdict.UNPROVEN),
    ],
)
def test_snapshot_uses_four_state_vocabulary(result: ScanResult, expected: SnapshotVerdict) -> None:
    snapshot = snapshot_from_result(result)
    assert snapshot.status is expected
    assert snapshot.safe is (expected is SnapshotVerdict.PASS)


def test_indeterminate_outranks_failure() -> None:
    snapshot = snapshot_from_result(_result(findings=[_finding()], errors=["timeout"]))
    assert snapshot.status is SnapshotVerdict.INDETERMINATE


def test_incomplete_scanner_coverage_never_passes() -> None:
    result = _result(packages=3)
    result.scanner_coverage = {
        "local": ScanState.PASS,
        "remote": ScanState.INDETERMINATE,
    }
    result.scanner_errors = {"remote": "network disabled"}

    snapshot = snapshot_from_result(result, offline=True)

    assert snapshot.status is SnapshotVerdict.INDETERMINATE
    assert snapshot.coverage.completed == ("local",)
    assert snapshot.coverage.skipped == ("remote",)
    assert snapshot.safe is False


def test_contract_round_trip_and_atomic_store(tmp_path) -> None:
    path = tmp_path / "nested" / "snapshot.json"
    store = JsonSnapshotStore(path)
    snapshot = snapshot_from_result(_result(findings=[_finding()]), offline=True)
    store.write(snapshot)

    payload = json.loads(path.read_text())
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["mode"] == "offline"
    assert payload["assurance"]["tamper_resistant"] is False
    assert store.read() == DepFenceSnapshot.from_dict(payload)


def test_snapshot_redacts_credentials_and_omits_raw_detail() -> None:
    snapshot = snapshot_from_result(_result(findings=[_finding("token=ghp_abcdefghijklmnopqrstuvwxyz123456")]))
    encoded = snapshot.to_json()
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in encoded
    assert "raw context must not enter snapshots" not in encoded
    assert "[REDACTED]" in encoded


def test_delta_uses_stable_finding_ids() -> None:
    first = snapshot_from_result(_result(findings=[_finding()]))
    second = snapshot_from_result(_result(findings=[_finding()]), previous=first)
    third = snapshot_from_result(_result(), previous=second)
    assert second.delta.new_finding_ids == ()
    assert third.delta.resolved_finding_ids == (first.findings[0].id,)


def test_distinct_findings_do_not_collapse_to_one_id() -> None:
    first = _finding("First assertion")
    second = _finding("Second assertion")
    snapshot = snapshot_from_result(_result(findings=[first, second]))
    assert len({finding.id for finding in snapshot.findings}) == 2


def test_unknown_schema_is_rejected() -> None:
    payload = snapshot_from_result(_result()).to_dict()
    payload["schema_version"] = "depfence.snapshot/v99"
    with pytest.raises(ValueError, match="unsupported snapshot schema"):
        DepFenceSnapshot.from_dict(payload)
