from __future__ import annotations

from depfence.core.finding_identity import finding_id
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.core.snapshot import snapshot_from_result
from depfence.flywheel.regression_gate import finding_id as ledger_finding_id
from depfence.reporters.json_out import scan_document
from depfence.reporters.kg_out import _finding_name, normalize_depfence
from depfence.reporters.sarif import generate_sarif


def _finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_type=FindingType.SECRET_EXPOSED,
        severity=severity,
        package=PackageId("file", "config/example.env"),
        title="Credential-like assignment",
        detail="redacted",
        cwe="CWE-798",
        metadata={"source_file": "config/example.env", "line": 7},
    )


def test_identity_is_shared_across_machine_outputs() -> None:
    finding = _finding()
    result = ScanResult(target=".", ecosystem="multi", packages_scanned=1, findings=[finding])
    expected = finding_id(finding)

    assert scan_document(result)["findings"][0]["id"] == expected
    assert snapshot_from_result(result).findings[0].id == expected
    assert generate_sarif(result)["runs"][0]["results"][0]["partialFingerprints"][
        "primaryLocationLineHash/v1"
    ] == expected
    record = normalize_depfence(result)[0]
    assert _finding_name(record) == expected
    assert ledger_finding_id(record) == expected


def test_identity_ignores_mutable_severity() -> None:
    assert finding_id(_finding(Severity.LOW)) == finding_id(_finding(Severity.CRITICAL))
