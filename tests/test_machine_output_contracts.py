"""Focused, offline contracts for versioned machine output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.core.snapshot import snapshot_from_result
from depfence.reporters.cyclonedx import generate_sbom
from depfence.reporters.json_out import JsonReporter, LegacyJsonReporter
from depfence.reporters.sarif import generate_sarif
from depfence.reporters.spdx_out import generate_spdx_with_packages
from depfence.schemas import load_schema, validate_document


def _result() -> ScanResult:
    return ScanResult(
        target="/workspace/package-lock.json",
        ecosystem="npm",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        packages_scanned=1,
    )


def test_packaged_schemas_validate_scan_and_snapshot() -> None:
    result = _result()
    scan = json.loads(JsonReporter().render(result))
    validate_document(scan)
    validate_document(snapshot_from_result(result).to_dict())
    assert load_schema("depfence.scan/v1")["$id"].endswith("/v1.json")


def test_json_v1_is_default_and_legacy_remains_available() -> None:
    result = _result()
    assert json.loads(JsonReporter().render(result))["schema_version"] == "depfence.scan/v1"
    assert "schema_version" not in json.loads(LegacyJsonReporter().render(result))


def test_sarif_uses_relative_locations_stable_rules_and_error_notifications() -> None:
    result = _result()
    result.errors = ["scanner timed out"]
    result.findings = [
        Finding(
            FindingType.KNOWN_VULN,
            Severity.HIGH,
            PackageId("npm", "lodash", "4.17.20"),
            "Vulnerability",
            "Affected",
            cve="CVE-2020-0001",
        )
    ]
    document = generate_sarif(result)
    run = document["runs"][0]
    assert not run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/")
    assert run["tool"]["driver"]["rules"][0]["id"] == "depfence/vulnerability"
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["toolExecutionNotifications"]


def test_cyclonedx_versions_dedupe_and_do_not_infer_exploitation_from_epss() -> None:
    package = PackageId("npm", "@scope/example", "1.0.0")
    finding = Finding(
        FindingType.KNOWN_VULN,
        Severity.HIGH,
        package,
        "CVE-2026-0001",
        "Affected",
        cve="CVE-2026-0001",
        metadata={"epss_score": 0.99},
    )
    document = generate_sbom([package, package], [finding, finding])
    assert document["specVersion"] == "1.7"
    assert document["components"][0]["purl"] == "pkg:npm/%40scope/example@1.0.0"
    assert len(document["components"]) == len(document["vulnerabilities"]) == 1
    assert document["vulnerabilities"][0]["analysis"]["state"] == "in_triage"
    assert generate_sbom([], [], spec_version="1.5")["specVersion"] == "1.5"


def test_spdx_rejects_other_versions_and_uses_canonical_purl() -> None:
    package = PackageId("maven", "org.example:demo", "1.0")
    document = generate_spdx_with_packages(_result(), [package, package])
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:maven/org.example/demo@1.0"
    with pytest.raises(ValueError, match="2.3"):
        generate_spdx_with_packages(_result(), [], spec_version="3.0")
