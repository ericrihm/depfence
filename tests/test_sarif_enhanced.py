"""Tests for the enhanced SARIF 2.1.0 reporter."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity, ScanResult
from depfence.reporters.sarif_out import SarifReporter, _partial_fingerprint

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_NPM_PKG = PackageId("npm", "lodash", "4.17.21")
_PYPI_PKG = PackageId("pypi", "requests", "2.31.0")


def _make_result(findings=None, target="package-lock.json") -> ScanResult:
    return ScanResult(
        target=target,
        ecosystem="npm",
        started_at=datetime(2024, 6, 1, 12, 0, 0),
        findings=findings or [],
    )


def _vuln_finding(
    pkg=None,
    severity=Severity.HIGH,
    cve="CVE-2019-10744",
    cwe="CWE-1321",
    refs=None,
    lockfile_paths=None,
) -> Finding:
    pkg = pkg or _NPM_PKG
    metadata = {}
    if lockfile_paths:
        metadata["lockfile_paths"] = lockfile_paths
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=pkg,
        title="Prototype Pollution in lodash",
        detail="lodash before 4.17.21 is vulnerable to prototype pollution.",
        cve=cve,
        cwe=cwe,
        references=refs or ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"],
        metadata=metadata,
    )


def _typo_finding(pkg=None, severity=Severity.MEDIUM) -> Finding:
    pkg = pkg or _PYPI_PKG
    return Finding(
        finding_type=FindingType.TYPOSQUAT,
        severity=severity,
        package=pkg,
        title="Possible typosquat",
        detail="Package name resembles a popular package.",
    )


def _render(findings=None, target="package-lock.json", run_id=None) -> dict:
    reporter = SarifReporter()
    result = _make_result(findings=findings, target=target)
    return json.loads(reporter.render(result, run_id=run_id))


# ---------------------------------------------------------------------------
# 1. Top-level SARIF 2.1.0 structure
# ---------------------------------------------------------------------------


def test_sarif_schema_and_version():
    sarif = _render()
    assert sarif["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in sarif["$schema"]


def test_runs_array_present():
    sarif = _render()
    assert isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1


def test_tool_driver_fields():
    sarif = _render()
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "depfence"
    assert "semanticVersion" in driver
    assert "informationUri" in driver


def test_semantic_version_matches_package_version():
    from depfence import __version__
    sarif = _render()
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["semanticVersion"] == __version__
    assert driver["version"] == __version__


# ---------------------------------------------------------------------------
# 2. automationDetails for run-level deduplication
# ---------------------------------------------------------------------------


def test_automation_details_present():
    sarif = _render()
    run = sarif["runs"][0]
    assert "automationDetails" in run
    assert "id" in run["automationDetails"]


def test_automation_details_custom_run_id():
    custom_id = "ci/my-org/main/42/"
    sarif = _render(run_id=custom_id)
    assert sarif["runs"][0]["automationDetails"]["id"] == custom_id


def test_automation_details_default_contains_target():
    sarif = _render(target="yarn.lock")
    aid = sarif["runs"][0]["automationDetails"]["id"]
    assert "yarn.lock" in aid


# ---------------------------------------------------------------------------
# 3. Empty findings produce valid minimal SARIF
# ---------------------------------------------------------------------------


def test_empty_findings_valid_sarif():
    sarif = _render(findings=[])
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_empty_findings_has_automation_details():
    sarif = _render(findings=[])
    assert "automationDetails" in sarif["runs"][0]


# ---------------------------------------------------------------------------
# 4. rules[] array — population and full metadata
# ---------------------------------------------------------------------------


def test_rules_array_populated():
    sarif = _render(findings=[_vuln_finding()])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1


def test_rule_has_required_fields():
    sarif = _render(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    for field in ("id", "name", "shortDescription", "fullDescription",
                  "helpUri", "defaultConfiguration", "properties"):
        assert field in rule, f"Rule missing field: {field}"


def test_rule_short_and_full_description_are_text_objects():
    sarif = _render(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "text" in rule["shortDescription"]
    assert "text" in rule["fullDescription"]


def test_rule_help_uri_contains_finding_type():
    sarif = _render(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "known_vulnerability" in rule["helpUri"]


def test_rule_default_configuration_level():
    for severity, expected_level in [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ]:
        sarif = _render(findings=[_vuln_finding(severity=severity)])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == expected_level, (
            f"severity={severity} expected level={expected_level}"
        )


def test_rule_properties_tags_include_security_and_type():
    sarif = _render(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "security" in tags
    assert "supply-chain" in tags
    assert "known_vulnerability" in tags


def test_rule_properties_security_severity_present():
    sarif = _render(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]


def test_two_different_findings_produce_two_rules():
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _render(findings=findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2


def test_duplicate_package_and_type_produces_one_rule():
    # Two findings with same package + finding_type should share a rule.
    f1 = _vuln_finding(cve="CVE-2019-10744")
    f2 = _vuln_finding(cve="CVE-2020-8203")
    sarif = _render(findings=[f1, f2])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert len(sarif["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# 5. results[] — ruleId and ruleIndex correctness
# ---------------------------------------------------------------------------


def test_result_references_rule_by_id_and_index():
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _render(findings=findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]

    rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}

    for res in results:
        rid = res["ruleId"]
        assert rid in rule_id_to_index, f"ruleId '{rid}' not found in rules"
        assert res["ruleIndex"] == rule_id_to_index[rid]


def test_result_level_matches_severity():
    for severity, expected_level in [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ]:
        sarif = _render(findings=[_vuln_finding(severity=severity)])
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == expected_level


def test_result_has_message():
    sarif = _render(findings=[_vuln_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "text" in result["message"]
    assert result["message"]["text"]


def test_result_location_uri_matches_target():
    sarif = _render(findings=[_vuln_finding()], target="my/package-lock.json")
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "my/package-lock.json"


def test_result_location_has_uri_base_id():
    sarif = _render(findings=[_vuln_finding()])
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


# ---------------------------------------------------------------------------
# 6. partialFingerprints — stability and presence
# ---------------------------------------------------------------------------


def test_result_has_partial_fingerprints():
    sarif = _render(findings=[_vuln_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "partialFingerprints" in result
    assert "primaryLocationLineHash/v1" in result["partialFingerprints"]


def test_partial_fingerprint_is_stable():
    """Same inputs must always yield the same fingerprint."""
    fp1 = _partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = _partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    assert fp1 == fp2


def test_partial_fingerprint_differs_for_different_cve():
    fp1 = _partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = _partial_fingerprint("npm:lodash@4.17.21", "CVE-2020-8203", "known_vulnerability")
    assert fp1 != fp2


def test_partial_fingerprint_differs_for_different_package():
    fp1 = _partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = _partial_fingerprint("npm:lodash@4.17.20", "CVE-2019-10744", "known_vulnerability")
    assert fp1 != fp2


def test_partial_fingerprint_differs_for_different_type():
    fp1 = _partial_fingerprint("npm:lodash@4.17.21", None, "known_vulnerability")
    fp2 = _partial_fingerprint("npm:lodash@4.17.21", None, "typosquat")
    assert fp1 != fp2


def test_partial_fingerprint_none_cve_stable():
    fp1 = _partial_fingerprint("pypi:requests@2.31.0", None, "typosquat")
    fp2 = _partial_fingerprint("pypi:requests@2.31.0", None, "typosquat")
    assert fp1 == fp2


def test_sarif_fingerprint_matches_helper():
    """Fingerprint in rendered SARIF must match _partial_fingerprint directly."""
    finding = _vuln_finding()
    sarif = _render(findings=[finding])
    fp_in_sarif = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash/v1"]
    expected = _partial_fingerprint(
        str(finding.package), finding.cve, finding.finding_type.value
    )
    assert fp_in_sarif == expected


# ---------------------------------------------------------------------------
# 7. security-severity on results
# ---------------------------------------------------------------------------


def test_result_security_severity_present():
    sarif = _render(findings=[_vuln_finding()])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "security-severity" in props


def test_result_security_severity_values():
    expected = {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "2.0",
        Severity.INFO: "0.0",
    }
    for severity, expected_val in expected.items():
        sarif = _render(findings=[_vuln_finding(severity=severity)])
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["security-severity"] == expected_val, (
            f"severity={severity} expected security-severity={expected_val}"
        )


def test_result_security_severity_is_string():
    sarif = _render(findings=[_vuln_finding(severity=Severity.CRITICAL)])
    val = sarif["runs"][0]["results"][0]["properties"]["security-severity"]
    assert isinstance(val, str)


# ---------------------------------------------------------------------------
# 8. CVE / CWE / references propagated to result properties
# ---------------------------------------------------------------------------


def test_cve_in_result_properties():
    sarif = _render(findings=[_vuln_finding(cve="CVE-2019-10744")])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("cve") == "CVE-2019-10744"


def test_cwe_in_result_properties():
    sarif = _render(findings=[_vuln_finding(cwe="CWE-1321")])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("cwe") == "CWE-1321"


def test_references_in_result_properties():
    refs = ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]
    sarif = _render(findings=[_vuln_finding(refs=refs)])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("references") == refs


def test_no_cve_key_absent_from_properties():
    finding = Finding(
        finding_type=FindingType.TYPOSQUAT,
        severity=Severity.MEDIUM,
        package=_PYPI_PKG,
        title="Typosquat",
        detail="Looks like a typo.",
    )
    sarif = _render(findings=[finding])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "cve" not in props


# ---------------------------------------------------------------------------
# 9. relatedLocations for lockfile paths
# ---------------------------------------------------------------------------


def test_related_locations_present_when_lockfile_paths_set():
    finding = _vuln_finding(lockfile_paths=["package-lock.json", "node_modules/.package-lock.json"])
    sarif = _render(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "relatedLocations" in result
    assert len(result["relatedLocations"]) == 2


def test_related_locations_contain_uri():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _render(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert rl["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"


def test_related_locations_have_uri_base_id():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _render(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert rl["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


def test_related_locations_have_message():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _render(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert "text" in rl["message"]
    assert "package-lock.json" in rl["message"]["text"]


def test_no_related_locations_when_no_lockfile_paths():
    finding = _vuln_finding()  # no lockfile_paths in metadata
    sarif = _render(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "relatedLocations" not in result


def test_related_locations_ids_are_sequential():
    finding = _vuln_finding(lockfile_paths=["a.json", "b.json", "c.json"])
    sarif = _render(findings=[finding])
    rls = sarif["runs"][0]["results"][0]["relatedLocations"]
    ids = [rl["id"] for rl in rls]
    assert ids == [1, 2, 3]
