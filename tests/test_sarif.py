"""Tests for depfence/reporters/sarif.py — SARIF 2.1.0 output.

Covers:
- Schema compliance (version, $schema, runs[] structure)
- Severity → SARIF level mapping (critical/high → error, medium → warning, low/info → note)
- FindingType → SARIF rule-ID prefix mapping
- Rule generation (deduplication, required fields, properties)
- Result generation (locations, fingerprints, properties)
- codeFlows when lockfile_path metadata is present
- fixes[] when fix_version is set
- relatedLocations for lockfile_paths list
- artifacts[] collection
- automationDetails stable ID
- generate_sarif() signature / defaults
- render_sarif() JSON serialisation
- Edge cases: empty findings, single finding, many findings
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

import pytest

from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.reporters.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    generate_sarif,
    make_partial_fingerprint,
    map_finding_type_to_rule_id,
    map_severity_to_sarif_level,
    render_sarif,
)

# ---------------------------------------------------------------------------
# Test fixtures / factories
# ---------------------------------------------------------------------------

_NPM_PKG = PackageId("npm", "lodash", "4.17.21")
_PYPI_PKG = PackageId("pypi", "requests", "2.31.0")
_CARGO_PKG = PackageId("cargo", "serde", "1.0.0")


def _make_result(findings=None, target="package-lock.json", ecosystem="npm") -> ScanResult:
    return ScanResult(
        target=target,
        ecosystem=ecosystem,
        started_at=datetime(2024, 6, 1, 12, 0, 0),
        findings=findings or [],
    )


def _vuln_finding(
    pkg=None,
    severity=Severity.HIGH,
    cve="CVE-2019-10744",
    cwe="CWE-1321",
    fix_version=None,
    refs=None,
    lockfile_path=None,
    lockfile_paths=None,
) -> Finding:
    pkg = pkg or _NPM_PKG
    metadata: dict = {}
    if lockfile_path:
        metadata["lockfile_path"] = lockfile_path
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
        fix_version=fix_version,
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


def _dep_confusion_finding(pkg=None) -> Finding:
    pkg = pkg or _NPM_PKG
    return Finding(
        finding_type=FindingType.DEP_CONFUSION,
        severity=Severity.CRITICAL,
        package=pkg,
        title="Dependency confusion risk",
        detail="Package may be subject to dependency confusion.",
    )


def _gen(findings=None, target="package-lock.json", tool_name="depfence", tool_version="0.4.0") -> dict:
    result = _make_result(findings=findings, target=target)
    return generate_sarif(result, tool_name=tool_name, tool_version=tool_version)


# ---------------------------------------------------------------------------
# 1. Top-level SARIF 2.1.0 schema structure
# ---------------------------------------------------------------------------


def test_schema_field_present():
    sarif = _gen()
    assert "$schema" in sarif


def test_schema_field_contains_sarif_2_1_0():
    sarif = _gen()
    assert "sarif-schema-2.1.0" in sarif["$schema"]


def test_schema_matches_constant():
    sarif = _gen()
    assert sarif["$schema"] == SARIF_SCHEMA


def test_version_is_2_1_0():
    sarif = _gen()
    assert sarif["version"] == "2.1.0"


def test_version_matches_constant():
    sarif = _gen()
    assert sarif["version"] == SARIF_VERSION


def test_runs_key_present():
    sarif = _gen()
    assert "runs" in sarif


def test_runs_is_list():
    sarif = _gen()
    assert isinstance(sarif["runs"], list)


def test_exactly_one_run():
    sarif = _gen()
    assert len(sarif["runs"]) == 1


# ---------------------------------------------------------------------------
# 2. tool.driver block
# ---------------------------------------------------------------------------


def test_tool_driver_name_default():
    sarif = _gen()
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "depfence"


def test_tool_driver_name_custom():
    sarif = _gen(tool_name="my-scanner")
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "my-scanner"


def test_tool_driver_semantic_version_default():
    sarif = _gen()
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.4.0"


def test_tool_driver_semantic_version_custom():
    sarif = _gen(tool_version="1.2.3")
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "1.2.3"


def test_tool_driver_version_matches_semantic_version():
    sarif = _gen(tool_version="2.0.0")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == driver["semanticVersion"] == "2.0.0"


def test_tool_driver_information_uri_present():
    sarif = _gen()
    assert "informationUri" in sarif["runs"][0]["tool"]["driver"]


# ---------------------------------------------------------------------------
# 3. automationDetails
# ---------------------------------------------------------------------------


def test_automation_details_present():
    sarif = _gen()
    assert "automationDetails" in sarif["runs"][0]


def test_automation_details_has_id():
    sarif = _gen()
    assert "id" in sarif["runs"][0]["automationDetails"]


def test_automation_details_id_contains_target():
    sarif = _gen(target="yarn.lock")
    aid = sarif["runs"][0]["automationDetails"]["id"]
    assert "yarn.lock" in aid


def test_automation_details_id_contains_tool_name():
    sarif = _gen(tool_name="depfence")
    aid = sarif["runs"][0]["automationDetails"]["id"]
    assert "depfence" in aid


# ---------------------------------------------------------------------------
# 4. Empty findings → minimal valid SARIF
# ---------------------------------------------------------------------------


def test_empty_findings_rules_is_empty_list():
    sarif = _gen(findings=[])
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_empty_findings_results_is_empty_list():
    sarif = _gen(findings=[])
    assert sarif["runs"][0]["results"] == []


def test_empty_findings_artifacts_present():
    # artifacts[] should be a list (may be empty if target not added without findings)
    sarif = _gen(findings=[])
    assert "artifacts" in sarif["runs"][0]
    assert isinstance(sarif["runs"][0]["artifacts"], list)


# ---------------------------------------------------------------------------
# 5. Severity → SARIF level mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity,expected", [
    (Severity.CRITICAL, "error"),
    (Severity.HIGH, "error"),
    (Severity.MEDIUM, "warning"),
    (Severity.LOW, "note"),
    (Severity.INFO, "note"),
])
def test_map_severity_to_sarif_level(severity, expected):
    assert map_severity_to_sarif_level(severity) == expected


@pytest.mark.parametrize("severity,expected_level", [
    (Severity.CRITICAL, "error"),
    (Severity.HIGH, "error"),
    (Severity.MEDIUM, "warning"),
    (Severity.LOW, "note"),
    (Severity.INFO, "note"),
])
def test_result_level_matches_severity(severity, expected_level):
    sarif = _gen(findings=[_vuln_finding(severity=severity)])
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == expected_level


@pytest.mark.parametrize("severity,expected_level", [
    (Severity.CRITICAL, "error"),
    (Severity.HIGH, "error"),
    (Severity.MEDIUM, "warning"),
    (Severity.LOW, "note"),
])
def test_rule_default_configuration_level_matches_severity(severity, expected_level):
    sarif = _gen(findings=[_vuln_finding(severity=severity)])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == expected_level


# ---------------------------------------------------------------------------
# 6. FindingType → rule-ID prefix mapping
# ---------------------------------------------------------------------------


def test_map_finding_type_known_vuln():
    assert map_finding_type_to_rule_id(FindingType.KNOWN_VULN) == "depfence/vulnerability"


def test_map_finding_type_typosquat():
    assert map_finding_type_to_rule_id(FindingType.TYPOSQUAT) == "depfence/typosquat"


def test_map_finding_type_dep_confusion():
    assert map_finding_type_to_rule_id(FindingType.DEP_CONFUSION) == "depfence/dep-confusion"


def test_map_finding_type_malicious():
    assert map_finding_type_to_rule_id(FindingType.MALICIOUS) == "depfence/malicious"


def test_map_finding_type_behavioral():
    assert map_finding_type_to_rule_id(FindingType.BEHAVIORAL) == "depfence/behavioral"


def test_map_finding_type_license():
    assert map_finding_type_to_rule_id(FindingType.LICENSE) == "depfence/license"


def test_map_finding_type_unknown_falls_back():
    # Should not raise; falls back to depfence/<value>
    result = map_finding_type_to_rule_id(FindingType.DOCKERFILE)
    assert result.startswith("depfence/")


def test_rule_id_contains_finding_type_prefix():
    sarif = _gen(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "depfence/vulnerability" in rule["id"]


def test_rule_id_contains_package_string():
    sarif = _gen(findings=[_vuln_finding(pkg=_NPM_PKG)])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "lodash" in rule["id"]


def test_result_rule_id_matches_rule_in_rules_array():
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _gen(findings=findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    rule_ids = {r["id"] for r in rules}
    for res in results:
        assert res["ruleId"] in rule_ids


# ---------------------------------------------------------------------------
# 7. rules[] population and deduplication
# ---------------------------------------------------------------------------


def test_one_finding_produces_one_rule():
    sarif = _gen(findings=[_vuln_finding()])
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_two_different_type_findings_produce_two_rules():
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _gen(findings=findings)
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2


def test_same_package_and_type_deduplicates_to_one_rule():
    f1 = _vuln_finding(cve="CVE-2019-10744")
    f2 = _vuln_finding(cve="CVE-2020-8203")
    sarif = _gen(findings=[f1, f2])
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_rule_has_all_required_fields():
    sarif = _gen(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    for field in ("id", "name", "shortDescription", "fullDescription",
                  "helpUri", "defaultConfiguration", "properties"):
        assert field in rule, f"Rule missing '{field}'"


def test_rule_short_description_has_text():
    sarif = _gen(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "text" in rule["shortDescription"]
    assert rule["shortDescription"]["text"]


def test_rule_full_description_has_text():
    sarif = _gen(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "text" in rule["fullDescription"]


def test_rule_help_uri_contains_finding_type():
    sarif = _gen(findings=[_vuln_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "known_vulnerability" in rule["helpUri"]


def test_rule_properties_tags_include_security():
    sarif = _gen(findings=[_vuln_finding()])
    tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "security" in tags


def test_rule_properties_tags_include_supply_chain():
    sarif = _gen(findings=[_vuln_finding()])
    tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "supply-chain" in tags


def test_rule_properties_security_severity_present():
    sarif = _gen(findings=[_vuln_finding()])
    props = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    assert "security-severity" in props


# ---------------------------------------------------------------------------
# 8. results[] — ruleIndex correctness
# ---------------------------------------------------------------------------


def test_result_rule_index_references_correct_rule():
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _gen(findings=findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}
    for res in sarif["runs"][0]["results"]:
        assert res["ruleIndex"] == rule_id_to_index[res["ruleId"]]


def test_result_has_message_with_text():
    sarif = _gen(findings=[_vuln_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "message" in result
    assert "text" in result["message"]
    assert result["message"]["text"]


def test_result_location_uri_matches_target():
    sarif = _gen(findings=[_vuln_finding()], target="my/package-lock.json")
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "my/package-lock.json"


def test_result_location_uri_base_id_is_srcroot():
    sarif = _gen(findings=[_vuln_finding()])
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


# ---------------------------------------------------------------------------
# 9. partialFingerprints
# ---------------------------------------------------------------------------


def test_result_has_partial_fingerprints():
    sarif = _gen(findings=[_vuln_finding()])
    assert "partialFingerprints" in sarif["runs"][0]["results"][0]
    assert "primaryLocationLineHash/v1" in sarif["runs"][0]["results"][0]["partialFingerprints"]


def test_fingerprint_is_stable():
    fp1 = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    assert fp1 == fp2


def test_fingerprint_changes_for_different_cve():
    fp1 = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2020-8203", "known_vulnerability")
    assert fp1 != fp2


def test_fingerprint_changes_for_different_package():
    fp1 = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    fp2 = make_partial_fingerprint("npm:lodash@4.17.20", "CVE-2019-10744", "known_vulnerability")
    assert fp1 != fp2


def test_fingerprint_changes_for_different_type():
    fp1 = make_partial_fingerprint("npm:lodash@4.17.21", None, "known_vulnerability")
    fp2 = make_partial_fingerprint("npm:lodash@4.17.21", None, "typosquat")
    assert fp1 != fp2


def test_fingerprint_none_cve_is_stable():
    fp1 = make_partial_fingerprint("pypi:requests@2.31.0", None, "typosquat")
    fp2 = make_partial_fingerprint("pypi:requests@2.31.0", None, "typosquat")
    assert fp1 == fp2


def test_fingerprint_in_sarif_matches_helper():
    finding = _vuln_finding()
    sarif = _gen(findings=[finding])
    fp_in_sarif = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash/v1"]
    expected = make_partial_fingerprint(
        str(finding.package), finding.cve, finding.finding_type.value
    )
    assert fp_in_sarif == expected


def test_fingerprint_is_sha256_hex():
    fp = make_partial_fingerprint("npm:lodash@4.17.21", "CVE-2019-10744", "known_vulnerability")
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# 10. security-severity values on results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity,expected_val", [
    (Severity.CRITICAL, "9.5"),
    (Severity.HIGH, "8.0"),
    (Severity.MEDIUM, "5.5"),
    (Severity.LOW, "2.0"),
    (Severity.INFO, "0.0"),
])
def test_result_security_severity_values(severity, expected_val):
    sarif = _gen(findings=[_vuln_finding(severity=severity)])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["security-severity"] == expected_val


def test_result_security_severity_is_string():
    sarif = _gen(findings=[_vuln_finding(severity=Severity.CRITICAL)])
    val = sarif["runs"][0]["results"][0]["properties"]["security-severity"]
    assert isinstance(val, str)


# ---------------------------------------------------------------------------
# 11. CVE / CWE / references propagated to result properties
# ---------------------------------------------------------------------------


def test_cve_present_in_result_properties():
    sarif = _gen(findings=[_vuln_finding(cve="CVE-2019-10744")])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("cve") == "CVE-2019-10744"


def test_cwe_present_in_result_properties():
    sarif = _gen(findings=[_vuln_finding(cwe="CWE-1321")])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("cwe") == "CWE-1321"


def test_references_present_in_result_properties():
    refs = ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]
    sarif = _gen(findings=[_vuln_finding(refs=refs)])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props.get("references") == refs


def test_no_cve_key_absent_when_finding_has_no_cve():
    finding = _typo_finding()  # no CVE
    sarif = _gen(findings=[finding])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "cve" not in props


# ---------------------------------------------------------------------------
# 12. codeFlows when lockfile_path metadata is present
# ---------------------------------------------------------------------------


def test_code_flows_present_when_lockfile_path_set():
    finding = _vuln_finding(lockfile_path="package-lock.json")
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "codeFlows" in result
    assert len(result["codeFlows"]) == 1


def test_code_flows_absent_when_no_lockfile_path():
    finding = _vuln_finding()  # no lockfile_path in metadata
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "codeFlows" not in result


def test_code_flows_thread_flow_uri_matches_lockfile():
    finding = _vuln_finding(lockfile_path="my/package-lock.json")
    sarif = _gen(findings=[finding])
    cf = sarif["runs"][0]["results"][0]["codeFlows"][0]
    tf_loc = cf["threadFlows"][0]["locations"][0]["location"]
    uri = tf_loc["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "my/package-lock.json"


def test_code_flows_lockfile_added_to_artifacts():
    finding = _vuln_finding(lockfile_path="my/package-lock.json")
    sarif = _gen(findings=[finding])
    artifact_uris = {a["location"]["uri"] for a in sarif["runs"][0]["artifacts"]}
    assert "my/package-lock.json" in artifact_uris


# ---------------------------------------------------------------------------
# 13. fixes[] when fix_version is available
# ---------------------------------------------------------------------------


def test_fixes_present_when_fix_version_set():
    finding = _vuln_finding(fix_version="4.17.21")
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "fixes" in result
    assert len(result["fixes"]) == 1


def test_fixes_description_mentions_fix_version():
    finding = _vuln_finding(fix_version="4.17.21")
    sarif = _gen(findings=[finding])
    fix = sarif["runs"][0]["results"][0]["fixes"][0]
    assert "4.17.21" in fix["description"]["text"]


def test_fixes_absent_when_no_fix_version():
    finding = _vuln_finding(fix_version=None)
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "fixes" not in result


# ---------------------------------------------------------------------------
# 14. relatedLocations for lockfile_paths list
# ---------------------------------------------------------------------------


def test_related_locations_present_for_lockfile_paths():
    finding = _vuln_finding(lockfile_paths=["package-lock.json", "node_modules/.package-lock.json"])
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "relatedLocations" in result
    assert len(result["relatedLocations"]) == 2


def test_related_locations_uri_matches_lockfile():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _gen(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert rl["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"


def test_related_locations_have_uri_base_id():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _gen(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert rl["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


def test_related_locations_have_message_with_lockfile():
    finding = _vuln_finding(lockfile_paths=["package-lock.json"])
    sarif = _gen(findings=[finding])
    rl = sarif["runs"][0]["results"][0]["relatedLocations"][0]
    assert "package-lock.json" in rl["message"]["text"]


def test_related_locations_ids_sequential():
    finding = _vuln_finding(lockfile_paths=["a.json", "b.json", "c.json"])
    sarif = _gen(findings=[finding])
    ids = [rl["id"] for rl in sarif["runs"][0]["results"][0]["relatedLocations"]]
    assert ids == [1, 2, 3]


def test_related_locations_absent_when_no_lockfile_paths():
    finding = _vuln_finding()
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert "relatedLocations" not in result


def test_related_locations_uris_added_to_artifacts():
    finding = _vuln_finding(lockfile_paths=["lock1.json", "lock2.json"])
    sarif = _gen(findings=[finding])
    artifact_uris = {a["location"]["uri"] for a in sarif["runs"][0]["artifacts"]}
    assert "lock1.json" in artifact_uris
    assert "lock2.json" in artifact_uris


# ---------------------------------------------------------------------------
# 15. artifacts[] collection
# ---------------------------------------------------------------------------


def test_artifacts_list_present():
    sarif = _gen(findings=[_vuln_finding()])
    assert "artifacts" in sarif["runs"][0]
    assert isinstance(sarif["runs"][0]["artifacts"], list)


def test_artifacts_contain_target_uri():
    sarif = _gen(findings=[_vuln_finding()], target="yarn.lock")
    artifact_uris = {a["location"]["uri"] for a in sarif["runs"][0]["artifacts"]}
    assert "yarn.lock" in artifact_uris


def test_artifacts_entries_have_uri_base_id():
    sarif = _gen(findings=[_vuln_finding()], target="package-lock.json")
    for artifact in sarif["runs"][0]["artifacts"]:
        assert artifact["location"]["uriBaseId"] == "%SRCROOT%"


def test_artifacts_no_duplicates():
    # Two findings with same target → only one artifact entry for target
    findings = [_vuln_finding(pkg=_NPM_PKG), _typo_finding(pkg=_PYPI_PKG)]
    sarif = _gen(findings=findings, target="package-lock.json")
    artifact_uris = [a["location"]["uri"] for a in sarif["runs"][0]["artifacts"]]
    assert len(artifact_uris) == len(set(artifact_uris))


# ---------------------------------------------------------------------------
# 16. render_sarif() — JSON serialisation wrapper
# ---------------------------------------------------------------------------


def test_render_sarif_returns_string():
    result = _make_result(findings=[_vuln_finding()])
    output = render_sarif(result)
    assert isinstance(output, str)


def test_render_sarif_is_valid_json():
    result = _make_result(findings=[_vuln_finding()])
    output = render_sarif(result)
    parsed = json.loads(output)
    assert parsed["version"] == "2.1.0"


def test_render_sarif_is_indented():
    result = _make_result(findings=[])
    output = render_sarif(result)
    assert "\n" in output  # indented JSON has newlines


def test_render_sarif_custom_tool_name():
    result = _make_result(findings=[])
    output = render_sarif(result, tool_name="custom-scanner", tool_version="9.9.9")
    parsed = json.loads(output)
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "custom-scanner"


# ---------------------------------------------------------------------------
# 17. generate_sarif() default parameters
# ---------------------------------------------------------------------------


def test_generate_sarif_default_tool_name():
    result = _make_result()
    sarif = generate_sarif(result)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "depfence"


def test_generate_sarif_default_tool_version():
    result = _make_result()
    sarif = generate_sarif(result)
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.4.0"


def test_generate_sarif_returns_dict():
    result = _make_result()
    sarif = generate_sarif(result)
    assert isinstance(sarif, dict)


# ---------------------------------------------------------------------------
# 18. dep-confusion finding type
# ---------------------------------------------------------------------------


def test_dep_confusion_rule_id_prefix():
    finding = _dep_confusion_finding()
    sarif = _gen(findings=[finding])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "depfence/dep-confusion" in rule["id"]


def test_dep_confusion_severity_maps_to_error():
    finding = _dep_confusion_finding()
    sarif = _gen(findings=[finding])
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
