"""Tests for CycloneDX VEX (Vulnerability Exploitability Exchange) output.

Covers the vulnerability array enrichment added to generate_sbom:
- presence and structure of the vulnerabilities array
- CVE filtering (non-CVE findings excluded)
- fix recommendation field
- EPSS data in the analysis block
- severity mapping to CycloneDX strings
- VEX analysis state logic
"""

from __future__ import annotations

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.reporters.cyclonedx import generate_sbom

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_NPM_PKG = PackageId("npm", "lodash", "4.17.21")
_PYPI_PKG = PackageId("pypi", "requests", "2.31.0")
_CARGO_PKG = PackageId("cargo", "serde", "1.0.0")


def _vuln_finding(
    pkg: PackageId = _NPM_PKG,
    cve: str | None = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    detail: str = "A serious vulnerability.",
    fix_version: str | None = None,
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=pkg,
        title="Test Vuln",
        detail=detail,
        cve=cve,
        fix_version=fix_version,
        metadata=metadata or {},
    )


def _non_vuln_finding(pkg: PackageId = _PYPI_PKG) -> Finding:
    return Finding(
        finding_type=FindingType.TYPOSQUAT,
        severity=Severity.MEDIUM,
        package=pkg,
        title="Possible typosquat",
        detail="Looks like a popular package",
    )


# ---------------------------------------------------------------------------
# 1. Vulnerabilities array is present when findings have CVEs
# ---------------------------------------------------------------------------


class TestVulnerabilitiesArrayPresence:
    def test_vulnerabilities_key_always_present(self):
        sbom = generate_sbom([], [])
        assert "vulnerabilities" in sbom

    def test_empty_when_no_findings(self):
        sbom = generate_sbom([_NPM_PKG], [])
        assert sbom["vulnerabilities"] == []

    def test_populated_when_cve_finding_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert len(sbom["vulnerabilities"]) == 1

    def test_multiple_cve_findings_all_included(self):
        f1 = _vuln_finding(pkg=_NPM_PKG, cve="CVE-2024-0001")
        f2 = _vuln_finding(pkg=_PYPI_PKG, cve="CVE-2024-0002")
        sbom = generate_sbom([_NPM_PKG, _PYPI_PKG], [f1, f2])
        assert len(sbom["vulnerabilities"]) == 2

    def test_vuln_count_matches_known_vuln_findings(self):
        findings = [
            _vuln_finding(pkg=_NPM_PKG, cve="CVE-2024-0001"),
            _vuln_finding(pkg=_PYPI_PKG, cve="CVE-2024-0002"),
            _non_vuln_finding(),
        ]
        sbom = generate_sbom([_NPM_PKG, _PYPI_PKG], findings)
        assert len(sbom["vulnerabilities"]) == 2


# ---------------------------------------------------------------------------
# 2. Each vuln has id, ratings, affects
# ---------------------------------------------------------------------------


class TestVulnerabilityRequiredFields:
    def test_id_field_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding(cve="CVE-2024-9999")])
        assert sbom["vulnerabilities"][0]["id"] == "CVE-2024-9999"

    def test_ratings_field_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert "ratings" in sbom["vulnerabilities"][0]

    def test_ratings_is_non_empty_list(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        ratings = sbom["vulnerabilities"][0]["ratings"]
        assert isinstance(ratings, list)
        assert len(ratings) >= 1

    def test_ratings_entry_has_severity(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding(severity=Severity.HIGH)])
        rating = sbom["vulnerabilities"][0]["ratings"][0]
        assert "severity" in rating

    def test_ratings_entry_has_method(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        rating = sbom["vulnerabilities"][0]["ratings"][0]
        assert rating["method"] == "other"

    def test_affects_field_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert "affects" in sbom["vulnerabilities"][0]

    def test_affects_is_non_empty_list(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        affects = sbom["vulnerabilities"][0]["affects"]
        assert isinstance(affects, list)
        assert len(affects) >= 1

    def test_affects_ref_matches_component_bom_ref(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding(pkg=_NPM_PKG)])
        vuln = sbom["vulnerabilities"][0]
        component_bom_ref = sbom["components"][0]["bom-ref"]
        assert vuln["affects"][0]["ref"] == component_bom_ref

    def test_affects_ref_correct_value(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding(pkg=_NPM_PKG)])
        assert sbom["vulnerabilities"][0]["affects"][0]["ref"] == "npm:lodash@4.17.21"

    def test_description_field_populated_from_detail(self):
        detail = "Specific vulnerability detail text."
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding(detail=detail)])
        assert sbom["vulnerabilities"][0]["description"] == detail

    def test_source_name_is_depfence(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert sbom["vulnerabilities"][0]["source"]["name"] == "depfence"

    def test_source_url_is_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert "url" in sbom["vulnerabilities"][0]["source"]

    def test_source_url_value(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert sbom["vulnerabilities"][0]["source"]["url"] == "https://github.com/ericrihm/depfence"

    def test_analysis_block_always_present(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert "analysis" in sbom["vulnerabilities"][0]

    def test_analysis_has_state(self):
        sbom = generate_sbom([_NPM_PKG], [_vuln_finding()])
        assert "state" in sbom["vulnerabilities"][0]["analysis"]


# ---------------------------------------------------------------------------
# 3. Fix recommendation included when fix_version exists
# ---------------------------------------------------------------------------


class TestFixRecommendation:
    def test_recommendation_present_when_fix_version_set(self):
        finding = _vuln_finding(fix_version="4.17.22")
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert "recommendation" in sbom["vulnerabilities"][0]

    def test_recommendation_contains_fix_version(self):
        finding = _vuln_finding(fix_version="4.17.22")
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert "4.17.22" in sbom["vulnerabilities"][0]["recommendation"]

    def test_recommendation_format(self):
        finding = _vuln_finding(fix_version="2.0.0")
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"][0]["recommendation"] == "Upgrade to 2.0.0"

    def test_recommendation_absent_when_no_fix_version(self):
        finding = _vuln_finding(fix_version=None)
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert "recommendation" not in sbom["vulnerabilities"][0]

    def test_recommendation_absent_when_fix_version_empty_string(self):
        # fix_version="" is falsy — should behave the same as None
        finding = _vuln_finding(fix_version="")
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert "recommendation" not in sbom["vulnerabilities"][0]


# ---------------------------------------------------------------------------
# 4. EPSS data appears in analysis when present in metadata
# ---------------------------------------------------------------------------


class TestEpssInAnalysis:
    def test_epss_score_in_analysis_detail(self):
        finding = _vuln_finding(metadata={"epss_score": 0.85, "epss_percentile": 0.95})
        sbom = generate_sbom([_NPM_PKG], [finding])
        analysis = sbom["vulnerabilities"][0]["analysis"]
        assert "detail" in analysis
        assert "0.85" in analysis["detail"]

    def test_epss_score_label_in_detail(self):
        finding = _vuln_finding(metadata={"epss_score": 0.42})
        sbom = generate_sbom([_NPM_PKG], [finding])
        detail = sbom["vulnerabilities"][0]["analysis"]["detail"]
        assert "EPSS score" in detail

    def test_no_epss_means_no_detail_key(self):
        finding = _vuln_finding(metadata={})
        sbom = generate_sbom([_NPM_PKG], [finding])
        analysis = sbom["vulnerabilities"][0]["analysis"]
        assert "detail" not in analysis

    def test_epss_score_zero_treated_as_not_exploitable(self):
        finding = _vuln_finding(metadata={"epss_score": 0.0})
        sbom = generate_sbom([_NPM_PKG], [finding])
        # 0.0 EPSS => no exploitation signal => in_triage
        assert sbom["vulnerabilities"][0]["analysis"]["state"] == "in_triage"

    def test_positive_epss_score_yields_exploitable_state(self):
        finding = _vuln_finding(metadata={"epss_score": 0.75})
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"][0]["analysis"]["state"] == "exploitable"

    def test_no_epss_yields_in_triage_state(self):
        finding = _vuln_finding(metadata={})
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"][0]["analysis"]["state"] == "in_triage"

    def test_low_epss_score_still_exploitable(self):
        finding = _vuln_finding(metadata={"epss_score": 0.001})
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"][0]["analysis"]["state"] == "exploitable"

    def test_epss_detail_format(self):
        finding = _vuln_finding(metadata={"epss_score": 0.123})
        sbom = generate_sbom([_NPM_PKG], [finding])
        detail = sbom["vulnerabilities"][0]["analysis"]["detail"]
        assert detail == "EPSS score: 0.123"


# ---------------------------------------------------------------------------
# 5. Findings without CVEs are excluded from the vulnerabilities array
# ---------------------------------------------------------------------------


class TestNonCveExclusion:
    def test_typosquat_finding_excluded(self):
        sbom = generate_sbom([_PYPI_PKG], [_non_vuln_finding()])
        assert sbom["vulnerabilities"] == []

    def test_malicious_finding_excluded(self):
        finding = Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=_NPM_PKG,
            title="Malicious package",
            detail="Contains malware",
        )
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"] == []

    def test_behavioral_finding_excluded(self):
        finding = Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.HIGH,
            package=_NPM_PKG,
            title="Behavioral anomaly",
            detail="Unexpected network calls",
        )
        sbom = generate_sbom([_NPM_PKG], [finding])
        assert sbom["vulnerabilities"] == []

    def test_mixed_findings_only_known_vuln_included(self):
        vuln = _vuln_finding(pkg=_NPM_PKG, cve="CVE-2024-5555")
        typo = _non_vuln_finding(pkg=_PYPI_PKG)
        malicious = Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=_CARGO_PKG,
            title="Evil",
            detail="Very evil",
        )
        sbom = generate_sbom([_NPM_PKG, _PYPI_PKG, _CARGO_PKG], [vuln, typo, malicious])
        assert len(sbom["vulnerabilities"]) == 1
        assert sbom["vulnerabilities"][0]["id"] == "CVE-2024-5555"

    def test_all_non_cve_findings_produces_empty_array(self):
        findings = [_non_vuln_finding(_NPM_PKG), _non_vuln_finding(_PYPI_PKG)]
        sbom = generate_sbom([_NPM_PKG, _PYPI_PKG], findings)
        assert sbom["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# 6. Severity mapping to CycloneDX strings
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    @pytest.mark.parametrize("severity, expected", [
        (Severity.CRITICAL, "critical"),
        (Severity.HIGH, "high"),
        (Severity.MEDIUM, "medium"),
        (Severity.LOW, "low"),
        (Severity.INFO, "info"),
    ])
    def test_severity_mapped_correctly(self, severity: Severity, expected: str):
        finding = _vuln_finding(severity=severity)
        sbom = generate_sbom([_NPM_PKG], [finding])
        rating = sbom["vulnerabilities"][0]["ratings"][0]
        assert rating["severity"] == expected
