"""Tests for the SPDX 2.3 SBOM reporter."""

from __future__ import annotations

import re

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity, ScanResult
from depfence.reporters.spdx_out import generate_spdx, generate_spdx_with_packages

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_NPM_PKG = PackageId("npm", "lodash", "4.17.21")
_PYPI_PKG = PackageId("pypi", "requests", "2.31.0")
_CARGO_PKG = PackageId("cargo", "serde", "1.0.0")
_GO_PKG = PackageId("go", "github.com/gin-gonic/gin", "1.9.1")
_MAVEN_PKG = PackageId("maven", "com.google.guava:guava", "32.1.2")
_NUGET_PKG = PackageId("nuget", "Newtonsoft.Json", "13.0.3")

ALL_PKGS = [_NPM_PKG, _PYPI_PKG, _CARGO_PKG, _GO_PKG, _MAVEN_PKG, _NUGET_PKG]

_VULN_FINDING = Finding(
    finding_type=FindingType.KNOWN_VULN,
    severity=Severity.HIGH,
    package=_NPM_PKG,
    title="Prototype Pollution",
    detail="lodash is vulnerable to prototype pollution",
    cve="CVE-2019-10744",
)

_TYPO_FINDING = Finding(
    finding_type=FindingType.TYPOSQUAT,
    severity=Severity.MEDIUM,
    package=_PYPI_PKG,
    title="Possible typosquat",
    detail="Package name resembles a popular package",
)

_NAMESPACE_RE = re.compile(r"^https://depfence\.dev/spdx/.+/[0-9a-f\-]{36}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _make_result(*findings: Finding) -> ScanResult:
    r = ScanResult(target="/tmp/test", ecosystem="npm")
    r.findings = list(findings)
    return r


# ---------------------------------------------------------------------------
# Valid SPDX structure
# ---------------------------------------------------------------------------


def test_spdx_version():
    doc = generate_spdx(_make_result(), project_name="my-project")
    assert doc["spdxVersion"] == "SPDX-2.3"


def test_data_license():
    doc = generate_spdx(_make_result())
    assert doc["dataLicense"] == "CC0-1.0"


def test_spdx_id_is_document():
    doc = generate_spdx(_make_result())
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"


def test_name_uses_project_name():
    doc = generate_spdx(_make_result(), project_name="my-app")
    assert doc["name"] == "my-app"


def test_name_defaults_to_depfence_scan():
    doc = generate_spdx(_make_result())
    assert doc["name"] == "depfence-scan"


def test_document_namespace_is_unique_uri():
    doc1 = generate_spdx(_make_result(), project_name="proj")
    doc2 = generate_spdx(_make_result(), project_name="proj")
    assert _NAMESPACE_RE.match(doc1["documentNamespace"]), doc1["documentNamespace"]
    assert doc1["documentNamespace"] != doc2["documentNamespace"]


def test_creation_info_has_tool():
    doc = generate_spdx(_make_result())
    creators = doc["creationInfo"]["creators"]
    assert any("depfence" in c for c in creators)


def test_creation_info_tool_version():
    doc = generate_spdx(_make_result())
    creators = doc["creationInfo"]["creators"]
    assert any("0.4.0" in c for c in creators)


def test_creation_info_timestamp_format():
    doc = generate_spdx(_make_result())
    ts = doc["creationInfo"]["created"]
    assert _TIMESTAMP_RE.match(ts), f"Unexpected timestamp: {ts!r}"


def test_top_level_keys_present():
    doc = generate_spdx(_make_result())
    for key in ("spdxVersion", "dataLicense", "SPDXID", "name",
                 "documentNamespace", "creationInfo", "packages", "relationships"):
        assert key in doc, f"Missing key: {key!r}"


# ---------------------------------------------------------------------------
# Packages included with correct ecosystem
# ---------------------------------------------------------------------------


def test_packages_derived_from_findings():
    result = _make_result(_VULN_FINDING, _TYPO_FINDING)
    doc = generate_spdx(result)
    assert len(doc["packages"]) == 2


def test_package_spdxid_prefix():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["SPDXID"].startswith("SPDXRef-")


def test_package_name():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["name"] == "lodash"


def test_package_version():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["versionInfo"] == "4.17.21"


def test_package_download_location_noassertion():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["downloadLocation"] == "NOASSERTION"


def test_package_supplier_noassertion():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["supplier"] == "NOASSERTION"


def test_package_files_analyzed_false():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    assert doc["packages"][0]["filesAnalyzed"] is False


def test_generate_spdx_with_packages_all_ecosystems():
    result = _make_result()
    doc = generate_spdx_with_packages(result, ALL_PKGS, project_name="full-scan")
    assert len(doc["packages"]) == len(ALL_PKGS)
    names = {p["name"] for p in doc["packages"]}
    assert "lodash" in names
    assert "requests" in names
    assert "serde" in names


# ---------------------------------------------------------------------------
# PURLs in externalRefs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pkg, expected_purl", [
    (_NPM_PKG,   "pkg:npm/lodash@4.17.21"),
    (_PYPI_PKG,  "pkg:pypi/requests@2.31.0"),
    (_CARGO_PKG, "pkg:cargo/serde@1.0.0"),
    (_GO_PKG,    "pkg:golang/github.com/gin-gonic/gin@1.9.1"),
    (_MAVEN_PKG, "pkg:maven/com.google.guava:guava@32.1.2"),
    (_NUGET_PKG, "pkg:nuget/Newtonsoft.Json@13.0.3"),
])
def test_purl_in_external_refs(pkg: PackageId, expected_purl: str):
    result = _make_result()
    doc = generate_spdx_with_packages(result, [pkg])
    pkg_entry = doc["packages"][0]
    purls = [
        ref["referenceLocator"]
        for ref in pkg_entry["externalRefs"]
        if ref["referenceType"] == "purl"
    ]
    assert expected_purl in purls, f"Expected PURL {expected_purl!r}, got {purls}"


def test_external_ref_category_is_package_manager():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    for ref in doc["packages"][0]["externalRefs"]:
        assert ref["referenceCategory"] == "PACKAGE-MANAGER"


def test_external_ref_type_is_purl():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    types = [ref["referenceType"] for ref in doc["packages"][0]["externalRefs"]]
    assert "purl" in types


# ---------------------------------------------------------------------------
# Relationships: DOCUMENT DESCRIBES each package
# ---------------------------------------------------------------------------


def test_relationships_count_matches_packages():
    result = _make_result(_VULN_FINDING, _TYPO_FINDING)
    doc = generate_spdx(result)
    assert len(doc["relationships"]) == len(doc["packages"])


def test_relationships_all_from_document():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    for rel in doc["relationships"]:
        assert rel["spdxElementId"] == "SPDXRef-DOCUMENT"


def test_relationships_type_describes():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    for rel in doc["relationships"]:
        assert rel["relationshipType"] == "DESCRIBES"


def test_relationships_target_matches_package_spdxid():
    result = _make_result(_VULN_FINDING)
    doc = generate_spdx(result)
    pkg_ids = {p["SPDXID"] for p in doc["packages"]}
    rel_targets = {r["relatedSpdxElement"] for r in doc["relationships"]}
    assert pkg_ids == rel_targets


# ---------------------------------------------------------------------------
# Empty scan result handling
# ---------------------------------------------------------------------------


def test_empty_result_produces_valid_doc():
    result = _make_result()
    doc = generate_spdx(result)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["packages"] == []
    assert doc["relationships"] == []


def test_empty_packages_list_with_generate_spdx_with_packages():
    result = _make_result()
    doc = generate_spdx_with_packages(result, [])
    assert doc["packages"] == []
    assert doc["relationships"] == []
    assert doc["spdxVersion"] == "SPDX-2.3"


def test_empty_result_namespace_is_unique():
    result = _make_result()
    doc1 = generate_spdx(result)
    doc2 = generate_spdx(result)
    assert doc1["documentNamespace"] != doc2["documentNamespace"]


def test_empty_result_name_default():
    result = _make_result()
    doc = generate_spdx(result)
    assert doc["name"] == "depfence-scan"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_duplicate_packages_deduplicated():
    result = _make_result()
    doc = generate_spdx_with_packages(result, [_NPM_PKG, _NPM_PKG, _NPM_PKG])
    assert len(doc["packages"]) == 1


def test_duplicate_findings_deduplicated_in_generate_spdx():
    # Two findings on the same package should produce one package entry
    finding2 = Finding(
        finding_type=FindingType.MALICIOUS,
        severity=Severity.CRITICAL,
        package=_NPM_PKG,
        title="Malicious code",
        detail="Malicious payload detected",
    )
    result = _make_result(_VULN_FINDING, finding2)
    doc = generate_spdx(result)
    assert len(doc["packages"]) == 1
