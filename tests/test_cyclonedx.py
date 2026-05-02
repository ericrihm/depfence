"""Tests for the CycloneDX 1.5 SBOM generator."""

from __future__ import annotations

import json
import re
import tempfile
import uuid
from pathlib import Path

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.reporters.cyclonedx import generate_sbom, write_sbom

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

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

_NON_VULN_FINDING = Finding(
    finding_type=FindingType.TYPOSQUAT,
    severity=Severity.MEDIUM,
    package=_PYPI_PKG,
    title="Possible typosquat",
    detail="Package name resembles a popular package",
)


# ---------------------------------------------------------------------------
# Top-level structure
# ---------------------------------------------------------------------------


def test_sbom_format():
    sbom = generate_sbom([], [])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["version"] == 1


def test_serial_number_is_valid_uuid_urn():
    sbom = generate_sbom([], [])
    assert _UUID_RE.match(sbom["serialNumber"]), (
        f"serialNumber {sbom['serialNumber']!r} is not a valid UUID URN"
    )


def test_serial_number_unique_across_calls():
    sbom1 = generate_sbom([], [])
    sbom2 = generate_sbom([], [])
    assert sbom1["serialNumber"] != sbom2["serialNumber"]


def test_metadata_timestamp_format():
    sbom = generate_sbom([], [])
    ts = sbom["metadata"]["timestamp"]
    # Should end with Z and parse as ISO-8601
    assert ts.endswith("Z")
    # Basic shape: YYYY-MM-DDTHH:MM:SSZ
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts)


def test_metadata_tools():
    sbom = generate_sbom([], [])
    tools = sbom["metadata"]["tools"]
    assert len(tools) >= 1
    tool = tools[0]
    assert tool["vendor"] == "depfence"
    assert tool["name"] == "depfence"
    assert "version" in tool


def test_metadata_component_project_info():
    sbom = generate_sbom([], [], project_name="my-app", project_version="1.2.3")
    comp = sbom["metadata"]["component"]
    assert comp["type"] == "application"
    assert comp["name"] == "my-app"
    assert comp["version"] == "1.2.3"


def test_top_level_keys_present():
    sbom = generate_sbom([], [])
    for key in ("bomFormat", "specVersion", "version", "serialNumber", "metadata",
                 "components", "vulnerabilities", "dependencies"):
        assert key in sbom, f"Missing top-level key: {key!r}"


# ---------------------------------------------------------------------------
# Empty inputs produce a valid minimal SBOM
# ---------------------------------------------------------------------------


def test_empty_inputs_valid_sbom():
    sbom = generate_sbom([], [])
    assert sbom["components"] == []
    assert sbom["vulnerabilities"] == []
    assert sbom["dependencies"] == []
    assert sbom["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# Component generation
# ---------------------------------------------------------------------------


def test_component_count_matches_packages():
    sbom = generate_sbom(ALL_PKGS, [])
    assert len(sbom["components"]) == len(ALL_PKGS)


def test_component_type_is_library():
    sbom = generate_sbom([_NPM_PKG], [])
    assert sbom["components"][0]["type"] == "library"


def test_component_name_and_version():
    sbom = generate_sbom([_NPM_PKG], [])
    comp = sbom["components"][0]
    assert comp["name"] == "lodash"
    assert comp["version"] == "4.17.21"


def test_component_bom_ref():
    sbom = generate_sbom([_NPM_PKG], [])
    assert sbom["components"][0]["bom-ref"] == "npm:lodash@4.17.21"


def test_component_purl_present():
    sbom = generate_sbom([_NPM_PKG], [])
    assert "purl" in sbom["components"][0]


# ---------------------------------------------------------------------------
# PURL generation per ecosystem
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pkg, expected_purl",
    [
        (_NPM_PKG, "pkg:npm/lodash@4.17.21"),
        (_PYPI_PKG, "pkg:pypi/requests@2.31.0"),
        (_CARGO_PKG, "pkg:cargo/serde@1.0.0"),
        (_GO_PKG, "pkg:golang/github.com/gin-gonic/gin@1.9.1"),
        (_MAVEN_PKG, "pkg:maven/com.google.guava:guava@32.1.2"),
        (_NUGET_PKG, "pkg:nuget/Newtonsoft.Json@13.0.3"),
    ],
)
def test_purl_per_ecosystem(pkg: PackageId, expected_purl: str):
    sbom = generate_sbom([pkg], [])
    assert sbom["components"][0]["purl"] == expected_purl


# ---------------------------------------------------------------------------
# Vulnerability mapping
# ---------------------------------------------------------------------------


def test_known_vuln_finding_mapped_to_vulnerability():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING])
    assert len(sbom["vulnerabilities"]) == 1


def test_vulnerability_id_uses_cve():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING])
    vuln = sbom["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2019-10744"


def test_vulnerability_source_is_depfence():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING])
    source = sbom["vulnerabilities"][0]["source"]
    assert source["name"] == "depfence"
    assert source["url"] == "https://github.com/ericrihm/depfence"


def test_vulnerability_rating_severity():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING])
    ratings = sbom["vulnerabilities"][0]["ratings"]
    assert ratings[0]["severity"] == "high"


def test_vulnerability_affects_bom_ref():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING])
    affects = sbom["vulnerabilities"][0]["affects"]
    assert affects[0]["ref"] == "npm:lodash@4.17.21"


def test_non_vuln_findings_excluded():
    sbom = generate_sbom([_PYPI_PKG], [_NON_VULN_FINDING])
    assert sbom["vulnerabilities"] == []


def test_multiple_findings_only_vulns_mapped():
    sbom = generate_sbom([_NPM_PKG, _PYPI_PKG], [_VULN_FINDING, _NON_VULN_FINDING])
    assert len(sbom["vulnerabilities"]) == 1
    assert sbom["vulnerabilities"][0]["id"] == "CVE-2019-10744"


def test_finding_without_cve_uses_title():
    finding_no_cve = Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=Severity.MEDIUM,
        package=_PYPI_PKG,
        title="GHSA-1234-abcd-5678",
        detail="Some advisory without CVE",
        cve=None,
    )
    sbom = generate_sbom([_PYPI_PKG], [finding_no_cve])
    assert sbom["vulnerabilities"][0]["id"] == "GHSA-1234-abcd-5678"


# ---------------------------------------------------------------------------
# Dependencies section
# ---------------------------------------------------------------------------


def test_dependencies_count_matches_packages():
    sbom = generate_sbom(ALL_PKGS, [])
    assert len(sbom["dependencies"]) == len(ALL_PKGS)


def test_dependency_ref_matches_bom_ref():
    sbom = generate_sbom([_NPM_PKG], [])
    assert sbom["dependencies"][0]["ref"] == sbom["components"][0]["bom-ref"]


# ---------------------------------------------------------------------------
# write_sbom
# ---------------------------------------------------------------------------


def test_write_sbom_creates_valid_json_file():
    sbom = generate_sbom([_NPM_PKG], [_VULN_FINDING], project_name="test", project_version="0.1")
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "sbom.json"
        write_sbom(sbom, out)
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded["bomFormat"] == "CycloneDX"
        assert loaded["specVersion"] == "1.5"
        assert len(loaded["components"]) == 1
        assert len(loaded["vulnerabilities"]) == 1


def test_write_sbom_indented():
    sbom = generate_sbom([_NPM_PKG], [])
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "sbom.json"
        write_sbom(sbom, out)
        raw = out.read_text()
        # indent=2 means lines start with spaces
        assert "\n  " in raw
