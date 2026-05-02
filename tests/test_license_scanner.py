"""Tests for the license compliance scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.license_scanner import LicenseScanner

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-declared-type]


@pytest.fixture
def scanner() -> LicenseScanner:
    return LicenseScanner()


# ---------------------------------------------------------------------------
# scan() — per-package findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mit_package_clean(scanner: LicenseScanner) -> None:
    """MIT license should produce no findings."""
    meta = PackageMeta(pkg=PackageId("pypi", "requests", "2.31.0"), license="MIT")
    findings = await scanner.scan([meta])
    assert findings == [], f"Expected no findings for MIT, got: {findings}"


@pytest.mark.asyncio
async def test_gpl3_package_high(scanner: LicenseScanner) -> None:
    """GPL-3.0 should produce a HIGH finding."""
    meta = PackageMeta(pkg=PackageId("pypi", "some-gpl-lib", "1.0.0"), license="GPL-3.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.finding_type == FindingType.BEHAVIORAL
    assert f.metadata["risk_tier"] == "HIGH"
    assert f.metadata["commercial_use"] is False


@pytest.mark.asyncio
async def test_agpl_package_critical(scanner: LicenseScanner) -> None:
    """AGPL-3.0 should produce a CRITICAL finding."""
    meta = PackageMeta(pkg=PackageId("pypi", "agpl-service", "0.9.0"), license="AGPL-3.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.metadata["risk_tier"] == "CRITICAL"
    assert f.metadata["commercial_use"] is False
    assert "AGPL-3.0" in f.metadata["license"]


@pytest.mark.asyncio
async def test_unknown_license_medium(scanner: LicenseScanner) -> None:
    """Empty or 'UNKNOWN' license string should produce a MEDIUM finding."""
    for lic in ("", "UNKNOWN", None):
        meta = PackageMeta(
            pkg=PackageId("npm", "mystery-pkg", "1.0.0"),
            license=lic or "",
        )
        findings = await scanner.scan([meta])
        assert len(findings) == 1, f"Expected MEDIUM finding for license={lic!r}"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["risk_tier"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_apache_clean(scanner: LicenseScanner) -> None:
    """Apache-2.0 should produce a LOW finding (patent clause note)."""
    meta = PackageMeta(pkg=PackageId("pypi", "boto3", "1.34.0"), license="Apache-2.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.LOW
    assert f.metadata["risk_tier"] == "LOW"
    assert f.metadata["commercial_use"] is True


@pytest.mark.asyncio
async def test_isc_clean(scanner: LicenseScanner) -> None:
    """ISC license (common in npm) should produce no findings."""
    meta = PackageMeta(pkg=PackageId("npm", "semver", "7.6.0"), license="ISC")
    findings = await scanner.scan([meta])
    assert findings == []


@pytest.mark.asyncio
async def test_sspl_critical(scanner: LicenseScanner) -> None:
    """SSPL-1.0 (MongoDB driver style) should be CRITICAL."""
    meta = PackageMeta(pkg=PackageId("pypi", "some-db-driver", "1.0.0"), license="SSPL-1.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_mpl2_medium(scanner: LicenseScanner) -> None:
    """MPL-2.0 should be MEDIUM (file-level copyleft)."""
    meta = PackageMeta(pkg=PackageId("npm", "some-mpl-lib", "2.0.0"), license="MPL-2.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_multiple_packages_mixed(scanner: LicenseScanner) -> None:
    """Mixed batch: clean packages produce no findings; risky ones do."""
    packages = [
        PackageMeta(pkg=PackageId("pypi", "requests", "2.31.0"), license="Apache-2.0"),  # LOW
        PackageMeta(pkg=PackageId("pypi", "flask", "3.0.0"), license="BSD-3-Clause"),    # LOW
        PackageMeta(pkg=PackageId("pypi", "numpy", "1.26.0"), license="BSD-3-Clause"),   # LOW
        PackageMeta(pkg=PackageId("pypi", "gpl-tool", "1.0.0"), license="GPL-3.0"),      # HIGH
        PackageMeta(pkg=PackageId("pypi", "mit-tool", "1.0.0"), license="MIT"),          # CLEAN
    ]
    findings = await scanner.scan(packages)
    risky_names = {f.package.name for f in findings}
    assert "gpl-tool" in risky_names
    assert "mit-tool" not in risky_names


# ---------------------------------------------------------------------------
# classify_license() — variations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("license_str,expected_tier", [
    # SPDX exact
    ("MIT",                        "CLEAN"),
    ("ISC",                        "CLEAN"),
    ("BSD-2-Clause",               "CLEAN"),
    ("Unlicense",                  "CLEAN"),
    ("0BSD",                       "CLEAN"),
    ("CC0-1.0",                    "CLEAN"),
    ("Apache-2.0",                 "LOW"),
    ("BSD-3-Clause",               "LOW"),
    ("GPL-2.0",                    "HIGH"),
    ("GPL-3.0",                    "HIGH"),
    ("LGPL-2.1",                   "HIGH"),
    ("LGPL-3.0",                   "HIGH"),
    ("AGPL-3.0",                   "CRITICAL"),
    ("SSPL-1.0",                   "CRITICAL"),
    ("MPL-2.0",                    "MEDIUM"),
    ("EPL-2.0",                    "MEDIUM"),
    # Human variations
    ("MIT License",                "CLEAN"),
    ("The MIT License",            "CLEAN"),
    ("Apache License 2.0",         "LOW"),
    ("Apache-2.0 license",         "LOW"),
    ("Apache 2",                   "LOW"),
    ("GPLv3",                      "HIGH"),
    ("GNU GPL v3",                 "HIGH"),
    ("GNU General Public License v3", "HIGH"),
    ("GPLv2",                      "HIGH"),
    ("GNU GPL v2",                 "HIGH"),
    ("LGPLv3",                     "HIGH"),
    ("LGPL v2.1",                  "HIGH"),
    ("AGPL v3",                    "CRITICAL"),
    ("GNU AGPL",                   "CRITICAL"),
    ("Mozilla Public License 2.0", "MEDIUM"),
    ("Creative Commons Zero",      "CLEAN"),
    ("Unlicensed",                 "CLEAN"),
    ("WTFPL",                      "CLEAN"),
    # Unknown
    ("",                           "UNKNOWN"),
    ("UNKNOWN",                    "UNKNOWN"),
])
def test_classify_variations(
    scanner: LicenseScanner,
    license_str: str,
    expected_tier: str,
) -> None:
    tier, severity = scanner.classify_license(license_str)
    assert tier == expected_tier, (
        f"classify_license({license_str!r}) → tier={tier!r}, expected {expected_tier!r}"
    )


def test_classify_returns_none_severity_for_clean(scanner: LicenseScanner) -> None:
    tier, severity = scanner.classify_license("MIT")
    assert tier == "CLEAN"
    assert severity is None


def test_classify_returns_severity_for_gpl(scanner: LicenseScanner) -> None:
    tier, severity = scanner.classify_license("GPL-3.0")
    assert tier == "HIGH"
    assert severity == Severity.HIGH


def test_classify_unknown_is_medium_severity(scanner: LicenseScanner) -> None:
    tier, severity = scanner.classify_license("UNKNOWN")
    assert severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# check_compatibility()
# ---------------------------------------------------------------------------

def test_compatibility_mit_with_gpl(scanner: LicenseScanner) -> None:
    """MIT project + GPL dep → incompatible."""
    incompatible = scanner.check_compatibility("MIT", ["GPL-3.0", "MIT", "Apache-2.0"])
    assert "GPL-3.0" in incompatible
    assert "MIT" not in incompatible
    assert "Apache-2.0" not in incompatible


def test_compatibility_gpl_with_mit(scanner: LicenseScanner) -> None:
    """GPL project + MIT dep → compatible (copyleft can consume anything)."""
    incompatible = scanner.check_compatibility("GPL-3.0", ["MIT", "BSD-2-Clause", "AGPL-3.0"])
    assert incompatible == []


def test_compatibility_apache_with_gpl(scanner: LicenseScanner) -> None:
    """Apache project cannot include GPL deps."""
    incompatible = scanner.check_compatibility("Apache-2.0", ["GPL-2.0", "MIT"])
    assert "GPL-2.0" in incompatible
    assert "MIT" not in incompatible


def test_compatibility_apache_with_agpl(scanner: LicenseScanner) -> None:
    """Apache project cannot include AGPL deps."""
    incompatible = scanner.check_compatibility("Apache-2.0", ["AGPL-3.0"])
    assert "AGPL-3.0" in incompatible


def test_compatibility_mit_with_permissive_only(scanner: LicenseScanner) -> None:
    """MIT project + all permissive deps → empty list."""
    incompatible = scanner.check_compatibility(
        "MIT", ["MIT", "ISC", "BSD-2-Clause", "Apache-2.0"]
    )
    assert incompatible == []


def test_compatibility_gpl2_with_gpl3(scanner: LicenseScanner) -> None:
    """GPL-2.0 project can consume GPL-3.0 dep (both copyleft)."""
    incompatible = scanner.check_compatibility("GPL-2.0", ["GPL-3.0", "AGPL-3.0"])
    assert incompatible == []


def test_compatibility_handles_variations(scanner: LicenseScanner) -> None:
    """Variation strings work in both project_license and dep_licenses."""
    # "MIT License" project, "GPLv3" dep
    incompatible = scanner.check_compatibility("MIT License", ["GPLv3", "Apache License 2.0"])
    assert "GPLv3" in incompatible
    assert "Apache License 2.0" not in incompatible


# ---------------------------------------------------------------------------
# detect_project_license()
# ---------------------------------------------------------------------------

def test_detect_from_pyproject_toml(scanner: LicenseScanner, tmp_path: Path) -> None:
    """Should read license from pyproject.toml [project] table."""
    ppt = tmp_path / "pyproject.toml"
    ppt.write_text('[project]\nname = "mypkg"\nlicense = "MIT"\n', encoding="utf-8")
    result = scanner.detect_project_license(tmp_path)
    assert result == "MIT"


def test_detect_from_package_json(scanner: LicenseScanner, tmp_path: Path) -> None:
    """Should read license from package.json."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"name": "mypkg", "license": "ISC"}), encoding="utf-8")
    result = scanner.detect_project_license(tmp_path)
    assert result == "ISC"


def test_detect_from_license_file(scanner: LicenseScanner, tmp_path: Path) -> None:
    """Should fall back to first line of LICENSE file."""
    lic_file = tmp_path / "LICENSE"
    lic_file.write_text("MIT License\n\nCopyright (c) 2024 ...\n", encoding="utf-8")
    result = scanner.detect_project_license(tmp_path)
    assert result == "MIT License"


def test_detect_returns_none_when_no_files(scanner: LicenseScanner, tmp_path: Path) -> None:
    """Returns None if no license files exist."""
    result = scanner.detect_project_license(tmp_path)
    assert result is None


def test_detect_pyproject_takes_precedence(scanner: LicenseScanner, tmp_path: Path) -> None:
    """pyproject.toml takes precedence over package.json."""
    ppt = tmp_path / "pyproject.toml"
    ppt.write_text('[project]\nlicense = "Apache-2.0"\n', encoding="utf-8")
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"license": "MIT"}), encoding="utf-8")
    result = scanner.detect_project_license(tmp_path)
    assert result == "Apache-2.0"


# ---------------------------------------------------------------------------
# finding metadata shape
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_finding_metadata_keys(scanner: LicenseScanner) -> None:
    """Every finding must carry license, risk_tier, and commercial_use metadata."""
    meta = PackageMeta(pkg=PackageId("npm", "evil-lib", "1.0.0"), license="AGPL-3.0")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    md = findings[0].metadata
    assert "license" in md
    assert "risk_tier" in md
    assert "commercial_use" in md


@pytest.mark.asyncio
async def test_finding_type_is_behavioral(scanner: LicenseScanner) -> None:
    """License findings should use FindingType.BEHAVIORAL."""
    meta = PackageMeta(pkg=PackageId("pypi", "gpl-pkg", "1.0.0"), license="GPL-2.0")
    findings = await scanner.scan([meta])
    assert all(f.finding_type == FindingType.BEHAVIORAL for f in findings)
