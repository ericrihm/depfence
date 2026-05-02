"""Tests for core data models."""

from depfence.core.models import (
    Finding,
    FindingType,
    PackageId,
    PackageMeta,
    ScanResult,
    Severity,
)


def test_package_id_str():
    pkg = PackageId("npm", "lodash", "4.17.21")
    assert str(pkg) == "npm:lodash@4.17.21"


def test_package_id_no_version():
    pkg = PackageId("pypi", "requests")
    assert str(pkg) == "pypi:requests"


def test_scan_result_counts():
    result = ScanResult(target=".", ecosystem="npm")
    result.findings = [
        Finding(FindingType.KNOWN_VULN, Severity.CRITICAL, PackageId("npm", "a"), "t", "d"),
        Finding(FindingType.KNOWN_VULN, Severity.HIGH, PackageId("npm", "b"), "t", "d"),
        Finding(FindingType.BEHAVIORAL, Severity.MEDIUM, PackageId("npm", "c"), "t", "d"),
    ]
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.has_blockers is True


def test_scan_result_no_blockers():
    result = ScanResult(target=".", ecosystem="npm")
    result.findings = [
        Finding(FindingType.REPUTATION, Severity.LOW, PackageId("npm", "x"), "t", "d"),
    ]
    assert result.has_blockers is False


def test_malicious_is_blocker():
    result = ScanResult(target=".", ecosystem="npm")
    result.findings = [
        Finding(FindingType.MALICIOUS, Severity.LOW, PackageId("npm", "evil"), "t", "d"),
    ]
    assert result.has_blockers is True
