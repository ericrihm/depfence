"""Tests for scan statistics module."""

import pytest
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.core.scan_stats import comparison_summary, compute_stats


def _make_finding(ftype=FindingType.KNOWN_VULN, sev=Severity.HIGH, cve=None, fix=None):
    return Finding(
        finding_type=ftype,
        severity=sev,
        package=PackageId("npm", "test-pkg", "1.0.0"),
        title="Test finding",
        detail="Detail",
        cve=cve,
        fix_version=fix,
    )


def _make_result(findings):
    r = ScanResult(target=".", ecosystem="npm")
    r.findings = findings
    r.packages_scanned = 10
    return r


class TestComputeStats:
    def test_empty(self):
        result = _make_result([])
        stats = compute_stats(result)
        assert stats.total_findings == 0
        assert stats.advisory_only_count == 0
        assert stats.beyond_advisory_count == 0

    def test_severity_breakdown(self):
        findings = [
            _make_finding(sev=Severity.CRITICAL),
            _make_finding(sev=Severity.CRITICAL),
            _make_finding(sev=Severity.HIGH),
            _make_finding(sev=Severity.LOW),
        ]
        stats = compute_stats(_make_result(findings))
        assert stats.by_severity["critical"] == 2
        assert stats.by_severity["high"] == 1
        assert stats.by_severity["low"] == 1

    def test_advisory_vs_beyond(self):
        findings = [
            _make_finding(FindingType.KNOWN_VULN),
            _make_finding(FindingType.KNOWN_VULN),
            _make_finding(FindingType.TYPOSQUAT),
            _make_finding(FindingType.BEHAVIORAL),
            _make_finding(FindingType.MALICIOUS),
        ]
        stats = compute_stats(_make_result(findings))
        assert stats.advisory_only_count == 2
        assert stats.beyond_advisory_count == 3

    def test_unique_cves(self):
        findings = [
            _make_finding(cve="CVE-2024-001"),
            _make_finding(cve="CVE-2024-001"),  # duplicate
            _make_finding(cve="CVE-2024-002"),
            _make_finding(cve=None),
        ]
        stats = compute_stats(_make_result(findings))
        assert stats.unique_cves == 2

    def test_actionable_count(self):
        findings = [
            _make_finding(fix="2.0.0"),
            _make_finding(fix="1.5.1"),
            _make_finding(fix=None),
        ]
        stats = compute_stats(_make_result(findings))
        assert stats.actionable_count == 2


class TestComparisonSummary:
    def test_value_add_percentage(self):
        findings = [
            _make_finding(FindingType.KNOWN_VULN),
            _make_finding(FindingType.TYPOSQUAT),
            _make_finding(FindingType.BEHAVIORAL),
            _make_finding(FindingType.MALICIOUS),
        ]
        stats = compute_stats(_make_result(findings))
        summary = comparison_summary(stats)
        assert summary["value_add_percentage"] == 75.0
        assert summary["advisory_findings"] == 1
        assert summary["beyond_advisory_findings"] == 3

    def test_detection_categories(self):
        findings = [
            _make_finding(FindingType.TYPOSQUAT),
            _make_finding(FindingType.SLOPSQUAT),
            _make_finding(FindingType.REPUTATION),
            _make_finding(FindingType.LICENSE),
        ]
        stats = compute_stats(_make_result(findings))
        summary = comparison_summary(stats)
        cats = summary["detection_categories"]
        assert cats["supply_chain_attacks"] == 2
        assert cats["maintainer_risks"] == 1
        assert cats["compliance_issues"] == 1

    def test_empty_produces_zero_percentage(self):
        stats = compute_stats(_make_result([]))
        summary = comparison_summary(stats)
        assert summary["value_add_percentage"] == 0
        assert summary["total_findings"] == 0
