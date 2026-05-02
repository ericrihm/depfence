"""Tests for compliance report generator."""

from datetime import datetime
from pathlib import Path

import pytest

from depfence.core.models import Finding, FindingType, ScanResult, Severity
from depfence.reporters.compliance_report import (
    generate_compliance_report,
    render_compliance_json,
    render_compliance_markdown,
)


def _make_result(findings: list[Finding]) -> ScanResult:
    result = ScanResult(target=".", ecosystem="npm", findings=findings)
    return result


def _finding(pkg: str, sev: Severity, ftype: FindingType = FindingType.KNOWN_VULN) -> Finding:
    return Finding(
        finding_type=ftype,
        severity=sev,
        package=pkg,
        title=f"Test {sev.name}",
        detail="detail",
    )


class TestGenerateReport:
    def test_basic_report_structure(self, tmp_path):
        findings = [_finding("npm:lodash@4.17.20", Severity.HIGH)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)

        assert "meta" in report
        assert "summary" in report
        assert "risk_scores" in report
        assert "license_compliance" in report
        assert "findings" in report
        assert report["meta"]["tool"] == "depfence"

    def test_pass_when_no_critical(self, tmp_path):
        findings = [_finding("npm:pkg@1.0", Severity.MEDIUM)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        assert report["summary"]["pass"] is True

    def test_fail_when_critical(self, tmp_path):
        findings = [_finding("npm:evil@1.0", Severity.CRITICAL)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        assert report["summary"]["pass"] is False

    def test_severity_breakdown(self, tmp_path):
        findings = [
            _finding("a", Severity.CRITICAL),
            _finding("b", Severity.HIGH),
            _finding("c", Severity.HIGH),
            _finding("d", Severity.LOW),
        ]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        assert report["summary"]["severity_breakdown"]["CRITICAL"] == 1
        assert report["summary"]["severity_breakdown"]["HIGH"] == 2

    def test_empty_findings(self, tmp_path):
        result = _make_result([])
        report = generate_compliance_report(result, tmp_path)
        assert report["summary"]["total_findings"] == 0
        assert report["summary"]["pass"] is True


class TestMarkdownRender:
    def test_renders_markdown(self, tmp_path):
        findings = [_finding("npm:lodash@4.17.20", Severity.HIGH)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        md = render_compliance_markdown(report)
        assert "# Supply Chain Compliance Report" in md
        assert "PASS" in md
        assert "Total Findings" in md

    def test_fail_status_shown(self, tmp_path):
        findings = [_finding("npm:evil@1.0", Severity.CRITICAL)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        md = render_compliance_markdown(report)
        assert "FAIL" in md


class TestJsonRender:
    def test_renders_valid_json(self, tmp_path):
        import json
        findings = [_finding("npm:pkg@1.0", Severity.MEDIUM)]
        result = _make_result(findings)
        report = generate_compliance_report(result, tmp_path)
        json_str = render_compliance_json(report)
        parsed = json.loads(json_str)
        assert parsed["meta"]["tool"] == "depfence"
