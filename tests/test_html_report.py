"""Tests for the HTML report generator."""

from __future__ import annotations

from depfence.core.html_report import generate_html_report
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity


def _make_result(findings: list[Finding] | None = None, packages_scanned: int = 10) -> ScanResult:
    result = ScanResult(target="/tmp/myproject", ecosystem="npm")
    result.packages_scanned = packages_scanned
    result.findings = findings or []
    return result


def _make_finding(
    severity: Severity = Severity.HIGH,
    finding_type: FindingType = FindingType.KNOWN_VULN,
    pkg_name: str = "lodash",
    ecosystem: str = "npm",
    version: str = "4.17.20",
    title: str = "Prototype Pollution",
    detail: str = "lodash before 4.17.21 is vulnerable",
    fix_version: str | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        severity=severity,
        package=PackageId(ecosystem, pkg_name, version),
        title=title,
        detail=detail,
        fix_version=fix_version,
    )


# ── test_generates_valid_html ──────────────────────────────────────────────────

def test_generates_valid_html():
    result = _make_result()
    html = generate_html_report(result, project_name="MyProject")
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "<body" in html
    assert "</html>" in html
    assert "</body>" in html


def test_html_contains_project_name():
    result = _make_result()
    html = generate_html_report(result, project_name="AcmeCorp")
    assert "AcmeCorp" in html


def test_html_contains_scan_target():
    result = _make_result()
    html = generate_html_report(result, project_name="X")
    assert "/tmp/myproject" in html


# ── test_includes_findings ─────────────────────────────────────────────────────

def test_includes_findings():
    finding = _make_finding(
        pkg_name="requests",
        ecosystem="pypi",
        title="SSRF vulnerability",
        detail="requests 2.x allows SSRF via redirect",
    )
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="Proj")

    assert "requests" in html
    assert "SSRF vulnerability" in html
    assert "requests 2.x allows SSRF via redirect" in html
    assert "pypi" in html.lower()


def test_includes_extra_findings():
    base_finding = _make_finding(pkg_name="express", ecosystem="npm", title="Base vuln")
    extra_finding = _make_finding(pkg_name="werkzeug", ecosystem="pypi", title="Extra vuln")
    result = _make_result(findings=[base_finding])
    html = generate_html_report(result, project_name="P", extra_findings=[extra_finding])

    assert "express" in html
    assert "Base vuln" in html
    assert "werkzeug" in html
    assert "Extra vuln" in html


def test_package_version_shown():
    finding = _make_finding(pkg_name="axios", version="0.21.0")
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "0.21.0" in html


def test_packages_scanned_count():
    result = _make_result(packages_scanned=42)
    html = generate_html_report(result, project_name="P")
    assert "42" in html


# ── test_severity_badges ───────────────────────────────────────────────────────

def test_severity_badges_critical():
    finding = _make_finding(severity=Severity.CRITICAL)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "CRITICAL" in html
    # Critical color should be present in the badge styling
    assert "#ff4d4f" in html


def test_severity_badges_high():
    finding = _make_finding(severity=Severity.HIGH)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "HIGH" in html
    assert "#ff7a45" in html


def test_severity_badges_medium():
    finding = _make_finding(severity=Severity.MEDIUM)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "MEDIUM" in html
    assert "#ffc53d" in html


def test_severity_badges_low():
    finding = _make_finding(severity=Severity.LOW)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "LOW" in html
    assert "#52c41a" in html


def test_status_badge_critical():
    finding = _make_finding(severity=Severity.CRITICAL)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    # Overall status badge should say CRITICAL
    assert "CRITICAL" in html


def test_status_badge_pass():
    result = _make_result(findings=[])
    html = generate_html_report(result, project_name="P")
    assert "PASS" in html


def test_status_badge_warn():
    finding = _make_finding(severity=Severity.HIGH)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "WARN" in html


# ── test_empty_findings ────────────────────────────────────────────────────────

def test_empty_findings_produces_valid_html():
    result = _make_result(findings=[])
    html = generate_html_report(result, project_name="EmptyProject")
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "<body" in html


def test_empty_findings_shows_no_issues_message():
    result = _make_result(findings=[])
    html = generate_html_report(result, project_name="EmptyProject")
    assert "no issues" in html.lower() or "No security issues" in html


def test_empty_findings_zero_counts():
    result = _make_result(findings=[], packages_scanned=5)
    html = generate_html_report(result, project_name="EmptyProject")
    # All severity counters should show 0
    assert ">0<" in html or "0</div>" in html


def test_empty_findings_pass_status():
    result = _make_result(findings=[])
    html = generate_html_report(result, project_name="EmptyProject")
    assert "PASS" in html


# ── fix suggestions ────────────────────────────────────────────────────────────

def test_fix_suggestions_shown_when_fix_version_present():
    finding = _make_finding(
        pkg_name="lodash",
        severity=Severity.HIGH,
        title="Prototype Pollution",
        fix_version="4.17.21",
    )
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "4.17.21" in html
    assert "Auto-fixable" in html


def test_no_fix_section_when_no_fix_versions():
    finding = _make_finding(severity=Severity.HIGH, fix_version=None)
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name="P")
    assert "Auto-fixable" not in html


# ── JavaScript / filtering ─────────────────────────────────────────────────────

def test_filter_javascript_present():
    result = _make_result()
    html = generate_html_report(result, project_name="P")
    assert "<script>" in html or "<script" in html
    assert "applyFilters" in html
    assert "filter-sev" in html
    assert "filter-eco" in html


# ── HTML escaping ──────────────────────────────────────────────────────────────

def test_html_special_chars_escaped():
    finding = _make_finding(
        pkg_name="<script>alert(1)</script>",
        title='XSS <img src=x onerror="alert(1)">',
        detail="Detail with <b>bold</b> & 'quotes'",
    )
    result = _make_result(findings=[finding])
    html = generate_html_report(result, project_name='Project "X" & <Y>')

    # Raw dangerous strings must NOT appear unescaped
    assert "<script>alert(1)</script>" not in html
    assert 'onerror="alert(1)"' not in html
    # Escaped versions should be present
    assert "&lt;script&gt;" in html or "&#x27;" in html or "&amp;" in html
