"""Enhanced tests for the HTML report generator."""

from __future__ import annotations

import re

import pytest

from depfence.core.html_report import generate_html_report
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(findings=None, packages_scanned=10, target="/tmp/myproject"):
    result = ScanResult(target=target, ecosystem="npm")
    result.packages_scanned = packages_scanned
    result.findings = findings or []
    return result


def _make_finding(
    severity=Severity.HIGH,
    finding_type=FindingType.KNOWN_VULN,
    pkg_name="lodash",
    ecosystem="npm",
    version="4.17.20",
    title="Prototype Pollution",
    detail="lodash before 4.17.21 is vulnerable",
    fix_version=None,
    cve=None,
    metadata=None,
):
    return Finding(
        finding_type=finding_type,
        severity=severity,
        package=PackageId(ecosystem, pkg_name, version),
        title=title,
        detail=detail,
        fix_version=fix_version,
        cve=cve,
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# 1. Valid HTML structure
# ---------------------------------------------------------------------------

def test_valid_html_doctype():
    result = _make_result()
    out = generate_html_report(result, project_name="TestProject")
    assert out.strip().startswith("<!DOCTYPE html>")


def test_valid_html_tags():
    result = _make_result()
    out = generate_html_report(result, project_name="TestProject")
    assert "<html" in out
    assert "<head>" in out or "<head" in out
    assert "<body>" in out or "<body" in out
    assert "</html>" in out


# ---------------------------------------------------------------------------
# 2. Section presence
# ---------------------------------------------------------------------------

def test_section_executive_summary():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "Executive Summary" in out


def test_section_severity_breakdown():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "Severity Breakdown" in out


def test_section_findings():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "Findings" in out


def test_section_detection_categories_present_when_findings():
    finding = _make_finding()
    result = _make_result(findings=[finding])
    out = generate_html_report(result, project_name="P")
    assert "Detection Categories" in out


def test_section_recommendations():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "Recommendations" in out


def test_section_footer_with_version():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "depfence v" in out
    assert "footer" in out.lower()


# ---------------------------------------------------------------------------
# 3. Severity badge colours
# ---------------------------------------------------------------------------

def test_badge_critical_color():
    result = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
    out = generate_html_report(result, project_name="P")
    assert "#ff4d4f" in out


def test_badge_high_color():
    result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
    out = generate_html_report(result, project_name="P")
    assert "#ff7a45" in out


def test_badge_medium_color():
    result = _make_result(findings=[_make_finding(severity=Severity.MEDIUM)])
    out = generate_html_report(result, project_name="P")
    assert "#ffc53d" in out


def test_badge_low_color():
    result = _make_result(findings=[_make_finding(severity=Severity.LOW)])
    out = generate_html_report(result, project_name="P")
    assert "#52c41a" in out


# ---------------------------------------------------------------------------
# 4. Zero findings — "clean" message
# ---------------------------------------------------------------------------

def test_zero_findings_clean_message():
    result = _make_result(findings=[])
    out = generate_html_report(result, project_name="Clean")
    assert "clean" in out.lower() or "no security issues" in out.lower()


def test_zero_findings_pass_status():
    result = _make_result(findings=[])
    out = generate_html_report(result, project_name="Clean")
    assert "PASS" in out


def test_zero_findings_valid_html():
    result = _make_result(findings=[])
    out = generate_html_report(result, project_name="Clean")
    assert "<!DOCTYPE html>" in out
    assert "</html>" in out


# ---------------------------------------------------------------------------
# 5. Critical findings appear before lower-severity ones
# ---------------------------------------------------------------------------

def test_critical_first_in_findings_table():
    critical = _make_finding(severity=Severity.CRITICAL, pkg_name="evil-pkg", title="Critical Issue")
    low = _make_finding(severity=Severity.LOW, pkg_name="low-pkg", title="Low Issue")
    result = _make_result(findings=[low, critical])  # intentionally reversed
    out = generate_html_report(result, project_name="P")
    # CRITICAL badge should appear before LOW badge in the table body
    crit_pos = out.find("badge-critical")
    low_pos = out.find("badge-low")
    assert crit_pos != -1 and low_pos != -1
    assert crit_pos < low_pos, "Critical finding should appear before low finding in output"


def test_critical_before_high_before_medium():
    findings = [
        _make_finding(severity=Severity.MEDIUM, pkg_name="m-pkg", title="Medium Issue"),
        _make_finding(severity=Severity.CRITICAL, pkg_name="c-pkg", title="Critical Issue"),
        _make_finding(severity=Severity.HIGH, pkg_name="h-pkg", title="High Issue"),
    ]
    result = _make_result(findings=findings)
    out = generate_html_report(result, project_name="P")
    crit_pos = out.find("badge-critical")
    high_pos = out.find("badge-high")
    med_pos = out.find("badge-medium")
    assert crit_pos < high_pos < med_pos


# ---------------------------------------------------------------------------
# 6. Dark mode CSS
# ---------------------------------------------------------------------------

def test_dark_mode_media_query_present():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "prefers-color-scheme: dark" in out


def test_dark_mode_has_dark_bg_variable():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    # Dark background token should appear inside the dark media query
    dark_section_start = out.find("prefers-color-scheme: dark")
    assert dark_section_start != -1
    dark_block = out[dark_section_start:dark_section_start + 400]
    assert "#0d1117" in dark_block or "0d1117" in dark_block


# ---------------------------------------------------------------------------
# 7. Project name in header
# ---------------------------------------------------------------------------

def test_project_name_in_header():
    result = _make_result()
    out = generate_html_report(result, project_name="MyAwesomeProject")
    assert "MyAwesomeProject" in out


def test_project_name_in_title_tag():
    result = _make_result()
    out = generate_html_report(result, project_name="TitleProject")
    assert "<title>" in out.lower() or "title" in out.lower()
    assert "TitleProject" in out


def test_empty_project_name_falls_back_to_target():
    result = _make_result(target="/path/to/myrepo")
    out = generate_html_report(result, project_name="")
    assert "myrepo" in out


# ---------------------------------------------------------------------------
# 8. EPSS / KEV metadata
# ---------------------------------------------------------------------------

def test_epss_score_shown_when_in_metadata():
    finding = _make_finding(
        cve="CVE-2023-1234",
        metadata={"epss_score": 0.75},
    )
    result = _make_result(findings=[finding])
    out = generate_html_report(result, project_name="P")
    assert "0.750" in out or "0.75" in out


def test_epss_score_via_enrichments_map():
    finding = _make_finding(cve="CVE-2023-9999")
    result = _make_result(findings=[finding])
    out = generate_html_report(
        result,
        project_name="P",
        enrichments={"epss": {"CVE-2023-9999": 0.88}},
    )
    assert "0.880" in out or "0.88" in out


def test_kev_count_in_executive_summary():
    finding = _make_finding(cve="CVE-2023-0001")
    result = _make_result(findings=[finding])
    out = generate_html_report(
        result,
        project_name="P",
        enrichments={"kev": ["CVE-2023-0001"]},
    )
    assert "KEV" in out


def test_epss_high_count_card_present():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    # The EPSS card label should always appear
    assert "EPSS" in out


# ---------------------------------------------------------------------------
# 9. Grade badge
# ---------------------------------------------------------------------------

def test_grade_f_for_critical():
    result = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
    out = generate_html_report(result, project_name="P")
    assert "grade-badge" in out
    # Grade F should be present
    assert ">F<" in out


def test_grade_a_for_no_findings():
    result = _make_result(findings=[])
    out = generate_html_report(result, project_name="P")
    assert ">A<" in out


# ---------------------------------------------------------------------------
# 10. Auto-fixable section
# ---------------------------------------------------------------------------

def test_autofixable_section_shown_when_fix_version_present():
    finding = _make_finding(fix_version="4.17.21")
    result = _make_result(findings=[finding])
    out = generate_html_report(result, project_name="P")
    assert "Auto-fixable" in out
    assert "4.17.21" in out


def test_autofixable_section_absent_when_no_fix():
    finding = _make_finding(fix_version=None)
    result = _make_result(findings=[finding])
    out = generate_html_report(result, project_name="P")
    assert "Auto-fixable" not in out


# ---------------------------------------------------------------------------
# 11. Supply Chain Health section
# ---------------------------------------------------------------------------

def test_supply_chain_health_section_shown_when_enrichment_provided():
    result = _make_result()
    enrichments = {
        "supply_chain_health": [
            {"name": "2FA Enforcement", "status": "PASS", "detail": "All maintainers use 2FA"},
            {"name": "Branch Protection", "status": "WARN", "detail": "No required reviews"},
        ]
    }
    out = generate_html_report(result, project_name="P", enrichments=enrichments)
    assert "Supply Chain Health" in out
    assert "2FA Enforcement" in out
    assert "Branch Protection" in out


def test_supply_chain_health_absent_without_enrichments():
    result = _make_result()
    out = generate_html_report(result, project_name="P")
    assert "Supply Chain Health" not in out


# ---------------------------------------------------------------------------
# 12. HTML escaping
# ---------------------------------------------------------------------------

def test_xss_in_project_name_escaped():
    result = _make_result()
    out = generate_html_report(result, project_name='<script>alert(1)</script>')
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_xss_in_package_name_escaped():
    finding = _make_finding(pkg_name='<img src=x onerror=alert(1)>')
    result = _make_result(findings=[finding])
    out = generate_html_report(result, project_name="P")
    assert '<img src=x onerror=alert(1)>' not in out


# ---------------------------------------------------------------------------
# 13. Backward compat: extra_findings kwarg still works
# ---------------------------------------------------------------------------

def test_extra_findings_kwarg_backward_compat():
    base = _make_finding(pkg_name="base-pkg", title="Base vuln")
    extra = _make_finding(pkg_name="extra-pkg", title="Extra vuln")
    result = _make_result(findings=[base])
    out = generate_html_report(result, project_name="P", extra_findings=[extra])
    assert "base-pkg" in out
    assert "extra-pkg" in out


# ---------------------------------------------------------------------------
# 14. Scan stats visible
# ---------------------------------------------------------------------------

def test_packages_scanned_count_in_output():
    result = _make_result(packages_scanned=99)
    out = generate_html_report(result, project_name="P")
    assert "99" in out


def test_total_findings_count_in_summary():
    findings = [_make_finding() for _ in range(3)]
    result = _make_result(findings=findings)
    out = generate_html_report(result, project_name="P")
    # 3 total findings card value
    assert ">3<" in out or "3</div>" in out


# ---------------------------------------------------------------------------
# 15. Donut / detection categories not shown for zero findings
# ---------------------------------------------------------------------------

def test_detection_categories_absent_for_zero_findings():
    result = _make_result(findings=[])
    out = generate_html_report(result, project_name="P")
    assert "Detection Categories" not in out
