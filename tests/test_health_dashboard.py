"""Tests for project health dashboard."""

import pytest

from depfence.core.health_dashboard import (
    HealthDashboard,
    compute_health,
    render_health_text,
)
from depfence.core.models import Finding, FindingType, ScanResult, Severity


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(target=".", ecosystem="npm", findings=findings)


def _finding(sev: Severity, ftype: FindingType = FindingType.KNOWN_VULN) -> Finding:
    return Finding(finding_type=ftype, severity=sev, package="pkg:test", title="Test", detail="detail")


class TestComputeHealth:
    def test_perfect_score(self):
        result = _result([])
        dashboard = compute_health(result, has_lockfile=True, has_policy=True)
        assert dashboard.overall_score == 100.0
        assert dashboard.grade == "A+"

    def test_critical_vulns_tank_score(self):
        result = _result([_finding(Severity.CRITICAL), _finding(Severity.CRITICAL)])
        dashboard = compute_health(result)
        assert dashboard.overall_score < 70
        assert dashboard.grade in ("D", "F")

    def test_no_lockfile_reduces_score(self):
        result = _result([])
        dashboard = compute_health(result, has_lockfile=False)
        assert dashboard.overall_score < 95

    def test_recommendations_generated(self):
        result = _result([_finding(Severity.CRITICAL)])
        dashboard = compute_health(result, has_lockfile=False, has_policy=False)
        assert len(dashboard.recommendations) >= 2
        assert any("lockfile" in r for r in dashboard.recommendations)

    def test_behavioral_findings_affect_hygiene(self):
        findings = [_finding(Severity.HIGH, FindingType.BEHAVIORAL)] * 5
        result = _result(findings)
        dashboard = compute_health(result)
        hygiene = next(m for m in dashboard.metrics if m.name == "Supply Chain Hygiene")
        assert hygiene.score < 70


class TestRenderHealth:
    def test_renders_text(self):
        result = _result([_finding(Severity.HIGH)])
        dashboard = compute_health(result)
        text = render_health_text(dashboard)
        assert "Supply Chain Health" in text
        assert "Vulnerabilities" in text

    def test_empty_project_shows_a_plus(self):
        result = _result([])
        dashboard = compute_health(result, has_lockfile=True, has_policy=True)
        text = render_health_text(dashboard)
        assert "A+" in text
