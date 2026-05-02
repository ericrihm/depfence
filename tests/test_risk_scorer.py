"""Tests for risk scoring engine."""

import pytest

from depfence.core.models import Finding, FindingType, Severity
from depfence.core.risk_scorer import (
    PackageRiskScore,
    risk_summary,
    score_all_packages,
    score_package,
)


def _finding(pkg: str, severity: Severity, ftype: FindingType = FindingType.KNOWN_VULN) -> Finding:
    return Finding(
        finding_type=ftype,
        severity=severity,
        package=pkg,
        title=f"Test {severity.name}",
        detail="detail",
    )


def test_score_no_findings():
    result = score_package("npm:lodash@4.17.21", [])
    assert result.score == 0.0
    assert result.grade == "A"


def test_score_single_critical():
    findings = [_finding("npm:lodash@4.17.20", Severity.CRITICAL)]
    result = score_package("npm:lodash@4.17.20", findings)
    assert result.score >= 4.0
    assert result.grade in ("C", "D", "F")


def test_score_multiple_findings():
    findings = [
        _finding("npm:evil-pkg@1.0.0", Severity.CRITICAL, FindingType.BEHAVIORAL),
        _finding("npm:evil-pkg@1.0.0", Severity.HIGH, FindingType.INSTALL_SCRIPT),
        _finding("npm:evil-pkg@1.0.0", Severity.HIGH, FindingType.KNOWN_VULN),
    ]
    result = score_package("npm:evil-pkg@1.0.0", findings)
    assert result.score >= 8.0
    assert result.grade == "F"
    assert result.is_critical


def test_score_capped_at_10():
    findings = [_finding("pkg", Severity.CRITICAL, FindingType.BEHAVIORAL)] * 20
    result = score_package("pkg", findings)
    assert result.score == 10.0


def test_score_all_packages_sorted():
    findings = [
        _finding("npm:safe@1.0", Severity.LOW),
        _finding("npm:risky@1.0", Severity.CRITICAL),
        _finding("npm:risky@1.0", Severity.HIGH),
    ]
    scores = score_all_packages(findings)
    assert scores[0].package == "npm:risky@1.0"
    assert scores[0].score > scores[1].score


def test_grade_assignment():
    assert score_package("a", [_finding("a", Severity.LOW)]).grade in ("A", "B")
    critical_findings = [
        _finding("b", Severity.CRITICAL, FindingType.BEHAVIORAL),
        _finding("b", Severity.CRITICAL, FindingType.KNOWN_VULN),
        _finding("b", Severity.HIGH, FindingType.INSTALL_SCRIPT),
    ]
    assert score_package("b", critical_findings).grade == "F"


def test_risk_summary():
    findings = [
        _finding("pkg1", Severity.CRITICAL, FindingType.BEHAVIORAL),
        _finding("pkg1", Severity.CRITICAL, FindingType.KNOWN_VULN),
        _finding("pkg1", Severity.HIGH),
        _finding("pkg2", Severity.LOW),
        _finding("pkg3", Severity.MEDIUM),
    ]
    scores = score_all_packages(findings)
    summary = risk_summary(scores)
    assert summary["total_packages_scored"] == 3
    assert "top_risks" in summary
    assert len(summary["top_risks"]) <= 10


def test_diversity_bonus():
    single_type = [_finding("pkg", Severity.HIGH, FindingType.KNOWN_VULN)] * 3
    diverse = [
        _finding("pkg", Severity.HIGH, FindingType.KNOWN_VULN),
        _finding("pkg", Severity.HIGH, FindingType.BEHAVIORAL),
        _finding("pkg", Severity.HIGH, FindingType.INSTALL_SCRIPT),
    ]
    score_single = score_package("pkg", single_type)
    score_diverse = score_package("pkg", diverse)
    assert score_diverse.score > score_single.score
