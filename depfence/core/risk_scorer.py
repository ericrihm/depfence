"""Supply chain risk scoring engine.

Aggregates multiple signals into a composite risk score per package.
Scores range from 0.0 (no risk) to 10.0 (critical supply chain threat).

Signal categories:
- Vulnerability severity (CVEs, known malware)
- Maintainer trust (ownership changes, single maintainer)
- Freshness (last release, deprecation status)
- Behavioral indicators (obfuscation, install scripts, network)
- Provenance (unpinned deps, no signing, no reproducible builds)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from depfence.core.models import Finding, FindingType, Severity


@dataclass
class PackageRiskScore:
    package: str
    score: float
    grade: str  # A-F
    signals: list[str] = field(default_factory=list)
    findings_count: int = 0

    @property
    def is_critical(self) -> bool:
        return self.score >= 8.0


_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 2.5,
    Severity.MEDIUM: 1.5,
    Severity.LOW: 0.5,
}

_FINDING_TYPE_MULTIPLIERS = {
    FindingType.KNOWN_VULN: 1.2,
    FindingType.BEHAVIORAL: 1.5,
    FindingType.INSTALL_SCRIPT: 1.3,
    FindingType.PROVENANCE: 0.8,
}


def score_package(package_key: str, findings: list[Finding]) -> PackageRiskScore:
    """Compute composite risk score for a single package."""
    if not findings:
        return PackageRiskScore(package=package_key, score=0.0, grade="A")

    raw_score = 0.0
    signals: list[str] = []

    for f in findings:
        weight = _SEVERITY_WEIGHTS.get(f.severity, 1.0)
        multiplier = _FINDING_TYPE_MULTIPLIERS.get(f.finding_type, 1.0)
        raw_score += weight * multiplier
        signals.append(f"{f.severity.name}: {f.title}")

    # Diversity penalty: more signal categories = higher confidence in risk
    finding_types = set(f.finding_type for f in findings)
    diversity_bonus = min(len(finding_types) * 0.3, 1.5)
    raw_score += diversity_bonus

    # Cap at 10
    final_score = min(raw_score, 10.0)
    grade = _score_to_grade(final_score)

    return PackageRiskScore(
        package=package_key,
        score=round(final_score, 1),
        grade=grade,
        signals=signals,
        findings_count=len(findings),
    )


def score_all_packages(findings: list[Finding]) -> list[PackageRiskScore]:
    """Score all packages from a scan result, sorted by risk (highest first)."""
    by_package: dict[str, list[Finding]] = {}
    for f in findings:
        by_package.setdefault(f.package, []).append(f)

    scores = [score_package(pkg, pkg_findings) for pkg, pkg_findings in by_package.items()]
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores


def risk_summary(scores: list[PackageRiskScore]) -> dict:
    """Generate a risk summary for reporting."""
    critical = [s for s in scores if s.grade == "F"]
    high = [s for s in scores if s.grade == "D"]
    medium = [s for s in scores if s.grade == "C"]
    low = [s for s in scores if s.grade in ("A", "B")]

    avg_score = sum(s.score for s in scores) / max(len(scores), 1)

    return {
        "total_packages_scored": len(scores),
        "average_score": round(avg_score, 1),
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": len(medium),
        "low_count": len(low),
        "top_risks": [{"package": s.package, "score": s.score, "grade": s.grade} for s in scores[:10]],
    }


def _score_to_grade(score: float) -> str:
    if score >= 8.0:
        return "F"
    elif score >= 6.0:
        return "D"
    elif score >= 4.0:
        return "C"
    elif score >= 2.0:
        return "B"
    return "A"
