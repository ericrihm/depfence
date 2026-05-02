"""Project health dashboard — unified supply chain security posture.

Aggregates all scanner results into a single health score with
actionable recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from depfence.core.models import Finding, FindingType, ScanResult, Severity
from depfence.core.risk_scorer import score_all_packages


@dataclass
class HealthMetric:
    name: str
    score: float  # 0-100
    status: str  # "good", "warning", "critical"
    detail: str


@dataclass
class HealthDashboard:
    overall_score: float  # 0-100
    grade: str  # A+ to F
    metrics: list[HealthMetric] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


def compute_health(result: ScanResult, has_lockfile: bool = True, has_policy: bool = False) -> HealthDashboard:
    """Compute project health dashboard from scan results."""
    metrics: list[HealthMetric] = []
    recommendations: list[str] = []

    # 1. Vulnerability score (0-100, 100 = no vulns)
    vuln_score = _vuln_metric(result.findings)
    metrics.append(vuln_score)

    # 2. Supply chain hygiene
    hygiene_score = _hygiene_metric(result.findings, has_lockfile, has_policy)
    metrics.append(hygiene_score)

    # 3. Dependency freshness
    freshness_score = _freshness_metric(result.findings)
    metrics.append(freshness_score)

    # 4. Code integrity
    integrity_score = _integrity_metric(result.findings)
    metrics.append(integrity_score)

    # Overall score (weighted average)
    weights = {"Vulnerabilities": 0.35, "Supply Chain Hygiene": 0.25, "Freshness": 0.15, "Code Integrity": 0.25}
    total_weight = sum(weights.get(m.name, 0.2) for m in metrics)
    overall = sum(m.score * weights.get(m.name, 0.2) for m in metrics) / max(total_weight, 0.01)

    # Recommendations
    if vuln_score.score < 70:
        recommendations.append("Fix critical/high vulnerabilities immediately (run `depfence fix . --apply`)")
    if not has_lockfile:
        recommendations.append("Add a lockfile (package-lock.json, yarn.lock, or requirements.txt with ==)")
    if not has_policy:
        recommendations.append("Add a .depfence-policy.yml to enforce security standards")
    if hygiene_score.score < 60:
        recommendations.append("Review packages with behavioral findings (run `depfence scan . --format json`)")
    if freshness_score.score < 50:
        recommendations.append("Update stale dependencies (run `depfence update-plan .`)")

    grade = _score_to_grade(overall)

    return HealthDashboard(
        overall_score=round(overall, 1),
        grade=grade,
        metrics=metrics,
        recommendations=recommendations,
    )


def render_health_text(dashboard: HealthDashboard) -> str:
    """Render dashboard as text for CLI display."""
    lines = []
    lines.append(f"Supply Chain Health: {dashboard.grade} ({dashboard.overall_score:.0f}/100)")
    lines.append("")

    for m in dashboard.metrics:
        icon = {"good": "+", "warning": "!", "critical": "X"}[m.status]
        lines.append(f"  [{icon}] {m.name}: {m.score:.0f}/100 — {m.detail}")

    if dashboard.recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for r in dashboard.recommendations:
            lines.append(f"  - {r}")

    return "\n".join(lines)


def _vuln_metric(findings: list[Finding]) -> HealthMetric:
    vuln_findings = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    critical = sum(1 for f in vuln_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in vuln_findings if f.severity == Severity.HIGH)

    if critical > 0:
        score = max(0, 30 - critical * 15)
        return HealthMetric("Vulnerabilities", score, "critical", f"{critical} critical, {high} high")
    elif high > 0:
        score = max(30, 70 - high * 10)
        return HealthMetric("Vulnerabilities", score, "warning", f"{high} high severity")
    elif vuln_findings:
        score = max(60, 90 - len(vuln_findings) * 5)
        return HealthMetric("Vulnerabilities", score, "warning", f"{len(vuln_findings)} medium/low")
    return HealthMetric("Vulnerabilities", 100, "good", "No known vulnerabilities")


def _hygiene_metric(findings: list[Finding], has_lockfile: bool, has_policy: bool) -> HealthMetric:
    behavioral = [f for f in findings if f.finding_type == FindingType.BEHAVIORAL]
    install_script = [f for f in findings if f.finding_type == FindingType.INSTALL_SCRIPT]
    score = 100.0

    if not has_lockfile:
        score -= 30
    if not has_policy:
        score -= 10
    score -= len(behavioral) * 8
    score -= len(install_script) * 12

    score = max(0, score)
    status = "good" if score >= 70 else ("warning" if score >= 40 else "critical")
    issues = len(behavioral) + len(install_script)
    detail = f"{issues} behavioral findings" if issues else "Clean"
    if not has_lockfile:
        detail += ", no lockfile"

    return HealthMetric("Supply Chain Hygiene", score, status, detail)


def _freshness_metric(findings: list[Finding]) -> HealthMetric:
    stale = [f for f in findings if "stale" in f.title.lower() or "deprecated" in f.title.lower() or "Pre-1.0" in f.title]
    score = max(0, 100 - len(stale) * 15)
    status = "good" if score >= 70 else ("warning" if score >= 40 else "critical")
    return HealthMetric("Freshness", score, status, f"{len(stale)} stale/deprecated packages" if stale else "All deps maintained")


def _integrity_metric(findings: list[Finding]) -> HealthMetric:
    provenance = [f for f in findings if f.finding_type == FindingType.PROVENANCE]
    score = max(0, 100 - len(provenance) * 10)
    status = "good" if score >= 70 else ("warning" if score >= 40 else "critical")
    return HealthMetric("Code Integrity", score, status, f"{len(provenance)} provenance issues" if provenance else "Strong provenance")


def _score_to_grade(score: float) -> str:
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"
