"""Scan statistics and comparison metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from depfence.core.models import Finding, FindingType, Severity, ScanResult


@dataclass
class ScanStats:
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    packages_scanned: int = 0
    ecosystems: list[str] = field(default_factory=list)
    advisory_only_count: int = 0
    beyond_advisory_count: int = 0
    unique_cves: int = 0
    actionable_count: int = 0


def compute_stats(result: ScanResult) -> ScanStats:
    """Compute detailed statistics from a scan result."""
    findings = result.findings
    stats = ScanStats()
    stats.total_findings = len(findings)
    stats.packages_scanned = result.packages_scanned

    # By severity
    for sev in Severity:
        count = sum(1 for f in findings if f.severity == sev)
        if count > 0:
            stats.by_severity[sev.value] = count

    # By finding type
    for ft in FindingType:
        count = sum(1 for f in findings if f.finding_type == ft)
        if count > 0:
            stats.by_type[ft.value] = count

    # Advisory vs beyond-advisory
    advisory_types = {FindingType.KNOWN_VULN}
    stats.advisory_only_count = sum(
        1 for f in findings if f.finding_type in advisory_types
    )
    stats.beyond_advisory_count = stats.total_findings - stats.advisory_only_count

    # Unique CVEs
    cves = {f.cve for f in findings if f.cve}
    stats.unique_cves = len(cves)

    # Actionable (has fix_version)
    stats.actionable_count = sum(1 for f in findings if f.fix_version)

    return stats


def comparison_summary(stats: ScanStats) -> dict:
    """Generate a comparison showing depfence value-add over basic audit tools."""
    total = stats.total_findings
    beyond = stats.beyond_advisory_count
    advisory = stats.advisory_only_count

    pct_beyond = (beyond / total * 100) if total > 0 else 0

    return {
        "total_findings": total,
        "advisory_findings": advisory,
        "beyond_advisory_findings": beyond,
        "value_add_percentage": round(pct_beyond, 1),
        "unique_cves": stats.unique_cves,
        "actionable_fixes": stats.actionable_count,
        "finding_categories": len(stats.by_type),
        "severity_breakdown": stats.by_severity,
        "detection_categories": {
            "known_vulnerabilities": advisory,
            "supply_chain_attacks": sum(
                stats.by_type.get(t.value, 0) for t in [
                    FindingType.TYPOSQUAT, FindingType.SLOPSQUAT,
                    FindingType.MALICIOUS, FindingType.INSTALL_SCRIPT,
                ]
            ),
            "behavioral_anomalies": stats.by_type.get(FindingType.BEHAVIORAL.value, 0),
            "maintainer_risks": sum(
                stats.by_type.get(t.value, 0) for t in [
                    FindingType.MAINTAINER, FindingType.REPUTATION,
                ]
            ),
            "compliance_issues": sum(
                stats.by_type.get(t.value, 0) for t in [
                    FindingType.LICENSE, FindingType.PROVENANCE,
                ]
            ),
        },
    }
