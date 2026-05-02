"""Compliance report generator — produces a comprehensive supply chain security report.

Combines:
- License compatibility analysis
- Vulnerability summary
- Risk scores
- SBOM metadata
- Policy compliance status

Output formats: JSON, Markdown
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from depfence import __version__
from depfence.core.license_compat import check_license_compatibility, detect_project_license
from depfence.core.models import Finding, ScanResult, Severity
from depfence.core.risk_scorer import risk_summary, score_all_packages


def generate_compliance_report(
    result: ScanResult,
    project_dir: Path,
    dependencies: list[dict] | None = None,
) -> dict:
    """Generate a comprehensive compliance report as a dict."""
    project_license = detect_project_license(project_dir)
    scores = score_all_packages(result.findings)
    summary = risk_summary(scores)

    license_conflicts = []
    if dependencies and project_license:
        conflicts = check_license_compatibility(project_license, dependencies)
        license_conflicts = [
            {
                "package": c.package,
                "package_license": c.package_license,
                "project_license": c.project_license,
                "reason": c.reason,
                "severity": c.severity,
            }
            for c in conflicts
        ]

    sev_counts = _severity_breakdown(result.findings)

    report = {
        "meta": {
            "tool": "depfence",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project": str(project_dir),
            "project_license": project_license or "unknown",
        },
        "summary": {
            "total_findings": len(result.findings),
            "severity_breakdown": sev_counts,
            "risk_score_average": summary["average_score"],
            "critical_packages": summary["critical_count"],
            "license_conflicts": len(license_conflicts),
            "pass": _is_passing(result.findings, license_conflicts),
        },
        "risk_scores": {
            "top_risks": summary["top_risks"],
            "total_scored": summary["total_packages_scored"],
        },
        "license_compliance": {
            "project_license": project_license or "unknown",
            "conflicts": license_conflicts,
        },
        "vulnerability_summary": {
            "by_type": _findings_by_type(result.findings),
            "by_ecosystem": _findings_by_ecosystem(result.findings),
        },
        "findings": [
            {
                "package": f.package,
                "severity": f.severity.name,
                "type": f.finding_type.value,
                "title": f.title,
                "detail": f.detail,
                "cve": f.cve,
                "fix_version": f.fix_version,
            }
            for f in sorted(result.findings, key=lambda x: x.severity.value)
        ],
    }

    return report


def render_compliance_markdown(report: dict) -> str:
    """Render compliance report as Markdown."""
    lines = []
    meta = report["meta"]
    summary = report["summary"]

    status = "PASS" if summary["pass"] else "FAIL"
    lines.append(f"# Supply Chain Compliance Report")
    lines.append("")
    lines.append(f"**Status:** {status}")
    lines.append(f"**Project:** {meta['project']}")
    lines.append(f"**License:** {meta['project_license']}")
    lines.append(f"**Generated:** {meta['generated_at']}")
    lines.append(f"**Tool:** depfence v{meta['version']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Findings | {summary['total_findings']} |")
    lines.append(f"| Critical | {summary['severity_breakdown'].get('CRITICAL', 0)} |")
    lines.append(f"| High | {summary['severity_breakdown'].get('HIGH', 0)} |")
    lines.append(f"| Medium | {summary['severity_breakdown'].get('MEDIUM', 0)} |")
    lines.append(f"| Low | {summary['severity_breakdown'].get('LOW', 0)} |")
    lines.append(f"| Avg Risk Score | {summary['risk_score_average']:.1f} |")
    lines.append(f"| License Conflicts | {summary['license_conflicts']} |")
    lines.append("")

    # Top risks
    top_risks = report["risk_scores"]["top_risks"]
    if top_risks:
        lines.append("## Top Risk Packages")
        lines.append("")
        lines.append("| Package | Score | Grade |")
        lines.append("|---------|-------|-------|")
        for r in top_risks[:10]:
            lines.append(f"| {r['package']} | {r['score']} | {r['grade']} |")
        lines.append("")

    # License conflicts
    conflicts = report["license_compliance"]["conflicts"]
    if conflicts:
        lines.append("## License Conflicts")
        lines.append("")
        for c in conflicts:
            sev_marker = "**ERROR**" if c["severity"] == "error" else "WARNING"
            lines.append(f"- [{sev_marker}] `{c['package']}` ({c['package_license']}) — {c['reason']}")
        lines.append("")

    # Findings by type
    by_type = report["vulnerability_summary"]["by_type"]
    if by_type:
        lines.append("## Findings by Category")
        lines.append("")
        for ftype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{ftype}**: {count}")
        lines.append("")

    return "\n".join(lines)


def render_compliance_json(report: dict) -> str:
    """Render compliance report as JSON."""
    return json.dumps(report, indent=2)


def _severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    return counts


def _findings_by_type(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.finding_type.value] = counts.get(f.finding_type.value, 0) + 1
    return counts


def _findings_by_ecosystem(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        eco = f.package.split(":")[0] if ":" in f.package else "unknown"
        counts[eco] = counts.get(eco, 0) + 1
    return counts


def _is_passing(findings: list[Finding], license_conflicts: list[dict]) -> bool:
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_license_error = any(c["severity"] == "error" for c in license_conflicts)
    return not has_critical and not has_license_error
