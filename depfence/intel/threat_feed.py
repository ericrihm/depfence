"""Threat feed aggregator — combines EPSS trends, KEV status, and scan findings
into a unified threat picture and executive summary.

Powers the ``depfence threat-brief`` CLI command.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depfence.core.models import Finding
    from depfence.intel.epss_tracker import EPSSTracker


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ThreatSnapshot:
    """Aggregated threat picture at a point in time."""

    # Overall risk score 0–100 (weighted combination of EPSS + KEV + severity)
    total_risk_score: float

    # Top CVEs by combined urgency (EPSS score + KEV status + severity)
    top_risks: list[dict] = field(default_factory=list)

    # CVEs whose EPSS score is rising fast over the last 7 days
    trending_cves: list[dict] = field(default_factory=list)

    # New KEV additions (CVEs in KEV that appear in the current findings)
    new_advisories: list[dict] = field(default_factory=list)

    # Fraction of findings that have been enriched with EPSS data (0.0–1.0)
    coverage_score: float = 0.0

    # Timestamp of this snapshot
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Counts for convenience
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    ransomware_kev_count: int = 0


# ---------------------------------------------------------------------------
# ThreatFeed
# ---------------------------------------------------------------------------


class ThreatFeed:
    """Aggregates EPSS trends, KEV membership, and scan findings.

    Usage::

        feed = ThreatFeed()
        snapshot = feed.aggregate(findings, epss_tracker)
        print(feed.generate_brief(snapshot))
    """

    # EPSS score thresholds
    HIGH_EPSS = 0.5      # >= this is "high exploitation probability"
    MEDIUM_EPSS = 0.1    # >= this is "medium exploitation probability"

    # Weight factors for risk score formula
    _W_SEVERITY = 0.40
    _W_EPSS = 0.35
    _W_KEV = 0.25

    def __init__(self) -> None:
        from depfence.intel.kev_monitor import KEVMonitor
        self._kev_monitor = KEVMonitor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def aggregate(
        self,
        findings: list,
        epss_tracker: EPSSTracker | None = None,
    ) -> ThreatSnapshot:
        """Combine EPSS trends, KEV status, and findings into a snapshot.

        Parameters
        ----------
        findings:
            Scan findings from :func:`~depfence.core.engine.scan_directory`.
        epss_tracker:
            Optional :class:`~depfence.intel.epss_tracker.EPSSTracker`
            instance.  When provided, EPSS trend data is incorporated.

        Returns
        -------
        ThreatSnapshot
            The aggregated threat picture.
        """
        from depfence.core.models import Severity

        if not findings:
            return ThreatSnapshot(
                total_risk_score=0.0,
                coverage_score=1.0,
                total_findings=0,
            )

        # ---- KEV cross-reference -----------------------------------------
        kev_hits = self._kev_monitor.check_local_kev(findings)
        kev_cves = {e.cve for e in kev_hits}
        ransomware_kev_cves = {e.cve for e in kev_hits if e.known_ransomware}

        # ---- EPSS data lookup --------------------------------------------
        epss_data: dict[str, float] = {}
        epss_trends: dict[str, object] = {}
        if epss_tracker is not None:
            for cve in {f.cve for f in findings if getattr(f, "cve", None)}:
                trend = epss_tracker.get_trend(cve)
                epss_data[cve] = trend.current_score
                epss_trends[cve] = trend

        # ---- Coverage score ----------------------------------------------
        cve_findings = [f for f in findings if getattr(f, "cve", None)]
        covered = sum(1 for f in cve_findings if f.cve in epss_data)
        coverage = covered / len(cve_findings) if cve_findings else 1.0

        # ---- Severity mapping to numeric ---------------------------------
        sev_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.4,
            Severity.LOW: 0.15,
            Severity.INFO: 0.05,
        }

        # ---- Per-finding urgency -----------------------------------------
        scored: list[dict] = []
        for f in findings:
            sev_num = sev_scores.get(f.severity, 0.1)
            epss_num = epss_data.get(getattr(f, "cve", None) or "", 0.0)
            kev_bonus = 0.3 if getattr(f, "cve", None) in kev_cves else 0.0
            urgency = (
                self._W_SEVERITY * sev_num
                + self._W_EPSS * epss_num
                + self._W_KEV * kev_bonus
            )
            scored.append({
                "cve": getattr(f, "cve", None),
                "package": str(f.package),
                "title": f.title,
                "severity": f.severity.value,
                "epss_score": epss_num,
                "in_kev": getattr(f, "cve", None) in kev_cves,
                "ransomware": getattr(f, "cve", None) in ransomware_kev_cves,
                "urgency": round(urgency, 4),
            })

        scored.sort(key=lambda x: x["urgency"], reverse=True)
        top_risks = scored[:5]

        # ---- Trending CVEs (from EPSS tracker) ---------------------------
        trending: list[dict] = []
        if epss_tracker is not None:
            rising = epss_tracker.get_rising(threshold=0.05, days=7)
            for r in rising[:10]:
                trending.append({
                    "cve": r.cve,
                    "current_score": r.current_score,
                    "delta_7d": r.delta_7d,
                    "affected_packages": r.affected_packages,
                })

        # ---- New advisories (KEV intersect findings) ----------------------
        new_advisories: list[dict] = []
        for entry in kev_hits:
            new_advisories.append({
                "cve": entry.cve,
                "vendor": entry.vendor,
                "product": entry.product,
                "date_added": entry.date_added,
                "due_date": entry.due_date,
                "ransomware": entry.known_ransomware,
            })
        new_advisories.sort(key=lambda x: x["date_added"], reverse=True)

        # ---- Overall risk score (0–100) ----------------------------------
        if scored:
            mean_urgency = sum(s["urgency"] for s in scored) / len(scored)
            kev_factor = 1.0 + 0.2 * min(len(kev_hits), 5)
            total_risk = min(mean_urgency * kev_factor * 100, 100.0)
        else:
            total_risk = 0.0

        # ---- Counts ------------------------------------------------------
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        return ThreatSnapshot(
            total_risk_score=round(total_risk, 2),
            top_risks=top_risks,
            trending_cves=trending,
            new_advisories=new_advisories,
            coverage_score=round(coverage, 4),
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            kev_count=len(kev_hits),
            ransomware_kev_count=len(ransomware_kev_cves),
        )

    def generate_brief(self, snapshot: ThreatSnapshot | None = None) -> str:
        """Generate a plain-text executive summary block.

        Parameters
        ----------
        snapshot:
            Pre-computed :class:`ThreatSnapshot`.  When ``None``, an empty
            snapshot is used (useful for testing the formatter).

        Returns
        -------
        str
            Multi-line executive summary suitable for terminal output.
        """
        if snapshot is None:
            snapshot = ThreatSnapshot(total_risk_score=0.0)

        lines: list[str] = []
        sep = "=" * 60

        lines.append(sep)
        lines.append("  DEPFENCE THREAT BRIEF")
        lines.append(f"  Generated: {snapshot.generated_at}")
        lines.append(sep)
        lines.append("")

        # ---- Overall risk score ----------------------------------------
        risk = snapshot.total_risk_score
        if risk >= 70:
            risk_label = "CRITICAL"
        elif risk >= 40:
            risk_label = "HIGH"
        elif risk >= 15:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        lines.append(f"Overall Risk Score: {risk:.1f}/100  [{risk_label}]")
        lines.append(
            f"Findings: {snapshot.total_findings} total  "
            f"({snapshot.critical_count} critical, {snapshot.high_count} high)"
        )
        lines.append(
            f"KEV Matches: {snapshot.kev_count}  "
            f"({snapshot.ransomware_kev_count} ransomware-linked)"
        )
        lines.append(f"EPSS Coverage: {snapshot.coverage_score * 100:.0f}%")
        lines.append("")

        # ---- Top 5 urgent CVEs -----------------------------------------
        lines.append("TOP URGENT CVEs")
        lines.append("-" * 40)
        if snapshot.top_risks:
            for i, risk_item in enumerate(snapshot.top_risks, 1):
                cve = risk_item.get("cve") or "N/A"
                pkg = risk_item.get("package", "unknown")
                sev = risk_item.get("severity", "?").upper()
                urgency = risk_item.get("urgency", 0)
                epss = risk_item.get("epss_score", 0)
                kev_tag = " [KEV]" if risk_item.get("in_kev") else ""
                ransomware_tag = " [RANSOMWARE]" if risk_item.get("ransomware") else ""
                lines.append(
                    f"  {i}. {cve}{kev_tag}{ransomware_tag}"
                )
                lines.append(
                    f"     Package: {pkg}  Severity: {sev}  "
                    f"EPSS: {epss:.3f}  Urgency: {urgency:.3f}"
                )
        else:
            lines.append("  No urgent CVEs identified.")
        lines.append("")

        # ---- Trending threats ------------------------------------------
        lines.append("TRENDING THREATS (7-DAY EPSS RISE)")
        lines.append("-" * 40)
        if snapshot.trending_cves:
            for t in snapshot.trending_cves[:5]:
                cve = t.get("cve", "?")
                score = t.get("current_score", 0)
                delta = t.get("delta_7d", 0)
                lines.append(
                    f"  {cve}  score={score:.3f}  +{delta:.3f} in 7d"
                )
        else:
            lines.append("  No notable EPSS trends detected.")
        lines.append("")

        # ---- New advisories --------------------------------------------
        lines.append("NEW KEV ADVISORIES")
        lines.append("-" * 40)
        if snapshot.new_advisories:
            for adv in snapshot.new_advisories[:5]:
                cve = adv.get("cve", "?")
                vendor = adv.get("vendor", "?")
                product = adv.get("product", "?")
                due = adv.get("due_date", "?")
                rsw = "  [RANSOMWARE]" if adv.get("ransomware") else ""
                lines.append(f"  {cve} — {vendor} {product}  Due: {due}{rsw}")
        else:
            lines.append("  No new KEV advisories affecting scanned packages.")
        lines.append("")

        # ---- Recommended actions ---------------------------------------
        lines.append("RECOMMENDED ACTIONS")
        lines.append("-" * 40)
        actions = self._recommend_actions(snapshot)
        for action in actions:
            lines.append(f"  • {action}")
        lines.append("")
        lines.append(sep)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _recommend_actions(self, snapshot: ThreatSnapshot) -> list[str]:
        """Generate prioritised recommended actions from the snapshot."""
        actions: list[str] = []

        if snapshot.kev_count > 0:
            actions.append(
                f"IMMEDIATE: Patch {snapshot.kev_count} KEV-listed CVE(s) "
                "per CISA binding operational directive."
            )
        if snapshot.ransomware_kev_count > 0:
            actions.append(
                f"URGENT: {snapshot.ransomware_kev_count} CVE(s) are linked "
                "to active ransomware campaigns — treat as highest priority."
            )
        if snapshot.critical_count > 0:
            actions.append(
                f"Remediate {snapshot.critical_count} CRITICAL finding(s) "
                "within 24 hours or apply compensating controls."
            )
        if snapshot.high_count > 0:
            actions.append(
                f"Schedule fixes for {snapshot.high_count} HIGH severity "
                "finding(s) within 7 days."
            )
        if snapshot.trending_cves:
            actions.append(
                f"Monitor {len(snapshot.trending_cves)} trending CVE(s) "
                "with rapidly rising EPSS scores."
            )
        if snapshot.coverage_score < 0.5:
            actions.append(
                "Low EPSS coverage — ensure CVE identifiers are populated "
                "for all vulnerability findings."
            )
        if not actions:
            actions.append(
                "No immediate actions required. Continue routine scanning."
            )
        return actions
