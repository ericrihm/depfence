"""EPSS enrichment for vulnerability findings.

Fetches EPSS scores for all CVE-backed findings in a scan result and
annotates each finding's ``metadata`` dict with exploitability information.
"""

from __future__ import annotations

import logging

from depfence.core.epss_client import EpssClient
from depfence.core.models import Finding, Severity

log = logging.getLogger(__name__)

# Percentile thresholds for the human-readable priority label
_PRIORITY_CRITICAL_THRESHOLD = 0.9
_PRIORITY_HIGH_THRESHOLD = 0.7
_PRIORITY_MEDIUM_THRESHOLD = 0.4

# Score threshold above which a MEDIUM-severity finding gets an annotation
_ACTIVE_EXPLOITATION_SCORE_THRESHOLD = 0.5


def _epss_priority(percentile: float) -> str:
    """Return a human-readable priority label based on EPSS percentile."""
    if percentile > _PRIORITY_CRITICAL_THRESHOLD:
        return "critical"
    if percentile > _PRIORITY_HIGH_THRESHOLD:
        return "high"
    if percentile > _PRIORITY_MEDIUM_THRESHOLD:
        return "medium"
    return "low"


async def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Enrich a list of findings with EPSS exploitability scores.

    For each finding that has a ``cve`` field set, this function queries the
    EPSS API (in batches) and populates ``finding.metadata`` with:

    * ``epss_score`` — float 0–1 probability of exploitation in the wild
    * ``epss_percentile`` — float 0–1 relative to all scored CVEs
    * ``epss_priority`` — one of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``

    Additionally, if a finding's EPSS score exceeds
    :data:`_ACTIVE_EXPLOITATION_SCORE_THRESHOLD` and its severity is
    ``MEDIUM``, the finding title is prefixed with ``"[Active Exploitation Risk] "``.

    Findings without a ``cve`` field pass through unchanged.

    Parameters
    ----------
    findings:
        List of :class:`~depfence.core.models.Finding` objects to enrich.
        The list is mutated in-place *and* returned for convenience.

    Returns
    -------
    list[Finding]
        The same list passed in, with EPSS metadata populated where available.
    """
    if not findings:
        return findings

    # Collect unique CVE IDs from findings that have one
    cve_to_findings: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.cve:
            cve_to_findings.setdefault(finding.cve, []).append(finding)

    if not cve_to_findings:
        return findings

    cve_ids = list(cve_to_findings.keys())
    log.debug("Fetching EPSS scores for %d CVEs", len(cve_ids))

    async with EpssClient() as client:
        scores = await client.get_scores(cve_ids)

    for cve_id, epss_score in scores.items():
        for finding in cve_to_findings.get(cve_id, []):
            finding.metadata["epss_score"] = epss_score.score
            finding.metadata["epss_percentile"] = epss_score.percentile
            finding.metadata["epss_priority"] = _epss_priority(epss_score.percentile)

            # Annotate medium-severity findings with high exploitation probability
            if (
                epss_score.score > _ACTIVE_EXPLOITATION_SCORE_THRESHOLD
                and finding.severity == Severity.MEDIUM
                and not finding.title.startswith("[Active Exploitation Risk]")
            ):
                finding.title = f"[Active Exploitation Risk] {finding.title}"

    return findings
