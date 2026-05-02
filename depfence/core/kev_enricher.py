"""CISA KEV enrichment for vulnerability findings.

Checks each CVE-backed finding against the CISA Known Exploited Vulnerabilities
catalog and annotates findings that are actively exploited in the wild.

Annotations written to ``finding.metadata``:
* ``kev_exploited``  — ``True``
* ``kev_date_added`` — ISO date string when the CVE was added to the catalog
* ``kev_due_date``   — CISA remediation due-date string
* ``kev_ransomware`` — ``True`` when the CVE is linked to ransomware campaigns

In addition, findings at MEDIUM or LOW severity that appear in the KEV catalog
are elevated to HIGH, and their title is prefixed with ``"[CISA KEV] "`` (the
prefix is only applied once — re-running enrichment is idempotent).
"""

from __future__ import annotations

import logging

from depfence.core.kev_client import KevClient
from depfence.core.models import Finding, Severity

log = logging.getLogger(__name__)

_KEV_TITLE_PREFIX = "[CISA KEV] "
_ELEVATE_SEVERITIES = {Severity.MEDIUM, Severity.LOW}


async def enrich_with_kev(findings: list[Finding]) -> list[Finding]:
    """Enrich a list of findings with CISA KEV catalog data.

    For each finding that has a ``cve`` field set and whose CVE appears in the
    KEV catalog this function:

    1. Populates ``finding.metadata`` with ``kev_exploited``, ``kev_date_added``,
       ``kev_due_date``, and ``kev_ransomware``.
    2. Elevates severity to ``HIGH`` when the current severity is ``MEDIUM`` or
       ``LOW``.
    3. Prefixes the finding title with ``"[CISA KEV] "`` (idempotent).

    Findings without a ``cve`` field pass through unchanged.

    Parameters
    ----------
    findings:
        List of :class:`~depfence.core.models.Finding` objects to enrich.
        The list is mutated in-place *and* returned for convenience.

    Returns
    -------
    list[Finding]
        The same list passed in, with KEV metadata populated where applicable.
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

    log.debug("Checking %d CVEs against CISA KEV catalog", len(cve_to_findings))

    async with KevClient() as client:
        catalog = await client.fetch_catalog()

    for cve_id, affected_findings in cve_to_findings.items():
        entry = catalog.get(cve_id)
        if entry is None:
            continue

        for finding in affected_findings:
            # Annotate metadata
            finding.metadata["kev_exploited"] = True
            finding.metadata["kev_date_added"] = entry.date_added
            finding.metadata["kev_due_date"] = entry.due_date
            finding.metadata["kev_ransomware"] = entry.ransomware

            # Elevate severity for lower-severity findings
            if finding.severity in _ELEVATE_SEVERITIES:
                finding.severity = Severity.HIGH

            # Prefix title (idempotent)
            if not finding.title.startswith(_KEV_TITLE_PREFIX):
                finding.title = f"{_KEV_TITLE_PREFIX}{finding.title}"

    return findings
