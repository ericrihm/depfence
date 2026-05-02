"""Scanner that checks Python packages against OSV."""

from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageMeta, Severity
from depfence.core.threat_db import ThreatDB

_THREAT_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_MALICIOUS_THREAT_TYPES = {"malware", "malicious", "backdoor", "credential_theft", "exfiltration"}


class PypiAdvisoryScanner:
    name = "pypi_advisory"
    ecosystems = ["pypi"]

    def __init__(self, threat_db: ThreatDB | None = None) -> None:
        self._threat_db = threat_db if threat_db is not None else ThreatDB()

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        pypi_pkgs = [p for p in packages if p.pkg.ecosystem == "pypi"]
        if not pypi_pkgs:
            return findings

        async with httpx.AsyncClient(timeout=30.0) as client:
            for pkg_meta in pypi_pkgs:
                pkg = pkg_meta.pkg
                payload = {
                    "package": {"name": pkg.name, "ecosystem": "PyPI"},
                }
                if pkg.version:
                    payload["version"] = pkg.version

                try:
                    resp = await client.post(
                        "https://api.osv.dev/v1/query",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception:
                    log.debug("pypi_advisory: OSV query failed for %s", pkg.name, exc_info=True)
                    continue

                for vuln in data.get("vulns", []):
                    severity = self._parse_severity(vuln)
                    cve = next(
                        (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                        None,
                    )
                    fix_version = self._find_fix(vuln, pkg.name)

                    findings.append(Finding(
                        finding_type=FindingType.KNOWN_VULN,
                        severity=severity,
                        package=pkg,
                        title=vuln.get("summary", vuln.get("id", "")),
                        detail=vuln.get("details", ""),
                        cve=cve,
                        fix_version=fix_version,
                        references=[
                            r["url"] for r in vuln.get("references", [])[:5] if "url" in r
                        ],
                    ))

        findings.extend(self._query_threat_db(pypi_pkgs))
        return findings

    def _query_threat_db(self, packages: list[PackageMeta]) -> list[Finding]:
        """Check the local threat intel DB and emit findings for any hits."""
        findings: list[Finding] = []
        for pkg_meta in packages:
            pkg = pkg_meta.pkg

            if self._threat_db.is_known_malicious("pypi", pkg.name):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"[Local Intel] {pkg.name} is flagged as malicious",
                    detail=(
                        "The local threat intelligence database has one or more critical "
                        "or explicitly malicious entries for this package."
                    ),
                    metadata={"source": "local_threat_db"},
                ))

            for threat in self._threat_db.lookup("pypi", pkg.name):
                severity = _THREAT_SEVERITY_MAP.get(
                    (threat.get("severity") or "").lower(), Severity.MEDIUM
                )
                threat_type = (threat.get("threat_type") or "").lower()
                finding_type = (
                    FindingType.MALICIOUS
                    if threat_type in _MALICIOUS_THREAT_TYPES
                    else FindingType.KNOWN_VULN
                )
                findings.append(Finding(
                    finding_type=finding_type,
                    severity=severity,
                    package=pkg,
                    title=threat.get("title") or f"[Local Intel] Threat detected in {pkg.name}",
                    detail=threat.get("detail") or "",
                    cve=threat.get("cve") or None,
                    metadata={
                        "source": "local_threat_db",
                        "threat_type": threat.get("threat_type"),
                        "intel_source": threat.get("source"),
                        "version_range": threat.get("version_range"),
                        "first_seen": threat.get("first_seen"),
                        "last_updated": threat.get("last_updated"),
                    },
                ))

        return findings

    def _parse_severity(self, vuln: dict) -> Severity:
        for s in vuln.get("severity", []):
            if "CVSS" in s.get("type", ""):
                try:
                    score = float(s["score"].split("/")[0].split(":")[-1])
                    if score >= 9.0:
                        return Severity.CRITICAL
                    if score >= 7.0:
                        return Severity.HIGH
                    if score >= 4.0:
                        return Severity.MEDIUM
                    return Severity.LOW
                except (ValueError, IndexError):
                    log.debug("Suppressed exception", exc_info=True)
        return Severity.MEDIUM

    def _find_fix(self, vuln: dict, name: str) -> str | None:
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("name") == name:
                for rng in affected.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            return ev["fixed"]
        return None
