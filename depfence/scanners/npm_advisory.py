"""Scanner that checks packages against the GitHub Advisory Database (GHSA) and OSV."""

from __future__ import annotations

import logging

import httpx

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageMeta, Severity
from depfence.core.threat_db import ThreatDB

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_THREAT_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_MALICIOUS_THREAT_TYPES = {"malware", "malicious", "backdoor", "credential_theft", "exfiltration"}


class NpmAdvisoryScanner:
    name = "npm_advisory"
    ecosystems = ["npm"]

    def __init__(self, threat_db: ThreatDB | None = None) -> None:
        self._threat_db = threat_db if threat_db is not None else ThreatDB()

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        npm_pkgs = [p for p in packages if p.pkg.ecosystem == "npm"]
        if not npm_pkgs:
            return findings

        findings.extend(await self._query_osv(npm_pkgs))
        findings.extend(self._query_threat_db(npm_pkgs))
        return findings

    def _query_threat_db(self, packages: list[PackageMeta]) -> list[Finding]:
        """Check the local threat intel DB and emit findings for any hits."""
        findings: list[Finding] = []
        for pkg_meta in packages:
            pkg = pkg_meta.pkg

            if self._threat_db.is_known_malicious("npm", pkg.name):
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

            for threat in self._threat_db.lookup("npm", pkg.name):
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

    async def _query_osv(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for pkg_meta in packages:
                pkg = pkg_meta.pkg
                payload = {
                    "package": {"name": pkg.name, "ecosystem": "npm"},
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
                    log.debug("npm_advisory: OSV query failed for %s", pkg.name, exc_info=True)
                    continue

                for vuln in data.get("vulns", []):
                    severity = self._extract_severity(vuln)
                    cve = None
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("CVE-"):
                            cve = alias
                            break

                    fix_version = self._extract_fix_version(vuln, pkg.name)
                    refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

                    findings.append(Finding(
                        finding_type=FindingType.KNOWN_VULN,
                        severity=severity,
                        package=pkg,
                        title=vuln.get("summary", vuln.get("id", "Unknown vulnerability")),
                        detail=vuln.get("details", ""),
                        cve=cve,
                        fix_version=fix_version,
                        references=refs[:5],
                    ))

        return findings

    def _extract_severity(self, vuln: dict) -> Severity:
        for severity_entry in vuln.get("severity", []):
            score_str = severity_entry.get("score", "")
            if "CVSS" in severity_entry.get("type", ""):
                try:
                    score = float(score_str.split("/")[0].split(":")[-1])
                    if score >= 9.0:
                        return Severity.CRITICAL
                    if score >= 7.0:
                        return Severity.HIGH
                    if score >= 4.0:
                        return Severity.MEDIUM
                    return Severity.LOW
                except (ValueError, IndexError):
                    log.debug("Suppressed exception", exc_info=True)

        db_severity = vuln.get("database_specific", {}).get("severity", "").lower()
        return _SEVERITY_MAP.get(db_severity, Severity.MEDIUM)

    def _extract_fix_version(self, vuln: dict, pkg_name: str) -> str | None:
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("name") == pkg_name:
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            return event["fixed"]
        return None
