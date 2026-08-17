"""OSV.dev vulnerability scanner.

Queries the OSV.dev batch API for known vulnerabilities affecting a list of
packages and converts the results into Finding objects.

Results are cached in ~/.depfence/cache/advisories.db to avoid redundant
network calls on repeated scans.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity
from depfence.core.osv_client import OsvClient, OsvVulnerability, _parse_vuln

log = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _map_severity(osv_severity: str) -> Severity:
    """Convert an OSV severity string to our Severity enum, defaulting to MEDIUM."""
    return _SEVERITY_MAP.get(osv_severity.upper(), Severity.MEDIUM)


def _vuln_to_finding(pkg: PackageId, vuln: OsvVulnerability) -> Finding:
    """Convert an OsvVulnerability into a Finding for the given package."""
    # Only treat the ID as cve if it looks like a CVE or GHSA identifier.
    cve: str | None = None
    if vuln.id.startswith("CVE-") or vuln.id.startswith("GHSA-"):
        cve = vuln.id
    else:
        cve = next((alias for alias in vuln.aliases if alias.startswith("CVE-")), None)

    matching_affected = []
    for affected in vuln.affected:
        package = affected.get("package") or {}
        if package.get("name") == pkg.name and str(package.get("ecosystem", "")).lower() == str(
            {"pypi": "PyPI", "cargo": "crates.io"}.get(pkg.ecosystem.lower(), pkg.ecosystem)
        ).lower():
            matching_affected.append(affected)

    matching_fixes = []
    for affected in matching_affected:
        for affected_range in affected.get("ranges") or []:
            for event in affected_range.get("events") or []:
                fixed = event.get("fixed")
                if fixed and fixed not in matching_fixes:
                    matching_fixes.append(fixed)

    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=_map_severity(vuln.severity),
        package=pkg,
        title=vuln.summary or vuln.id,
        detail=vuln.details or (f"{vuln.id}: {vuln.summary}" if vuln.summary else vuln.id),
        cve=cve,
        fix_version=matching_fixes[0] if matching_fixes else vuln.fixed_version,
        references=list(vuln.references),
        metadata={
            "osv_id": vuln.id,
            "published": vuln.published,
            "modified": vuln.modified,
            "aliases": vuln.aliases,
            "withdrawn": vuln.withdrawn,
            "affected_versions": vuln.affected_versions,
            "affected": matching_affected,
            "fixed_versions": matching_fixes or vuln.fixed_versions,
            "severity_details": vuln.severity_details,
            "cvss": vuln.cvss,
            "schema_version": vuln.schema_version,
            "upstream": vuln.upstream,
            "related": vuln.related,
            "database_specific": vuln.database_specific,
            "requested_package": {
                "ecosystem": pkg.ecosystem,
                "name": pkg.name,
                "version": pkg.version,
            },
        },
    )


class OsvScanner:
    """Scanner that queries OSV.dev for known package vulnerabilities.

    Uses ``OsvClient.query_batch()`` to issue a single HTTP request for all
    packages, minimising network round-trips.  Results are cached for 1 hour
    (24 hours for packages with no vulnerabilities).

    Pass ``use_cache=False`` to bypass the cache entirely.

    Example::

        scanner = OsvScanner()
        packages = [PackageId("pypi", "requests", "2.28.0")]
        findings = await scanner.scan(packages)
    """

    ecosystems = ["npm", "pypi", "maven", "nuget", "cargo", "go", "packagist", "rubygems"]

    def __init__(self, timeout: float = 15.0, use_cache: bool = True) -> None:
        self._timeout = timeout
        self._use_cache = use_cache
        self.last_error: str | None = None
        self._cache: AdvisoryCache | None = None
        if use_cache:
            try:
                from depfence.cache.advisory_cache import AdvisoryCache
                self._cache = AdvisoryCache()
            except Exception as exc:  # noqa: BLE001
                log.debug("OsvScanner: could not initialise advisory cache — %s", exc)

    async def scan(self, packages: list[PackageId | PackageMeta]) -> list[Finding]:
        """Query OSV in batch for all packages and return findings.

        Parameters
        ----------
        packages:
            Packages to scan.  Each must have at least ``ecosystem`` and
            ``name``; ``version`` is optional but strongly recommended for
            accurate results.

        Returns
        -------
        list[Finding]
            One Finding per (package, vulnerability) pair.  Empty when no
            vulnerabilities are found or on network error.
        """
        package_ids = [value.pkg if isinstance(value, PackageMeta) else value for value in packages]
        self.last_error = None
        if not package_ids:
            return []

        # Separate packages into cache-hits and those needing a network call
        to_fetch: list[PackageId] = []
        cached_results: dict[str, dict[str, Any]] = {}

        if self._cache:
            for pkg in package_ids:
                cached = self._cache.get(pkg.ecosystem, pkg.name, pkg.version or "")
                if cached is not None:
                    key = (
                        f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                        if pkg.version
                        else f"{pkg.ecosystem}:{pkg.name}"
                    )
                    cached_results[key] = cached
                    log.debug("OsvScanner: cache hit for %s", key)
                else:
                    to_fetch.append(pkg)
        else:
            to_fetch = list(package_ids)

        # Build a lookup so we can associate results back to the original PackageId.
        pkg_by_key: dict[str, PackageId] = {}
        for pkg in package_ids:
            key = (
                f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg.version
                else f"{pkg.ecosystem}:{pkg.name}"
            )
            pkg_by_key[key] = pkg

        # Fetch remaining packages from OSV
        network_results: dict[str, dict[str, Any]] = {}
        if to_fetch:
            batch_input = [
                {
                    "ecosystem": pkg.ecosystem,
                    "name": pkg.name,
                    **({"version": pkg.version} if pkg.version else {}),
                }
                for pkg in to_fetch
            ]

            async with OsvClient(timeout=self._timeout) as client:
                raw_results = await client.query_batch(batch_input)
                batch_error = client.last_error if isinstance(client.last_error, str) else None

            if batch_error:
                # Keep any successfully hydrated findings, but do not turn a
                # partial/failed response into a negative cache entry.
                log.warning("OsvScanner: advisory coverage incomplete — %s", batch_error)
                self.last_error = batch_error

            # raw_results maps key -> list[OsvVulnerability]; we need the raw API
            # response for caching, so we re-serialise vulnerability objects.
            for key, vulns in raw_results.items():
                vuln_dicts = [
                    {
                        "raw": v.raw,
                        "id": v.id,
                        "summary": v.summary,
                        "severity": v.severity,
                        "affected_versions": v.affected_versions,
                        "fixed_version": v.fixed_version,
                        "references": v.references,
                        "published": v.published,
                        "aliases": v.aliases,
                        "withdrawn": v.withdrawn,
                        "modified": v.modified,
                        "affected": v.affected,
                        "fixed_versions": v.fixed_versions,
                        "severity_details": v.severity_details,
                        "cvss": v.cvss,
                    }
                    for v in vulns
                ]
                response_payload = {"vulns": vuln_dicts}
                network_results[key] = response_payload

                # Store in cache
                if self._cache and not batch_error:
                    cached_pkg = pkg_by_key.get(key)
                    if cached_pkg:
                        try:
                            self._cache.put(
                                cached_pkg.ecosystem,
                                cached_pkg.name,
                                cached_pkg.version or "",
                                response_payload,
                            )
                        except Exception as exc:  # noqa: BLE001
                            log.debug("OsvScanner: cache write failed for %s — %s", key, exc)

        all_results: dict[str, dict[str, Any]] = {**cached_results, **network_results}

        findings: list[Finding] = []
        for key, payload in all_results.items():
            finding_pkg = pkg_by_key.get(key)
            if finding_pkg is None:
                log.warning("OsvScanner: no PackageId found for key %r", key)
                continue

            cached_vulns: list[dict[str, Any]] = payload.get("vulns") or []
            for vd in cached_vulns:
                raw = vd.get("raw")
                if isinstance(raw, dict) and raw:
                    vuln = _parse_vuln(raw)
                else:
                    # Backwards-compatible read of v0.7 cache entries.
                    vuln = OsvVulnerability(
                        id=vd["id"],
                        summary=vd["summary"],
                        severity=vd["severity"],
                        affected_versions=vd.get("affected_versions", []),
                        fixed_version=vd.get("fixed_version"),
                        references=vd.get("references", []),
                        published=vd.get("published", ""),
                        aliases=vd.get("aliases", []),
                        withdrawn=vd.get("withdrawn"),
                        modified=vd.get("modified", ""),
                        affected=vd.get("affected", []),
                        fixed_versions=vd.get("fixed_versions", []),
                        severity_details=vd.get("severity_details", []),
                        cvss=vd.get("cvss", []),
                    )
                # Withdrawn records are retained in cache/data contracts but
                # are not active vulnerability findings.
                if not vuln.withdrawn:
                    findings.append(_vuln_to_finding(finding_pkg, vuln))

        log.debug(
            "OsvScanner: scanned %d packages (%d cached), found %d findings",
            len(packages),
            len(cached_results),
            len(findings),
        )
        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan a project directory for vulnerabilities.

        This base implementation is a no-op; ecosystem-specific subclasses or
        companion scanners are responsible for parsing lockfiles and calling
        ``scan()`` with the discovered packages.
        """
        return []
