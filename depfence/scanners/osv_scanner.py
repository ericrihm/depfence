"""OSV.dev vulnerability scanner.

Queries the OSV.dev batch API for known vulnerabilities affecting a list of
packages and converts the results into Finding objects.

Results are cached in ~/.depfence/cache/advisories.db to avoid redundant
network calls on repeated scans.
"""

from __future__ import annotations

import logging
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.core.osv_client import OsvClient, OsvVulnerability

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

    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=_map_severity(vuln.severity),
        package=pkg,
        title=vuln.summary or vuln.id,
        detail=(
            f"{vuln.id}: {vuln.summary}"
            if vuln.summary
            else vuln.id
        ),
        cve=cve,
        fix_version=vuln.fixed_version,
        references=list(vuln.references),
        metadata={
            "osv_id": vuln.id,
            "published": vuln.published,
            "affected_versions": vuln.affected_versions,
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
        self._cache: "AdvisoryCache | None" = None
        if use_cache:
            try:
                from depfence.cache.advisory_cache import AdvisoryCache
                self._cache = AdvisoryCache()
            except Exception as exc:  # noqa: BLE001
                log.debug("OsvScanner: could not initialise advisory cache — %s", exc)

    async def scan(self, packages: list[PackageId]) -> list[Finding]:
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
        if not packages:
            return []

        # Separate packages into cache-hits and those needing a network call
        to_fetch: list[PackageId] = []
        cached_results: dict[str, dict] = {}

        if self._cache:
            for pkg in packages:
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
            to_fetch = list(packages)

        # Build a lookup so we can associate results back to the original PackageId.
        pkg_by_key: dict[str, PackageId] = {}
        for pkg in packages:
            key = (
                f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg.version
                else f"{pkg.ecosystem}:{pkg.name}"
            )
            pkg_by_key[key] = pkg

        # Fetch remaining packages from OSV
        network_results: dict[str, dict] = {}
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

            # raw_results maps key -> list[OsvVulnerability]; we need the raw API
            # response for caching, so we re-serialise vulnerability objects.
            for key, vulns in raw_results.items():
                vuln_dicts = [
                    {
                        "id": v.id,
                        "summary": v.summary,
                        "severity": v.severity,
                        "affected_versions": v.affected_versions,
                        "fixed_version": v.fixed_version,
                        "references": v.references,
                        "published": v.published,
                    }
                    for v in vulns
                ]
                response_payload = {"vulns": vuln_dicts}
                network_results[key] = response_payload

                # Store in cache
                if self._cache:
                    pkg = pkg_by_key.get(key)
                    if pkg:
                        try:
                            self._cache.put(
                                pkg.ecosystem,
                                pkg.name,
                                pkg.version or "",
                                response_payload,
                            )
                        except Exception as exc:  # noqa: BLE001
                            log.debug("OsvScanner: cache write failed for %s — %s", key, exc)

        all_results = {**cached_results, **network_results}

        findings: list[Finding] = []
        for key, payload in all_results.items():
            pkg = pkg_by_key.get(key)
            if pkg is None:
                log.warning("OsvScanner: no PackageId found for key %r", key)
                continue

            vuln_dicts = payload.get("vulns") or []
            for vd in vuln_dicts:
                # Re-hydrate from dict (cached path) or use as-is (network path
                # already has dicts after serialisation above)
                from depfence.core.osv_client import OsvVulnerability
                vuln = OsvVulnerability(
                    id=vd["id"],
                    summary=vd["summary"],
                    severity=vd["severity"],
                    affected_versions=vd.get("affected_versions", []),
                    fixed_version=vd.get("fixed_version"),
                    references=vd.get("references", []),
                    published=vd.get("published", ""),
                )
                findings.append(_vuln_to_finding(pkg, vuln))

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
