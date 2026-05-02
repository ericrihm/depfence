"""Dependency freshness scanner — flags unmaintained or abandoned packages.

Detects:
1. Packages with no release in 2+ years
2. Packages with deprecated markers
3. Known abandoned packages (maintained list)
4. Pre-1.0 packages in production dependencies
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageId, Severity

_ABANDONED_THRESHOLD_DAYS = 730  # 2 years

_KNOWN_DEPRECATED = {
    "npm": {"request", "querystring", "uuid-v4", "npmconf", "graceful-fs@3"},
    "pypi": {"pycrypto", "distribute", "pep8", "nose", "optparse"},
}

_KNOWN_REPLACEMENTS = {
    "npm:request": "got, node-fetch, or axios",
    "pypi:pycrypto": "pycryptodome",
    "pypi:nose": "pytest",
    "pypi:pep8": "pycodestyle",
}


class FreshnessScanner:
    ecosystems = ["npm", "pypi", "maven"]

    def __init__(self, registry_cache_path: Path | None = None) -> None:
        self._cache_path = registry_cache_path or Path.home() / ".depfence" / "registry_cache.db"

    async def scan(self, packages: list[PackageId]) -> list[Finding]:
        findings: list[Finding] = []
        for pkg in packages:
            findings.extend(self._check_deprecated(pkg))
            findings.extend(self._check_freshness(pkg))
            findings.extend(self._check_pre_release(pkg))
        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        return []

    def _check_deprecated(self, pkg: PackageId) -> list[Finding]:
        findings = []
        eco_deprecated = _KNOWN_DEPRECATED.get(pkg.ecosystem, set())
        if pkg.name in eco_deprecated:
            replacement = _KNOWN_REPLACEMENTS.get(f"{pkg.ecosystem}:{pkg.name}", "a maintained alternative")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
                title=f"Deprecated package: {pkg.name}",
                detail=f"This package is deprecated or abandoned. Consider switching to {replacement}.",
            ))
        return findings

    def _check_freshness(self, pkg: PackageId) -> list[Finding]:
        findings = []
        last_release = self._get_last_release_date(pkg)
        if last_release is None:
            return findings

        now = datetime.now(timezone.utc)
        age_days = (now - last_release).days

        if age_days > _ABANDONED_THRESHOLD_DAYS:
            years = age_days / 365.25
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.LOW if age_days < 1095 else Severity.MEDIUM,
                package=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
                title=f"Stale package: no release in {years:.1f} years",
                detail=f"Last release was {age_days} days ago. Unmaintained packages "
                       f"may contain unpatched vulnerabilities.",
            ))
        return findings

    def _check_pre_release(self, pkg: PackageId) -> list[Finding]:
        findings = []
        if not pkg.version:
            return findings

        version = pkg.version
        if version.startswith("0.") and not version.startswith("0.9"):
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.LOW,
                package=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
                title=f"Pre-1.0 package in use: {pkg.name}@{version}",
                detail="Pre-1.0 packages have no API stability guarantees and may "
                       "have incomplete security review.",
            ))
        return findings

    def _get_last_release_date(self, pkg: PackageId) -> datetime | None:
        if not self._cache_path.exists():
            return None
        try:
            conn = sqlite3.connect(f"file:{self._cache_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                """SELECT last_release_date FROM package_metadata
                   WHERE ecosystem = ? AND name = ?""",
                (pkg.ecosystem, pkg.name),
            )
            row = cur.fetchone()
            conn.close()
            if row and row["last_release_date"]:
                return datetime.fromisoformat(row["last_release_date"])
        except (sqlite3.OperationalError, ValueError):
            log.debug("freshness: failed reading registry cache for %s:%s", pkg.ecosystem, pkg.name, exc_info=True)
        return None
