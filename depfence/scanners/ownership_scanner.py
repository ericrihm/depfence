"""Ownership change & version anomaly scanner.

Detects:
1. Maintainer ownership transfers on established packages
2. Version-order anomalies (backfilled old major versions)
3. Sudden maintainer count changes
"""

from __future__ import annotations

import logging

from depfence.core.models import Finding, FindingType, PackageMeta, Severity

log = logging.getLogger(__name__)


class OwnershipScanner:
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for meta in packages:
            findings.extend(self._check_ownership(meta))
        return findings

    def _check_ownership(self, meta: PackageMeta) -> list[Finding]:
        findings: list[Finding] = []

        # Check 1: Recent ownership change on established package
        for m in meta.maintainers:
            if m.recent_ownership_change:
                age = meta.first_published
                if age and meta.latest_publish and meta.download_count:
                    if meta.download_count > 10000:
                        findings.append(Finding(
                            finding_type=FindingType.MAINTAINER,
                            severity=Severity.HIGH,
                            package=meta.pkg,
                            title="Maintainer ownership change on popular package",
                            detail=(
                                f"New maintainer '{m.username}' gained publish rights on "
                                f"{meta.pkg.name} ({meta.download_count:,} downloads). "
                                f"Account age: {m.account_age_days or 'unknown'} days."
                            ),
                        ))
                    elif meta.download_count > 1000:
                        findings.append(Finding(
                            finding_type=FindingType.MAINTAINER,
                            severity=Severity.MEDIUM,
                            package=meta.pkg,
                            title="Maintainer change on moderately popular package",
                            detail=(
                                f"New maintainer '{m.username}' on {meta.pkg.name} "
                                f"({meta.download_count:,} downloads)."
                            ),
                        ))

        # Check 2: New maintainer with very young account
        for m in meta.maintainers:
            if m.account_age_days is not None and m.account_age_days < 30:
                if m.recent_ownership_change:
                    findings.append(Finding(
                        finding_type=FindingType.MAINTAINER,
                        severity=Severity.HIGH,
                        package=meta.pkg,
                        title="New maintainer has very young account",
                        detail=(
                            f"Maintainer '{m.username}' account is only "
                            f"{m.account_age_days} days old and was recently added."
                        ),
                    ))

        # Check 3: Single maintainer without 2FA
        if len(meta.maintainers) == 1:
            m = meta.maintainers[0]
            if m.has_2fa is False and meta.download_count and meta.download_count > 50000:
                findings.append(Finding(
                    finding_type=FindingType.MAINTAINER,
                    severity=Severity.MEDIUM,
                    package=meta.pkg,
                    title="Popular package has single maintainer without 2FA",
                    detail=(
                        f"{meta.pkg.name} ({meta.download_count:,} downloads) has "
                        f"only one maintainer and no 2FA enabled — high takeover risk."
                    ),
                ))

        return findings


def check_version_anomaly(
    package_name: str,
    ecosystem: str,
    versions: list[dict],
) -> list[Finding]:
    """Check for version-order anomalies given a list of {version, published_at} dicts.

    Called externally when version history is available (e.g., from registry API).
    """
    if len(versions) < 3:
        return []

    findings: list[Finding] = []
    from datetime import datetime

    sorted_by_time = sorted(versions, key=lambda v: v.get("published_at", ""))
    sorted_by_semver = sorted(versions, key=lambda v: _version_tuple(v.get("version", "0")))

    # Detect backfilled old versions (published after newer versions)
    latest_major = _version_tuple(sorted_by_semver[-1].get("version", "0"))[0] if sorted_by_semver else 0

    for i, entry in enumerate(sorted_by_time):
        ver = entry.get("version", "")
        published = entry.get("published_at", "")
        ver_tuple = _version_tuple(ver)

        if ver_tuple[0] < latest_major and i > len(sorted_by_time) // 2:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=f"{ecosystem}:{package_name}@{ver}",
                title="Version published out of chronological order",
                detail=(
                    f"Version {ver} (major {ver_tuple[0]}) was published after "
                    f"major {latest_major} versions exist. This pattern is used by "
                    f"attackers to inject malicious code into old version ranges."
                ),
            ))

    # Detect sudden burst of versions (>5 in 24h on established package)
    if len(sorted_by_time) >= 5:
        timestamps = []
        for entry in sorted_by_time:
            try:
                ts = datetime.fromisoformat(entry["published_at"].replace("Z", "+00:00"))
                timestamps.append(ts)
            except (KeyError, ValueError):
                log.debug("ownership: failed parsing published_at timestamp", exc_info=True)

        if len(timestamps) >= 5:
            for i in range(len(timestamps) - 5):
                window = timestamps[i + 4] - timestamps[i]
                if window.total_seconds() < 86400:
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        package=f"{ecosystem}:{package_name}",
                        title="Burst of versions published in short window",
                        detail=(
                            f"5+ versions published within 24 hours. This may indicate "
                            f"automated publishing or an account compromise."
                        ),
                    ))
                    break

    return findings


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for segment in v.split("."):
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)
