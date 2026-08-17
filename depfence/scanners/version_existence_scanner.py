"""Resolve-never-predict for package versions: flag pins to versions never published.

The package-registry analog of a fabricated GitHub Action SHA (see
resolve_existence_scanner). An AI assistant or human can pin a dependency to an exact
version that was never published — e.g. ``requests==9.9.9`` — which is syntactically
fine but resolves to nothing. Slopsquatting research shows LLMs routinely emit such
non-existent identifiers. This scanner resolves each EXACT pin against the registry and
reports the ones that do not exist as CRITICAL ``fabricated_reference``.

Online, deterministic (confidence 1.0) — distinct from the offline fuzzy ``slopsquat``
name-similarity scanner. False-positive discipline is the whole game:
- Only EXACT pins are checked; ranges, wildcards, dist-tags, git/url/local specs, and
  ``None`` versions are skipped with NO network call.
- A yanked-but-real version still EXISTS (present in the registry's release map) and is
  never flagged.
- PyPI versions are compared canonically (``1.0`` == ``1.0.0``) and a "missing" verdict
  requires BOTH the release map to lack it AND the per-version endpoint to 404.
- Any network/auth/rate-limit ambiguity degrades to INFO ``unverified_reference`` —
  never a false CRITICAL. Honors ``--no-fetch`` (offline) via fetcher.fetch_enabled().
- Reversible kill-switch ``DEPFENCE_VERSION_EXISTENCE=0``.
"""

from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion, Version

from depfence.core.fetcher import _get_client, fetch_enabled
from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_DISABLE = {"0", "false", "no", "off"}
# Characters / prefixes that mean "not a single exact version".
_RANGE_CHARS = set("^~><=*| \t,")
_SKIP_PREFIXES = ("git+", "git:", "file:", "http", "github:", ".", "/", "npm:")
_NPM_DIST_TAGS = {"latest", "next", "beta", "alpha", "canary", "rc", "experimental", "dev"}
_WILDCARD_RE = re.compile(r"(^|\.)[xX*](\.|$)")


def _is_exact(version: str | None) -> bool:
    if not version or not isinstance(version, str):
        return False
    v = version.strip()
    if not v or v.lower() in _NPM_DIST_TAGS:
        return False
    if v.startswith(_SKIP_PREFIXES):
        return False
    if "://" in v or "||" in v:
        return False
    if any(c in _RANGE_CHARS for c in v):
        return False
    if _WILDCARD_RE.search(v):
        return False
    return True


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


async def _resolve_npm(client: httpx.AsyncClient, name: str, version: str) -> str:
    # Scoped names (@scope/pkg) must URL-encode the slash.
    url = f"https://registry.npmjs.org/{quote(name, safe='')}"
    try:
        r = await client.get(url)
    except (httpx.HTTPError, OSError):
        return "unverified"
    if r.status_code == 404:
        return "package_missing"
    if r.status_code in (401, 403, 429):
        return "unverified"
    if r.status_code != 200:
        return "unverified"
    try:
        versions = r.json().get("versions", {})
    except ValueError:
        return "unverified"
    return "exists" if version in versions else "version_missing"


def _canon(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


async def _resolve_pypi(client: httpx.AsyncClient, name: str, version: str) -> str:
    nm = _pep503(name)
    try:
        r = await client.get(f"https://pypi.org/pypi/{nm}/json")
    except (httpx.HTTPError, OSError):
        return "unverified"
    if r.status_code == 404:
        return "package_missing"
    if r.status_code in (401, 403, 429):
        return "unverified"
    if r.status_code != 200:
        return "unverified"
    try:
        releases = r.json().get("releases", {})
    except ValueError:
        return "unverified"

    # Canonical membership (covers yanked, and 1.0 == 1.0.0).
    target = _canon(version)
    if version in releases:
        return "exists"
    if target is not None and any((c := _canon(k)) is not None and c == target for k in releases):
        return "exists"

    # Second, authoritative signal: the per-version endpoint must also 404.
    try:
        rv = await client.get(f"https://pypi.org/pypi/{nm}/{version}/json")
    except (httpx.HTTPError, OSError):
        return "unverified"
    if rv.status_code == 200:
        return "exists"  # release map was stale; the version is real
    if rv.status_code == 404:
        return "version_missing"
    return "unverified"


class VersionExistenceScanner:
    """Flag exact dependency pins whose version was never published."""

    name = "version_existence"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        if os.environ.get("DEPFENCE_VERSION_EXISTENCE", "1").lower() in _DISABLE:
            return []
        if not fetch_enabled():  # respect --no-fetch / offline policy
            return []

        # Unique exact pins only — skip ranges/wildcards/aliases/urls/None (no network).
        targets: set[tuple[str, str, str]] = set()
        for package_meta in packages:
            version = package_meta.pkg.version
            if package_meta.pkg.ecosystem in ("npm", "pypi") and _is_exact(version):
                assert version is not None
                targets.add((package_meta.pkg.ecosystem, package_meta.pkg.name, version))
        if not targets:
            return []

        client = _get_client()
        sem = asyncio.Semaphore(10)

        async def _one(eco: str, name: str, ver: str) -> tuple[tuple[str, str, str], str]:
            async with sem:
                if eco == "npm":
                    kind = await _resolve_npm(client, name, ver)
                else:
                    kind = await _resolve_pypi(client, name, ver)
                return (eco, name, ver), kind

        resolved = dict(await asyncio.gather(*[_one(e, n, v) for e, n, v in targets]))

        findings: list[Finding] = []
        unverified: list[str] = []
        for m in packages:
            version = m.pkg.version
            if version is None:
                continue
            key = (m.pkg.ecosystem, m.pkg.name, version)
            kind = resolved.get(key)
            if kind is None:
                continue
            if kind == "exists":
                continue
            if kind == "unverified":
                unverified.append(f"{m.pkg.ecosystem}:{m.pkg.name}@{m.pkg.version}")
                continue
            if kind == "version_missing":
                findings.append(Finding(
                    finding_type=FindingType.FABRICATED_REF,
                    severity=Severity.CRITICAL,
                    package=m.pkg,
                    title=f"Dependency pinned to a version that was never published: {m.pkg.name}",
                    detail=(
                        f"{m.pkg.ecosystem}:{m.pkg.name}=={m.pkg.version} does not exist in the "
                        f"registry. The pin is fabricated, typo'd, or hallucinated and will fail "
                        f"to install. Verify the version against the registry."
                    ),
                    references=[_registry_url(m.pkg.ecosystem, m.pkg.name)],
                    metadata={"ecosystem": m.pkg.ecosystem, "name": m.pkg.name,
                              "version": m.pkg.version, "fault": "version_never_published"},
                ))
            elif kind == "package_missing":
                findings.append(Finding(
                    finding_type=FindingType.FABRICATED_REF,
                    severity=Severity.CRITICAL,
                    package=m.pkg,
                    title=f"Dependency references a package that does not exist: {m.pkg.name}",
                    detail=(
                        f"{m.pkg.ecosystem}:{m.pkg.name} is not published on the registry "
                        f"(HTTP 404). The package name is fabricated or typo'd."
                    ),
                    references=[_registry_url(m.pkg.ecosystem, m.pkg.name)],
                    metadata={"ecosystem": m.pkg.ecosystem, "name": m.pkg.name,
                              "version": m.pkg.version, "fault": "package_missing"},
                ))

        # De-duplicate identical findings (same pin in multiple manifests).
        seen: set[tuple[str, str, str | None, object]] = set()
        deduped: list[Finding] = []
        for f in findings:
            finding_package = f.package
            k: tuple[str, str, str | None, object]
            if isinstance(finding_package, str):
                k = ("", finding_package, None, f.metadata.get("fault"))
            else:
                k = (
                    finding_package.ecosystem,
                    finding_package.name,
                    finding_package.version,
                    f.metadata.get("fault"),
                )
            if k not in seen:
                seen.add(k)
                deduped.append(f)

        if unverified:
            uniq = sorted(set(unverified))
            deduped.append(Finding(
                finding_type=FindingType.UNVERIFIED_REF,
                severity=Severity.INFO,
                package=packages[0].pkg if packages else _anon_pkg(),
                title=f"{len(uniq)} dependency version(s) could not be verified",
                detail=(
                    "Existence of these exact pins was NOT confirmed (rate limit / network "
                    "error) — not proof they are real. Refs: " + ", ".join(uniq[:25])
                    + (" ..." if len(uniq) > 25 else "")
                ),
                metadata={"unverified": uniq},
            ))
        return deduped


def _registry_url(eco: str, name: str) -> str:
    if eco == "npm":
        return f"https://www.npmjs.com/package/{name}"
    return f"https://pypi.org/project/{name}/"


def _anon_pkg() -> PackageId:
    return PackageId("multi", "(dependencies)")
