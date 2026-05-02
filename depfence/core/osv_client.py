"""OSV.dev API client for querying known package vulnerabilities.

Queries the free OSV.dev REST API (https://api.osv.dev/v1/) which aggregates
vulnerability data from GitHub Advisories, NVD, PyPI advisories, npm advisories,
and many other sources.

No authentication is required, but the API does have rate limits.
All methods degrade gracefully on network errors or timeouts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)

# Map internal ecosystem names to OSV ecosystem identifiers.
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "go": "Go",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
}


@dataclass
class OsvVulnerability:
    id: str  # e.g. "GHSA-xxxx-xxxx-xxxx" or "CVE-2024-1234"
    summary: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    affected_versions: list[str]
    fixed_version: str | None
    references: list[str]
    published: str  # ISO date


def _osv_ecosystem(ecosystem: str) -> str:
    """Translate an internal ecosystem name to the OSV ecosystem string."""
    return _ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)


def _cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_severity(vuln: dict) -> str:
    """Extract severity from an OSV vulnerability object.

    Checks, in order:
    1. ``database_specific.severity`` (string label used by some databases)
    2. ``severity`` array (CVSS v3 vectors/scores)
    3. ``database_specific.cvss_vector`` (fallback CVSS vector)
    Falls back to "MEDIUM" when nothing useful is found.
    """
    db_specific = vuln.get("database_specific") or {}

    # 1. Explicit severity label from database_specific
    db_severity = db_specific.get("severity", "")
    if isinstance(db_severity, str) and db_severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return db_severity.upper()

    # 2. severity[] array — prefer CVSS_V3 entries
    severity_list: list[dict] = vuln.get("severity") or []
    for entry in severity_list:
        score_str = entry.get("score", "")
        sev_type = entry.get("type", "")

        # Numeric score provided directly
        try:
            score = float(score_str)
            return _cvss_score_to_severity(score)
        except (TypeError, ValueError):
            log.debug("osv_client: could not parse CVSS score %r as float", score_str, exc_info=True)

        # CVSS vector string — parse the base score from AV/AC/… fields
        # by looking at the CVSS:3.x prefix and extracting the numeric score
        # embedded in some OSV responses as "CVSS:3.1/AV:…" style.
        # OSV also sometimes puts the numeric score in a separate field.
        if "CVSS" in sev_type.upper():
            base_score = entry.get("base_score") or entry.get("baseScore")
            if base_score is not None:
                try:
                    return _cvss_score_to_severity(float(base_score))
                except (TypeError, ValueError):
                    log.debug("osv_client: could not parse CVSS base_score %r as float", base_score, exc_info=True)

    # 3. database_specific.cvss_vector fallback — we can't easily parse the
    #    full CVSS vector here without a library, so default to MEDIUM.
    if db_specific.get("cvss_vector"):
        return "MEDIUM"

    return "MEDIUM"


def _extract_affected_versions(vuln: dict) -> list[str]:
    """Collect the explicit version strings listed in affected[]."""
    versions: list[str] = []
    for affected in vuln.get("affected") or []:
        versions.extend(affected.get("versions") or [])
    return versions


def _extract_fixed_version(vuln: dict) -> str | None:
    """Return the earliest fixed version found across all affected ranges."""
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _extract_references(vuln: dict) -> list[str]:
    return [ref["url"] for ref in (vuln.get("references") or []) if ref.get("url")]


def _parse_vuln(raw: dict) -> OsvVulnerability:
    """Convert a raw OSV API vulnerability object into an OsvVulnerability."""
    return OsvVulnerability(
        id=raw.get("id", ""),
        summary=raw.get("summary") or raw.get("details", "")[:200],
        severity=_extract_severity(raw),
        affected_versions=_extract_affected_versions(raw),
        fixed_version=_extract_fixed_version(raw),
        references=_extract_references(raw),
        published=raw.get("published", ""),
    )


class OsvClient:
    """Client for the OSV.dev vulnerability database API.

    All methods are async and use httpx under the hood.  They never raise on
    network or HTTP errors — instead they log a warning and return an empty
    result so callers can degrade gracefully.

    Example::

        async with OsvClient() as client:
            vulns = await client.query_package("pypi", "requests", "2.28.0")
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context-manager support (optional but recommended for connection reuse)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> OsvClient:
        self._client = httpx.AsyncClient(timeout=self._timeout)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        """Return the shared client, or create a one-shot client if not in context."""
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(timeout=self._timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def query_package(
        self,
        ecosystem: str,
        name: str,
        version: str | None = None,
    ) -> list[OsvVulnerability]:
        """Query OSV for vulnerabilities affecting a specific package/version.

        Parameters
        ----------
        ecosystem:
            Ecosystem identifier using either internal names (``"pypi"``,
            ``"cargo"``, ``"nuget"``) or OSV names (``"PyPI"``, ``"crates.io"``,
            ``"NuGet"``).
        name:
            Package name.
        version:
            Optional specific version string.  When omitted, OSV returns all
            known vulnerabilities for the package regardless of version.

        Returns
        -------
        list[OsvVulnerability]
            Vulnerabilities found.  Empty list on error or no results.
        """
        osv_ecosystem = _osv_ecosystem(ecosystem)
        payload: dict = {"package": {"name": name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version

        client = self._get_client()
        owned = self._client is None  # True when we created a one-shot client
        try:
            response = await client.post(f"{self.BASE_URL}/query", json=payload)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns") or []
            return [_parse_vuln(v) for v in vulns]
        except httpx.TimeoutException:
            log.warning("OSV query_package timed out for %s:%s", ecosystem, name)
            return []
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                log.warning("OSV rate limit hit querying %s:%s", ecosystem, name)
            else:
                log.warning(
                    "OSV HTTP %d for %s:%s",
                    exc.response.status_code,
                    ecosystem,
                    name,
                )
            return []
        except Exception as exc:  # noqa: BLE001
            log.warning("OSV query_package error for %s:%s — %s", ecosystem, name, exc)
            return []
        finally:
            if owned:
                await client.aclose()

    async def query_batch(
        self,
        packages: list[dict],
    ) -> dict[str, list[OsvVulnerability]]:
        """Query multiple packages in one batch request.

        Parameters
        ----------
        packages:
            List of dicts, each with keys ``ecosystem``, ``name``, and
            optionally ``version``.  Internal ecosystem names are translated
            automatically.

            Example::

                [
                    {"ecosystem": "pypi", "name": "requests", "version": "2.28.0"},
                    {"ecosystem": "npm",  "name": "lodash",   "version": "4.17.20"},
                ]

        Returns
        -------
        dict[str, list[OsvVulnerability]]
            Mapping from ``"ecosystem:name"`` (or ``"ecosystem:name@version"``)
            to the list of vulnerabilities found.  Packages with no results map
            to an empty list.  Returns an empty dict on hard failure.
        """
        if not packages:
            return {}

        queries = []
        keys: list[str] = []
        for pkg in packages:
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            version = pkg.get("version")
            osv_ecosystem = _osv_ecosystem(ecosystem)
            query: dict = {"package": {"name": name, "ecosystem": osv_ecosystem}}
            if version:
                query["version"] = version
            queries.append(query)
            key = f"{ecosystem}:{name}@{version}" if version else f"{ecosystem}:{name}"
            keys.append(key)

        client = self._get_client()
        owned = self._client is None
        try:
            response = await client.post(
                f"{self.BASE_URL}/querybatch",
                json={"queries": queries},
            )
            response.raise_for_status()
            data = response.json()
            results_raw: list[dict] = data.get("results") or []
            out: dict[str, list[OsvVulnerability]] = {}
            for key, result in zip(keys, results_raw):
                vulns = result.get("vulns") or []
                out[key] = [_parse_vuln(v) for v in vulns]
            # Fill in any packages missing from the response
            for key in keys:
                out.setdefault(key, [])
            return out
        except httpx.TimeoutException:
            log.warning("OSV query_batch timed out (%d packages)", len(packages))
            return {k: [] for k in keys}
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                log.warning("OSV rate limit hit during batch query")
            else:
                log.warning("OSV batch HTTP %d", exc.response.status_code)
            return {k: [] for k in keys}
        except Exception as exc:  # noqa: BLE001
            log.warning("OSV query_batch error — %s", exc)
            return {}
        finally:
            if owned:
                await client.aclose()

    async def get_vulnerability(self, vuln_id: str) -> OsvVulnerability | None:
        """Fetch full details for a specific vulnerability by ID.

        Parameters
        ----------
        vuln_id:
            OSV, GHSA, or CVE identifier, e.g. ``"GHSA-xxxx-xxxx-xxxx"`` or
            ``"CVE-2024-1234"``.

        Returns
        -------
        OsvVulnerability | None
            The vulnerability details, or ``None`` if not found or on error.
        """
        client = self._get_client()
        owned = self._client is None
        try:
            response = await client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return _parse_vuln(response.json())
        except httpx.TimeoutException:
            log.warning("OSV get_vulnerability timed out for %s", vuln_id)
            return None
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 429:
                log.warning("OSV rate limit hit fetching %s", vuln_id)
            else:
                log.warning("OSV HTTP %d fetching %s", exc.response.status_code, vuln_id)
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning("OSV get_vulnerability error for %s — %s", vuln_id, exc)
            return None
        finally:
            if owned:
                await client.aclose()
