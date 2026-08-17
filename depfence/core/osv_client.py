"""OSV.dev API client for querying known package vulnerabilities.

Queries the free OSV.dev REST API (https://api.osv.dev/v1/) which aggregates
vulnerability data from GitHub Advisories, NVD, PyPI advisories, npm advisories,
and many other sources.

No authentication is required, but the API does have rate limits.
All methods degrade gracefully on network errors or timeouts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from depfence.core.fetcher import fetch_enabled

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
    aliases: list[str] = field(default_factory=list)
    withdrawn: str | None = None
    modified: str = ""
    affected: list[dict[str, Any]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    severity_details: list[dict[str, Any]] = field(default_factory=list)
    cvss: list[dict[str, Any]] = field(default_factory=list)
    details: str = ""
    schema_version: str = ""
    upstream: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)
    database_specific: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


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

    # 2. severity[] array.  Preserve the original vector separately in
    # OsvVulnerability.severity_details; only derive a label when OSV supplies a
    # numeric base score.  Guessing a score from a vector would require a
    # version-specific CVSS implementation and can produce incorrect severity.
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
                if isinstance(fixed, str) and fixed:
                    return fixed
    return None


def _extract_fixed_versions(vuln: dict) -> list[str]:
    """Return all fixed events without collapsing independent affected ranges."""
    fixed_versions: list[str] = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed not in fixed_versions:
                    fixed_versions.append(fixed)
    return fixed_versions


def _extract_references(vuln: dict) -> list[str]:
    return [ref["url"] for ref in (vuln.get("references") or []) if ref.get("url")]


def _extract_cvss(vuln: dict) -> list[dict[str, Any]]:
    """Normalise CVSS provenance while retaining OSV's original severity entry."""
    cvss: list[dict[str, Any]] = []
    for entry in vuln.get("severity") or []:
        severity_type = str(entry.get("type") or "")
        if "CVSS" not in severity_type.upper():
            continue
        score = entry.get("score")
        cvss.append(
            {
                "version": severity_type,
                "vector": score if isinstance(score, str) and score.upper().startswith("CVSS:") else None,
                "source": entry.get("source"),
                "base_score": entry.get("base_score", entry.get("baseScore")),
            }
        )
    return cvss


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
        aliases=list(raw.get("aliases") or []),
        withdrawn=raw.get("withdrawn"),
        modified=raw.get("modified", ""),
        affected=list(raw.get("affected") or []),
        fixed_versions=_extract_fixed_versions(raw),
        severity_details=[dict(value) for value in (raw.get("severity") or [])],
        cvss=_extract_cvss(raw),
        details=raw.get("details", ""),
        schema_version=raw.get("schema_version", ""),
        upstream=list(raw.get("upstream") or []),
        related=list(raw.get("related") or []),
        database_specific=dict(raw.get("database_specific") or {}),
        raw=dict(raw),
    )


def _validate_full_vuln(raw: object) -> dict[str, Any]:
    """Validate fields required to distinguish a full OSV record from an ID stub."""
    if not isinstance(raw, dict):
        raise ValueError("OSV vulnerability is not an object")
    if not isinstance(raw.get("id"), str) or not raw["id"]:
        raise ValueError("OSV vulnerability has no valid id")
    if not isinstance(raw.get("modified"), str) or not raw["modified"]:
        raise ValueError(f"OSV vulnerability {raw['id']} is missing modified timestamp")
    for field_name in ("aliases", "affected", "severity", "references"):
        value = raw.get(field_name)
        if value is not None and not isinstance(value, list):
            raise ValueError(f"OSV vulnerability {raw['id']} has malformed {field_name}")
    withdrawn = raw.get("withdrawn")
    if withdrawn is not None and not isinstance(withdrawn, str):
        raise ValueError(f"OSV vulnerability {raw['id']} has malformed withdrawn timestamp")
    return raw


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

    def __init__(
        self,
        timeout: float = 10.0,
        *,
        max_concurrency: int = 8,
        max_pages: int = 20,
    ) -> None:
        self._timeout = timeout
        self._max_concurrency = max(1, max_concurrency)
        self._max_pages = max(1, max_pages)
        self._client: httpx.AsyncClient | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------
    # Context-manager support (optional but recommended for connection reuse)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> OsvClient:
        if fetch_enabled():
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
        self.last_error = None
        if not fetch_enabled():
            self.last_error = "network fetching is disabled"
            return []
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
            if not isinstance(data, dict):
                raise ValueError("OSV query response is not an object")
            vulns = data.get("vulns") or []
            if not isinstance(vulns, list):
                raise ValueError("OSV query vulnerabilities are malformed")
            return [_parse_vuln(_validate_full_vuln(vuln)) for vuln in vulns]
        except httpx.TimeoutException:
            self.last_error = "request timed out"
            log.warning("OSV query_package timed out for %s:%s", ecosystem, name)
            return []
        except httpx.HTTPStatusError as exc:
            self.last_error = f"HTTP {exc.response.status_code}"
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
            self.last_error = str(exc)
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
        self.last_error = None
        if not packages:
            return {}
        if not fetch_enabled():
            self.last_error = "network fetching is disabled"
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
            results_raw = data.get("results")
            if not isinstance(results_raw, list) or len(results_raw) != len(keys):
                raise ValueError("OSV batch response did not contain one result per query")

            ids_by_key: dict[str, list[str]] = {}
            next_tokens: dict[str, str] = {}
            for key, result in zip(keys, results_raw):
                if not isinstance(result, dict):
                    raise ValueError(f"OSV batch result for {key} is malformed")
                vulns = result.get("vulns") or []
                if not isinstance(vulns, list):
                    raise ValueError(f"OSV batch vulnerabilities for {key} are malformed")
                ids_by_key[key] = self._extract_ids(vulns, key)
                token = result.get("next_page_token")
                if token:
                    next_tokens[key] = str(token)

            # querybatch returns abbreviated vulnerability records.  Follow
            # per-query pagination first, then hydrate every unique ID through
            # /vulns/{id}; both fan-outs share a bounded concurrency budget.
            semaphore = asyncio.Semaphore(self._max_concurrency)
            query_by_key = dict(zip(keys, queries))
            page_errors = await self._collect_pages(
                client, query_by_key, ids_by_key, next_tokens, semaphore
            )
            unique_ids = list(dict.fromkeys(vuln_id for ids in ids_by_key.values() for vuln_id in ids))
            hydrated, hydration_errors = await self._hydrate_ids(client, unique_ids, semaphore)

            errors = page_errors + hydration_errors
            if errors:
                self.last_error = "; ".join(errors)

            out: dict[str, list[OsvVulnerability]] = {}
            for key in keys:
                out[key] = [hydrated[vuln_id] for vuln_id in ids_by_key[key] if vuln_id in hydrated]
            return out
        except httpx.TimeoutException:
            self.last_error = "request timed out"
            log.warning("OSV query_batch timed out (%d packages)", len(packages))
            return {k: [] for k in keys}
        except httpx.HTTPStatusError as exc:
            self.last_error = f"HTTP {exc.response.status_code}"
            if exc.response.status_code == 429:
                log.warning("OSV rate limit hit during batch query")
            else:
                log.warning("OSV batch HTTP %d", exc.response.status_code)
            return {k: [] for k in keys}
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            log.warning("OSV query_batch error — %s", exc)
            return {k: [] for k in keys}
        finally:
            if owned:
                await client.aclose()

    @staticmethod
    def _extract_ids(vulns: list[object], key: str) -> list[str]:
        ids: list[str] = []
        for raw in vulns:
            if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                raise ValueError(f"OSV batch vulnerability for {key} has no valid id")
            if raw["id"] not in ids:
                ids.append(raw["id"])
        return ids

    async def _collect_pages(
        self,
        client: httpx.AsyncClient,
        query_by_key: dict[str, dict[str, Any]],
        ids_by_key: dict[str, list[str]],
        next_tokens: dict[str, str],
        semaphore: asyncio.Semaphore,
    ) -> list[str]:
        active = dict(next_tokens)
        for _page in range(self._max_pages):
            if not active:
                return []
            page_keys = list(active)
            page_queries: list[dict[str, Any]] = []
            for key in page_keys:
                query = dict(query_by_key[key])
                query["page_token"] = active[key]
                page_queries.append(query)
            try:
                async with semaphore:
                    response = await client.post(
                        f"{self.BASE_URL}/querybatch",
                        json={"queries": page_queries},
                    )
                response.raise_for_status()
                data = response.json()
                results = data.get("results")
                if not isinstance(results, list) or len(results) != len(page_keys):
                    raise ValueError("response did not contain one result per paginated query")

                next_active: dict[str, str] = {}
                for key, result in zip(page_keys, results):
                    if not isinstance(result, dict):
                        raise ValueError(f"paginated result for {key} is malformed")
                    vulns = result.get("vulns") or []
                    if not isinstance(vulns, list):
                        raise ValueError(f"paginated vulnerabilities for {key} are malformed")
                    for vuln_id in self._extract_ids(vulns, key):
                        if vuln_id not in ids_by_key[key]:
                            ids_by_key[key].append(vuln_id)
                    token = result.get("next_page_token")
                    if token:
                        next_active[key] = str(token)
                active = next_active
            except Exception as exc:  # noqa: BLE001
                return [f"querybatch pagination failed: {exc}"]

        return [
            f"pagination exceeded {self._max_pages} pages for {key}"
            for key in active
        ]

    async def _hydrate_ids(
        self,
        client: httpx.AsyncClient,
        vuln_ids: list[str],
        semaphore: asyncio.Semaphore,
    ) -> tuple[dict[str, OsvVulnerability], list[str]]:
        async def hydrate(vuln_id: str) -> tuple[str, OsvVulnerability | None, str | None]:
            try:
                async with semaphore:
                    response = await client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
                response.raise_for_status()
                raw = _validate_full_vuln(response.json())
                if raw.get("id") != vuln_id:
                    raise ValueError("response identity did not match requested vulnerability")
                return vuln_id, _parse_vuln(raw), None
            except Exception as exc:  # noqa: BLE001
                return vuln_id, None, f"hydration failed for {vuln_id}: {exc}"

        results = await asyncio.gather(*(hydrate(vuln_id) for vuln_id in vuln_ids))
        hydrated = {vuln_id: vuln for vuln_id, vuln, _error in results if vuln is not None}
        errors = [error for _vuln_id, _vuln, error in results if error]
        return hydrated, errors

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
        self.last_error = None
        if not fetch_enabled():
            self.last_error = "network fetching is disabled"
            return None
        client = self._get_client()
        owned = self._client is None
        try:
            response = await client.get(f"{self.BASE_URL}/vulns/{vuln_id}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return _parse_vuln(_validate_full_vuln(response.json()))
        except httpx.TimeoutException:
            self.last_error = "request timed out"
            log.warning("OSV get_vulnerability timed out for %s", vuln_id)
            return None
        except httpx.HTTPStatusError as exc:
            self.last_error = f"HTTP {exc.response.status_code}"
            if exc.response.status_code == 429:
                log.warning("OSV rate limit hit fetching %s", vuln_id)
            else:
                log.warning("OSV HTTP %d fetching %s", exc.response.status_code, vuln_id)
            return None
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            log.warning("OSV get_vulnerability error for %s — %s", vuln_id, exc)
            return None
        finally:
            if owned:
                await client.aclose()
