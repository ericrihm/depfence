"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Downloads and caches the free CISA KEV catalog from:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The catalog lists CVEs that are actively exploited in the wild according to
the US government.  A 24-hour on-disk cache is maintained at
``~/.depfence/cache/kev_catalog.json`` so repeated runs don't hit the network.
On any network error the client falls back to the cached copy silently.

No authentication is required.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
_DEFAULT_CACHE_PATH = Path.home() / ".depfence" / "cache" / "kev_catalog.json"


@dataclass
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    description: str
    required_action: str
    due_date: str
    ransomware: bool


def _parse_entry(raw: dict) -> KevEntry:
    """Convert one raw KEV JSON object into a KevEntry."""
    ransomware_raw = raw.get("knownRansomwareCampaignUse", "")
    ransomware = isinstance(ransomware_raw, str) and ransomware_raw.strip().lower() == "known"
    return KevEntry(
        cve_id=raw.get("cveID", ""),
        vendor=raw.get("vendorProject", ""),
        product=raw.get("product", ""),
        name=raw.get("vulnerabilityName", ""),
        date_added=raw.get("dateAdded", ""),
        description=raw.get("shortDescription", ""),
        required_action=raw.get("requiredAction", ""),
        due_date=raw.get("dueDate", ""),
        ransomware=ransomware,
    )


def _catalog_from_payload(data: dict) -> dict[str, KevEntry]:
    """Build a CVE-keyed dict from the raw KEV catalog JSON payload."""
    out: dict[str, KevEntry] = {}
    for raw in data.get("vulnerabilities") or []:
        entry = _parse_entry(raw)
        if entry.cve_id:
            out[entry.cve_id] = entry
    return out


class KevClient:
    """Client for the CISA Known Exploited Vulnerabilities catalog.

    Caches the full catalog on disk with a 24-hour TTL and falls back to the
    cached copy when the network is unavailable.  All methods degrade
    gracefully on errors.

    Example::

        async with KevClient() as client:
            catalog = await client.fetch_catalog()
            if client.is_exploited("CVE-2021-44228"):
                entry = client.get_entry("CVE-2021-44228")
    """

    def __init__(
        self,
        timeout: float = 30.0,
        cache_path: Path | None = None,
    ) -> None:
        self._timeout = timeout
        self._cache_path = cache_path or _DEFAULT_CACHE_PATH
        self._client: httpx.AsyncClient | None = None
        self._catalog: dict[str, KevEntry] = {}

    # ------------------------------------------------------------------
    # Context-manager support (optional but recommended for connection reuse)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> KevClient:
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
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_is_fresh(self) -> bool:
        """Return True when the on-disk cache exists and is younger than the TTL."""
        if not self._cache_path.exists():
            return False
        age = time.time() - self._cache_path.stat().st_mtime
        return age < _CACHE_TTL_SECONDS

    def _load_cache(self) -> dict[str, KevEntry] | None:
        """Load the catalog from disk cache.  Returns None on any error."""
        try:
            raw_text = self._cache_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            return _catalog_from_payload(data)
        except Exception as exc:  # noqa: BLE001
            log.warning("KEV cache load failed — %s", exc)
            return None

    def _save_cache(self, data: dict) -> None:
        """Persist the raw catalog payload to disk."""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("KEV cache save failed — %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_catalog(self) -> dict[str, KevEntry]:
        """Fetch the full CISA KEV catalog, returning a dict keyed by CVE ID.

        The catalog is downloaded at most once per 24 hours.  On a network
        error the method falls back to the cached copy (if any) and returns
        that instead of raising.

        Returns
        -------
        dict[str, KevEntry]
            Mapping from CVE ID (e.g. ``"CVE-2021-44228"``) to entry details.
            Empty dict when both the network and cache are unavailable.
        """
        # Serve from in-memory cache if already populated
        if self._catalog:
            return self._catalog

        # Serve from on-disk cache if it's still fresh
        if self._cache_is_fresh():
            cached = self._load_cache()
            if cached is not None:
                self._catalog = cached
                return self._catalog

        # Fetch from the network
        client = self._get_client()
        owned = self._client is None
        try:
            response = await client.get(_CATALOG_URL)
            response.raise_for_status()
            data = response.json()
            self._save_cache(data)
            self._catalog = _catalog_from_payload(data)
            return self._catalog
        except Exception as exc:  # noqa: BLE001
            log.warning("KEV catalog fetch failed — %s; trying cache fallback", exc)
            # Fallback: load stale cache even if TTL has expired
            cached = self._load_cache()
            if cached is not None:
                self._catalog = cached
                return self._catalog
            log.warning("KEV cache fallback also unavailable")
            return {}
        finally:
            if owned:
                await client.aclose()

    def is_exploited(self, cve_id: str) -> bool:
        """Return True when *cve_id* appears in the KEV catalog.

        Requires :meth:`fetch_catalog` to have been called first (the in-memory
        catalog must be populated).
        """
        return cve_id in self._catalog

    def get_entry(self, cve_id: str) -> KevEntry | None:
        """Return the :class:`KevEntry` for *cve_id*, or ``None`` if not found.

        Requires :meth:`fetch_catalog` to have been called first.
        """
        return self._catalog.get(cve_id)
