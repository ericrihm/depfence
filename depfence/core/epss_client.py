"""EPSS (Exploit Prediction Scoring System) API client.

Queries the free FIRST.org EPSS API (https://api.first.org/data/v1/epss) to
enrich vulnerability findings with real-world exploitability probabilities.

No authentication is required.  All methods degrade gracefully on network
errors or timeouts, returning an empty dict and logging a warning.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

_BATCH_SIZE = 30  # Maximum CVEs per EPSS API request


@dataclass
class EpssScore:
    cve: str
    score: float       # 0.0–1.0 probability of exploitation
    percentile: float  # 0.0–1.0 relative to all scored CVEs


class EpssClient:
    """Client for the FIRST.org EPSS API.

    All methods are async and use httpx under the hood.  They never raise on
    network or HTTP errors — instead they log a warning and return an empty
    result so callers can degrade gracefully.

    Results are cached in-memory for the lifetime of the client instance so
    repeated lookups within the same session do not hit the network.

    Example::

        async with EpssClient() as client:
            scores = await client.get_scores(["CVE-2024-1234", "CVE-2024-5678"])
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._cache: dict[str, EpssScore] = {}

    # ------------------------------------------------------------------
    # Context-manager support (optional but recommended for connection reuse)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> EpssClient:
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

    async def get_scores(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """Fetch EPSS scores for one or more CVE identifiers.

        Parameters
        ----------
        cve_ids:
            List of CVE identifiers, e.g. ``["CVE-2024-1234", "CVE-2024-5678"]``.
            Duplicates are de-duplicated automatically.

        Returns
        -------
        dict[str, EpssScore]
            Mapping from CVE ID to its EPSS score.  CVEs not found in the EPSS
            dataset are omitted.  Returns an empty dict on hard failure.
        """
        if not cve_ids:
            return {}

        unique_ids = list(dict.fromkeys(cve_ids))  # deduplicate, preserve order

        # Serve any cached results immediately
        result: dict[str, EpssScore] = {}
        uncached: list[str] = []
        for cve in unique_ids:
            if cve in self._cache:
                result[cve] = self._cache[cve]
            else:
                uncached.append(cve)

        if not uncached:
            return result

        # Split into batches of _BATCH_SIZE
        batches = [
            uncached[i : i + _BATCH_SIZE]
            for i in range(0, len(uncached), _BATCH_SIZE)
        ]

        client = self._get_client()
        owned = self._client is None  # True when we created a one-shot client
        try:
            for batch in batches:
                batch_result = await self._fetch_batch(client, batch)
                result.update(batch_result)
                self._cache.update(batch_result)
        finally:
            if owned:
                await client.aclose()

        return result

    async def _fetch_batch(
        self, client: httpx.AsyncClient, cve_ids: list[str]
    ) -> dict[str, EpssScore]:
        """Fetch a single batch of CVE scores (max _BATCH_SIZE) from the API."""
        cve_param = ",".join(cve_ids)
        try:
            response = await client.get(self.BASE_URL, params={"cve": cve_param})
            response.raise_for_status()
            data = response.json()
            scores: dict[str, EpssScore] = {}
            for entry in data.get("data") or []:
                cve = entry.get("cve", "")
                if not cve:
                    continue
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                except (TypeError, ValueError):
                    continue
                scores[cve] = EpssScore(cve=cve, score=score, percentile=percentile)
            return scores
        except httpx.TimeoutException:
            log.warning("EPSS request timed out for %d CVEs", len(cve_ids))
            return {}
        except httpx.HTTPStatusError as exc:
            log.warning("EPSS HTTP %d for batch of %d CVEs", exc.response.status_code, len(cve_ids))
            return {}
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS fetch error for batch of %d CVEs — %s", len(cve_ids), exc)
            return {}
