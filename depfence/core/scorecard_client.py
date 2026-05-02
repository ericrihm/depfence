"""OpenSSF Scorecard API client.

Fetches repository security scores from the OpenSSF Scorecard API
(https://api.securityscorecards.dev) to flag packages with poor supply
chain practices.

No authentication is required.  All methods degrade gracefully on network
errors or timeouts, returning None / empty dict and logging a warning.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)

_BASE_URL = "https://api.securityscorecards.dev"
_BATCH_CONCURRENCY = 10  # max concurrent requests in batch_scores


@dataclass
class ScorecardCheck:
    name: str
    score: int   # -1 (not applicable) or 0–10
    reason: str


@dataclass
class ScorecardResult:
    repo: str
    overall_score: float
    checks: list[ScorecardCheck]
    date: str


def _parse_repo_path(repo_url: str) -> str | None:
    """Extract 'owner/repo' from a variety of GitHub URL forms.

    Accepts:
    * ``https://github.com/owner/repo``
    * ``http://github.com/owner/repo``
    * ``github.com/owner/repo``
    * Any of the above with a trailing ``.git`` suffix or extra path segments.

    Returns the canonical ``owner/repo`` string, or ``None`` when the URL
    cannot be parsed as a GitHub repository reference.
    """
    url = repo_url.strip()

    # Strip trailing .git
    if url.endswith(".git"):
        url = url[:-4]

    # Normalise to just the path part after 'github.com'
    match = re.search(r"github\.com[/:]([^/\s]+/[^/\s#?]+)", url)
    if match:
        # Take only the first two path components (owner/repo)
        path = match.group(1).split("/")
        if len(path) >= 2:
            return f"{path[0]}/{path[1]}"
    return None


def _parse_result(data: dict) -> ScorecardResult:
    """Convert a raw Scorecard API response dict into a ScorecardResult."""
    repo_name = (data.get("repo") or {}).get("name", "")
    overall_score = float(data.get("score", 0.0))
    date = data.get("date", "")

    checks: list[ScorecardCheck] = []
    for raw_check in data.get("checks") or []:
        checks.append(
            ScorecardCheck(
                name=raw_check.get("name", ""),
                score=int(raw_check.get("score", -1)),
                reason=raw_check.get("reason", ""),
            )
        )

    return ScorecardResult(
        repo=repo_name,
        overall_score=overall_score,
        checks=checks,
        date=date,
    )


class ScorecardClient:
    """Client for the OpenSSF Scorecard REST API.

    All methods are async and use httpx under the hood.  They never raise on
    network or HTTP errors — instead they log a warning and return a graceful
    empty result so callers can degrade safely.

    Example::

        async with ScorecardClient() as client:
            result = await client.get_score("https://github.com/psf/requests")
            if result:
                print(result.overall_score)
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Async context-manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> ScorecardClient:
        self._client = httpx.AsyncClient(timeout=self._timeout)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(timeout=self._timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_score(self, repo_url: str) -> ScorecardResult | None:
        """Fetch the Scorecard score for a GitHub repository.

        Parameters
        ----------
        repo_url:
            A GitHub repository reference in any of these forms:

            * ``https://github.com/owner/repo``
            * ``github.com/owner/repo``
            * ``https://github.com/owner/repo.git``

        Returns
        -------
        ScorecardResult | None
            The parsed score result, or ``None`` when the repository is not
            found (HTTP 404), the URL cannot be parsed, or a network error
            occurs.
        """
        repo_path = _parse_repo_path(repo_url)
        if not repo_path:
            log.warning("ScorecardClient: could not parse repo URL %r", repo_url)
            return None

        api_path = f"github.com/{repo_path}"
        url = f"{_BASE_URL}/projects/{api_path}"

        client = self._get_client()
        owned = self._client is None
        try:
            response = await client.get(url)
            if response.status_code == 404:
                log.debug("Scorecard: repo not found — %s", api_path)
                return None
            response.raise_for_status()
            return _parse_result(response.json())
        except httpx.TimeoutException:
            log.warning("Scorecard: request timed out for %s", api_path)
            return None
        except httpx.HTTPStatusError as exc:
            log.warning(
                "Scorecard: HTTP %d for %s", exc.response.status_code, api_path
            )
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning("Scorecard: error fetching %s — %s", api_path, exc)
            return None
        finally:
            if owned:
                await client.aclose()

    async def batch_scores(
        self, repo_urls: list[str]
    ) -> dict[str, ScorecardResult]:
        """Fetch scores for multiple repositories concurrently.

        Up to :data:`_BATCH_CONCURRENCY` requests are issued in parallel.
        Repositories that return ``None`` (not found / error) are omitted from
        the result dict.

        Parameters
        ----------
        repo_urls:
            List of GitHub repository URLs / shorthand references.

        Returns
        -------
        dict[str, ScorecardResult]
            Mapping from the *original* URL string to its ``ScorecardResult``.
            URLs that produced no result are absent from the map.
        """
        if not repo_urls:
            return {}

        semaphore = asyncio.Semaphore(_BATCH_CONCURRENCY)

        async def _fetch_one(url: str) -> tuple[str, ScorecardResult | None]:
            async with semaphore:
                result = await self.get_score(url)
            return url, result

        tasks = [_fetch_one(url) for url in repo_urls]
        pairs = await asyncio.gather(*tasks)

        return {url: result for url, result in pairs if result is not None}
