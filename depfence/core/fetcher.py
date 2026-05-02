"""Package metadata fetchers for npm, PyPI, and other registries.

Responses are cached in ~/.depfence/cache/advisories.db (metadata table) for
6 hours by default to avoid redundant registry calls on repeated scans.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

import httpx

from depfence.core.models import MaintainerInfo, PackageId, PackageMeta

log = logging.getLogger(__name__)

_CLIENT: httpx.AsyncClient | None = None

# Lazy-initialised download cache (None when cache is unavailable or disabled)
_DOWNLOAD_CACHE: "DownloadCache | None" = None
_CACHE_ENABLED: bool = True


def _get_client() -> httpx.AsyncClient:
    global _CLIENT
    if _CLIENT is None or _CLIENT.is_closed:
        _CLIENT = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
    return _CLIENT


def _get_download_cache() -> "DownloadCache | None":
    global _DOWNLOAD_CACHE
    if not _CACHE_ENABLED:
        return None
    if _DOWNLOAD_CACHE is None:
        try:
            from depfence.cache.download_cache import DownloadCache
            _DOWNLOAD_CACHE = DownloadCache()
        except Exception as exc:  # noqa: BLE001
            log.debug("fetcher: could not initialise download cache — %s", exc)
    return _DOWNLOAD_CACHE


def set_cache_enabled(enabled: bool) -> None:
    """Enable or disable the metadata download cache process-wide."""
    global _CACHE_ENABLED, _DOWNLOAD_CACHE
    _CACHE_ENABLED = enabled
    if not enabled:
        _DOWNLOAD_CACHE = None


async def fetch_npm_meta(pkg: PackageId) -> PackageMeta:
    cache = _get_download_cache()

    # Check cache first
    if cache:
        cached = cache.get("npm", pkg.name)
        if cached is not None:
            log.debug("fetcher: npm cache hit for %s", pkg.name)
            return _parse_npm_meta(pkg, cached)

    client = _get_client()
    url = f"https://registry.npmjs.org/{pkg.name}"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()

    # Store in cache
    if cache:
        try:
            cache.put("npm", pkg.name, data)
        except Exception as exc:  # noqa: BLE001
            log.debug("fetcher: npm cache write failed for %s — %s", pkg.name, exc)

    return _parse_npm_meta(pkg, data)


def _parse_npm_meta(pkg: PackageId, data: dict) -> PackageMeta:
    version_data = {}
    if pkg.version and pkg.version in data.get("versions", {}):
        version_data = data["versions"][pkg.version]
    elif "latest" in data.get("dist-tags", {}):
        latest = data["dist-tags"]["latest"]
        version_data = data.get("versions", {}).get(latest, {})

    maintainers = []
    for m in data.get("maintainers", []):
        maintainers.append(MaintainerInfo(
            username=m.get("name", ""),
            email=m.get("email"),
        ))

    scripts = version_data.get("scripts", {})
    has_install = any(
        k in scripts for k in ["preinstall", "install", "postinstall", "preuninstall"]
    )

    time_data = data.get("time", {})
    first_pub = None
    latest_pub = None
    if "created" in time_data:
        first_pub = datetime.fromisoformat(time_data["created"].replace("Z", "+00:00"))
    if "modified" in time_data:
        latest_pub = datetime.fromisoformat(time_data["modified"].replace("Z", "+00:00"))

    deps = version_data.get("dependencies", {})

    return PackageMeta(
        pkg=pkg,
        description=data.get("description", ""),
        homepage=data.get("homepage", ""),
        repository=_extract_repo_url(data.get("repository", {})),
        license=version_data.get("license", data.get("license", "")),
        maintainers=maintainers,
        has_install_scripts=has_install,
        has_native_code=bool(version_data.get("gypfile")),
        first_published=first_pub,
        latest_publish=latest_pub,
        dependency_count=len(deps),
    )


async def fetch_pypi_meta(pkg: PackageId) -> PackageMeta:
    cache = _get_download_cache()

    # Cache key uses name only (version differentiated by URL but metadata is per-package)
    cache_key = pkg.name if not pkg.version else f"{pkg.name}@{pkg.version}"

    if cache:
        cached = cache.get("pypi", cache_key)
        if cached is not None:
            log.debug("fetcher: pypi cache hit for %s", cache_key)
            return _parse_pypi_meta(pkg, cached)

    client = _get_client()
    url = f"https://pypi.org/pypi/{pkg.name}/json"
    if pkg.version:
        url = f"https://pypi.org/pypi/{pkg.name}/{pkg.version}/json"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()

    if cache:
        try:
            cache.put("pypi", cache_key, data)
        except Exception as exc:  # noqa: BLE001
            log.debug("fetcher: pypi cache write failed for %s — %s", cache_key, exc)

    return _parse_pypi_meta(pkg, data)


def _parse_pypi_meta(pkg: PackageId, data: dict) -> PackageMeta:
    info = data.get("info", {})

    maintainers = []
    if info.get("author"):
        maintainers.append(MaintainerInfo(
            username=info["author"],
            email=info.get("author_email"),
        ))

    return PackageMeta(
        pkg=pkg,
        description=info.get("summary", ""),
        homepage=info.get("home_page", ""),
        repository=info.get("project_urls", {}).get("Source", ""),
        license=info.get("license", ""),
        maintainers=maintainers,
        has_install_scripts=False,
        first_published=None,
        latest_publish=None,
        dependency_count=len(info.get("requires_dist", []) or []),
    )


async def fetch_meta(pkg: PackageId) -> PackageMeta:
    fetchers = {
        "npm": fetch_npm_meta,
        "pypi": fetch_pypi_meta,
    }
    fetcher = fetchers.get(pkg.ecosystem)
    if fetcher:
        return await fetcher(pkg)
    return PackageMeta(pkg=pkg)


async def fetch_batch(packages: list[PackageId], concurrency: int = 20) -> list[PackageMeta]:
    sem = asyncio.Semaphore(concurrency)

    async def _fetch(p: PackageId) -> PackageMeta:
        async with sem:
            try:
                return await fetch_meta(p)
            except Exception:
                return PackageMeta(pkg=p)

    return await asyncio.gather(*[_fetch(p) for p in packages])


def _extract_repo_url(repo: dict | str) -> str:
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        return repo.get("url", "")
    return ""
