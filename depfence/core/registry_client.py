"""Multi-registry package intelligence client.

Queries public package registries for metadata used in reputation scoring:
- npm registry (registry.npmjs.org)
- PyPI (pypi.org/pypi/PKG/json)
- Maven Central (search.maven.org)

All methods degrade gracefully on network errors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

import httpx

log = logging.getLogger(__name__)


@dataclass
class PackageMetadata:
    name: str
    ecosystem: str
    version: str | None = None
    description: str = ""
    homepage: str | None = None
    repository: str | None = None
    license: str | None = None
    maintainers: list[str] = field(default_factory=list)
    weekly_downloads: int | None = None
    created_at: str | None = None
    last_published: str | None = None
    versions_count: int = 0
    has_types: bool = False


class RegistryClient:
    """Async client for querying package registries."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def get_npm_metadata(self, package_name: str) -> PackageMetadata | None:
        """Query npm registry for package metadata."""
        url = f"https://registry.npmjs.org/{package_name}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()

            latest_ver = data.get("dist-tags", {}).get("latest", "")
            time_data = data.get("time", {})
            versions = data.get("versions", {})
            latest_data = versions.get(latest_ver, {})

            maintainers = [m.get("name", "") for m in data.get("maintainers", [])]
            repo = data.get("repository", {})
            repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)

            return PackageMetadata(
                name=package_name,
                ecosystem="npm",
                version=latest_ver,
                description=data.get("description", ""),
                homepage=latest_data.get("homepage"),
                repository=repo_url or None,
                license=latest_data.get("license") if isinstance(latest_data.get("license"), str) else None,
                maintainers=maintainers,
                created_at=time_data.get("created"),
                last_published=time_data.get(latest_ver),
                versions_count=len(versions),
                has_types="@types/" in package_name or "types" in latest_data.get("keywords", []),
            )
        except Exception as exc:
            log.warning("npm registry query failed for %s: %s", package_name, exc)
            return None

    async def get_pypi_metadata(self, package_name: str) -> PackageMetadata | None:
        """Query PyPI for package metadata."""
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()

            info = data.get("info", {})
            releases = data.get("releases", {})

            # Find maintainers from author/maintainer fields
            maintainers = []
            if info.get("author"):
                maintainers.append(info["author"])
            if info.get("maintainer") and info["maintainer"] != info.get("author"):
                maintainers.append(info["maintainer"])

            # Find repository URL from project_urls
            project_urls = info.get("project_urls") or {}
            repo_url = (
                project_urls.get("Repository")
                or project_urls.get("Source")
                or project_urls.get("GitHub")
                or project_urls.get("Source Code")
            )

            return PackageMetadata(
                name=package_name,
                ecosystem="pypi",
                version=info.get("version"),
                description=info.get("summary", ""),
                homepage=info.get("home_page") or project_urls.get("Homepage"),
                repository=repo_url,
                license=info.get("license"),
                maintainers=maintainers,
                versions_count=len(releases),
                has_types=any("py3" in (info.get("classifiers") or [])),
            )
        except Exception as exc:
            log.warning("PyPI registry query failed for %s: %s", package_name, exc)
            return None

    async def get_metadata(self, ecosystem: str, package_name: str) -> PackageMetadata | None:
        """Get metadata for a package from the appropriate registry."""
        if ecosystem == "npm":
            return await self.get_npm_metadata(package_name)
        elif ecosystem == "pypi":
            return await self.get_pypi_metadata(package_name)
        return None

    async def batch_metadata(self, packages: list[tuple[str, str]]) -> dict[str, PackageMetadata]:
        """Query metadata for multiple packages. Returns {eco:name: metadata}."""
        results: dict[str, PackageMetadata] = {}
        for ecosystem, name in packages:
            meta = await self.get_metadata(ecosystem, name)
            if meta:
                results[f"{ecosystem}:{name}"] = meta
        return results
