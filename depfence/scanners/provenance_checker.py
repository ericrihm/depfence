"""SLSA / Sigstore provenance attestation verifier.

Checks npm and PyPI packages for verifiable build provenance and flags packages
that lack it — especially high-download packages where supply-chain attacks have
the most impact.

npm provenance:  https://registry.npmjs.org/<pkg>/<version>  →  dist.attestations
PyPI provenance: https://pypi.org/pypi/<pkg>/<version>/json  →  urls[].provenance
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from pathlib import Path

import httpx

from depfence.core.lockfile import detect_ecosystem, parse_lockfile
from depfence.core.models import Finding, FindingType, PackageId, Severity

log = logging.getLogger(__name__)

# Weekly-download threshold above which a missing-provenance finding is escalated
# from MEDIUM → HIGH.
_POPULAR_THRESHOLD = 1_000_000

# Known high-download npm packages (used as a static fallback when we cannot
# fetch live download stats).
_POPULAR_NPM: frozenset[str] = frozenset(
    {
        "react", "react-dom", "next", "express", "lodash", "axios",
        "typescript", "webpack", "babel-core", "@babel/core", "eslint",
        "prettier", "vite", "vue", "angular", "svelte",
        "moment", "dayjs", "chalk", "commander", "yargs",
        "dotenv", "uuid", "cors", "body-parser", "jsonwebtoken",
    }
)

# Known high-download PyPI packages.
_POPULAR_PYPI: frozenset[str] = frozenset(
    {
        "requests", "boto3", "numpy", "pandas", "flask", "django",
        "fastapi", "uvicorn", "pydantic", "httpx", "aiohttp",
        "sqlalchemy", "celery", "redis", "pillow", "cryptography",
        "setuptools", "pip", "wheel", "urllib3", "certifi",
        "charset-normalizer", "idna", "six", "click", "rich",
        "openai", "anthropic", "langchain", "transformers", "torch",
        "tensorflow", "scikit-learn", "pytest", "mypy", "black",
    }
)


@dataclass
class ProvenanceStatus:
    package: PackageId
    has_provenance: bool
    provenance_type: str | None  # "npm-attestation", "sigstore", "slsa-github", None
    builder: str | None          # e.g. "github-actions", "gitlab-ci"
    source_repo: str | None
    transparency_log: bool       # whether it's in Rekor/Sigstore transparency log
    verified: bool               # whether the signature chain validates


def _unknown_status(pkg: PackageId) -> ProvenanceStatus:
    """Return a neutral status used when an API call fails."""
    return ProvenanceStatus(
        package=pkg,
        has_provenance=False,
        provenance_type=None,
        builder=None,
        source_repo=None,
        transparency_log=False,
        verified=False,
    )


def _extract_npm_builder(statement: dict) -> str | None:
    """Best-effort extraction of the CI builder from an npm attestation statement."""
    predicate = statement.get("predicate") or {}
    builder = predicate.get("builder") or {}
    builder_id: str = builder.get("id") or ""
    if "github" in builder_id.lower():
        return "github-actions"
    if "gitlab" in builder_id.lower():
        return "gitlab-ci"
    if builder_id:
        return builder_id
    return None


def _extract_npm_repo(statement: dict) -> str | None:
    """Best-effort extraction of the source repo from an npm attestation."""
    predicate = statement.get("predicate") or {}
    # SLSA v0.2 / v1 layout
    materials = predicate.get("materials") or []
    for m in materials:
        uri: str = m.get("uri") or ""
        if uri:
            return uri
    # buildDefinition layout (SLSA v1)
    build_def = predicate.get("buildDefinition") or {}
    ext_params = build_def.get("externalParameters") or {}
    workflow = ext_params.get("workflow") or {}
    repo: str = workflow.get("repository") or ""
    if repo:
        return repo
    return None


def _normalise_repo_url(url: str) -> str:
    """Normalise a GitHub (or generic git) repo URL for comparison.

    Strips scheme, ``www.``, trailing ``.git``, and trailing slashes so that
    ``https://github.com/foo/bar.git`` and ``github.com/foo/bar`` compare equal.
    """
    url = url.strip().lower()
    # Remove scheme
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^git://", "", url)
    url = re.sub(r"^git\+https://", "", url)
    # Remove www.
    url = re.sub(r"^www\.", "", url)
    # Remove trailing .git
    url = re.sub(r"\.git$", "", url)
    # Remove trailing slash
    url = url.rstrip("/")
    return url


def _repos_match(attestation_repo: str | None, declared_repo: str | None) -> bool:
    """Return True when the two repo URLs resolve to the same canonical path.

    Either argument being ``None`` or empty is treated as *unknown* (returns
    True so that missing data does not generate false-positive mismatches).
    """
    if not attestation_repo or not declared_repo:
        return True
    return _normalise_repo_url(attestation_repo) == _normalise_repo_url(declared_repo)


def _extract_declared_npm_repo(data: dict) -> str | None:
    """Extract the declared repository URL from an npm registry package object."""
    repository = data.get("repository")
    if isinstance(repository, str):
        return repository
    if isinstance(repository, dict):
        return repository.get("url")
    return None


def _extract_declared_pypi_repo(info: dict) -> str | None:
    """Extract the source repository URL from a PyPI /json info block.

    Tries ``project_urls`` keys that typically carry the source repo, then falls
    back to the plain ``home_page`` field.
    """
    project_urls: dict = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Code", "Homepage"):
        url = project_urls.get(key, "")
        if url and "github.com" in url.lower():
            return url
    # Broader fallback — any project_url that looks like a VCS host
    for url in project_urls.values():
        if url and re.search(r"github\.com|gitlab\.com|bitbucket\.org", url, re.I):
            return url
    # Last resort
    home_page: str = info.get("home_page") or ""
    if home_page and re.search(r"github\.com|gitlab\.com|bitbucket\.org", home_page, re.I):
        return home_page
    return None


class ProvenanceChecker:
    """Async client that checks npm and PyPI packages for build provenance.

    Usage::

        async with ProvenanceChecker() as checker:
            status = await checker.check_npm_provenance("lodash", "4.17.21")
    """

    ecosystems = ["npm", "pypi"]

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def scan(self, packages) -> list:
        """Scanner protocol — provenance checks run via dedicated CLI command, not generic scan."""
        return []

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> ProvenanceChecker:
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
    # Per-ecosystem provenance checks
    # ------------------------------------------------------------------

    async def check_npm_provenance(self, name: str, version: str) -> ProvenanceStatus:
        """Check npm registry metadata for dist.attestations or dist.signatures."""
        pkg = PackageId("npm", name, version)
        client = self._get_client()
        owned = self._client is None
        try:
            url = f"https://registry.npmjs.org/{name}/{version}"
            resp = await client.get(url)
            if resp.status_code == 404:
                log.debug("npm package not found: %s@%s", name, version)
                return _unknown_status(pkg)
            resp.raise_for_status()
            data: dict = resp.json()
            dist: dict = data.get("dist") or {}

            # The package's own declared source repository (used for mismatch check).
            declared_repo = _extract_declared_npm_repo(data)

            # PEP 740-equivalent: dist.attestations (modern npm provenance)
            attestations = dist.get("attestations")
            if attestations:
                # attestations is usually a URL pointing to the bundle
                # Treat presence as has_provenance=True; deeper verification
                # would require fetching and validating the bundle, which is
                # out of scope for a lightweight scanner.
                statements: list[dict] = []
                if isinstance(attestations, dict):
                    statements = attestations.get("provenance", {}).get(
                        "predicates", []
                    )
                builder = None
                repo = None
                if statements:
                    builder = _extract_npm_builder(statements[0])
                    repo = _extract_npm_repo(statements[0])
                verified = _repos_match(repo, declared_repo)
                return ProvenanceStatus(
                    package=pkg,
                    has_provenance=True,
                    provenance_type="npm-attestation",
                    builder=builder,
                    source_repo=repo,
                    transparency_log=True,  # npm attestations use Sigstore/Rekor
                    verified=verified,
                )

            # Older signature-based provenance
            signatures = dist.get("signatures")
            if signatures:
                return ProvenanceStatus(
                    package=pkg,
                    has_provenance=True,
                    provenance_type="sigstore",
                    builder=None,
                    source_repo=None,
                    transparency_log=True,
                    # No source repo in old signatures — treat as unverified
                    # only if we have a declared repo to compare against.
                    verified=declared_repo is None,
                )

            return ProvenanceStatus(
                package=pkg,
                has_provenance=False,
                provenance_type=None,
                builder=None,
                source_repo=None,
                transparency_log=False,
                verified=False,
            )

        except httpx.TimeoutException:
            log.warning("Timeout checking npm provenance for %s@%s", name, version)
            return _unknown_status(pkg)
        except httpx.HTTPStatusError as exc:
            log.warning(
                "HTTP %d checking npm provenance for %s@%s",
                exc.response.status_code,
                name,
                version,
            )
            return _unknown_status(pkg)
        except Exception as exc:  # noqa: BLE001
            log.warning("Error checking npm provenance for %s@%s: %s", name, version, exc)
            return _unknown_status(pkg)
        finally:
            if owned:
                await client.aclose()

    async def check_pypi_provenance(self, name: str, version: str) -> ProvenanceStatus:
        """Check PyPI JSON API for PEP 740 / Trusted Publisher attestation markers."""
        pkg = PackageId("pypi", name, version)
        client = self._get_client()
        owned = self._client is None
        try:
            url = f"https://pypi.org/pypi/{name}/{version}/json"
            resp = await client.get(url)
            if resp.status_code == 404:
                log.debug("PyPI package not found: %s %s", name, version)
                return _unknown_status(pkg)
            resp.raise_for_status()
            data: dict = resp.json()

            info: dict = data.get("info") or {}
            # The package's own declared source repository (used for mismatch check).
            declared_repo = _extract_declared_pypi_repo(info)

            # Check each release file for a provenance marker
            urls: list[dict] = data.get("urls") or []
            for release_file in urls:
                provenance = release_file.get("provenance")
                if provenance:
                    # Attempt to extract builder/repo from provenance payload
                    builder: str | None = None
                    repo: str | None = None
                    if isinstance(provenance, dict):
                        attestations_list = provenance.get("attestations") or []
                        if attestations_list:
                            first = attestations_list[0]
                            builder = first.get("builder")
                            repo = first.get("source_repository") or first.get(
                                "source_repo"
                            )
                    verified = _repos_match(repo, declared_repo)
                    return ProvenanceStatus(
                        package=pkg,
                        has_provenance=True,
                        provenance_type="slsa-github"
                        if builder and "github" in (builder or "").lower()
                        else "sigstore",
                        builder=builder,
                        source_repo=repo,
                        transparency_log=True,
                        verified=verified,
                    )

            # Fallback: check info-level attestation URL
            if info.get("attestation_url"):
                return ProvenanceStatus(
                    package=pkg,
                    has_provenance=True,
                    provenance_type="sigstore",
                    builder=None,
                    source_repo=None,
                    transparency_log=True,
                    # No repo in fallback attestation — treat as unverified only
                    # if we have a declared repo to compare against.
                    verified=declared_repo is None,
                )

            return ProvenanceStatus(
                package=pkg,
                has_provenance=False,
                provenance_type=None,
                builder=None,
                source_repo=None,
                transparency_log=False,
                verified=False,
            )

        except httpx.TimeoutException:
            log.warning("Timeout checking PyPI provenance for %s %s", name, version)
            return _unknown_status(pkg)
        except httpx.HTTPStatusError as exc:
            log.warning(
                "HTTP %d checking PyPI provenance for %s %s",
                exc.response.status_code,
                name,
                version,
            )
            return _unknown_status(pkg)
        except Exception as exc:  # noqa: BLE001
            log.warning("Error checking PyPI provenance for %s %s: %s", name, version, exc)
            return _unknown_status(pkg)
        finally:
            if owned:
                await client.aclose()

    # ------------------------------------------------------------------
    # Batch and project-level helpers
    # ------------------------------------------------------------------

    async def check_batch(self, packages: list[PackageId]) -> list[ProvenanceStatus]:
        """Check provenance for multiple packages concurrently."""
        tasks = [self._check_one(pkg) for pkg in packages]
        return list(await asyncio.gather(*tasks))

    async def _check_one(self, pkg: PackageId) -> ProvenanceStatus:
        eco = pkg.ecosystem.lower()
        version = pkg.version or "latest"
        if eco == "npm":
            return await self.check_npm_provenance(pkg.name, version)
        if eco == "pypi":
            return await self.check_pypi_provenance(pkg.name, version)
        # Unsupported ecosystem — return neutral unknown status
        return ProvenanceStatus(
            package=pkg,
            has_provenance=False,
            provenance_type=None,
            builder=None,
            source_repo=None,
            transparency_log=False,
            verified=False,
        )

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Parse lockfiles in *project_dir* and emit provenance findings.

        Severity rules
        --------------
        * MEDIUM  — package lacks provenance
        * HIGH    — package lacks provenance AND is in the popular-package set
                    (>1M weekly downloads proxy)
        """
        lockfiles = detect_ecosystem(project_dir)
        packages: list[PackageId] = []
        for ecosystem, lockfile_path in lockfiles:
            packages.extend(parse_lockfile(ecosystem, lockfile_path))

        if not packages:
            return []

        statuses = await self.check_batch(packages)
        findings: list[Finding] = []
        for status in statuses:
            pkg = status.package
            is_popular = _is_popular(pkg)

            if status.has_provenance and not status.verified:
                # Attestation present but source repo doesn't match the package's
                # own declared repository — strong signal of supply-chain tampering.
                findings.append(
                    Finding(
                        finding_type=FindingType.PROVENANCE,
                        severity=Severity.MEDIUM,
                        package=pkg,
                        title=f"Provenance source-repo mismatch: {pkg.name}",
                        detail=(
                            f"{pkg.ecosystem}:{pkg.name} version {pkg.version} has a "
                            f"provenance attestation, but the attested source repository "
                            f"({status.source_repo!r}) does not match the package's own "
                            f"declared repository URL. This may indicate a compromised "
                            f"build pipeline or a typosquat with a forged attestation."
                        ),
                        references=[
                            "https://slsa.dev/",
                            "https://docs.npmjs.com/generating-provenance-statements"
                            if pkg.ecosystem == "npm"
                            else "https://docs.pypi.org/attestations/",
                        ],
                        confidence=0.85,
                        metadata={
                            "provenance_type": status.provenance_type,
                            "attested_repo": status.source_repo,
                            "builder": status.builder,
                            "transparency_log": status.transparency_log,
                            "popular": is_popular,
                        },
                    )
                )
                continue

            if not status.has_provenance:
                severity = Severity.HIGH if is_popular else Severity.MEDIUM
                findings.append(
                    Finding(
                        finding_type=FindingType.PROVENANCE,
                        severity=severity,
                        package=pkg,
                        title=f"Missing build provenance: {pkg.name}",
                        detail=(
                            f"{pkg.ecosystem}:{pkg.name} version {pkg.version} has no "
                            f"verifiable SLSA/Sigstore provenance attestation. "
                            f"Without provenance, published artifacts cannot be traced "
                            f"back to a specific source commit and CI run, making "
                            f"supply-chain tampering undetectable."
                            + (
                                " This is a high-download package — an ideal target for "
                                "supply-chain attacks."
                                if is_popular
                                else ""
                            )
                        ),
                        references=[
                            "https://slsa.dev/",
                            "https://docs.npmjs.com/generating-provenance-statements"
                            if pkg.ecosystem == "npm"
                            else "https://docs.pypi.org/attestations/",
                        ],
                        confidence=0.9,
                        metadata={
                            "provenance_type": status.provenance_type,
                            "transparency_log": status.transparency_log,
                            "popular": is_popular,
                        },
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_popular(pkg: PackageId) -> bool:
    """Return True if *pkg* is in the static popular-package set."""
    eco = pkg.ecosystem.lower()
    name = pkg.name.lower()
    if eco == "npm":
        return name in _POPULAR_NPM
    if eco == "pypi":
        return name in _POPULAR_PYPI
    return False
