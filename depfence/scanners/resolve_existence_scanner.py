"""Resolve-never-predict scanner: verify that pinned refs actually exist.

The rest of the ecosystem either *writes* pins (ratchet, pinact, frizbee,
StepSecurity, Renovate, Dependabot all resolve tag -> SHA at authoring time) or
*lints* pinned-ness (zizmor unpinned-uses, OpenSSF Scorecard Pinned-Dependencies
score format only). None of them re-verify that a SHA *already sitting in the tree*
resolves to a real upstream commit — so a workflow full of fabricated 40-hex SHAs
gets a perfect "pinned" score everywhere.

That gap is exactly how an AI-written/hand-typed SHA slips in: it is valid hex with
a plausible ``# v4`` comment but points to no commit that ever existed (the GitHub
API returns 422). This scanner treats every pinned ref as a *claim to be resolved*:

- ``GET /repos/{owner}/{repo}/commits/{sha}`` -> 422/404 == fabricated/hallucinated.
- For a fabricated pin that carries a ``# vX.Y.Z`` comment, the real tag is resolved
  to *characterize* the fault: if the fabricated SHA shares a long prefix with the
  tag's true SHA it is labelled "conflation" (the reported "real prefix + hallucinated
  tail" case). A real commit whose tag has merely moved on is NOT flagged — that is the
  normal, correct pinning case (lying-comment detection is a deliberate fast-follow).

It is a *project* scanner, so it only runs on online scans (``--no-fetch`` disables
all project scanners). Verification never silently passes: when it cannot reach the
API (no token / rate-limited / offline) it emits a single INFO "unverified" finding
rather than implying the pins are real. Set ``DEPFENCE_RESOLVE_EXISTENCE=0`` to
disable entirely (reversible kill-switch).
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import cast

import httpx

from depfence.core.fetcher import _get_client, fetch_enabled
from depfence.core.models import Finding, FindingType, PackageId, Severity

# uses: owner/repo[/subpath]@<40-hex>   [# comment]
_USES_PIN_RE = re.compile(
    r"""uses:\s*["']?
        (?P<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)   # owner/repo (subpath ignored)
        (?:/[A-Za-z0-9._/-]+)?                       # optional sub-action path
        @
        (?P<sha>[0-9a-fA-F]{40})                     # the pinned commit SHA
        ["']?
        (?:\s*\#\s*(?P<comment>\S+))?                # optional trailing # vX.Y.Z
    """,
    re.VERBOSE,
)

# A version-ish comment we can reconcile against a real tag (v1, v4.1.0, 1.2.3, ...).
_VERSION_COMMENT_RE = re.compile(r"^v?\d+(?:\.\d+){0,2}$")

_API = "https://api.github.com"
_DISABLE_VALUES = {"0", "false", "no", "off"}


class _Resolution:
    __slots__ = ("kind", "status", "tag_sha")

    def __init__(self, kind: str, status: int | None = None, tag_sha: str | None = None) -> None:
        self.kind = kind  # exists | fabricated_commit | fabricated_repo | unverified
        self.status = status
        self.tag_sha = tag_sha


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _resolve_commit(client: httpx.AsyncClient, repo: str, sha: str) -> _Resolution:
    """Resolve whether `sha` is a real commit in `repo`."""
    headers = _headers()
    try:
        r = await client.get(f"{_API}/repos/{repo}/commits/{sha}", headers=headers)
    except (httpx.HTTPError, OSError):
        return _Resolution("unverified")

    if r.status_code == 200:
        return _Resolution("exists", 200)
    if r.status_code == 422:
        # GitHub returns 422 "No commit found for SHA" for a non-existent commit.
        return _Resolution("fabricated_commit", 422)
    if r.status_code == 404:
        # 404 may mean the repo itself is gone — disambiguate so the message is honest.
        try:
            rr = await client.get(f"{_API}/repos/{repo}", headers=headers)
        except (httpx.HTTPError, OSError):
            return _Resolution("unverified")
        if rr.status_code == 404:
            return _Resolution("fabricated_repo", 404)
        if rr.status_code in (401, 403, 429):
            return _Resolution("unverified", rr.status_code)
        return _Resolution("fabricated_commit", 404)
    if r.status_code in (401, 403, 429):
        # auth / rate limit — cannot conclude anything; never a silent pass.
        return _Resolution("unverified", r.status_code)
    return _Resolution("unverified", r.status_code)


async def _resolve_tag(client: httpx.AsyncClient, repo: str, tag: str) -> str | None:
    """Return the commit SHA a tag points to, or None if it cannot be resolved."""
    headers = _headers()
    try:
        r = await client.get(f"{_API}/repos/{repo}/git/ref/tags/{tag}", headers=headers)
        if r.status_code != 200:
            return None
        obj = r.json().get("object", {})
        if obj.get("type") == "tag":  # annotated tag -> dereference to the commit
            rr = await client.get(f"{_API}/repos/{repo}/git/tags/{obj.get('sha')}", headers=headers)
            if rr.status_code != 200:
                return None
            return cast(str | None, rr.json().get("object", {}).get("sha"))
        return cast(str | None, obj.get("sha"))
    except (httpx.HTTPError, OSError, ValueError):
        return None


class ResolveExistenceScanner:
    """Flag pinned GitHub Action SHAs that do not resolve to a real commit."""

    name = "resolve_existence"
    ecosystems = ["gha"]

    async def scan(self, packages: list) -> list[Finding]:  # type: ignore[type-arg]
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        if os.environ.get("DEPFENCE_RESOLVE_EXISTENCE", "1").lower() in _DISABLE_VALUES:
            return []
        if not fetch_enabled():
            return []

        workflows_dir = project_dir / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return []

        # (repo, sha, comment, workflow_path) for every SHA-pinned `uses:`.
        pins: list[tuple[str, str, str | None, str]] = []
        for wf in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
            try:
                text = wf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _USES_PIN_RE.finditer(text):
                pins.append((m.group("repo"), m.group("sha").lower(), m.group("comment"), str(wf)))

        if not pins:
            return []

        client = _get_client()
        # Resolve each distinct (repo, sha) once — commit existence is immutable.
        unique = {(repo, sha) for repo, sha, _, _ in pins}
        sem = asyncio.Semaphore(10)

        async def _one(repo: str, sha: str) -> tuple[tuple[str, str], _Resolution]:
            async with sem:
                return (repo, sha), await _resolve_commit(client, repo, sha)

        resolved = dict(await asyncio.gather(*[_one(repo, sha) for repo, sha in unique]))

        findings: list[Finding] = []
        unverified: list[str] = []
        seen_fab: set[tuple[str, str, str]] = set()  # de-dupe identical findings across files

        for repo, sha, comment, workflow_path in pins:
            res = resolved[(repo, sha)]
            pkg = PackageId("gha", repo, sha)
            short = sha[:10]

            if res.kind == "exists":
                # A real commit. We deliberately do NOT flag "the `# vX` tag has moved
                # past this SHA": pinning to an older real commit while the tag advances
                # is the correct, normal case, and flagging it would false-positive on
                # virtually every well-pinned action. Detecting a *lying* comment (a SHA
                # that was never on that tag's line — the tj-actions CVE-2025-30066 class)
                # needs tag-ancestry resolution and is a deliberate fast-follow
                # (FindingType.MUTABLE_TAG is reserved for it).
                continue

            if res.kind == "unverified":
                unverified.append(f"{repo}@{short}" + (f" (HTTP {res.status})" if res.status else ""))
                continue

            # fabricated_commit / fabricated_repo
            key = ("fab", f"{repo}@{sha}", res.kind)
            if key in seen_fab:
                continue
            seen_fab.add(key)

            if res.kind == "fabricated_repo":
                findings.append(Finding(
                    finding_type=FindingType.FABRICATED_REF,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"Action references a non-existent repository: {repo}",
                    detail=(
                        f"`{repo}` does not exist on GitHub (HTTP 404). The action name is "
                        f"fabricated or typo'd; this workflow cannot run. Verify the correct "
                        f"owner/repo and re-pin with `ratchet pin`."
                    ),
                    references=[f"https://github.com/{repo}"],
                    metadata={"workflow": workflow_path, "repo": repo, "sha": sha,
                              "http_status": res.status, "fault_class": "fabricated_repo"},
                ))
                continue

            # fabricated_commit — characterise the fault (the incident was "conflation":
            # a real tag's SHA prefix followed by a hallucinated tail).
            fault = "pure_fabrication_or_typo"
            tag_hint = ""
            if comment and _VERSION_COMMENT_RE.match(comment):
                tag_sha = await _resolve_tag(client, repo, comment)
                if tag_sha:
                    real = tag_sha.lower()
                    common = len(os.path.commonprefix([real, sha]))
                    if common >= 7:
                        fault = "conflation"
                        tag_hint = (f" The real {comment} is {real[:10]} (shares a "
                                    f"{common}-char prefix — a real prefix with a hallucinated tail).")
                    else:
                        tag_hint = f" The real {comment} is {real[:10]}."
            findings.append(Finding(
                finding_type=FindingType.FABRICATED_REF,
                severity=Severity.CRITICAL,
                package=pkg,
                title=f"Action pinned to a non-existent commit: {repo}",
                detail=(
                    f"{repo}@{short} resolves to no commit in the upstream repo "
                    f"(HTTP {res.status}). The pin is fabricated, typo'd, or hallucinated — "
                    f"CI will fail at dispatch.{tag_hint} Never hand-write a SHA; resolve it "
                    f"with `ratchet pin`."
                ),
                references=[f"https://github.com/{repo}/commits"],
                metadata={"workflow": workflow_path, "repo": repo, "sha": sha,
                          "http_status": res.status, "fault_class": fault},
            ))

        if unverified:
            uniq = sorted(set(unverified))
            findings.append(Finding(
                finding_type=FindingType.UNVERIFIED_REF,
                severity=Severity.INFO,
                package=PackageId("gha", ".github/workflows"),
                title=f"{len(uniq)} action pin(s) could not be verified",
                detail=(
                    "Existence of these pins was NOT confirmed (no GITHUB_TOKEN, rate limit, "
                    "or network error) — this is not proof they are real. Set GITHUB_TOKEN "
                    "(5000 req/hr) and re-scan. Refs: " + ", ".join(uniq[:25])
                    + (" ..." if len(uniq) > 25 else "")
                ),
                metadata={"unverified": uniq},
            ))

        return findings
