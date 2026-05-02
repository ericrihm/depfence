"""OpenSSF Scorecard enrichment for package metadata.

Fetches Scorecard scores for packages that expose a GitHub repository URL,
then surfaces supply-chain findings for packages with poor scores.
"""

from __future__ import annotations

import logging

from depfence.core.models import Finding, FindingType, PackageMeta, Severity
from depfence.core.scorecard_client import ScorecardClient, ScorecardResult

log = logging.getLogger(__name__)

# Overall-score thresholds for risk classification
_CRITICAL_THRESHOLD = 3.0
_HIGH_THRESHOLD = 5.0
_MEDIUM_THRESHOLD = 7.0

# Per-check score below which the check is considered "weak"
_WEAK_CHECK_THRESHOLD = 5

# Minimum overall score to generate a Finding
_FINDING_SCORE_THRESHOLD = 5.0


def _risk_level(score: float) -> str:
    """Translate a numeric Scorecard overall score to a risk label."""
    if score < _CRITICAL_THRESHOLD:
        return "critical"
    if score < _HIGH_THRESHOLD:
        return "high"
    if score < _MEDIUM_THRESHOLD:
        return "medium"
    return "good"


def _severity_for_score(score: float) -> Severity:
    """Map a Scorecard overall score to a depfence Severity."""
    if score < _CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if score < _HIGH_THRESHOLD:
        return Severity.HIGH
    return Severity.MEDIUM


async def enrich_with_scorecard(packages: list[PackageMeta]) -> list[dict]:
    """Fetch OpenSSF Scorecard data for packages that have a repository URL.

    Parameters
    ----------
    packages:
        List of :class:`~depfence.core.models.PackageMeta` objects.  Only
        packages whose ``repository`` field is non-empty and points to a
        GitHub URL are queried.

    Returns
    -------
    list[dict]
        One dict per package that had a scoreable repository.  Each dict
        contains:

        * ``package`` — the :class:`~depfence.core.models.PackageId`
        * ``repo`` — the repository identifier string (``owner/repo``)
        * ``score`` — the overall Scorecard score (float)
        * ``risk_level`` — one of ``"critical"``, ``"high"``, ``"medium"``, ``"good"``
        * ``weak_checks`` — list of :class:`~depfence.core.scorecard_client.ScorecardCheck`
          objects whose score is below :data:`_WEAK_CHECK_THRESHOLD`
    """
    # Collect packages that have a GitHub repo URL
    repo_to_packages: dict[str, list[PackageMeta]] = {}
    for pkg_meta in packages:
        repo_url = pkg_meta.repository
        if not repo_url or "github.com" not in repo_url:
            continue
        repo_to_packages.setdefault(repo_url, []).append(pkg_meta)

    if not repo_to_packages:
        return []

    unique_urls = list(repo_to_packages.keys())
    log.debug("Fetching Scorecard scores for %d repositories", len(unique_urls))

    async with ScorecardClient() as client:
        scores: dict[str, ScorecardResult] = await client.batch_scores(unique_urls)

    results: list[dict] = []
    for repo_url, score_result in scores.items():
        weak_checks = [c for c in score_result.checks if c.score != -1 and c.score < _WEAK_CHECK_THRESHOLD]
        risk = _risk_level(score_result.overall_score)

        for pkg_meta in repo_to_packages[repo_url]:
            results.append(
                {
                    "package": pkg_meta.pkg,
                    "repo": score_result.repo,
                    "score": score_result.overall_score,
                    "risk_level": risk,
                    "weak_checks": weak_checks,
                }
            )

    return results


def scorecard_findings(results: list[dict]) -> list[Finding]:
    """Generate security findings for packages with poor Scorecard scores.

    A finding is generated for every entry in *results* whose overall score
    is below :data:`_FINDING_SCORE_THRESHOLD` (i.e. ``< 5``).

    Parameters
    ----------
    results:
        Output from :func:`enrich_with_scorecard`.

    Returns
    -------
    list[Finding]
        Findings with :attr:`~depfence.core.models.FindingType.PROVENANCE`
        type and severity scaled to the score.
    """
    findings: list[Finding] = []

    for entry in results:
        score: float = entry["score"]
        if score >= _FINDING_SCORE_THRESHOLD:
            continue

        package = entry["package"]
        repo = entry["repo"]
        weak_checks = entry["weak_checks"]
        severity = _severity_for_score(score)

        weak_names = ", ".join(c.name for c in weak_checks) if weak_checks else "none"
        detail_lines = [
            f"OpenSSF Scorecard overall score: {score:.1f}/10.",
            f"Repository: {repo}.",
        ]
        if weak_checks:
            detail_lines.append(f"Weak checks (score < 5): {weak_names}.")

        findings.append(
            Finding(
                finding_type=FindingType.PROVENANCE,
                severity=severity,
                package=package,
                title=f"Poor supply chain score: {score:.1f}/10 ({repo})",
                detail=" ".join(detail_lines),
                references=[
                    f"https://scorecard.dev/viewer/?uri=github.com/{repo}"
                ],
                metadata={
                    "scorecard_score": score,
                    "scorecard_repo": repo,
                    "weak_checks": [c.name for c in weak_checks],
                },
            )
        )

    return findings
