"""Package trust scoring system.

Combines multiple signals (download count, age, maintainer count, repo stars,
CI status, documentation quality) into a single 0-100 trust score with letter grade.

Higher score = more trustworthy. Lower score = riskier.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from depfence.core.models import PackageId


@dataclass
class TrustSignals:
    weekly_downloads: int | None = None
    age_days: int | None = None
    maintainer_count: int | None = None
    has_repository: bool = False
    has_readme: bool = False
    has_license: bool = False
    has_types: bool = False
    version_count: int | None = None
    last_publish_days: int | None = None
    has_ci: bool = False
    has_provenance: bool = False
    open_issues: int | None = None
    dependents_count: int | None = None


@dataclass
class TrustScore:
    package: PackageId
    score: float  # 0-100
    grade: str  # A, B, C, D, F
    signals: TrustSignals
    breakdown: dict[str, float]  # signal_name -> contribution to total score
    risk_factors: list[str]  # human-readable risk reasons


# ---------------------------------------------------------------------------
# Internal scoring helpers
# ---------------------------------------------------------------------------

def _score_downloads(weekly_downloads: int | None) -> tuple[float, list[str]]:
    """Downloads (weight 20%): 0 if <100/week, scales log to 100 at 1M+."""
    risks: list[str] = []
    if weekly_downloads is None:
        risks.append("Download count unknown")
        return 0.0, risks
    if weekly_downloads < 100:
        risks.append(f"Very low weekly downloads ({weekly_downloads:,})")
        return 0.0, risks
    # log10(100)=2, log10(1_000_000)=6 → map [2,6] -> [0,100]
    log_val = math.log10(max(weekly_downloads, 100))
    raw = (log_val - 2.0) / (6.0 - 2.0) * 100.0
    return min(raw, 100.0), risks


def _score_age(age_days: int | None) -> tuple[float, list[str]]:
    """Age (weight 15%): 0 if <7 days, 50 at 30 days, 100 at 365+ days."""
    risks: list[str] = []
    if age_days is None:
        risks.append("Package age unknown")
        return 0.0, risks
    if age_days < 0:
        age_days = 0
    if age_days < 7:
        risks.append(f"Published {age_days} day{'s' if age_days != 1 else ''} ago")
        return 0.0, risks
    if age_days < 30:
        # linear 7→30: 0→50
        raw = (age_days - 7) / (30 - 7) * 50.0
        risks.append(f"Package is only {age_days} days old")
        return raw, risks
    if age_days < 365:
        # linear 30→365: 50→100
        raw = 50.0 + (age_days - 30) / (365 - 30) * 50.0
        return raw, risks
    return 100.0, risks


def _score_maintainers(maintainer_count: int | None) -> tuple[float, list[str]]:
    """Maintainers (weight 10%): 0 if 0, 50 if 1, 80 if 2, 100 if 3+."""
    risks: list[str] = []
    if maintainer_count is None:
        risks.append("Maintainer count unknown")
        return 0.0, risks
    if maintainer_count <= 0:
        risks.append("No maintainers listed")
        return 0.0, risks
    if maintainer_count == 1:
        risks.append("Single maintainer")
        return 50.0, risks
    if maintainer_count == 2:
        return 80.0, risks
    return 100.0, risks


def _score_repository(has_repository: bool, has_ci: bool) -> tuple[float, list[str]]:
    """Repository (weight 15%): 0 if none, 50 if exists, 100 if has CI."""
    risks: list[str] = []
    if not has_repository:
        risks.append("No repository URL")
        return 0.0, risks
    if has_ci:
        return 100.0, risks
    risks.append("Repository exists but no CI detected")
    return 50.0, risks


def _score_documentation(has_readme: bool, has_license: bool, has_types: bool) -> tuple[float, list[str]]:
    """Documentation (weight 10%): sum of (readme, license, types) * 33."""
    risks: list[str] = []
    count = sum([has_readme, has_license, has_types])
    if not has_readme:
        risks.append("No README")
    if not has_license:
        risks.append("No license file")
    score = min(count * 33.0, 100.0)  # 3 items * 33 ≈ 99; cap at 100
    if count == 3:
        score = 100.0
    return score, risks


def _score_freshness(last_publish_days: int | None) -> tuple[float, list[str]]:
    """Freshness (weight 10%): 100 if <90 days, decreasing to 0 at 730+ days."""
    risks: list[str] = []
    if last_publish_days is None:
        risks.append("Last publish date unknown")
        return 0.0, risks
    if last_publish_days < 0:
        last_publish_days = 0
    if last_publish_days < 90:
        return 100.0, risks
    if last_publish_days >= 730:
        risks.append(f"Not updated in {last_publish_days} days (over 2 years)")
        return 0.0, risks
    # linear 90→730: 100→0
    raw = 100.0 - (last_publish_days - 90) / (730 - 90) * 100.0
    if last_publish_days > 365:
        risks.append(f"Not updated in {last_publish_days} days")
    return max(raw, 0.0), risks


def _score_provenance(has_provenance: bool) -> tuple[float, list[str]]:
    """Provenance (weight 10%): 0 or 100."""
    risks: list[str] = []
    if not has_provenance:
        risks.append("No build provenance / attestation")
        return 0.0, risks
    return 100.0, risks


def _score_dependents(dependents_count: int | None) -> tuple[float, list[str]]:
    """Dependents (weight 10%): 0 if 0, log scale to 100 at 1000+."""
    risks: list[str] = []
    if dependents_count is None:
        risks.append("Dependents count unknown")
        return 0.0, risks
    if dependents_count <= 0:
        risks.append("No known dependents")
        return 0.0, risks
    # log10(1)=0, log10(1000)=3 → map [0,3] -> [0,100]
    log_val = math.log10(max(dependents_count, 1))
    raw = log_val / 3.0 * 100.0
    return min(raw, 100.0), risks


# ---------------------------------------------------------------------------
# Weights (must sum to 1.0)
# ---------------------------------------------------------------------------
_WEIGHTS = {
    "downloads": 0.20,
    "age": 0.15,
    "maintainers": 0.10,
    "repository": 0.15,
    "documentation": 0.10,
    "freshness": 0.10,
    "provenance": 0.10,
    "dependents": 0.10,
}


def _score_to_grade(score: float) -> str:
    if score >= 80:
        return "A"
    elif score >= 65:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 35:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_trust(package: PackageId, signals: TrustSignals) -> TrustScore:
    """Compute a composite trust score for a package given its signals.

    Returns a TrustScore with a 0-100 score, letter grade, per-signal
    breakdown, and a list of human-readable risk factors.
    """
    dl_raw, dl_risks = _score_downloads(signals.weekly_downloads)
    age_raw, age_risks = _score_age(signals.age_days)
    maint_raw, maint_risks = _score_maintainers(signals.maintainer_count)
    repo_raw, repo_risks = _score_repository(signals.has_repository, signals.has_ci)
    doc_raw, doc_risks = _score_documentation(
        signals.has_readme, signals.has_license, signals.has_types
    )
    fresh_raw, fresh_risks = _score_freshness(signals.last_publish_days)
    prov_raw, prov_risks = _score_provenance(signals.has_provenance)
    dep_raw, dep_risks = _score_dependents(signals.dependents_count)

    # Weighted contributions (each is the signal's 0-100 score × weight × 100
    # such that the sum equals the 0-100 final score)
    breakdown = {
        "downloads": round(dl_raw * _WEIGHTS["downloads"], 2),
        "age": round(age_raw * _WEIGHTS["age"], 2),
        "maintainers": round(maint_raw * _WEIGHTS["maintainers"], 2),
        "repository": round(repo_raw * _WEIGHTS["repository"], 2),
        "documentation": round(doc_raw * _WEIGHTS["documentation"], 2),
        "freshness": round(fresh_raw * _WEIGHTS["freshness"], 2),
        "provenance": round(prov_raw * _WEIGHTS["provenance"], 2),
        "dependents": round(dep_raw * _WEIGHTS["dependents"], 2),
    }

    total_score = round(sum(breakdown.values()), 2)
    grade = _score_to_grade(total_score)

    risk_factors = (
        dl_risks
        + age_risks
        + maint_risks
        + repo_risks
        + doc_risks
        + fresh_risks
        + prov_risks
        + dep_risks
    )

    return TrustScore(
        package=package,
        score=total_score,
        grade=grade,
        signals=signals,
        breakdown=breakdown,
        risk_factors=risk_factors,
    )


def batch_trust_scores(
    packages: list[tuple[PackageId, TrustSignals]],
) -> list[TrustScore]:
    """Compute trust scores for a list of (PackageId, TrustSignals) pairs.

    Returns results sorted by score ascending (riskiest packages first).
    """
    scores = [compute_trust(pkg, signals) for pkg, signals in packages]
    scores.sort(key=lambda ts: ts.score)
    return scores
