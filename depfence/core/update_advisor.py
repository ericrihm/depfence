"""Dependency update safety advisor.

Evaluates whether proposed dependency updates are safe to merge:
- Semver analysis (patch vs minor vs major)
- Breaking change risk estimation
- Test coverage signal
- Package popularity/stability indicators
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class UpdateRisk(Enum):
    SAFE = "safe"  # Auto-mergeable
    LOW = "low"  # Likely safe, brief review
    MEDIUM = "medium"  # Needs review
    HIGH = "high"  # Needs thorough review
    BREAKING = "breaking"  # Major version bump, manual only


@dataclass
class UpdateRecommendation:
    package: str
    ecosystem: str
    current_version: str
    target_version: str
    risk: UpdateRisk
    reasons: list[str] = field(default_factory=list)
    auto_merge: bool = False

    @property
    def summary(self) -> str:
        return f"{self.package}: {self.current_version} → {self.target_version} [{self.risk.value}]"


def analyze_update(
    package: str,
    ecosystem: str,
    current_version: str,
    target_version: str,
    is_dev_dep: bool = False,
    has_lockfile: bool = True,
    test_coverage: float | None = None,
) -> UpdateRecommendation:
    """Analyze a single dependency update for safety."""
    reasons: list[str] = []
    risk = UpdateRisk.SAFE

    # Parse versions
    current = _parse_semver(current_version)
    target = _parse_semver(target_version)

    if current is None or target is None:
        reasons.append("Could not parse semver — manual review needed")
        return UpdateRecommendation(
            package=package, ecosystem=ecosystem,
            current_version=current_version, target_version=target_version,
            risk=UpdateRisk.MEDIUM, reasons=reasons, auto_merge=False,
        )

    # Determine bump type
    if target[0] > current[0]:
        risk = UpdateRisk.BREAKING
        reasons.append(f"Major version bump ({current[0]} → {target[0]}): likely breaking changes")
    elif target[1] > current[1]:
        risk = UpdateRisk.LOW
        reasons.append(f"Minor version bump: new features, should be backward-compatible")
        if target[1] - current[1] > 3:
            risk = UpdateRisk.MEDIUM
            reasons.append(f"Multiple minor versions skipped ({target[1] - current[1]}): increased risk")
    elif target[2] > current[2]:
        risk = UpdateRisk.SAFE
        reasons.append("Patch version bump: bug fixes only")
    else:
        reasons.append("Same or lower version — no update needed")
        return UpdateRecommendation(
            package=package, ecosystem=ecosystem,
            current_version=current_version, target_version=target_version,
            risk=UpdateRisk.SAFE, reasons=reasons, auto_merge=False,
        )

    # Dev dependency discount
    if is_dev_dep and risk in (UpdateRisk.LOW, UpdateRisk.MEDIUM):
        risk = UpdateRisk.SAFE if risk == UpdateRisk.LOW else UpdateRisk.LOW
        reasons.append("Dev dependency: lower risk to production")

    # Lockfile protection
    if has_lockfile:
        reasons.append("Lockfile present: transitive deps are pinned")
    else:
        if risk == UpdateRisk.SAFE:
            risk = UpdateRisk.LOW
        reasons.append("No lockfile: transitive deps may change unexpectedly")

    # Test coverage factor
    if test_coverage is not None:
        if test_coverage > 0.8:
            reasons.append(f"High test coverage ({test_coverage:.0%}): regressions likely caught")
        elif test_coverage < 0.3:
            if risk == UpdateRisk.LOW:
                risk = UpdateRisk.MEDIUM
            reasons.append(f"Low test coverage ({test_coverage:.0%}): regressions may go undetected")

    # Auto-merge decision
    auto_merge = risk == UpdateRisk.SAFE

    return UpdateRecommendation(
        package=package, ecosystem=ecosystem,
        current_version=current_version, target_version=target_version,
        risk=risk, reasons=reasons, auto_merge=auto_merge,
    )


def batch_analyze(
    updates: list[dict],
    has_lockfile: bool = True,
    test_coverage: float | None = None,
) -> list[UpdateRecommendation]:
    """Analyze a batch of proposed updates.

    Each update dict should have: package, ecosystem, current_version, target_version, is_dev_dep (optional)
    """
    results = []
    for u in updates:
        rec = analyze_update(
            package=u["package"],
            ecosystem=u["ecosystem"],
            current_version=u["current_version"],
            target_version=u["target_version"],
            is_dev_dep=u.get("is_dev_dep", False),
            has_lockfile=has_lockfile,
            test_coverage=test_coverage,
        )
        results.append(rec)

    results.sort(key=lambda r: _risk_order(r.risk))
    return results


def generate_update_plan(recommendations: list[UpdateRecommendation]) -> dict:
    """Generate an update plan from recommendations."""
    auto_merge = [r for r in recommendations if r.auto_merge]
    needs_review = [r for r in recommendations if not r.auto_merge and r.risk != UpdateRisk.BREAKING]
    breaking = [r for r in recommendations if r.risk == UpdateRisk.BREAKING]

    return {
        "auto_merge": [r.summary for r in auto_merge],
        "needs_review": [r.summary for r in needs_review],
        "breaking_changes": [r.summary for r in breaking],
        "stats": {
            "total": len(recommendations),
            "auto_mergeable": len(auto_merge),
            "needs_review": len(needs_review),
            "breaking": len(breaking),
        },
    }


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    """Parse a semver string into (major, minor, patch)."""
    # Strip leading 'v' or '^' or '~'
    v = version.lstrip("v^~>=<! ")
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    if not m:
        return None
    return (
        int(m.group(1)),
        int(m.group(2) or 0),
        int(m.group(3) or 0),
    )


def _risk_order(risk: UpdateRisk) -> int:
    return {
        UpdateRisk.BREAKING: 0,
        UpdateRisk.HIGH: 1,
        UpdateRisk.MEDIUM: 2,
        UpdateRisk.LOW: 3,
        UpdateRisk.SAFE: 4,
    }[risk]
