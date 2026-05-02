"""Remediation strategy definitions for classifying how a finding should be fixed."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from depfence.core.models import Finding, FindingType


class StrategyKind(str, enum.Enum):
    VERSION_BUMP = "version_bump"
    REPLACE = "replace_package"
    REMOVE = "remove_dependency"
    MANUAL = "manual"  # no automated fix available


@dataclass
class VersionBumpStrategy:
    """Bump the package to a safe semver version."""

    kind: StrategyKind = field(default=StrategyKind.VERSION_BUMP, init=False)
    package: str = ""
    ecosystem: str = ""
    current_version: str | None = None
    fix_version: str = ""

    @classmethod
    def from_finding(cls, finding: Finding) -> "VersionBumpStrategy":
        pkg_str = str(finding.package)
        parts = pkg_str.split(":")
        ecosystem = parts[0] if len(parts) == 2 else "unknown"
        name_ver = parts[1] if len(parts) == 2 else pkg_str
        if "@" in name_ver:
            name, current = name_ver.rsplit("@", 1)
        else:
            name, current = name_ver, None
        return cls(
            package=name,
            ecosystem=ecosystem,
            current_version=current,
            fix_version=finding.fix_version or "",
        )


@dataclass
class ReplaceStrategy:
    """Replace the package with a safe alternative (e.g. a fork or successor)."""

    kind: StrategyKind = field(default=StrategyKind.REPLACE, init=False)
    package: str = ""
    ecosystem: str = ""
    current_version: str | None = None
    replacement: str = ""
    reason: str = ""

    @classmethod
    def from_finding(cls, finding: Finding, replacement: str = "", reason: str = "") -> "ReplaceStrategy":
        pkg_str = str(finding.package)
        parts = pkg_str.split(":")
        ecosystem = parts[0] if len(parts) == 2 else "unknown"
        name_ver = parts[1] if len(parts) == 2 else pkg_str
        name, current = (name_ver.rsplit("@", 1) if "@" in name_ver else (name_ver, None))
        return cls(
            package=name,
            ecosystem=ecosystem,
            current_version=current,
            replacement=replacement or f"{name}-safe",
            reason=reason or finding.detail,
        )


@dataclass
class RemoveStrategy:
    """Remove the dependency entirely (malicious or abandoned)."""

    kind: StrategyKind = field(default=StrategyKind.REMOVE, init=False)
    package: str = ""
    ecosystem: str = ""
    current_version: str | None = None
    reason: str = ""

    @classmethod
    def from_finding(cls, finding: Finding) -> "RemoveStrategy":
        pkg_str = str(finding.package)
        parts = pkg_str.split(":")
        ecosystem = parts[0] if len(parts) == 2 else "unknown"
        name_ver = parts[1] if len(parts) == 2 else pkg_str
        name, current = (name_ver.rsplit("@", 1) if "@" in name_ver else (name_ver, None))
        return cls(
            package=name,
            ecosystem=ecosystem,
            current_version=current,
            reason=finding.detail,
        )


# Findings that should be removed rather than bumped
_REMOVE_TYPES = {FindingType.MALICIOUS}

# Findings where replace is preferred when no fix_version is available
_REPLACE_PREFERRED_TYPES = {FindingType.DEPRECATED, FindingType.TYPOSQUAT, FindingType.SLOPSQUAT}


AnyStrategy = VersionBumpStrategy | ReplaceStrategy | RemoveStrategy


def classify_finding(finding: Finding) -> AnyStrategy | None:
    """Return the best-fit strategy for *finding*, or None if not remediable."""
    if finding.finding_type in _REMOVE_TYPES:
        return RemoveStrategy.from_finding(finding)

    if finding.fix_version:
        return VersionBumpStrategy.from_finding(finding)

    if finding.finding_type in _REPLACE_PREFERRED_TYPES:
        alt = finding.metadata.get("alternative", "")
        return ReplaceStrategy.from_finding(finding, replacement=str(alt) if alt else "")

    return None
