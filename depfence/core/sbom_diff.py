"""SBOM diffing — compare dependency sets between builds/releases."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import PackageId


@dataclass
class SbomDiff:
    added: list[PackageId] = field(default_factory=list)
    removed: list[PackageId] = field(default_factory=list)
    upgraded: list[tuple[PackageId, PackageId]] = field(default_factory=list)
    downgraded: list[tuple[PackageId, PackageId]] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.removed) + len(self.upgraded) + len(self.downgraded)

    @property
    def risk_score(self) -> int:
        """Rough risk score: new deps are riskiest, downgrades are suspicious."""
        score = 0
        score += len(self.added) * 3
        score += len(self.downgraded) * 5
        score += len(self.upgraded) * 1
        score += len(self.removed) * 0
        return min(score, 100)

    def to_dict(self) -> dict:
        return {
            "added": [str(p) for p in self.added],
            "removed": [str(p) for p in self.removed],
            "upgraded": [{"from": str(a), "to": str(b)} for a, b in self.upgraded],
            "downgraded": [{"from": str(a), "to": str(b)} for a, b in self.downgraded],
            "total_changes": self.total_changes,
            "risk_score": self.risk_score,
        }

    def render_table(self) -> str:
        lines = []
        if self.added:
            lines.append(f"  + {len(self.added)} new dependencies:")
            for p in self.added:
                lines.append(f"    + {p}")
        if self.removed:
            lines.append(f"  - {len(self.removed)} removed:")
            for p in self.removed:
                lines.append(f"    - {p}")
        if self.upgraded:
            lines.append(f"  ^ {len(self.upgraded)} upgraded:")
            for old, new in self.upgraded:
                lines.append(f"    ^ {old.name}: {old.version} -> {new.version}")
        if self.downgraded:
            lines.append(f"  ! {len(self.downgraded)} DOWNGRADED (suspicious):")
            for old, new in self.downgraded:
                lines.append(f"    ! {old.name}: {old.version} -> {new.version}")
        if not lines:
            return "  No changes detected."
        lines.append(f"\n  Risk score: {self.risk_score}/100 | Total changes: {self.total_changes}")
        return "\n".join(lines)


def diff_sboms(before: list[PackageId], after: list[PackageId]) -> SbomDiff:
    """Compute the diff between two package lists."""
    before_map: dict[tuple[str, str], PackageId] = {
        (p.ecosystem, p.name): p for p in before
    }
    after_map: dict[tuple[str, str], PackageId] = {
        (p.ecosystem, p.name): p for p in after
    }

    result = SbomDiff()

    for key, pkg in after_map.items():
        if key not in before_map:
            result.added.append(pkg)
        elif before_map[key].version != pkg.version:
            old = before_map[key]
            if _is_upgrade(old.version, pkg.version):
                result.upgraded.append((old, pkg))
            else:
                result.downgraded.append((old, pkg))

    for key, pkg in before_map.items():
        if key not in after_map:
            result.removed.append(pkg)

    return result


def diff_sbom_files(before_path: Path, after_path: Path) -> SbomDiff:
    """Diff two CycloneDX SBOM JSON files."""
    before_pkgs = _parse_cyclonedx(before_path)
    after_pkgs = _parse_cyclonedx(after_path)
    return diff_sboms(before_pkgs, after_pkgs)


def _parse_cyclonedx(path: Path) -> list[PackageId]:
    """Extract PackageIds from a CycloneDX SBOM."""
    data = json.loads(path.read_text())
    packages = []
    for comp in data.get("components", []):
        purl = comp.get("purl", "")
        if purl.startswith("pkg:"):
            eco, rest = _parse_purl(purl)
            if eco and rest:
                name, version = rest
                packages.append(PackageId(eco, name, version))
        else:
            eco = _guess_ecosystem(comp)
            name = comp.get("name", "")
            version = comp.get("version", "unknown")
            if name:
                packages.append(PackageId(eco, name, version))
    return packages


def _parse_purl(purl: str) -> tuple[str, tuple[str, str] | None]:
    """Parse a Package URL into (ecosystem, (name, version))."""
    # pkg:npm/lodash@4.17.21
    try:
        without_prefix = purl[4:]  # strip "pkg:"
        eco_and_rest = without_prefix.split("/", 1)
        eco = eco_and_rest[0]
        name_ver = eco_and_rest[1] if len(eco_and_rest) > 1 else ""
        if "@" in name_ver:
            at_idx = name_ver.rfind("@")
            name = name_ver[:at_idx]
            version = name_ver[at_idx + 1:].split("?")[0]
        else:
            name = name_ver
            version = "unknown"
        return eco, (name, version)
    except (IndexError, ValueError):
        return "", None


def _guess_ecosystem(component: dict) -> str:
    """Best-effort ecosystem guess from CycloneDX component."""
    ptype = component.get("type", "")
    if ptype == "npm":
        return "npm"
    bom_ref = component.get("bom-ref", "")
    if "npm" in bom_ref:
        return "npm"
    if "pypi" in bom_ref or "pip" in bom_ref:
        return "pypi"
    return "unknown"


def _is_upgrade(old_ver: str | None, new_ver: str | None) -> bool:
    """Compare semver-ish versions. Returns True if new > old."""
    if not old_ver or not new_ver:
        return True
    old_parts = _version_tuple(old_ver)
    new_parts = _version_tuple(new_ver)
    return new_parts >= old_parts


def _version_tuple(v: str) -> tuple[int, ...]:
    """Convert version string to comparable tuple."""
    parts = []
    for segment in v.split("."):
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)
