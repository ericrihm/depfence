"""Lockfile drift detection — catch when CI/local lockfile differs from git HEAD."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import PackageId


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VersionChange:
    name: str
    ecosystem: str
    old_version: str | None
    new_version: str | None

    @property
    def is_major_bump(self) -> bool:
        """True if the major version number increased."""
        try:
            old_major = int((self.old_version or "0").split(".")[0].lstrip("v~^"))
            new_major = int((self.new_version or "0").split(".")[0].lstrip("v~^"))
            return new_major > old_major
        except (ValueError, IndexError):
            return False

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name} {self.old_version} -> {self.new_version}"


@dataclass
class LockfileDiff:
    """Package-level diff between two lockfile snapshots."""
    additions: list[PackageId] = field(default_factory=list)
    removals: list[PackageId] = field(default_factory=list)
    version_changes: list[VersionChange] = field(default_factory=list)
    new_ecosystems: list[str] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.additions) + len(self.removals) + len(self.version_changes)

    @property
    def is_clean(self) -> bool:
        return self.total_changes == 0

    @property
    def major_bumps(self) -> list[VersionChange]:
        return [c for c in self.version_changes if c.is_major_bump]

    def to_dict(self) -> dict:
        return {
            "additions": [str(p) for p in self.additions],
            "removals": [str(p) for p in self.removals],
            "version_changes": [
                {
                    "package": f"{c.ecosystem}:{c.name}",
                    "old": c.old_version,
                    "new": c.new_version,
                    "major_bump": c.is_major_bump,
                }
                for c in self.version_changes
            ],
            "new_ecosystems": self.new_ecosystems,
            "total_changes": self.total_changes,
            "is_clean": self.is_clean,
        }


@dataclass
class DriftReport:
    """Result of comparing disk lockfile state vs. git HEAD."""
    added: list[PackageId] = field(default_factory=list)
    removed: list[PackageId] = field(default_factory=list)
    updated: list[VersionChange] = field(default_factory=list)
    lockfile_path: str = ""
    is_clean: bool = True
    git_available: bool = True
    error: str | None = None

    @property
    def supply_chain_risk_packages(self) -> list[PackageId]:
        """New packages are potential supply-chain risk; return them."""
        return self.added

    @property
    def major_version_jumps(self) -> list[VersionChange]:
        return [u for u in self.updated if u.is_major_bump]

    def to_dict(self) -> dict:
        return {
            "lockfile_path": self.lockfile_path,
            "is_clean": self.is_clean,
            "git_available": self.git_available,
            "error": self.error,
            "added": [str(p) for p in self.added],
            "removed": [str(p) for p in self.removed],
            "updated": [
                {
                    "package": f"{u.ecosystem}:{u.name}",
                    "old": u.old_version,
                    "new": u.new_version,
                    "major_bump": u.is_major_bump,
                }
                for u in self.updated
            ],
            "major_version_jumps": len(self.major_version_jumps),
            "supply_chain_risks": len(self.supply_chain_risk_packages),
        }

    def render_table(self) -> str:
        lines: list[str] = []
        if self.error:
            lines.append(f"  Error: {self.error}")
            return "\n".join(lines)
        if self.is_clean:
            return "  No drift detected — lockfile matches git HEAD."
        if self.lockfile_path:
            lines.append(f"  Lockfile: {self.lockfile_path}")
        if self.added:
            lines.append(f"  + {len(self.added)} added (potential supply-chain risk):")
            for p in self.added:
                lines.append(f"    \033[32m+ {p}\033[0m")
        if self.removed:
            lines.append(f"  - {len(self.removed)} removed:")
            for p in self.removed:
                lines.append(f"    \033[31m- {p}\033[0m")
        if self.updated:
            majors = [u for u in self.updated if u.is_major_bump]
            lines.append(f"  ~ {len(self.updated)} version changes ({len(majors)} major bumps):")
            for u in self.updated:
                flag = " \033[33m[MAJOR]\033[0m" if u.is_major_bump else ""
                lines.append(f"    \033[33m~ {u}\033[0m{flag}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helper: parse lockfiles
# ---------------------------------------------------------------------------

def _parse_packages_from_bytes(ecosystem: str, content: bytes, filename: str) -> list[PackageId]:
    """Parse package list from raw lockfile bytes without writing a temp file."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=f"_{filename}", delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        from depfence.core.lockfile import parse_lockfile
        return parse_lockfile(ecosystem, tmp_path)
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _packages_by_key(packages: list[PackageId]) -> dict[tuple[str, str], PackageId]:
    return {(p.ecosystem, p.name): p for p in packages}


def _run_git(args: list[str], cwd: Path) -> tuple[bool, bytes, str]:
    """Run a git command; returns (success, stdout_bytes, stderr_str)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0, result.stdout, result.stderr.decode(errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, b"", str(exc)


# ---------------------------------------------------------------------------
# Core detector
# ---------------------------------------------------------------------------

class DriftDetector:
    """Detects lockfile drift between disk state and git history."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_drift(self, project_dir: Path) -> DriftReport:
        """Compare every lockfile on disk against git HEAD."""
        from depfence.core.lockfile import detect_ecosystem

        project_dir = Path(project_dir).resolve()
        lockfiles = detect_ecosystem(project_dir)
        if not lockfiles:
            return DriftReport(
                is_clean=True,
                error="No lockfiles found in project directory.",
            )

        # Combine diffs across all lockfiles
        report = DriftReport(is_clean=True)
        for eco, lf_path in lockfiles:
            single = self._diff_single_lockfile(project_dir, eco, lf_path)
            if single.error and not report.error:
                report.error = single.error
                report.git_available = single.git_available
            report.added.extend(single.added)
            report.removed.extend(single.removed)
            report.updated.extend(single.updated)

        report.is_clean = (
            not report.added and not report.removed and not report.updated
        )
        if lockfiles:
            report.lockfile_path = str(lockfiles[0][1])
        return report

    def compare_lockfiles(self, old_path: Path, new_path: Path) -> LockfileDiff:
        """Package-level diff between two lockfiles on disk."""
        old_path = Path(old_path)
        new_path = Path(new_path)

        old_eco = self._guess_ecosystem_from_path(old_path)
        new_eco = self._guess_ecosystem_from_path(new_path)

        from depfence.core.lockfile import parse_lockfile
        old_pkgs = parse_lockfile(old_eco, old_path)
        new_pkgs = parse_lockfile(new_eco, new_path)

        diff = self._compute_lockfile_diff(old_pkgs, new_pkgs)

        # Detect new ecosystems
        old_ecos = {p.ecosystem for p in old_pkgs}
        new_ecos = {p.ecosystem for p in new_pkgs}
        diff.new_ecosystems = sorted(new_ecos - old_ecos)

        return diff

    # ------------------------------------------------------------------
    # CI drift detection
    # ------------------------------------------------------------------

    def detect_ci_drift(self, lockfile_path: Path) -> bool:
        """
        Return True if the lockfile on disk differs from git HEAD version.
        Useful in CI to catch uncommitted lockfile mutations.
        """
        lockfile_path = Path(lockfile_path).resolve()
        project_dir = lockfile_path.parent
        try:
            rel = lockfile_path.relative_to(project_dir)
        except ValueError:
            rel = lockfile_path

        ok, git_content, _ = _run_git(
            ["show", f"HEAD:{rel}"], cwd=project_dir
        )
        if not ok:
            # Not tracked or not in a git repo — treat as no drift
            return False

        disk_content = lockfile_path.read_bytes()
        return hashlib.sha256(disk_content).hexdigest() != hashlib.sha256(git_content).hexdigest()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _diff_single_lockfile(
        self, project_dir: Path, ecosystem: str, lf_path: Path
    ) -> DriftReport:
        """Compare a single lockfile against git HEAD."""
        report = DriftReport(lockfile_path=str(lf_path), is_clean=True)
        try:
            rel = lf_path.relative_to(project_dir)
        except ValueError:
            rel = lf_path

        ok, git_bytes, stderr = _run_git(["show", f"HEAD:{rel}"], cwd=project_dir)
        if not ok:
            if "not a git repository" in stderr.lower():
                report.git_available = False
                report.error = "Not a git repository."
            else:
                # File not tracked in git — all current packages are "added"
                from depfence.core.lockfile import parse_lockfile
                current_pkgs = parse_lockfile(ecosystem, lf_path)
                report.added = current_pkgs
                report.is_clean = len(current_pkgs) == 0
            return report

        # Parse HEAD version
        git_pkgs = _parse_packages_from_bytes(ecosystem, git_bytes, lf_path.name)
        # Parse disk version
        from depfence.core.lockfile import parse_lockfile
        disk_pkgs = parse_lockfile(ecosystem, lf_path)

        diff = self._compute_lockfile_diff(git_pkgs, disk_pkgs)
        report.added = diff.additions
        report.removed = diff.removals
        report.updated = diff.version_changes
        report.is_clean = diff.is_clean
        return report

    @staticmethod
    def _compute_lockfile_diff(
        old_pkgs: list[PackageId], new_pkgs: list[PackageId]
    ) -> LockfileDiff:
        old_map = _packages_by_key(old_pkgs)
        new_map = _packages_by_key(new_pkgs)

        additions: list[PackageId] = []
        removals: list[PackageId] = []
        changes: list[VersionChange] = []

        for key, pkg in new_map.items():
            if key not in old_map:
                additions.append(pkg)
            elif old_map[key].version != pkg.version:
                changes.append(
                    VersionChange(
                        name=pkg.name,
                        ecosystem=pkg.ecosystem,
                        old_version=old_map[key].version,
                        new_version=pkg.version,
                    )
                )

        for key, pkg in old_map.items():
            if key not in new_map:
                removals.append(pkg)

        return LockfileDiff(
            additions=additions,
            removals=removals,
            version_changes=changes,
        )

    @staticmethod
    def _guess_ecosystem_from_path(path: Path) -> str:
        name = path.name.lower()
        mapping = {
            "package-lock.json": "npm",
            "yarn.lock": "npm",
            "pnpm-lock.yaml": "npm",
            "requirements.txt": "pypi",
            "poetry.lock": "pypi",
            "pipfile.lock": "pypi",
            "uv.lock": "pypi",
            "cargo.lock": "cargo",
            "go.sum": "go",
            "gradle.lockfile": "maven",
            "package.resolved": "swift",
            "podfile.lock": "swift",
            "packages.lock.json": "nuget",
            "gemfile.lock": "rubygems",
            "composer.lock": "packagist",
        }
        return mapping.get(name, "unknown")
