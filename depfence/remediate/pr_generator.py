"""PR draft generator — groups findings by strategy and builds PR metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from depfence.core.models import Finding, FindingType, Severity
from depfence.remediate.strategies import (
    AnyStrategy,
    RemoveStrategy,
    ReplaceStrategy,
    StrategyKind,
    VersionBumpStrategy,
    classify_finding,
)


@dataclass
class PullRequestDraft:
    """All information needed to open a remediation PR."""

    title: str
    body: str
    branch: str
    files_changed: list[str]
    findings_fixed: list[Finding]

    # Populated after the strategy groups are built
    strategy_kind: StrategyKind = StrategyKind.VERSION_BUMP

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PullRequestDraft branch={self.branch!r} fixes={len(self.findings_fixed)}>"


class RemediationPR:
    """Generate :class:`PullRequestDraft` objects from a list of findings.

    Usage::

        gen = RemediationPR(branch_prefix="depfence")
        drafts = gen.generate(findings, project_dir)
    """

    def __init__(self, branch_prefix: str = "depfence") -> None:
        self.branch_prefix = branch_prefix

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        findings: Sequence[Finding],
        project_dir: Path,
    ) -> list[PullRequestDraft]:
        """Return a list of PR drafts, one per strategy group."""
        classified: list[tuple[Finding, AnyStrategy]] = []
        for finding in findings:
            strategy = classify_finding(finding)
            if strategy is not None:
                classified.append((finding, strategy))

        if not classified:
            return []

        # Group by strategy kind
        bumps: list[tuple[Finding, VersionBumpStrategy]] = []
        replaces: list[tuple[Finding, ReplaceStrategy]] = []
        removes: list[tuple[Finding, RemoveStrategy]] = []

        for finding, strategy in classified:
            if isinstance(strategy, VersionBumpStrategy):
                bumps.append((finding, strategy))
            elif isinstance(strategy, ReplaceStrategy):
                replaces.append((finding, strategy))
            elif isinstance(strategy, RemoveStrategy):
                removes.append((finding, strategy))

        drafts: list[PullRequestDraft] = []

        if bumps:
            drafts.append(self._build_version_bump_pr(bumps, project_dir))

        for finding, strategy in replaces:
            drafts.append(self._build_replace_pr(finding, strategy, project_dir))

        for finding, strategy in removes:
            drafts.append(self._build_remove_pr(finding, strategy, project_dir))

        return drafts

    # ------------------------------------------------------------------
    # PR builders
    # ------------------------------------------------------------------

    def _build_version_bump_pr(
        self,
        items: list[tuple[Finding, VersionBumpStrategy]],
        project_dir: Path,
    ) -> PullRequestDraft:
        """Build a single PR that bumps all patchable packages."""
        cve_ids = sorted(
            {f.cve for f, _ in items if f.cve},
            key=lambda c: (c or ""),
        )

        branch = self._branch_name_for_bumps(cve_ids)
        title = self._title_for_bumps(items, cve_ids)
        body = self._body_for_bumps(items, project_dir)
        files_changed = self._infer_files(items, project_dir)

        return PullRequestDraft(
            title=title,
            body=body,
            branch=branch,
            files_changed=files_changed,
            findings_fixed=[f for f, _ in items],
            strategy_kind=StrategyKind.VERSION_BUMP,
        )

    def _build_replace_pr(
        self,
        finding: Finding,
        strategy: ReplaceStrategy,
        project_dir: Path,
    ) -> PullRequestDraft:
        pkg_label = strategy.package
        branch = f"{self.branch_prefix}/replace-{_slug(pkg_label)}"
        title = f"security: replace {pkg_label} with {strategy.replacement}"
        body = self._body_for_replace(finding, strategy, project_dir)
        files_changed = self._infer_files([(finding, strategy)], project_dir)

        return PullRequestDraft(
            title=title,
            body=body,
            branch=branch,
            files_changed=files_changed,
            findings_fixed=[finding],
            strategy_kind=StrategyKind.REPLACE,
        )

    def _build_remove_pr(
        self,
        finding: Finding,
        strategy: RemoveStrategy,
        project_dir: Path,
    ) -> PullRequestDraft:
        pkg_label = strategy.package
        cve_part = f"-{finding.cve}" if finding.cve else ""
        branch = f"{self.branch_prefix}/remove-{_slug(pkg_label)}{cve_part}"
        title = f"security: remove malicious dependency {pkg_label}"
        body = self._body_for_remove(finding, strategy, project_dir)
        files_changed = self._infer_files([(finding, strategy)], project_dir)

        return PullRequestDraft(
            title=title,
            body=body,
            branch=branch,
            files_changed=files_changed,
            findings_fixed=[finding],
            strategy_kind=StrategyKind.REMOVE,
        )

    # ------------------------------------------------------------------
    # Branch naming helpers
    # ------------------------------------------------------------------

    def _branch_name_for_bumps(self, cve_ids: list[str]) -> str:
        if len(cve_ids) == 1:
            return f"{self.branch_prefix}/fix-{cve_ids[0]}"
        if len(cve_ids) <= 3:
            return f"{self.branch_prefix}/fix-{'_'.join(cve_ids)}"
        return f"{self.branch_prefix}/security-updates"

    # ------------------------------------------------------------------
    # Title helpers
    # ------------------------------------------------------------------

    def _title_for_bumps(
        self,
        items: list[tuple[Finding, VersionBumpStrategy]],
        cve_ids: list[str],
    ) -> str:
        n = len(items)
        if n == 1:
            f, s = items[0]
            cve_part = f" ({f.cve})" if f.cve else ""
            return f"security: bump {s.package} to {s.fix_version}{cve_part}"
        if cve_ids:
            ids_str = ", ".join(cve_ids[:3])
            suffix = " and more" if len(cve_ids) > 3 else ""
            return f"security: fix {n} vulnerable dependencies ({ids_str}{suffix})"
        return f"security: bump {n} vulnerable dependencies to safe versions"

    # ------------------------------------------------------------------
    # Body builders
    # ------------------------------------------------------------------

    def _body_for_bumps(
        self,
        items: list[tuple[Finding, VersionBumpStrategy]],
        project_dir: Path,
    ) -> str:
        lines: list[str] = []
        lines.append("## Summary\n")
        lines.append(
            f"This PR was automatically generated by **depfence** to fix "
            f"{len(items)} vulnerable "
            + ("dependency." if len(items) == 1 else "dependencies.")
        )
        lines.append("")

        lines.append("## Findings Fixed\n")
        lines.append("| Package | Current Version | Fixed Version | CVE | Severity |")
        lines.append("|---------|----------------|--------------|-----|----------|")
        for finding, strategy in sorted(items, key=lambda t: _severity_rank(t[0].severity)):
            cve = finding.cve or "—"
            cur = strategy.current_version or "unknown"
            lines.append(
                f"| `{strategy.package}` | `{cur}` | `{strategy.fix_version}` "
                f"| {cve} | **{finding.severity.value.upper()}** |"
            )

        lines.append("")
        lines.append("## Risk Assessment\n")
        critical = sum(1 for f, _ in items if f.severity == Severity.CRITICAL)
        high = sum(1 for f, _ in items if f.severity == Severity.HIGH)
        medium = sum(1 for f, _ in items if f.severity == Severity.MEDIUM)
        low = sum(1 for f, _ in items if f.severity == Severity.LOW)
        if critical:
            lines.append(f"- :red_circle: **{critical} CRITICAL** — immediate action required")
        if high:
            lines.append(f"- :orange_circle: **{high} HIGH** — fix soon")
        if medium:
            lines.append(f"- :yellow_circle: **{medium} MEDIUM**")
        if low:
            lines.append(f"- :white_circle: **{low} LOW**")

        lines.append("")
        lines.append("## Details\n")
        for finding, strategy in items:
            cve_hdr = f" — {finding.cve}" if finding.cve else ""
            lines.append(f"### `{strategy.package}`{cve_hdr}")
            lines.append(f"**{finding.title}**")
            lines.append("")
            lines.append(finding.detail)
            if finding.references:
                lines.append("")
                lines.append("References:")
                for ref in finding.references[:3]:
                    lines.append(f"- {ref}")
            lines.append("")

        lines.append("---")
        lines.append("_Generated by [depfence](https://github.com/depfence/depfence). "
                     "Review changes before merging._")

        return "\n".join(lines)

    def _body_for_replace(
        self,
        finding: Finding,
        strategy: ReplaceStrategy,
        project_dir: Path,
    ) -> str:
        lines: list[str] = []
        lines.append("## Summary\n")
        lines.append(
            f"This PR replaces **`{strategy.package}`** with **`{strategy.replacement}`** "
            f"because no patched version is available."
        )
        lines.append("")
        lines.append("## Finding\n")
        cve = finding.cve or "—"
        lines.append(f"- **CVE/ID:** {cve}")
        lines.append(f"- **Severity:** {finding.severity.value.upper()}")
        lines.append(f"- **Title:** {finding.title}")
        lines.append(f"- **Detail:** {finding.detail}")
        lines.append("")
        lines.append("## Risk Assessment\n")
        lines.append(f"Replacing `{strategy.package}` eliminates the risk associated with {cve}.")
        lines.append(f"Reason: {strategy.reason}")
        lines.append("")
        lines.append("---")
        lines.append("_Generated by [depfence](https://github.com/depfence/depfence)._")
        return "\n".join(lines)

    def _body_for_remove(
        self,
        finding: Finding,
        strategy: RemoveStrategy,
        project_dir: Path,
    ) -> str:
        lines: list[str] = []
        lines.append("## Summary\n")
        lines.append(
            f"This PR **removes `{strategy.package}`** which has been identified as "
            f"a malicious or severely compromised package."
        )
        lines.append("")
        lines.append("## Finding\n")
        cve = finding.cve or "—"
        lines.append(f"- **CVE/ID:** {cve}")
        lines.append(f"- **Severity:** {finding.severity.value.upper()}")
        lines.append(f"- **Title:** {finding.title}")
        lines.append(f"- **Detail:** {finding.detail}")
        lines.append("")
        lines.append("> :warning: **Action required:** Audit your codebase for any use of "
                     f"`{strategy.package}` and remove all imports/usages before merging.")
        lines.append("")
        lines.append("## Risk Assessment\n")
        lines.append(f"Keeping `{strategy.package}` poses an active security risk. "
                     "Removal is the only safe remediation.")
        lines.append("")
        lines.append("---")
        lines.append("_Generated by [depfence](https://github.com/depfence/depfence)._")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Manifest file inference
    # ------------------------------------------------------------------

    def _infer_files(
        self,
        items: list[tuple[Finding, AnyStrategy]],
        project_dir: Path,
    ) -> list[str]:
        """Return manifest paths that would be modified for the given items."""
        ecosystems = {s.ecosystem for _, s in items}
        candidate_files: list[str] = []
        mapping = {
            "npm": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
            "pypi": ["requirements.txt", "pyproject.toml", "setup.cfg", "Pipfile"],
            "cargo": ["Cargo.toml", "Cargo.lock"],
            "go": ["go.mod", "go.sum"],
        }
        for eco in sorted(ecosystems):
            for fname in mapping.get(eco, []):
                fpath = project_dir / fname
                if fpath.exists():
                    candidate_files.append(str(fpath.relative_to(project_dir)))
        return candidate_files or ["(no manifest found)"]


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _slug(text: str) -> str:
    """Convert a string to a URL/branch-safe slug."""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", text).strip("-")


def _severity_rank(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }.get(sev, 9)
