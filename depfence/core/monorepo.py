"""Monorepo-aware scan orchestrator.

Discovers workspace packages across npm/pnpm/yarn/Python monorepos,
deduplicates findings across workspaces, and reports per-workspace impact.

Uses only stdlib (json, pathlib, glob, re) — no external dependencies.
YAML parsing for pnpm-workspace.yaml is handled with regex since the
format is simple enough not to need a full parser.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import Finding, PackageId, Severity


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WorkspaceInfo:
    name: str
    path: Path
    ecosystem: str
    packages: list[PackageId] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def _parse_yaml_packages(yaml_text: str) -> list[str]:
    """Extract the 'packages' list from a simple pnpm-workspace.yaml.

    Only handles the subset of YAML used by pnpm:
        packages:
          - 'glob/*'
          - "other/*"
          - bare_pattern
    """
    # Find the packages block and collect list items
    patterns: list[str] = []
    in_packages = False
    for line in yaml_text.splitlines():
        if re.match(r"^packages\s*:", line):
            in_packages = True
            continue
        if in_packages:
            # A list item starts with optional spaces then "- "
            m = re.match(r"^\s+-\s+['\"]?([^'\"#\n]+?)['\"]?\s*(?:#.*)?$", line)
            if m:
                patterns.append(m.group(1).strip())
            elif line.strip() and not line.startswith(" ") and not line.startswith("\t"):
                # New top-level key — end of packages block
                in_packages = False
    return patterns


def _resolve_patterns(root: Path, patterns: list[str]) -> list[Path]:
    """Resolve glob patterns relative to *root*, returning existing dirs."""
    dirs: list[Path] = []
    for pattern in patterns:
        # Strip leading "./" for cleaner glob
        pattern = pattern.lstrip("./")
        if "*" in pattern or "?" in pattern:
            matched = list(root.glob(pattern))
        else:
            matched = [root / pattern]
        for p in matched:
            if p.is_dir():
                dirs.append(p)
    return dirs


def _packages_from_npm_dir(pkg_dir: Path, ecosystem: str) -> list[PackageId]:
    """Return PackageIds for direct + dev deps listed in package.json."""
    pkg_json = pkg_dir / "package.json"
    if not pkg_json.exists():
        return []
    try:
        data = json.loads(pkg_json.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    ids: list[PackageId] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_spec in data.get(section, {}).items():
            # version_spec is a range like "^1.2.3"; strip leading ^~>=<
            ver = re.sub(r"^[\^~>=<]", "", version_spec).strip() or None
            ids.append(PackageId(ecosystem=ecosystem, name=name, version=ver))
    return ids


def _packages_from_pyproject(pyproject: Path) -> list[PackageId]:
    """Return PackageIds for deps listed in pyproject.toml [project.dependencies]."""
    try:
        text = pyproject.read_text()
    except OSError:
        return []

    ids: list[PackageId] = []
    # Minimal TOML parsing: extract [project].dependencies list
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^\[project\]", stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and not stripped.startswith("[project"):
            in_deps = False
        if not in_deps:
            continue
        m = re.match(r'^dependencies\s*=\s*\[', stripped)
        if m:
            # Inline list — collect items on this and subsequent lines
            # Re-read the whole deps block with a simple state machine
            break

    # Use regex to find the dependencies array in the file
    deps_block_match = re.search(
        r"^\[project\].*?^dependencies\s*=\s*\[([^\]]*)\]",
        text,
        re.DOTALL | re.MULTILINE,
    )
    if deps_block_match:
        block = deps_block_match.group(1)
        for item in block.split(","):
            item = item.strip().strip('"').strip("'").strip()
            if not item:
                continue
            # Parse "package>=1.0,<2.0" → name + optional version
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!,\s].*)?$", item)
            if m:
                name = m.group(1)
                ver_part = (m.group(2) or "").strip()
                # Take the first version constraint value
                ver_m = re.search(r"[\d][^\s,]*", ver_part)
                ver = ver_m.group(0) if ver_m else None
                ids.append(PackageId(ecosystem="pypi", name=name, version=ver))
    return ids


def _workspace_name_from_npm(pkg_dir: Path) -> str:
    pkg_json = pkg_dir / "package.json"
    try:
        data = json.loads(pkg_json.read_text())
        return data.get("name", pkg_dir.name)
    except (json.JSONDecodeError, OSError):
        return pkg_dir.name


def _workspace_name_from_pyproject(pyproject: Path) -> str:
    try:
        text = pyproject.read_text()
    except OSError:
        return pyproject.parent.name
    m = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    return m.group(1) if m else pyproject.parent.name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_workspaces(project_dir: Path) -> list[WorkspaceInfo]:
    """Discover workspace packages in *project_dir*.

    Supports:
    - npm workspaces  (package.json "workspaces": [...] or {"packages": [...]})
    - yarn workspaces (same as npm; detected by presence of yarn.lock)
    - pnpm workspaces (pnpm-workspace.yaml "packages" field)
    - Python monorepos (multiple pyproject.toml / setup.py files)

    Returns an empty list when no workspace configuration is found.
    """
    # pnpm takes precedence (most explicit)
    pnpm_ws = project_dir / "pnpm-workspace.yaml"
    if pnpm_ws.exists():
        return _discover_pnpm(project_dir, pnpm_ws)

    # npm / yarn — package.json with "workspaces" field
    pkg_json_path = project_dir / "package.json"
    if pkg_json_path.exists():
        try:
            root_data = json.loads(pkg_json_path.read_text())
        except (json.JSONDecodeError, OSError):
            root_data = {}
        workspaces_cfg = root_data.get("workspaces")
        if workspaces_cfg is not None:
            is_yarn = (project_dir / "yarn.lock").exists()
            return _discover_npm_yarn(project_dir, workspaces_cfg, is_yarn)

    # Python monorepo — multiple pyproject.toml files (one level deep)
    pyprojects = list(project_dir.glob("*/pyproject.toml"))
    if len(pyprojects) >= 2:
        return _discover_python(project_dir, pyprojects)

    # Also check for multiple setup.py (older Python monorepos)
    setup_pys = list(project_dir.glob("*/setup.py"))
    if len(setup_pys) >= 2:
        return [
            WorkspaceInfo(
                name=p.parent.name,
                path=p.parent,
                ecosystem="pypi",
                packages=[],
            )
            for p in setup_pys
            if p.parent.is_dir()
        ]

    return []


def _discover_pnpm(project_dir: Path, ws_file: Path) -> list[WorkspaceInfo]:
    try:
        yaml_text = ws_file.read_text()
    except OSError:
        return []
    patterns = _parse_yaml_packages(yaml_text)
    workspace_dirs = _resolve_patterns(project_dir, patterns)
    workspaces: list[WorkspaceInfo] = []
    for pkg_dir in workspace_dirs:
        name = _workspace_name_from_npm(pkg_dir)
        pkgs = _packages_from_npm_dir(pkg_dir, "npm")
        workspaces.append(WorkspaceInfo(name=name, path=pkg_dir, ecosystem="npm", packages=pkgs))
    return workspaces


def _discover_npm_yarn(
    project_dir: Path,
    workspaces_cfg: list | dict,
    is_yarn: bool,
) -> list[WorkspaceInfo]:
    if isinstance(workspaces_cfg, dict):
        patterns = workspaces_cfg.get("packages", [])
    else:
        patterns = list(workspaces_cfg)

    ecosystem = "npm"  # both npm and yarn packages are "npm" ecosystem
    workspace_dirs = _resolve_patterns(project_dir, patterns)
    workspaces: list[WorkspaceInfo] = []
    for pkg_dir in workspace_dirs:
        name = _workspace_name_from_npm(pkg_dir)
        pkgs = _packages_from_npm_dir(pkg_dir, ecosystem)
        workspaces.append(WorkspaceInfo(name=name, path=pkg_dir, ecosystem=ecosystem, packages=pkgs))
    return workspaces


def _discover_python(project_dir: Path, pyprojects: list[Path]) -> list[WorkspaceInfo]:
    workspaces: list[WorkspaceInfo] = []
    for pyproject in sorted(pyprojects):
        name = _workspace_name_from_pyproject(pyproject)
        pkgs = _packages_from_pyproject(pyproject)
        workspaces.append(
            WorkspaceInfo(name=name, path=pyproject.parent, ecosystem="pypi", packages=pkgs)
        )
    return workspaces


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_findings(
    findings: list[Finding],
    workspaces: list[WorkspaceInfo],
) -> list[dict]:
    """Group findings by (package_name, cve/title) and annotate affected workspaces.

    Each returned dict has the same fields as a Finding plus:
        affected_workspaces: list[str]  — workspace names that contain the package
        occurrence_count: int            — total raw occurrences before dedup
    """
    # Build a reverse map: package name → workspace names
    pkg_to_workspaces: dict[str, list[str]] = {}
    for ws in workspaces:
        for pkg_id in ws.packages:
            pkg_to_workspaces.setdefault(pkg_id.name, []).append(ws.name)

    # Group findings by dedup key
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        key = (finding.package.name, finding.cve or finding.title)
        groups.setdefault(key, []).append(finding)

    result: list[dict] = []
    for (pkg_name, _vuln_key), group in groups.items():
        # Pick representative finding (first in group)
        rep = group[0]
        affected = pkg_to_workspaces.get(pkg_name, [])
        result.append(
            {
                "finding_type": rep.finding_type,
                "severity": rep.severity,
                "package": rep.package,
                "title": rep.title,
                "detail": rep.detail,
                "cve": rep.cve,
                "cwe": rep.cwe,
                "fix_version": rep.fix_version,
                "references": rep.references,
                "confidence": rep.confidence,
                "metadata": rep.metadata,
                "affected_workspaces": affected,
                "occurrence_count": len(group),
            }
        )
    return result


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def workspace_summary(workspaces: list[WorkspaceInfo], findings: list[Finding]) -> dict:
    """Produce a per-workspace and overall summary.

    Per-workspace keys:
        package_count, finding_count, severity_breakdown

    Overall keys:
        total_packages_deduped, shared_packages, unique_packages,
        total_findings, workspace_count
    """
    # Index findings by package name for quick lookup
    findings_by_pkg: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_pkg.setdefault(f.package.name, []).append(f)

    severity_zero: dict[str, int] = {s.value: 0 for s in Severity}

    per_workspace: list[dict] = []
    all_pkg_names: list[str] = []
    pkg_name_to_ws_count: dict[str, int] = {}

    for ws in workspaces:
        ws_pkg_names = [p.name for p in ws.packages]
        all_pkg_names.extend(ws_pkg_names)
        for n in ws_pkg_names:
            pkg_name_to_ws_count[n] = pkg_name_to_ws_count.get(n, 0) + 1

        # Findings that affect this workspace (package name intersection)
        ws_pkg_set = {p.name for p in ws.packages}
        ws_findings = [f for f in findings if f.package.name in ws_pkg_set]

        sev_breakdown = dict(severity_zero)
        for f in ws_findings:
            sev_breakdown[f.severity.value] = sev_breakdown.get(f.severity.value, 0) + 1

        per_workspace.append(
            {
                "name": ws.name,
                "path": str(ws.path),
                "ecosystem": ws.ecosystem,
                "package_count": len(ws.packages),
                "finding_count": len(ws_findings),
                "severity_breakdown": sev_breakdown,
            }
        )

    # Overall stats
    all_pkg_set = set(all_pkg_names)
    shared = {name for name, count in pkg_name_to_ws_count.items() if count > 1}
    unique = all_pkg_set - shared

    return {
        "workspace_count": len(workspaces),
        "total_packages_deduped": len(all_pkg_set),
        "shared_packages": sorted(shared),
        "unique_packages": sorted(unique),
        "total_findings": len(findings),
        "workspaces": per_workspace,
    }
