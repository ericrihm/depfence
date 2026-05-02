"""Monorepo workspace scanner — detects and scans workspace packages independently.

Supports:
- npm workspaces (package.json "workspaces" field)
- pnpm workspaces (pnpm-workspace.yaml)
- Yarn workspaces (package.json "workspaces")
- Python monorepos (multiple pyproject.toml files)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class WorkspacePackage:
    name: str
    path: Path
    ecosystem: str
    version: str | None = None
    dependencies: list[str] = field(default_factory=list)


@dataclass
class WorkspaceInfo:
    root: Path
    workspace_type: str  # "npm", "pnpm", "yarn", "python"
    packages: list[WorkspacePackage] = field(default_factory=list)


def detect_workspace(project_dir: Path) -> WorkspaceInfo | None:
    """Detect if project is a monorepo workspace and identify packages."""
    # Check pnpm-workspace.yaml first (most explicit)
    pnpm_ws = project_dir / "pnpm-workspace.yaml"
    if pnpm_ws.exists():
        return _parse_pnpm_workspace(project_dir, pnpm_ws)

    # Check package.json workspaces
    pkg_json = project_dir / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            workspaces = data.get("workspaces")
            if workspaces:
                ws_type = "yarn" if (project_dir / "yarn.lock").exists() else "npm"
                return _parse_npm_workspace(project_dir, workspaces, ws_type)
        except (json.JSONDecodeError, OSError):
            pass

    # Check for Python monorepo (multiple pyproject.toml)
    pyprojects = list(project_dir.glob("*/pyproject.toml"))
    if len(pyprojects) >= 2:
        return _parse_python_monorepo(project_dir, pyprojects)

    return None


def _parse_pnpm_workspace(root: Path, ws_file: Path) -> WorkspaceInfo:
    """Parse pnpm-workspace.yaml."""
    try:
        data = yaml.safe_load(ws_file.read_text())
        patterns = data.get("packages", [])
    except (yaml.YAMLError, OSError):
        return WorkspaceInfo(root=root, workspace_type="pnpm")

    packages = _resolve_glob_patterns(root, patterns)
    return WorkspaceInfo(root=root, workspace_type="pnpm", packages=packages)


def _parse_npm_workspace(root: Path, workspaces: list | dict, ws_type: str) -> WorkspaceInfo:
    """Parse npm/yarn workspace config."""
    if isinstance(workspaces, dict):
        patterns = workspaces.get("packages", [])
    else:
        patterns = workspaces

    packages = _resolve_glob_patterns(root, patterns)
    return WorkspaceInfo(root=root, workspace_type=ws_type, packages=packages)


def _parse_python_monorepo(root: Path, pyprojects: list[Path]) -> WorkspaceInfo:
    """Parse Python monorepo from multiple pyproject.toml files."""
    packages = []
    for pp in pyprojects:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        try:
            data = tomllib.loads(pp.read_text())
            project = data.get("project", {})
            name = project.get("name", pp.parent.name)
            version = project.get("version")
            deps = [d.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
                    for d in project.get("dependencies", [])]
            packages.append(WorkspacePackage(
                name=name,
                path=pp.parent,
                ecosystem="pypi",
                version=version,
                dependencies=deps,
            ))
        except (OSError, ValueError, KeyError):
            continue

    return WorkspaceInfo(root=root, workspace_type="python", packages=packages)


def _resolve_glob_patterns(root: Path, patterns: list[str]) -> list[WorkspacePackage]:
    """Resolve workspace glob patterns to actual packages."""
    packages = []
    for pattern in patterns:
        # Expand globs
        if "*" in pattern:
            matches = list(root.glob(pattern))
        else:
            matches = [root / pattern]

        for pkg_dir in matches:
            if not pkg_dir.is_dir():
                continue
            pkg_json = pkg_dir / "package.json"
            if pkg_json.exists():
                try:
                    data = json.loads(pkg_json.read_text())
                    name = data.get("name", pkg_dir.name)
                    version = data.get("version")
                    deps = list(data.get("dependencies", {}).keys())
                    deps.extend(data.get("devDependencies", {}).keys())
                    packages.append(WorkspacePackage(
                        name=name,
                        path=pkg_dir,
                        ecosystem="npm",
                        version=version,
                        dependencies=deps,
                    ))
                except (json.JSONDecodeError, OSError):
                    continue

    return packages


def workspace_summary(info: WorkspaceInfo) -> dict:
    """Generate a summary of the workspace."""
    return {
        "type": info.workspace_type,
        "root": str(info.root),
        "package_count": len(info.packages),
        "packages": [
            {
                "name": p.name,
                "path": str(p.path.relative_to(info.root)),
                "ecosystem": p.ecosystem,
                "version": p.version,
                "dep_count": len(p.dependencies),
            }
            for p in info.packages
        ],
    }
