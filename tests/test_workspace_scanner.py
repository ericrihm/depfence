"""Tests for monorepo workspace scanner."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.workspace_scanner import (
    WorkspaceInfo,
    WorkspacePackage,
    detect_workspace,
    workspace_summary,
)


class TestNpmWorkspace:
    def test_detects_npm_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "name": "root",
                "workspaces": ["packages/*"],
            }))
            pkg_a = root / "packages" / "pkg-a"
            pkg_a.mkdir(parents=True)
            (pkg_a / "package.json").write_text(json.dumps({
                "name": "@scope/pkg-a",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            }))
            pkg_b = root / "packages" / "pkg-b"
            pkg_b.mkdir(parents=True)
            (pkg_b / "package.json").write_text(json.dumps({
                "name": "@scope/pkg-b",
                "version": "2.0.0",
                "dependencies": {"express": "^4.18.0"},
            }))

            info = detect_workspace(root)
            assert info is not None
            assert info.workspace_type == "npm"
            assert len(info.packages) == 2
            names = {p.name for p in info.packages}
            assert "@scope/pkg-a" in names
            assert "@scope/pkg-b" in names

    def test_yarn_detected_with_yarn_lock(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["packages/*"],
            }))
            (root / "yarn.lock").write_text("")
            pkg = root / "packages" / "pkg"
            pkg.mkdir(parents=True)
            (pkg / "package.json").write_text(json.dumps({"name": "pkg"}))

            info = detect_workspace(root)
            assert info is not None
            assert info.workspace_type == "yarn"


class TestPnpmWorkspace:
    def test_detects_pnpm_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pnpm-workspace.yaml").write_text("packages:\n  - 'apps/*'\n")
            app = root / "apps" / "web"
            app.mkdir(parents=True)
            (app / "package.json").write_text(json.dumps({
                "name": "web-app",
                "version": "0.1.0",
                "dependencies": {"react": "^18.0.0"},
            }))

            info = detect_workspace(root)
            assert info is not None
            assert info.workspace_type == "pnpm"
            assert len(info.packages) == 1
            assert info.packages[0].name == "web-app"


class TestPythonMonorepo:
    def test_detects_python_monorepo(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pkg_a = root / "service-a"
            pkg_a.mkdir()
            (pkg_a / "pyproject.toml").write_text('[project]\nname = "service-a"\nversion = "1.0.0"\ndependencies = ["flask>=2.0"]\n')
            pkg_b = root / "service-b"
            pkg_b.mkdir()
            (pkg_b / "pyproject.toml").write_text('[project]\nname = "service-b"\nversion = "2.0.0"\ndependencies = ["fastapi>=0.100"]\n')

            info = detect_workspace(root)
            assert info is not None
            assert info.workspace_type == "python"
            assert len(info.packages) == 2


class TestNoWorkspace:
    def test_returns_none_for_simple_project(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "name": "simple",
                "dependencies": {"lodash": "^4"},
            }))
            info = detect_workspace(root)
            assert info is None


class TestWorkspaceSummary:
    def test_summary_structure(self):
        info = WorkspaceInfo(
            root=Path("/tmp/project"),
            workspace_type="npm",
            packages=[
                WorkspacePackage(name="a", path=Path("/tmp/project/a"), ecosystem="npm", version="1.0.0", dependencies=["x", "y"]),
                WorkspacePackage(name="b", path=Path("/tmp/project/b"), ecosystem="npm", version="2.0.0", dependencies=["z"]),
            ],
        )
        summary = workspace_summary(info)
        assert summary["type"] == "npm"
        assert summary["package_count"] == 2
        assert summary["packages"][0]["dep_count"] == 2
