"""Tests for monorepo-aware scan orchestrator (depfence.core.monorepo)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.core.monorepo import (
    WorkspaceInfo,
    deduplicate_findings,
    discover_workspaces,
    workspace_summary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pkg_json(pkg_dir: Path, name: str, version: str = "1.0.0", deps: dict | None = None) -> None:
    pkg_dir.mkdir(parents=True, exist_ok=True)
    data: dict = {"name": name, "version": version}
    if deps:
        data["dependencies"] = deps
    (pkg_dir / "package.json").write_text(json.dumps(data))


def _make_pyproject(pkg_dir: Path, name: str, version: str = "1.0.0", deps: list[str] | None = None) -> None:
    pkg_dir.mkdir(parents=True, exist_ok=True)
    lines = ['[project]', f'name = "{name}"', f'version = "{version}"']
    if deps:
        items = ", ".join(f'"{d}"' for d in deps)
        lines.append(f"dependencies = [{items}]")
    (pkg_dir / "pyproject.toml").write_text("\n".join(lines) + "\n")


def _finding(name: str, version: str = "1.0.0", cve: str | None = "CVE-2023-0001",
              severity: Severity = Severity.HIGH, ecosystem: str = "npm") -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem=ecosystem, name=name, version=version),
        title=f"Vuln in {name}",
        detail="Some detail",
        cve=cve,
    )


# ---------------------------------------------------------------------------
# npm workspace detection
# ---------------------------------------------------------------------------

class TestNpmWorkspaceDiscovery:
    def test_array_workspaces_field(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "name": "root",
                "workspaces": ["packages/*"],
            }))
            _make_pkg_json(root / "packages" / "pkg-a", "@scope/pkg-a", deps={"lodash": "^4.17.21"})
            _make_pkg_json(root / "packages" / "pkg-b", "@scope/pkg-b", deps={"express": "^4.18.0"})

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 2
            names = {ws.name for ws in workspaces}
            assert "@scope/pkg-a" in names
            assert "@scope/pkg-b" in names

    def test_object_workspaces_field_with_packages_key(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "name": "root",
                "workspaces": {"packages": ["apps/*"]},
            }))
            _make_pkg_json(root / "apps" / "web", "web")

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            assert workspaces[0].name == "web"

    def test_packages_populated_from_dependencies(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["pkgs/*"],
            }))
            _make_pkg_json(root / "pkgs" / "alpha", "alpha", deps={"react": "^18.0.0", "axios": "^1.0.0"})

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            ws = workspaces[0]
            pkg_names = {p.name for p in ws.packages}
            assert "react" in pkg_names
            assert "axios" in pkg_names

    def test_ecosystem_is_npm(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({"workspaces": ["pkg/*"]}))
            _make_pkg_json(root / "pkg" / "x", "x")

            workspaces = discover_workspaces(root)
            assert all(ws.ecosystem == "npm" for ws in workspaces)

    def test_non_directory_globs_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({"workspaces": ["pkgs/*"]}))
            # Create a file instead of a directory under pkgs/
            pkgs = root / "pkgs"
            pkgs.mkdir()
            (pkgs / "not-a-dir.json").write_text("{}")
            # Only one real package dir
            _make_pkg_json(pkgs / "real-pkg", "real-pkg")

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            assert workspaces[0].name == "real-pkg"


# ---------------------------------------------------------------------------
# pnpm workspace detection
# ---------------------------------------------------------------------------

class TestPnpmWorkspaceDiscovery:
    def test_basic_pnpm_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pnpm-workspace.yaml").write_text(
                "packages:\n  - 'apps/*'\n  - 'packages/*'\n"
            )
            _make_pkg_json(root / "apps" / "web", "web-app", deps={"react": "^18.0.0"})
            _make_pkg_json(root / "packages" / "ui", "@co/ui")

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 2
            names = {ws.name for ws in workspaces}
            assert "web-app" in names
            assert "@co/ui" in names

    def test_pnpm_takes_precedence_over_package_json(self):
        """If pnpm-workspace.yaml exists, it is used even when package.json has workspaces."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pnpm-workspace.yaml").write_text("packages:\n  - 'apps/*'\n")
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["packages/*"],
            }))
            _make_pkg_json(root / "apps" / "alpha", "alpha")
            _make_pkg_json(root / "packages" / "beta", "beta")

            workspaces = discover_workspaces(root)
            names = {ws.name for ws in workspaces}
            # Only the pnpm-defined workspace should be discovered
            assert "alpha" in names
            assert "beta" not in names

    def test_pnpm_yaml_double_quoted_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pnpm-workspace.yaml").write_text(
                'packages:\n  - "services/*"\n'
            )
            _make_pkg_json(root / "services" / "api", "api-service")

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1

    def test_pnpm_packages_populated(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pnpm-workspace.yaml").write_text("packages:\n  - 'libs/*'\n")
            _make_pkg_json(root / "libs" / "core", "core", deps={"lodash": "^4.0.0"})

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            pkg_names = {p.name for p in workspaces[0].packages}
            assert "lodash" in pkg_names


# ---------------------------------------------------------------------------
# Yarn workspace detection
# ---------------------------------------------------------------------------

class TestYarnWorkspaceDiscovery:
    def test_yarn_detected_via_yarn_lock(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["packages/*"],
            }))
            (root / "yarn.lock").write_text("# yarn lockfile v1\n")
            _make_pkg_json(root / "packages" / "pkg", "my-pkg")

            # discover_workspaces doesn't distinguish yarn from npm at the
            # WorkspaceInfo level (ecosystem is always "npm"), but the
            # discovery should still work.
            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            assert workspaces[0].name == "my-pkg"


# ---------------------------------------------------------------------------
# Python monorepo detection
# ---------------------------------------------------------------------------

class TestPythonMonorepoDiscovery:
    def test_multiple_pyproject_toml(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_pyproject(root / "service-a", "service-a", deps=["flask>=2.0"])
            _make_pyproject(root / "service-b", "service-b", deps=["fastapi>=0.100"])

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 2
            names = {ws.name for ws in workspaces}
            assert "service-a" in names
            assert "service-b" in names

    def test_python_packages_parsed_from_pyproject(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_pyproject(root / "svc-a", "svc-a", deps=["requests>=2.28", "pydantic>=2.0"])
            _make_pyproject(root / "svc-b", "svc-b", deps=["httpx>=0.24"])

            workspaces = discover_workspaces(root)
            svc_a = next(ws for ws in workspaces if ws.name == "svc-a")
            pkg_names = {p.name for p in svc_a.packages}
            assert "requests" in pkg_names
            assert "pydantic" in pkg_names

    def test_python_ecosystem_label(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_pyproject(root / "a", "a")
            _make_pyproject(root / "b", "b")

            workspaces = discover_workspaces(root)
            assert all(ws.ecosystem == "pypi" for ws in workspaces)

    def test_single_pyproject_not_a_monorepo(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_pyproject(root / "only", "only")
            # Only one sub-project → not considered a monorepo
            workspaces = discover_workspaces(root)
            assert workspaces == []


# ---------------------------------------------------------------------------
# Glob resolution
# ---------------------------------------------------------------------------

class TestGlobResolution:
    def test_double_star_not_required_single_star_works(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["pkgs/*"],
            }))
            for name in ("alpha", "beta", "gamma"):
                _make_pkg_json(root / "pkgs" / name, name)

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 3

    def test_exact_path_without_glob(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["tools/cli"],
            }))
            _make_pkg_json(root / "tools" / "cli", "my-cli")

            workspaces = discover_workspaces(root)
            assert len(workspaces) == 1
            assert workspaces[0].name == "my-cli"

    def test_missing_glob_target_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "workspaces": ["nonexistent/*"],
            }))
            workspaces = discover_workspaces(root)
            assert workspaces == []


# ---------------------------------------------------------------------------
# No workspace
# ---------------------------------------------------------------------------

class TestNoWorkspace:
    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            workspaces = discover_workspaces(Path(d))
            assert workspaces == []

    def test_plain_npm_project_no_workspaces_field(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "package.json").write_text(json.dumps({
                "name": "simple-app",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4"},
            }))
            workspaces = discover_workspaces(root)
            assert workspaces == []

    def test_single_python_package_not_monorepo(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _make_pyproject(root / "myapp", "myapp")
            workspaces = discover_workspaces(root)
            assert workspaces == []


# ---------------------------------------------------------------------------
# Finding deduplication
# ---------------------------------------------------------------------------

class TestDeduplicateFindings:
    def _workspaces_with_packages(self) -> list[WorkspaceInfo]:
        return [
            WorkspaceInfo(
                name="app-a",
                path=Path("/proj/app-a"),
                ecosystem="npm",
                packages=[
                    PackageId("npm", "lodash", "4.17.21"),
                    PackageId("npm", "axios", "1.0.0"),
                ],
            ),
            WorkspaceInfo(
                name="app-b",
                path=Path("/proj/app-b"),
                ecosystem="npm",
                packages=[
                    PackageId("npm", "lodash", "4.17.21"),
                    PackageId("npm", "express", "4.18.0"),
                ],
            ),
        ]

    def test_same_cve_same_package_deduplicated(self):
        workspaces = self._workspaces_with_packages()
        # Both workspaces have lodash — same CVE should merge into one entry
        findings = [
            _finding("lodash", cve="CVE-2023-0001"),
            _finding("lodash", cve="CVE-2023-0001"),
        ]
        result = deduplicate_findings(findings, workspaces)
        assert len(result) == 1
        assert result[0]["occurrence_count"] == 2

    def test_affected_workspaces_populated(self):
        workspaces = self._workspaces_with_packages()
        findings = [_finding("lodash", cve="CVE-2023-0001")]
        result = deduplicate_findings(findings, workspaces)
        assert len(result) == 1
        affected = result[0]["affected_workspaces"]
        assert "app-a" in affected
        assert "app-b" in affected

    def test_package_in_only_one_workspace(self):
        workspaces = self._workspaces_with_packages()
        findings = [_finding("express", cve="CVE-2023-9999")]
        result = deduplicate_findings(findings, workspaces)
        assert len(result) == 1
        assert result[0]["affected_workspaces"] == ["app-b"]

    def test_different_cves_not_merged(self):
        workspaces = self._workspaces_with_packages()
        findings = [
            _finding("lodash", cve="CVE-2023-0001"),
            _finding("lodash", cve="CVE-2023-0002"),
        ]
        result = deduplicate_findings(findings, workspaces)
        assert len(result) == 2

    def test_no_cve_deduplication_by_title(self):
        workspaces = self._workspaces_with_packages()
        findings = [
            _finding("axios", cve=None),
            _finding("axios", cve=None),
        ]
        # Both have same title "Vuln in axios" — should be merged
        result = deduplicate_findings(findings, workspaces)
        assert len(result) == 1
        assert result[0]["occurrence_count"] == 2

    def test_empty_findings_returns_empty(self):
        workspaces = self._workspaces_with_packages()
        result = deduplicate_findings([], workspaces)
        assert result == []

    def test_empty_workspaces_affected_list_empty(self):
        """When no workspace info is provided, affected_workspaces is []."""
        findings = [_finding("lodash")]
        result = deduplicate_findings(findings, [])
        assert len(result) == 1
        assert result[0]["affected_workspaces"] == []

    def test_result_contains_required_fields(self):
        workspaces = self._workspaces_with_packages()
        findings = [_finding("lodash")]
        result = deduplicate_findings(findings, workspaces)
        required = {
            "finding_type", "severity", "package", "title", "detail",
            "cve", "cwe", "fix_version", "references", "confidence",
            "metadata", "affected_workspaces", "occurrence_count",
        }
        assert required.issubset(result[0].keys())


# ---------------------------------------------------------------------------
# Workspace summary
# ---------------------------------------------------------------------------

class TestWorkspaceSummary:
    def _make_workspaces(self) -> list[WorkspaceInfo]:
        return [
            WorkspaceInfo(
                name="frontend",
                path=Path("/proj/frontend"),
                ecosystem="npm",
                packages=[
                    PackageId("npm", "react", "18.0.0"),
                    PackageId("npm", "lodash", "4.17.21"),
                ],
            ),
            WorkspaceInfo(
                name="backend",
                path=Path("/proj/backend"),
                ecosystem="npm",
                packages=[
                    PackageId("npm", "express", "4.18.0"),
                    PackageId("npm", "lodash", "4.17.21"),  # shared with frontend
                ],
            ),
        ]

    def test_summary_top_level_keys(self):
        workspaces = self._make_workspaces()
        summary = workspace_summary(workspaces, [])
        expected_keys = {
            "workspace_count",
            "total_packages_deduped",
            "shared_packages",
            "unique_packages",
            "total_findings",
            "workspaces",
        }
        assert expected_keys.issubset(summary.keys())

    def test_workspace_count(self):
        summary = workspace_summary(self._make_workspaces(), [])
        assert summary["workspace_count"] == 2

    def test_total_packages_deduped(self):
        # react, lodash, express — lodash is shared, so 3 unique names
        summary = workspace_summary(self._make_workspaces(), [])
        assert summary["total_packages_deduped"] == 3

    def test_shared_packages(self):
        summary = workspace_summary(self._make_workspaces(), [])
        assert summary["shared_packages"] == ["lodash"]

    def test_unique_packages(self):
        summary = workspace_summary(self._make_workspaces(), [])
        unique = set(summary["unique_packages"])
        assert "react" in unique
        assert "express" in unique
        assert "lodash" not in unique

    def test_per_workspace_package_count(self):
        summary = workspace_summary(self._make_workspaces(), [])
        by_name = {ws["name"]: ws for ws in summary["workspaces"]}
        assert by_name["frontend"]["package_count"] == 2
        assert by_name["backend"]["package_count"] == 2

    def test_per_workspace_finding_count(self):
        workspaces = self._make_workspaces()
        findings = [
            _finding("react", severity=Severity.HIGH),
            _finding("lodash", severity=Severity.CRITICAL),
            _finding("express", severity=Severity.LOW),
        ]
        summary = workspace_summary(workspaces, findings)
        by_name = {ws["name"]: ws for ws in summary["workspaces"]}
        # frontend has react + lodash findings = 2
        assert by_name["frontend"]["finding_count"] == 2
        # backend has lodash + express findings = 2
        assert by_name["backend"]["finding_count"] == 2

    def test_severity_breakdown_structure(self):
        summary = workspace_summary(self._make_workspaces(), [])
        sev = summary["workspaces"][0]["severity_breakdown"]
        assert set(sev.keys()) == {"critical", "high", "medium", "low", "info"}

    def test_severity_counts(self):
        workspaces = self._make_workspaces()
        findings = [
            _finding("react", severity=Severity.CRITICAL),
            _finding("react", severity=Severity.CRITICAL),
            _finding("lodash", severity=Severity.HIGH),
        ]
        summary = workspace_summary(workspaces, findings)
        by_name = {ws["name"]: ws for ws in summary["workspaces"]}
        frontend_sev = by_name["frontend"]["severity_breakdown"]
        assert frontend_sev["critical"] == 2
        assert frontend_sev["high"] == 1

    def test_total_findings(self):
        workspaces = self._make_workspaces()
        findings = [_finding("react"), _finding("express"), _finding("lodash")]
        summary = workspace_summary(workspaces, findings)
        assert summary["total_findings"] == 3

    def test_empty_workspaces_and_findings(self):
        summary = workspace_summary([], [])
        assert summary["workspace_count"] == 0
        assert summary["total_packages_deduped"] == 0
        assert summary["shared_packages"] == []
        assert summary["unique_packages"] == []
        assert summary["total_findings"] == 0
        assert summary["workspaces"] == []

    def test_per_workspace_has_name_path_ecosystem(self):
        summary = workspace_summary(self._make_workspaces(), [])
        ws_entry = summary["workspaces"][0]
        assert "name" in ws_entry
        assert "path" in ws_entry
        assert "ecosystem" in ws_entry
