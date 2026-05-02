"""Phantom dependency scanner — detects declared but unused dependencies.

Reducing unused dependencies shrinks the attack surface. A phantom dep is one
that's in the lockfile but never imported/required in actual source code.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageId, Severity


class PhantomDepsScanner:
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list) -> list:
        """Delegate to scan_project() on the current working directory."""
        return await self.scan_project(Path("."))

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Find declared dependencies that are never imported."""
        findings: list[Finding] = []

        from depfence.core.lockfile import detect_ecosystem, parse_lockfile

        lockfiles = detect_ecosystem(project_dir)
        all_packages: dict[str, PackageId] = {}

        for eco, lf in lockfiles:
            pkgs = parse_lockfile(eco, lf)
            for pkg in pkgs:
                all_packages[pkg.name.lower()] = pkg

        if not all_packages:
            return []

        used_packages = self._find_used_packages(project_dir)

        for name, pkg in all_packages.items():
            normalized = self._normalize_name(name)
            if normalized not in used_packages and name not in used_packages:
                if not self._is_dev_tool(name):
                    findings.append(Finding(
                        finding_type=FindingType.REPUTATION,
                        severity=Severity.LOW,
                        package=pkg,
                        title="Phantom dependency — declared but never imported",
                        detail=(
                            f"Package '{name}' is in the lockfile but no import "
                            f"was found in source files. Consider removing to reduce attack surface."
                        ),
                    ))

        return findings

    def _find_used_packages(self, project_dir: Path) -> set[str]:
        """Scan source files for imports/requires."""
        used: set[str] = set()

        # Python imports
        for py_file in self._find_source_files(project_dir, {".py"}):
            try:
                content = py_file.read_text(errors="ignore")
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            used.add(alias.name.split(".")[0].lower())
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            used.add(node.module.split(".")[0].lower())
            except (SyntaxError, OSError):
                continue

        # JS/TS requires and imports
        require_pattern = re.compile(r"""(?:require|import)\s*\(?['"]([^'"./][^'"]*?)['"]""")
        for js_file in self._find_source_files(project_dir, {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}):
            try:
                content = js_file.read_text(errors="ignore")
                for match in require_pattern.finditer(content):
                    pkg_name = match.group(1)
                    if pkg_name.startswith("@"):
                        used.add(pkg_name.lower())
                    else:
                        used.add(pkg_name.split("/")[0].lower())
            except OSError:
                continue

        return used

    def _find_source_files(self, project_dir: Path, extensions: set[str]) -> list[Path]:
        """Find source files, excluding node_modules and venvs."""
        files = []
        exclude_dirs = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build"}

        for f in project_dir.rglob("*"):
            if any(d in f.parts for d in exclude_dirs):
                continue
            if f.suffix in extensions and f.is_file():
                files.append(f)
                if len(files) > 2000:
                    break
        return files

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize package name for matching (PyPI: _ -> -, npm: as-is)."""
        return name.lower().replace("-", "_").replace(".", "_")

    @staticmethod
    def _is_dev_tool(name: str) -> bool:
        """Skip dev tools that are used via CLI, not imported."""
        dev_tools = {
            "typescript", "eslint", "prettier", "jest", "mocha", "chai",
            "webpack", "vite", "rollup", "esbuild", "turbo", "nx",
            "pytest", "ruff", "mypy", "black", "isort", "flake8",
            "pre-commit", "tox", "nox", "coverage", "sphinx",
            "@types/node", "@types/react", "ts-node", "nodemon",
        }
        return name.lower() in dev_tools
