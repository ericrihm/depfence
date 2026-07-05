"""Flutter pubspec scanner — detects risky dependency patterns in pubspec.yaml.

Flutter/Dart projects declare dependencies in pubspec.yaml. Several patterns
introduce supply-chain risk that generic scanners miss:

Detection rules:
  FL-01: dependency_overrides (bypass version resolution — hides real versions)
  FL-02: git: dependencies (mutable, no registry audit trail)
  FL-03: path: dependencies pointing outside the project
  FL-04: Hosted deps from non-default registries
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "build", ".dart_tool"}

_OVERRIDE_SECTION = re.compile(r"^dependency_overrides\s*:", re.MULTILINE)

_GIT_DEP = re.compile(
    r"^\s+([a-zA-Z_][a-zA-Z0-9_]*):\s*\n\s+git:\s*\n\s+url:\s*(.+)",
    re.MULTILINE,
)

_PATH_DEP = re.compile(
    r"^\s+([a-zA-Z_][a-zA-Z0-9_]*):\s*\n\s+path:\s*(.+)",
    re.MULTILINE,
)

_HOSTED_DEP = re.compile(
    r"^\s+([a-zA-Z_][a-zA-Z0-9_]*):\s*\n\s+hosted:\s*\n\s+(?:name|url):\s*(.+)",
    re.MULTILINE,
)


class FlutterPubspecScanner:
    ecosystems = ["dart"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pubspec in self._find_pubspecs(project_dir):
            try:
                content = pubspec.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = pubspec.relative_to(project_dir)
            findings.extend(self._check_overrides(content, rel))
            findings.extend(self._check_git_deps(content, rel))
            findings.extend(self._check_path_deps(content, rel, project_dir, pubspec))
            findings.extend(self._check_hosted_deps(content, rel))
        return findings

    def _find_pubspecs(self, project_dir: Path) -> list[Path]:
        pubspecs = []
        for p in project_dir.rglob("pubspec.yaml"):
            if any(skip in p.parts for skip in _SKIP_DIRS):
                continue
            pubspecs.append(p)
        return pubspecs[:20]

    def _check_overrides(self, content: str, rel: Path) -> list[Finding]:
        if not _OVERRIDE_SECTION.search(content):
            return []
        return [Finding(
            finding_type=FindingType.UNPINNED,
            severity=Severity.HIGH,
            package=PackageId("dart", str(rel)),
            title=f"FL-01: dependency_overrides in {rel}",
            detail=(
                "dependency_overrides bypass pub's version resolution. "
                "The actual version used may differ from what the lockfile shows. "
                "This can hide vulnerable or malicious versions."
            ),
            metadata={"file": str(rel), "rule": "FL-01"},
        )]

    def _check_git_deps(self, content: str, rel: Path) -> list[Finding]:
        findings = []
        for match in _GIT_DEP.finditer(content):
            name = match.group(1)
            url = match.group(2).strip()
            findings.append(Finding(
                finding_type=FindingType.UNPINNED,
                severity=Severity.MEDIUM,
                package=PackageId("dart", name),
                title=f"FL-02: git dependency '{name}' in {rel}",
                detail=(
                    f"Package '{name}' is pulled from git ({url}). "
                    f"Git dependencies are mutable — the same ref can point to "
                    f"different code over time. No pub.dev audit trail exists."
                ),
                metadata={"file": str(rel), "url": url, "rule": "FL-02"},
            ))
        return findings

    def _check_path_deps(
        self, content: str, rel: Path, project_dir: Path, pubspec: Path,
    ) -> list[Finding]:
        findings = []
        for match in _PATH_DEP.finditer(content):
            name = match.group(1)
            dep_path = match.group(2).strip()
            resolved = (pubspec.parent / dep_path).resolve()
            try:
                resolved.relative_to(project_dir.resolve())
            except ValueError:
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.HIGH,
                    package=PackageId("dart", name),
                    title=f"FL-03: External path dependency '{name}' in {rel}",
                    detail=(
                        f"Package '{name}' points to '{dep_path}' which resolves "
                        f"outside the project directory. External path dependencies "
                        f"can be hijacked by placing a malicious package at that path."
                    ),
                    metadata={"file": str(rel), "path": dep_path, "rule": "FL-03"},
                ))
        return findings

    def _check_hosted_deps(self, content: str, rel: Path) -> list[Finding]:
        findings = []
        for match in _HOSTED_DEP.finditer(content):
            name = match.group(1)
            hosted = match.group(2).strip()
            if "pub.dev" not in hosted and "pub.dartlang.org" not in hosted:
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.MEDIUM,
                    package=PackageId("dart", name),
                    title=f"FL-04: Non-default package registry for '{name}' in {rel}",
                    detail=(
                        f"Package '{name}' is hosted on '{hosted}' instead of pub.dev. "
                        f"Non-default registries may not have the same security vetting."
                    ),
                    metadata={"file": str(rel), "hosted": hosted, "rule": "FL-04"},
                ))
        return findings
