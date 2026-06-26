"""Maven plugin scanner — detects supply-chain risks in pom.xml build plugins.

Maven plugins execute arbitrary Java code during build lifecycle phases.
Untrusted plugins, plugins bound to early phases (validate, initialize),
and plugins from non-standard repositories are all supply-chain risks.

Detection rules:
  MV-01: Plugin from non-standard repository (not Maven Central)
  MV-02: Plugin bound to early lifecycle phase (validate/initialize/generate-sources)
  MV-03: maven-antrun-plugin executing shell commands
  MV-04: exec-maven-plugin running arbitrary executables
  MV-05: Plugin with no version pinned (allows silent upgrade attacks)
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "target", ".mvn"}

_PLUGIN_BLOCK = re.compile(
    r'<plugin>\s*(.*?)</plugin>',
    re.DOTALL,
)

_GROUP_ID = re.compile(r'<groupId>\s*([^<]+?)\s*</groupId>')
_ARTIFACT_ID = re.compile(r'<artifactId>\s*([^<]+?)\s*</artifactId>')
_VERSION = re.compile(r'<version>\s*([^<]+?)\s*</version>')
_PHASE = re.compile(r'<phase>\s*([^<]+?)\s*</phase>')
_EXECUTABLE = re.compile(r'<executable>\s*([^<]+?)\s*</executable>')

_EARLY_PHASES = {"validate", "initialize", "generate-sources", "process-sources", "generate-resources"}

_TRUSTED_GROUPS = {
    "org.apache.maven.plugins",
    "org.codehaus.mojo",
    "org.sonatype.plugins",
    "org.eclipse.m2e",
    "com.google.cloud.tools",
    "org.springframework.boot",
    "org.jetbrains.kotlin",
    "com.google.protobuf",
}

_ANTRUN_PATTERN = re.compile(
    r'<artifactId>\s*maven-antrun-plugin\s*</artifactId>',
    re.DOTALL,
)

_EXEC_PATTERN = re.compile(
    r'<artifactId>\s*exec-maven-plugin\s*</artifactId>',
    re.DOTALL,
)

_SHELL_IN_ANTRUN = re.compile(
    r'<exec\s+executable\s*=\s*"([^"]+)"',
    re.DOTALL,
)

_REPO_BLOCK = re.compile(
    r'<(?:pluginRepositor(?:y|ies))\s*>.*?</(?:pluginRepositor(?:y|ies))>',
    re.DOTALL,
)

_REPO_URL = re.compile(r'<url>\s*([^<]+?)\s*</url>')

_TRUSTED_REPO_PREFIXES = {
    "https://repo.maven.apache.org",
    "https://repo1.maven.org",
    "https://plugins.gradle.org",
    "https://maven.google.com",
    "https://oss.sonatype.org",
    "https://s01.oss.sonatype.org",
}


class MavenPluginScanner:
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pom in project_dir.rglob("pom.xml"):
            if any(skip in pom.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_pom(pom, project_dir))
        return findings

    def _scan_pom(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        for repo_block in _REPO_BLOCK.finditer(content):
            for url_m in _REPO_URL.finditer(repo_block.group()):
                url = url_m.group(1).rstrip("/")
                if not any(url.startswith(trusted) for trusted in _TRUSTED_REPO_PREFIXES):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("maven", pkg_name),
                        title=f"MV-01: Untrusted plugin repository in {rel}",
                        detail=(
                            f"pom.xml declares plugin repository '{url}' which is not "
                            f"Maven Central or a known trusted mirror. Plugins from "
                            f"untrusted repos can execute arbitrary code during builds."
                        ),
                        metadata={"file": str(rel), "url": url, "rule": "MV-01"},
                    ))

        for plugin_m in _PLUGIN_BLOCK.finditer(content):
            block = plugin_m.group(1)
            group_m = _GROUP_ID.search(block)
            artifact_m = _ARTIFACT_ID.search(block)
            version_m = _VERSION.search(block)

            if not artifact_m:
                continue

            artifact = artifact_m.group(1)
            group = group_m.group(1) if group_m else "org.apache.maven.plugins"
            coord = f"{group}:{artifact}"

            if not version_m:
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=Severity.MEDIUM,
                    package=PackageId("maven", coord),
                    title=f"MV-05: Unpinned plugin '{artifact}' in {rel}",
                    detail=(
                        f"Plugin '{coord}' has no version specified. Maven will resolve "
                        f"the latest version, enabling silent upgrade attacks where a "
                        f"compromised version is automatically picked up."
                    ),
                    metadata={"file": str(rel), "plugin": coord, "rule": "MV-05"},
                ))

            for phase_m in _PHASE.finditer(block):
                phase = phase_m.group(1)
                if phase in _EARLY_PHASES and group not in _TRUSTED_GROUPS:
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("maven", coord),
                        title=f"MV-02: Plugin '{artifact}' bound to early phase '{phase}' in {rel}",
                        detail=(
                            f"Plugin '{coord}' executes during '{phase}' phase, which "
                            f"runs before compilation. Early-phase plugins from non-core "
                            f"groups can inject code before any other build step."
                        ),
                        metadata={"file": str(rel), "plugin": coord, "phase": phase, "rule": "MV-02"},
                    ))

            if _ANTRUN_PATTERN.search(plugin_m.group()):
                for shell_m in _SHELL_IN_ANTRUN.finditer(block):
                    executable = shell_m.group(1)
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("maven", pkg_name),
                        title=f"MV-03: antrun executes '{executable}' in {rel}",
                        detail=(
                            f"maven-antrun-plugin runs external command '{executable}' "
                            f"during the build. Antrun shell execution is a common "
                            f"vector for build-time attacks in Maven projects."
                        ),
                        metadata={"file": str(rel), "executable": executable, "rule": "MV-03"},
                    ))

            if _EXEC_PATTERN.search(plugin_m.group()):
                for exec_m in _EXECUTABLE.finditer(block):
                    executable = exec_m.group(1)
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("maven", pkg_name),
                        title=f"MV-04: exec-maven-plugin runs '{executable}' in {rel}",
                        detail=(
                            f"exec-maven-plugin executes '{executable}' during builds. "
                            f"This plugin is designed for arbitrary command execution "
                            f"and is a high-risk attack surface."
                        ),
                        metadata={"file": str(rel), "executable": executable, "rule": "MV-04"},
                    ))

        return findings
