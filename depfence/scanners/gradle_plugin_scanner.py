"""Gradle plugin injection scanner — detects supply-chain attacks via build plugins.

Gradle plugins execute arbitrary code at sync time (before any build). Attackers
can inject malicious plugins via:
  GP-01: Untrusted plugin repositories in settings.gradle(.kts)
  GP-02: buildSrc with network/exec calls (runs implicitly before every build)
  GP-03: Convention plugins from untrusted sources
  GP-04: Plugin version ranges allowing silent upgrades to compromised versions
  GP-05: init.gradle scripts that inject plugins globally
  GP-06: Annotation processor (kapt/ksp) deps that generate code at compile time

No competitor (Socket, Snyk, Semgrep, Phylum) covers this attack surface.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_GRADLE_FILES = {
    "settings.gradle", "settings.gradle.kts",
    "build.gradle", "build.gradle.kts",
}

_INIT_GRADLE = {"init.gradle", "init.gradle.kts"}

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "build", ".gradle"}

_TRUSTED_REPOS = {
    "https://plugins.gradle.org",
    "https://repo.maven.apache.org",
    "https://repo1.maven.org",
    "https://maven.google.com",
    "https://jcenter.bintray.com",
    "mavenCentral()",
    "google()",
    "gradlePluginPortal()",
}

_UNTRUSTED_REPO_PATTERN = re.compile(
    r"""(?:maven\s*\{[^}]*url\s*=?\s*(?:uri\()?["'])(https?://[^"']+)""",
    re.IGNORECASE | re.DOTALL,
)

_PLUGIN_VERSION_RANGE = re.compile(
    r"""(?:version|:)\s*["'][\[(]\d""",
    re.IGNORECASE,
)

_DANGEROUS_BUILDSRC_IMPORTS = {
    "java.net", "java.io", "ProcessBuilder", "Runtime.getRuntime",
    "URL(", "HttpURLConnection", "okhttp", "retrofit",
    "exec(", "execute(",
}

_KAPT_KSP_PATTERN = re.compile(
    r"""(?:kapt|ksp|annotationProcessor)\s*\(?["']([^"']+)["']""",
    re.IGNORECASE,
)

_TRUSTED_ANNOTATION_PROCESSORS = {
    "com.google.dagger",
    "com.google.auto",
    "org.projectlombok",
    "com.squareup.moshi",
    "androidx.room",
    "com.google.devtools.ksp",
    "com.airbnb.android",
    "io.realm",
    "org.mapstruct",
    "com.github.bumptech.glide",
    "com.jakewharton",
    "com.google.protobuf",
}

_PKG = PackageId(ecosystem="gradle", name="build-config", version=None)


class GradlePluginScanner:
    ecosystems = ["maven"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_settings_gradle(project_dir))
        findings.extend(self._scan_buildsrc(project_dir))
        findings.extend(self._scan_init_gradle(project_dir))
        findings.extend(self._scan_annotation_processors(project_dir))
        findings.extend(self._scan_plugin_versions(project_dir))
        return findings

    def _scan_settings_gradle(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in ("settings.gradle", "settings.gradle.kts"):
            path = project_dir / name
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            for match in _UNTRUSTED_REPO_PATTERN.finditer(content):
                url = match.group(1).rstrip("/")
                if not any(url.startswith(t.rstrip("/")) for t in _TRUSTED_REPOS if t.startswith("http")):
                    findings.append(Finding(
                        finding_type=FindingType.WORKFLOW,
                        severity=Severity.CRITICAL,
                        package=_PKG,
                        title=f"GP-01: Untrusted plugin repository in {name}",
                        detail=(
                            f"Plugin repository '{url}' is not in the trusted set. "
                            f"Gradle plugins execute at sync time — a compromised repo "
                            f"can inject arbitrary code before any build."
                        ),
                        metadata={"file": name, "url": url, "rule": "GP-01"},
                    ))
        return findings

    def _scan_buildsrc(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        buildsrc = project_dir / "buildSrc"
        if not buildsrc.is_dir():
            return findings

        for src_file in buildsrc.rglob("*"):
            if src_file.suffix not in (".kt", ".kts", ".java", ".groovy"):
                continue
            if any(skip in src_file.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for dangerous in _DANGEROUS_BUILDSRC_IMPORTS:
                if dangerous in content:
                    rel = src_file.relative_to(project_dir)
                    findings.append(Finding(
                        finding_type=FindingType.WORKFLOW,
                        severity=Severity.HIGH,
                        package=_PKG,
                        title=f"GP-02: Dangerous call in buildSrc ({rel})",
                        detail=(
                            f"buildSrc/{rel.name} contains '{dangerous}'. "
                            f"buildSrc executes implicitly before every Gradle build — "
                            f"network or process calls here can exfiltrate data or "
                            f"download payloads silently."
                        ),
                        metadata={"file": str(rel), "pattern": dangerous, "rule": "GP-02"},
                    ))
                    break
        return findings

    def _scan_init_gradle(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        gradle_dir = project_dir / ".gradle"
        if not gradle_dir.is_dir():
            return findings
        for name in _INIT_GRADLE:
            init = gradle_dir / name
            if init.exists():
                findings.append(Finding(
                    finding_type=FindingType.WORKFLOW,
                    severity=Severity.HIGH,
                    package=_PKG,
                    title=f"GP-05: init.gradle script detected ({name})",
                    detail=(
                        f".gradle/{name} injects plugins into every build in this project. "
                        f"Review its contents — init scripts run before settings.gradle and "
                        f"can silently add repositories or modify the build."
                    ),
                    metadata={"file": f".gradle/{name}", "rule": "GP-05"},
                ))
        return findings

    def _scan_annotation_processors(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in ("build.gradle", "build.gradle.kts"):
            path = project_dir / name
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            for match in _KAPT_KSP_PATTERN.finditer(content):
                dep = match.group(1)
                group = dep.split(":")[0] if ":" in dep else dep
                if not any(group.startswith(t) for t in _TRUSTED_ANNOTATION_PROCESSORS):
                    findings.append(Finding(
                        finding_type=FindingType.WORKFLOW,
                        severity=Severity.HIGH,
                        package=PackageId(ecosystem="maven", name=dep.rsplit(":", 1)[0] if ":" in dep else dep),
                        title=f"GP-06: Untrusted annotation processor: {dep}",
                        detail=(
                            f"Annotation processor '{dep}' in {name} generates code at compile time. "
                            f"An untrusted processor can inject arbitrary code into your app's "
                            f"compiled output without visible source changes."
                        ),
                        metadata={"file": name, "dependency": dep, "rule": "GP-06"},
                    ))
        return findings

    def _scan_plugin_versions(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in _GRADLE_FILES:
            path = project_dir / name
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            for match in _PLUGIN_VERSION_RANGE.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=Severity.MEDIUM,
                    package=_PKG,
                    title=f"GP-04: Plugin version range in {name}:{line_num}",
                    detail=(
                        f"Version range detected at line {line_num}. "
                        f"Gradle plugin version ranges allow silent upgrades to "
                        f"compromised versions. Pin to exact versions."
                    ),
                    metadata={"file": name, "line": line_num, "rule": "GP-04"},
                ))
        return findings
