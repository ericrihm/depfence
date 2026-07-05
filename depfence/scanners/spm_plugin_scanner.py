"""SPM build plugin scanner — detects supply-chain risks in Package.swift manifests.

Package.swift is executable Swift code evaluated by the Swift Package Manager.
Build tool plugins and command plugins execute arbitrary code during builds.
Binary targets download pre-compiled frameworks from arbitrary URLs.

Detection rules:
  SPM-01: Build tool plugins (.buildTool capability) — arbitrary code at build time
  SPM-02: Binary targets with remote URLs — pre-compiled code, no source audit
  SPM-03: unsafeFlags in build settings — bypass SPM sandbox protections
  SPM-04: Git dependencies without exact version — mutable refs (branch/revision)
  SPM-05: Command plugins (.command capability) — user-invokable arbitrary execution
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "build", ".build", "DerivedData"}

_BUILD_TOOL_PLUGIN = re.compile(
    r"\.plugin\s*\([^)]*capability\s*:\s*\.buildTool",
    re.DOTALL,
)

_COMMAND_PLUGIN = re.compile(
    r"\.plugin\s*\([^)]*capability\s*:\s*\.command",
    re.DOTALL,
)

_BINARY_TARGET_URL = re.compile(
    r"\.binaryTarget\s*\(\s*name\s*:\s*\"([^\"]+)\"\s*,\s*url\s*:\s*\"([^\"]+)\"",
    re.DOTALL,
)

_UNSAFE_FLAGS = re.compile(
    r"\.unsafeFlags\s*\(\s*\[",
    re.DOTALL,
)

_GIT_DEP_BRANCH = re.compile(
    r"\.package\s*\(\s*url\s*:\s*\"([^\"]+)\"\s*,\s*branch\s*:",
    re.DOTALL,
)

_GIT_DEP_REVISION = re.compile(
    r"\.package\s*\(\s*url\s*:\s*\"([^\"]+)\"\s*,\s*revision\s*:",
    re.DOTALL,
)

_GIT_DEP_RANGE = re.compile(
    r"\.package\s*\(\s*url\s*:\s*\"([^\"]+)\"\s*,\s*\"[^\"]*\"\s*\.\.\.",
    re.DOTALL,
)

_PLUGIN_NAME = re.compile(
    r"\.plugin\s*\(\s*name\s*:\s*\"([^\"]+)\"",
)

_PROCESS_LAUNCH = re.compile(
    r"Process\s*\(\s*\)|NSTask|CommandLine\.arguments|FileManager\.\s*default\.\s*createFile",
    re.DOTALL,
)

_NETWORK_CALLS = re.compile(
    r"URLSession|URLRequest|NSURLConnection|downloadTask",
    re.DOTALL,
)


class SpmPluginScanner:
    ecosystems = ["spm"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pkg_swift in project_dir.rglob("Package.swift"):
            if any(skip in pkg_swift.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_manifest(pkg_swift, project_dir))
        for plugin_swift in project_dir.rglob("Plugins/**/*.swift"):
            if any(skip in plugin_swift.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_plugin_source(plugin_swift, project_dir))
        return findings

    def _scan_manifest(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        for m in _BUILD_TOOL_PLUGIN.finditer(content):
            name_m = _PLUGIN_NAME.search(m.group())
            plugin_name = name_m.group(1) if name_m else "unknown"
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=PackageId("swift", pkg_name),
                title=f"SPM-01: Build tool plugin '{plugin_name}' in {rel}",
                detail=(
                    f"Package.swift declares a .buildTool plugin '{plugin_name}' that "
                    f"executes arbitrary code during every build. Unlike regular targets, "
                    f"build tool plugins run with full filesystem access and can modify "
                    f"the build process, inject source files, or exfiltrate data."
                ),
                metadata={"file": str(rel), "plugin": plugin_name, "rule": "SPM-01"},
            ))

        for m in _COMMAND_PLUGIN.finditer(content):
            name_m = _PLUGIN_NAME.search(m.group())
            plugin_name = name_m.group(1) if name_m else "unknown"
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.MEDIUM,
                package=PackageId("swift", pkg_name),
                title=f"SPM-05: Command plugin '{plugin_name}' in {rel}",
                detail=(
                    f"Package.swift declares a .command plugin '{plugin_name}'. "
                    f"Command plugins can be invoked by users and execute arbitrary "
                    f"Swift code with broad filesystem permissions."
                ),
                metadata={"file": str(rel), "plugin": plugin_name, "rule": "SPM-05"},
            ))

        for m in _BINARY_TARGET_URL.finditer(content):
            target_name = m.group(1)
            url = m.group(2)
            sev = Severity.CRITICAL if not url.startswith("https://") else Severity.HIGH
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=sev,
                package=PackageId("swift", target_name),
                title=f"SPM-02: Binary target '{target_name}' from remote URL",
                detail=(
                    f"Package.swift downloads a pre-compiled binary from {url}. "
                    f"Binary targets contain executable code that cannot be audited "
                    f"from source. The checksum only proves integrity, not safety."
                ),
                metadata={"file": str(rel), "target": target_name, "url": url, "rule": "SPM-02"},
            ))

        for m in _UNSAFE_FLAGS.finditer(content):
            start = max(0, m.start() - 80)
            context_snippet = content[start:m.end() + 40].replace("\n", " ").strip()
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=PackageId("swift", pkg_name),
                title=f"SPM-03: unsafeFlags in {rel}",
                detail=(
                    f"Package.swift uses .unsafeFlags() which bypasses SPM's build "
                    f"sandbox. This can disable security hardening (-fno-stack-protector), "
                    f"link arbitrary libraries, or pass dangerous compiler flags. "
                    f"Context: ...{context_snippet}..."
                ),
                metadata={"file": str(rel), "rule": "SPM-03"},
            ))

        for pattern, ref_type in [
            (_GIT_DEP_BRANCH, "branch"),
            (_GIT_DEP_REVISION, "revision"),
            (_GIT_DEP_RANGE, "range"),
        ]:
            for m in pattern.finditer(content):
                url = m.group(1)
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=Severity.MEDIUM,
                    package=PackageId("swift", url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")),
                    title=f"SPM-04: Mutable {ref_type} dependency on {url}",
                    detail=(
                        f"Package.swift depends on {url} via {ref_type} reference. "
                        f"This is mutable — the dependency can change without the "
                        f"manifest changing. Use .package(url:exact:) or "
                        f".package(url:from:) with a pinned version instead."
                    ),
                    metadata={"file": str(rel), "url": url, "ref_type": ref_type, "rule": "SPM-04"},
                ))

        return findings

    def _scan_plugin_source(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        plugin_name = path.parent.name

        if _PROCESS_LAUNCH.search(content):
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=PackageId("swift", plugin_name),
                title=f"SPM-01: Process execution in plugin source {rel}",
                detail=(
                    f"Plugin source '{rel}' launches external processes. Build tool "
                    f"plugins with process execution can run arbitrary commands "
                    f"during every build."
                ),
                metadata={"file": str(rel), "plugin": plugin_name, "rule": "SPM-01"},
            ))

        if _NETWORK_CALLS.search(content):
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.CRITICAL,
                package=PackageId("swift", plugin_name),
                title=f"SPM-01: Network access in plugin source {rel}",
                detail=(
                    f"Plugin source '{rel}' makes network calls. A build tool plugin "
                    f"with network access can exfiltrate source code, download "
                    f"additional payloads, or phone home during builds."
                ),
                metadata={"file": str(rel), "plugin": plugin_name, "rule": "SPM-01"},
            ))

        return findings
