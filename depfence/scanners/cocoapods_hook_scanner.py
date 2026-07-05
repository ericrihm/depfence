"""CocoaPods hook scanner — detects script_phase and post_install abuse in Podspecs.

Direct analog to npm preinstall scanning. CocoaPods podspecs can declare
script_phase blocks that execute arbitrary shell commands during `pod install`,
and Podfiles can have post_install hooks that modify Xcode project settings.

Detection rules:
  CP-01: script_phase in .podspec files (arbitrary shell execution)
  CP-02: post_install / pre_install hooks in Podfile with dangerous patterns
  CP-03: prepare_command in .podspec (runs before source integration)
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "build", "Pods"}

_SCRIPT_PHASE_PATTERN = re.compile(
    r"s\.script_phase\s*=|spec\.script_phase\s*=|\.script_phases?\s*=",
    re.IGNORECASE,
)

_PREPARE_COMMAND_PATTERN = re.compile(
    r"s\.prepare_command\s*=|spec\.prepare_command\s*=",
    re.IGNORECASE,
)

_DANGEROUS_SHELL_PATTERNS = [
    re.compile(r"curl\s+.*\|.*sh", re.I),
    re.compile(r"wget\s+.*\|.*sh", re.I),
    re.compile(r"eval\s*\(?\s*`", re.I),
    re.compile(r"\bchmod\s+\+?[0-7]*x\b", re.I),
    re.compile(r"(?:rm\s+-rf?\s+|rmdir\s+)/(?!tmp)", re.I),
    re.compile(r"(?:nc|ncat|netcat)\s+", re.I),
    re.compile(r"base64\s+(?:-d|--decode)", re.I),
    re.compile(r"(?:python|ruby|perl|node)\s+-e", re.I),
]

_PODFILE_HOOK_PATTERN = re.compile(
    r"(?:post_install|pre_install)\s+do\s*\|",
    re.IGNORECASE,
)

_PODFILE_DANGEROUS = [
    re.compile(r"system\s*\(", re.I),
    re.compile(r"`[^`]+`", re.I),
    re.compile(r"IO\.popen", re.I),
    re.compile(r"Kernel\.exec", re.I),
    re.compile(r"\.build_settings\[.*OTHER_LDFLAGS", re.I),
    re.compile(r"\.build_settings\[.*HEADER_SEARCH_PATHS", re.I),
]


class CocoaPodsHookScanner:
    ecosystems = ["cocoapods"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_podspecs(project_dir))
        findings.extend(self._scan_podfile(project_dir))
        return findings

    def _scan_podspecs(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for podspec in project_dir.rglob("*.podspec"):
            if any(skip in podspec.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = podspec.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = podspec.relative_to(project_dir)
            pod_name = podspec.stem

            if _SCRIPT_PHASE_PATTERN.search(content):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("cocoapods", pod_name),
                    title=f"CP-01: script_phase in {rel}",
                    detail=(
                        f"Podspec '{pod_name}' declares a script_phase that executes "
                        f"shell commands during `pod install`. This is the CocoaPods "
                        f"equivalent of npm preinstall scripts."
                    ),
                    metadata={"file": str(rel), "rule": "CP-01"},
                ))

            if _PREPARE_COMMAND_PATTERN.search(content):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("cocoapods", pod_name),
                    title=f"CP-03: prepare_command in {rel}",
                    detail=(
                        f"Podspec '{pod_name}' uses prepare_command which runs shell "
                        f"commands before source files are integrated into the project."
                    ),
                    metadata={"file": str(rel), "rule": "CP-03"},
                ))

            for pattern in _DANGEROUS_SHELL_PATTERNS:
                match = pattern.search(content)
                if match:
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.CRITICAL,
                        package=PackageId("cocoapods", pod_name),
                        title=f"CP-01: Dangerous shell command in {rel}",
                        detail=(
                            f"Podspec '{pod_name}' contains dangerous pattern: "
                            f"'{match.group()}'. This could download and execute "
                            f"arbitrary code during pod install."
                        ),
                        metadata={"file": str(rel), "pattern": match.group(), "rule": "CP-01"},
                    ))
                    break

        return findings

    def _scan_podfile(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        podfile = project_dir / "Podfile"
        if not podfile.exists():
            return findings

        try:
            content = podfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        if _PODFILE_HOOK_PATTERN.search(content):
            for pattern in _PODFILE_DANGEROUS:
                match = pattern.search(content)
                if match:
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("cocoapods", "Podfile"),
                        title="CP-02: Dangerous post_install hook in Podfile",
                        detail=(
                            f"Podfile hook contains '{match.group()}'. "
                            f"post_install hooks can modify Xcode build settings, "
                            f"inject linker flags, or execute shell commands."
                        ),
                        metadata={"file": "Podfile", "pattern": match.group(), "rule": "CP-02"},
                    ))

        return findings
