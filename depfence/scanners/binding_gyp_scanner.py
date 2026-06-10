"""Phantom Gyp scanner — detects malicious binding.gyp files.

Wave 2 attack vector: binding.gyp files trigger code execution during
npm install via node-gyp, bypassing standard preinstall/postinstall hook
detection. A binding.gyp in a package with no native C/C++ sources is
a strong indicator that gyp is being abused as a trojan execution vector.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_NATIVE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".m", ".mm"}

_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

_SUSPICIOUS_GYP_COMMANDS = re.compile(
    r"\b(?:curl|wget|fetch|nc|bash|sh|powershell|cmd)\b"
    r"|(?:https?://)"
    r"|\brm\s+-rf\b"
    r"|\bchmod\b",
    re.IGNORECASE,
)

_KNOWN_SAFE_GYP_ACTIONS = re.compile(
    r"\b(?:node-pre-gyp|prebuild-install|cmake-js|napi)\b",
    re.IGNORECASE,
)


class BindingGypScanner:
    name = "binding_gyp"
    ecosystems = ["npm"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        gyp_file = project_dir / "binding.gyp"
        if not gyp_file.is_file():
            return findings

        pkg_name = self._get_package_name(project_dir)
        pkg = PackageId(ecosystem="npm", name=pkg_name)

        has_native = self._has_native_sources(project_dir)

        try:
            content = gyp_file.read_text(errors="ignore")
        except OSError:
            return findings

        suspicious_commands = self._find_suspicious_commands(content)
        has_safe_tooling = bool(_KNOWN_SAFE_GYP_ACTIONS.search(content))

        if not has_native:
            severity = Severity.CRITICAL if suspicious_commands else Severity.HIGH
            detail = (
                "binding.gyp exists but no native C/C++ source files "
                "(.c/.cc/.cpp/.h) were found. This is a strong indicator of the "
                "Phantom Gyp attack — using node-gyp as a code execution vector "
                "during npm install without any legitimate native addon."
            )
            if suspicious_commands:
                detail += (
                    f" The gyp file also contains suspicious commands: "
                    f"{', '.join(suspicious_commands[:3])}"
                )

            # Emit the finding regardless of safe tooling.  When suspicious
            # commands are present alongside a known-safe tool invocation,
            # lower the confidence rather than suppressing the finding entirely
            # — safe tooling names do not neutralise shell-exec patterns.
            if has_safe_tooling and suspicious_commands:
                # Every suspicious token is adjacent to safe tooling: lower
                # confidence but still report.
                confidence = 0.6
            elif has_safe_tooling:
                # No suspicious commands but safe tooling present: downgrade
                # severity and confidence — likely a legitimate but unusual setup.
                severity = Severity.MEDIUM
                confidence = 0.45
            else:
                confidence = 0.92

            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=severity,
                package=pkg,
                title="Phantom Gyp: binding.gyp without native sources",
                detail=detail,
                cwe="CWE-506",
                confidence=confidence,
                metadata={
                    "file": "binding.gyp",
                    "has_native_sources": False,
                    "suspicious_commands": suspicious_commands[:5],
                    "has_safe_tooling": has_safe_tooling,
                    "check": "phantom_gyp_no_sources",
                },
            ))

        elif suspicious_commands and not has_safe_tooling:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title="binding.gyp contains suspicious commands",
                detail=(
                    f"binding.gyp shells out to unexpected commands: "
                    f"{', '.join(suspicious_commands[:3])}. While native sources exist, "
                    f"review these commands to ensure they are legitimate build steps."
                ),
                confidence=0.65,
                metadata={
                    "file": "binding.gyp",
                    "has_native_sources": True,
                    "suspicious_commands": suspicious_commands[:5],
                    "check": "phantom_gyp_suspicious_commands",
                },
            ))

        # Check actions/rules arrays regardless of native-source status.
        findings.extend(self._check_gyp_actions(content, pkg))

        return findings

    @staticmethod
    def _check_gyp_actions(content: str, pkg: PackageId) -> list[Finding]:
        """Parse binding.gyp as JSON and inspect actions[].action / rules[].action
        arrays for suspicious shell commands.  Emits HIGH findings when suspicious
        patterns are detected even when native sources are present, because explicit
        action/rule arrays are a direct code-execution path at build time.
        """
        findings: list[Finding] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # binding.gyp often uses comments / trailing commas; if strict JSON
            # fails we fall back to the regex scan that already ran.
            return findings

        targets = data.get("targets", [])
        if not isinstance(targets, list):
            return findings

        for target in targets:
            if not isinstance(target, dict):
                continue

            for section_key in ("actions", "rules"):
                section = target.get(section_key, [])
                if not isinstance(section, list):
                    continue

                for entry in section:
                    if not isinstance(entry, dict):
                        continue

                    action_list = entry.get("action", [])
                    if not isinstance(action_list, list):
                        action_list = [action_list]

                    for action_item in action_list:
                        if not isinstance(action_item, str):
                            continue
                        suspicious = _SUSPICIOUS_GYP_COMMANDS.findall(action_item)
                        if not suspicious:
                            continue

                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            severity=Severity.HIGH,
                            package=pkg,
                            title="binding.gyp action/rule contains suspicious commands",
                            detail=(
                                f"binding.gyp target '{target.get('target_name', '?')}' "
                                f"{section_key[:-1]} contains a direct shell command: "
                                f"{action_item!r}. Commands found: "
                                f"{', '.join(dict.fromkeys(suspicious))[:200]}"
                            ),
                            cwe="CWE-506",
                            confidence=0.88,
                            metadata={
                                "file": "binding.gyp",
                                "section": section_key,
                                "target": target.get("target_name", ""),
                                "action": action_item[:300],
                                "suspicious_commands": list(dict.fromkeys(suspicious))[:5],
                                "check": "phantom_gyp_action_exec",
                            },
                        ))

        return findings

    @staticmethod
    def _has_native_sources(project_dir: Path) -> bool:
        for f in project_dir.rglob("*"):
            if any(skip in f.parts for skip in _SKIP_DIRS):
                continue
            if f.is_file() and f.suffix in _NATIVE_EXTENSIONS:
                return True
        return False

    @staticmethod
    def _get_package_name(project_dir: Path) -> str:
        pkg_json = project_dir / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text())
                return data.get("name", project_dir.name)
            except (OSError, json.JSONDecodeError):
                pass
        return project_dir.name

    @staticmethod
    def _find_suspicious_commands(content: str) -> list[str]:
        matches = _SUSPICIOUS_GYP_COMMANDS.findall(content)
        return list(dict.fromkeys(matches))
