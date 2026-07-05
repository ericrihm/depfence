"""Composer script scanner — detects risky lifecycle hooks in PHP composer.json.

Composer supports post-install-cmd, post-update-cmd, and other lifecycle scripts
that run arbitrary commands or PHP classes during `composer install/update`.
Same attack class as npm preinstall.

Detection rules:
  CM-01: Lifecycle scripts with shell commands (direct command execution)
  CM-02: Lifecycle scripts invoking PHP classes (arbitrary PHP execution)
  CM-03: Inline script with dangerous patterns (curl|wget pipe, eval, exec)
  CM-04: custom-installer plugin (runs arbitrary PHP during package install)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "vendor"}

_LIFECYCLE_EVENTS = {
    "post-install-cmd", "pre-install-cmd",
    "post-update-cmd", "pre-update-cmd",
    "post-package-install", "post-package-update",
    "post-autoload-dump", "post-root-package-install",
    "post-create-project-cmd",
}

_DANGEROUS_SHELL = [
    re.compile(r"curl\s+.*\|.*(?:sh|php|bash)", re.I),
    re.compile(r"wget\s+.*\|.*(?:sh|php|bash)", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"\bsystem\s*\(", re.I),
    re.compile(r"\bpassthru\s*\(", re.I),
    re.compile(r"\bshell_exec\s*\(", re.I),
    re.compile(r"\bbase64_decode\s*\(", re.I),
    re.compile(r"\bproc_open\s*\(", re.I),
]

_PHP_CLASS_PATTERN = re.compile(r'^[A-Z][a-zA-Z0-9\\]+::\w+$')
_SHELL_COMMAND_PATTERN = re.compile(r'^(?:@?php\s|rm\s|cp\s|mv\s|chmod\s|curl\s|wget\s|sh\s|bash\s)')


class ComposerScriptScanner:
    ecosystems = ["composer"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for composer_json in project_dir.rglob("composer.json"):
            if any(skip in composer_json.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_composer(composer_json, project_dir))
        return findings

    def _scan_composer(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return findings

        if not isinstance(data, dict):
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = data.get("name", path.parent.name or "root")

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for event, commands in scripts.items():
                if event not in _LIFECYCLE_EVENTS:
                    continue
                if isinstance(commands, str):
                    commands = [commands]
                if not isinstance(commands, list):
                    continue

                for cmd in commands:
                    if not isinstance(cmd, str):
                        continue

                    for pat in _DANGEROUS_SHELL:
                        m = pat.search(cmd)
                        if m:
                            findings.append(Finding(
                                finding_type=FindingType.INSTALL_SCRIPT,
                                severity=Severity.CRITICAL,
                                package=PackageId("composer", pkg_name),
                                title=f"CM-03: Dangerous command in {event} in {rel}",
                                detail=(
                                    f"composer.json '{event}' contains dangerous pattern: "
                                    f"'{m.group()}' in command '{cmd}'. This can download "
                                    f"and execute arbitrary code during composer install."
                                ),
                                metadata={"file": str(rel), "event": event, "cmd": cmd, "rule": "CM-03"},
                            ))
                            break
                    else:
                        if _PHP_CLASS_PATTERN.match(cmd):
                            findings.append(Finding(
                                finding_type=FindingType.INSTALL_SCRIPT,
                                severity=Severity.MEDIUM,
                                package=PackageId("composer", pkg_name),
                                title=f"CM-02: PHP class hook in {event} in {rel}",
                                detail=(
                                    f"composer.json '{event}' invokes PHP class '{cmd}'. "
                                    f"Class-based hooks execute arbitrary PHP code during "
                                    f"composer lifecycle events."
                                ),
                                metadata={"file": str(rel), "event": event, "class": cmd, "rule": "CM-02"},
                            ))
                        elif _SHELL_COMMAND_PATTERN.match(cmd):
                            findings.append(Finding(
                                finding_type=FindingType.INSTALL_SCRIPT,
                                severity=Severity.HIGH,
                                package=PackageId("composer", pkg_name),
                                title=f"CM-01: Shell command in {event} in {rel}",
                                detail=(
                                    f"composer.json '{event}' runs shell command: '{cmd}'. "
                                    f"Shell commands execute during composer install/update "
                                    f"and can perform arbitrary actions."
                                ),
                                metadata={"file": str(rel), "event": event, "cmd": cmd, "rule": "CM-01"},
                            ))

        extra = data.get("extra", {})
        if isinstance(extra, dict) and "class" in extra:
            installer_class = extra["class"]
            if isinstance(installer_class, str):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("composer", pkg_name),
                    title=f"CM-04: Custom installer plugin in {rel}",
                    detail=(
                        f"composer.json declares custom installer class '{installer_class}'. "
                        f"Custom installers run arbitrary PHP code during package install "
                        f"and can modify files anywhere in the project."
                    ),
                    metadata={"file": str(rel), "class": installer_class, "rule": "CM-04"},
                ))

        return findings
