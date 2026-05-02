"""Install script analyzer — inspects pre/post-install scripts for suspicious behavior."""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_DANGEROUS_PATTERNS = [
    (r"curl\s+[^\|]*\|\s*(bash|sh|zsh)", Severity.CRITICAL, "Pipe-to-shell execution"),
    (r"wget\s+[^\|]*\|\s*(bash|sh|zsh)", Severity.CRITICAL, "Pipe-to-shell execution"),
    (r"powershell.*-enc", Severity.CRITICAL, "Encoded PowerShell command"),
    (r"Invoke-WebRequest|iwr\s", Severity.HIGH, "PowerShell web request"),
    (r"nc\s+-[el]|ncat\s+-[el]|netcat", Severity.CRITICAL, "Reverse shell indicator"),
    (r"/dev/tcp/", Severity.CRITICAL, "Bash TCP redirect (reverse shell)"),
    (r"mkfifo|mknod.*p\s", Severity.HIGH, "Named pipe creation (potential reverse shell)"),
    (r"base64\s+-d|base64\s+--decode", Severity.HIGH, "Base64 decoding in script"),
    (r"python[23]?\s+-c\s+['\"]import", Severity.MEDIUM, "Inline Python execution"),
    (r"node\s+-e\s+['\"]", Severity.MEDIUM, "Inline Node.js execution"),
    (r"\$\(curl|\$\(wget", Severity.CRITICAL, "Command substitution with download"),
    (r"chmod\s+[0-7]*[67][0-7]{2}", Severity.MEDIUM, "Setting executable permissions"),
    (r"crontab|/etc/cron", Severity.HIGH, "Crontab modification"),
    (r"/etc/hosts", Severity.HIGH, "Hosts file modification"),
    (r"iptables|ufw|firewall", Severity.HIGH, "Firewall modification"),
    (r"ssh-keygen|authorized_keys", Severity.CRITICAL, "SSH key manipulation"),
    (r"\.npmrc|\.pypirc|\.pip/pip\.conf", Severity.HIGH, "Credential file access"),
    (r"NPM_TOKEN|PYPI_TOKEN|GH_TOKEN|GITHUB_TOKEN", Severity.CRITICAL, "Token exfiltration"),
]


class InstallScriptAnalyzer:
    name = "install_script"

    async def analyze(self, package: PackageMeta, source_path: Path | None) -> list[Finding]:
        if source_path is None or not source_path.exists():
            return self._check_meta_only(package)

        findings: list[Finding] = []

        pkg_json = source_path / "package.json"
        if pkg_json.exists():
            findings.extend(self._analyze_npm_scripts(package.pkg, pkg_json))

        setup_py = source_path / "setup.py"
        if setup_py.exists():
            findings.extend(self._analyze_setup_py(package.pkg, setup_py))

        for sh_file in source_path.glob("*.sh"):
            findings.extend(self._analyze_shell_script(package.pkg, sh_file))

        return findings

    def _check_meta_only(self, meta: PackageMeta) -> list[Finding]:
        if meta.has_install_scripts:
            return [Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.MEDIUM,
                package=meta.pkg,
                title=f"{meta.pkg.name} declares install scripts",
                detail="Package has install hooks but source is not available for analysis.",
                confidence=0.4,
            )]
        return []

    def _analyze_npm_scripts(self, pkg: PackageId, pkg_json: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(pkg_json.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        scripts = data.get("scripts", {})
        install_hooks = {
            k: v for k, v in scripts.items()
            if k in ("preinstall", "install", "postinstall", "preuninstall", "postuninstall")
        }

        for hook_name, command in install_hooks.items():
            for pattern, severity, desc in _DANGEROUS_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=severity,
                        package=pkg,
                        title=f"{desc} in {hook_name}",
                        detail=f"Script `{hook_name}`: `{command[:200]}`",
                        confidence=0.9,
                        metadata={"hook": hook_name, "command": command},
                    ))

        return findings

    def _analyze_setup_py(self, pkg: PackageId, setup_py: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            source = setup_py.read_text(errors="replace")
        except OSError:
            return findings

        for pattern, severity, desc in _DANGEROUS_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=severity,
                    package=pkg,
                    title=f"{desc} in setup.py",
                    detail=f"Suspicious pattern found in setup.py",
                    confidence=0.8,
                ))

        if re.search(r"class\s+\w+Install.*Command", source):
            if re.search(r"(urlopen|requests\.get|urllib|httpx|curl)", source):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=pkg,
                    title="Custom install command with network access",
                    detail="setup.py overrides install command and makes network requests.",
                    confidence=0.8,
                ))

        return findings

    def _analyze_shell_script(self, pkg: PackageId, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            source = path.read_text(errors="replace")
        except OSError:
            return findings

        for pattern, severity, desc in _DANGEROUS_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=severity,
                    package=pkg,
                    title=f"{desc} in {path.name}",
                    detail=f"Suspicious pattern in shell script {path.name}",
                    confidence=0.7,
                ))

        return findings
