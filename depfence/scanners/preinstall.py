"""Pre-install analysis scanner — inspects package build hooks before installation.

Analyzes setup.py, pyproject.toml build hooks, and npm preinstall scripts
for dangerous patterns WITHOUT executing them. This catches the attack vector
used in the LiteLLM/TeamPCP compromise and the Shai-Hulud worm.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_DANGEROUS_IMPORTS = {
    "subprocess", "os", "shutil", "ctypes", "socket", "http.client",
    "urllib.request", "ftplib", "smtplib", "telnetlib", "webbrowser",
}

_DANGEROUS_CALLS = {
    "os.system", "os.popen", "os.exec", "os.execv", "os.execve",
    "os.spawn", "os.spawnl", "os.spawnle",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "eval", "exec", "compile", "__import__",
}

_EXFIL_PATTERNS = [
    re.compile(r"requests\.(?:get|post|put)\(.*(?:TOKEN|KEY|SECRET|PASS)", re.I),
    re.compile(r"urllib\.request\.urlopen\(.*(?:TOKEN|KEY|SECRET)", re.I),
    re.compile(r"httpx?\.(?:get|post)\(.*env", re.I),
    re.compile(r"os\.environ\[.*(?:TOKEN|KEY|SECRET|PASS)", re.I),
    re.compile(r"open\(['\"](?:/etc/passwd|~/?\.ssh|~/?\.aws)", re.I),
    re.compile(r"(?:ssh|scp|curl|wget)\s+.*\|", re.I),
]

_CREDENTIAL_PATHS = [
    ".ssh/", ".aws/", ".kube/", ".config/gcloud", ".npmrc",
    ".pypirc", ".env", "credentials", "id_rsa", "id_ed25519",
]

_NETWORK_PATTERNS = [
    re.compile(r"socket\.(?:socket|connect|create_connection)"),
    re.compile(r"http\.client\.HTTP"),
    re.compile(r"urllib\.request"),
    re.compile(r"(?:requests|httpx|aiohttp)\.(?:get|post|put|delete)"),
]


class PreinstallScanner:
    name = "preinstall"
    ecosystems = ["pypi", "npm"]

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    async def scan_setup_py(self, setup_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        pkg_name = setup_path.parent.name

        try:
            source = setup_path.read_text(errors="ignore")
        except OSError:
            return findings

        try:
            tree = ast.parse(source)
        except SyntaxError:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg_name,
                title="setup.py contains syntax errors (possible obfuscation)",
                detail="The setup.py file cannot be parsed as valid Python, which may indicate obfuscation.",
                metadata={"file": str(setup_path), "check": "preinstall"},
            ))
            return findings

        dangerous_imports = set()
        dangerous_calls = []
        network_access = False
        credential_access = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in _DANGEROUS_IMPORTS:
                        dangerous_imports.add(alias.name)

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in _DANGEROUS_IMPORTS:
                    dangerous_imports.add(node.module)

            elif isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in _DANGEROUS_CALLS:
                    dangerous_calls.append(func_name)

        for pattern in _NETWORK_PATTERNS:
            if pattern.search(source):
                network_access = True
                break

        for cred_path in _CREDENTIAL_PATHS:
            if cred_path in source:
                credential_access = True
                break

        for pattern in _EXFIL_PATTERNS:
            if pattern.search(source):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg_name,
                    title="setup.py contains credential exfiltration pattern",
                    detail=f"Detected pattern matching credential access + network exfiltration in {setup_path.name}",
                    metadata={"file": str(setup_path), "check": "preinstall_exfil"},
                ))
                break

        if credential_access and network_access:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.CRITICAL,
                package=pkg_name,
                title="setup.py accesses credentials AND makes network calls",
                detail=(
                    f"Build script reads sensitive credential paths and has network "
                    f"capabilities. This matches the TeamPCP/Shai-Hulud attack pattern."
                ),
                metadata={
                    "file": str(setup_path),
                    "imports": list(dangerous_imports),
                    "check": "preinstall_cred_net",
                },
            ))
        elif dangerous_calls and network_access:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg_name,
                title="setup.py executes commands and accesses network",
                detail=(
                    f"Build script uses {', '.join(dangerous_calls[:3])} and has "
                    f"network import capabilities. Review before installation."
                ),
                metadata={
                    "file": str(setup_path),
                    "calls": dangerous_calls,
                    "check": "preinstall_exec_net",
                },
            ))
        elif len(dangerous_calls) > 2:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg_name,
                title="setup.py uses multiple dangerous calls",
                detail=f"Build script uses: {', '.join(dangerous_calls[:5])}",
                metadata={"file": str(setup_path), "calls": dangerous_calls, "check": "preinstall"},
            ))

        return findings

    async def scan_npm_scripts(self, package_json_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        import json

        try:
            data = json.loads(package_json_path.read_text())
        except (OSError, json.JSONDecodeError):
            return findings

        pkg_name = data.get("name", package_json_path.parent.name)
        scripts = data.get("scripts", {})

        for hook in ("preinstall", "postinstall", "prepare", "prepack"):
            script = scripts.get(hook, "")
            if not script:
                continue

            if "|" in script and any(sh in script for sh in ("bash", "sh", "zsh", "node -e")):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg_name,
                    title=f"Pipe-to-shell in {hook} script",
                    detail=f"The {hook} script pipes content to a shell interpreter: {script[:200]}",
                    metadata={"hook": hook, "script": script, "check": "preinstall_pipe"},
                ))

            if re.search(r"curl|wget|fetch.*http", script, re.I):
                if re.search(r"\|.*(?:bash|sh|node|python)", script):
                    findings.append(Finding(
                        finding_type=FindingType.MALICIOUS,
                        severity=Severity.CRITICAL,
                        package=pkg_name,
                        title=f"Remote code execution in {hook} script",
                        detail=f"Downloads and executes remote code: {script[:200]}",
                        metadata={"hook": hook, "script": script, "check": "preinstall_rce"},
                    ))

            env_access = re.findall(r"\$\{?(\w*(?:TOKEN|KEY|SECRET|PASS)\w*)\}?", script, re.I)
            if env_access:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg_name,
                    title=f"Credential access in {hook} script",
                    detail=f"The {hook} script reads sensitive env vars: {', '.join(env_access[:5])}",
                    metadata={"hook": hook, "vars": env_access, "check": "preinstall_creds"},
                ))

        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        setup_py = project_dir / "setup.py"
        if setup_py.exists():
            findings.extend(await self.scan_setup_py(setup_py))

        package_json = project_dir / "package.json"
        if package_json.exists():
            findings.extend(await self.scan_npm_scripts(package_json))

        for setup in project_dir.rglob("setup.py"):
            if "node_modules" in str(setup) or ".venv" in str(setup):
                continue
            if setup != setup_py:
                findings.extend(await self.scan_setup_py(setup))

        return findings

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""
