"""Pre-install analysis scanner — inspects package build hooks before installation.

Analyzes setup.py, pyproject.toml build hooks, and npm preinstall scripts
for dangerous patterns WITHOUT executing them. This catches the attack vector
used in the LiteLLM/TeamPCP compromise and the Shai-Hulud worm.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity

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

# PLC-01: known-safe PyPI build backends (allowlist)
_KNOWN_BACKENDS = {
    "setuptools.build_meta",
    "hatchling.build",
    "poetry.core.masonry.api",
    "flit_core.buildapi",
    "pdm.backend",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
}

# PLC-07: build hook base classes that indicate custom build step execution
_BUILD_HOOK_CLASSES = {
    "install", "build_py", "develop", "build_ext", "egg_info",
    "install_lib", "install_scripts", "install_data",
    "build", "bdist_wheel",
}


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
        except (SyntaxError, ValueError):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg_name,
                title="setup.py contains syntax errors (possible obfuscation)",
                detail="The setup.py file cannot be parsed as valid Python, which may indicate obfuscation.",
                metadata={"file": str(setup_path), "check": "preinstall"},
            ))
            return findings

        # PLC-07: build alias map for resolving aliased imports in call detection
        aliases = self._build_alias_map(tree)

        dangerous_imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in _DANGEROUS_IMPORTS:
                        dangerous_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in _DANGEROUS_IMPORTS:
                    dangerous_imports.add(node.module)

        has_dangerous, network_access, credential_access, dangerous_calls = (
            self._ast_has_dangerous_or_network(tree, source, aliases)
        )

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
                    "Build script reads sensitive credential paths and has network "
                    "capabilities. This matches the TeamPCP/Shai-Hulud attack pattern."
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

        # PLC-07: detect setup(cmdclass={...}) with dangerous custom build classes
        findings.extend(self._check_cmdclass(tree, source, setup_path, pkg_name, aliases))

        return findings

    def _check_cmdclass(
        self,
        tree: ast.AST,
        source: str,
        setup_path: Path,
        pkg_name: str,
        aliases: dict[str, str],
    ) -> list[Finding]:
        """PLC-07: flag setup(cmdclass={...}) where the mapped class has dangerous behavior."""
        findings: list[Finding] = []

        # Collect names of classes that subclass a build hook base
        suspicious_class_names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                base_name = ""
                if isinstance(base, ast.Name):
                    base_name = base.id
                elif isinstance(base, ast.Attribute):
                    base_name = base.attr
                if base_name in _BUILD_HOOK_CLASSES:
                    suspicious_class_names.add(node.name)

        if not suspicious_class_names:
            return findings

        # Now check whether setup() is called with cmdclass referencing those classes
        cmdclass_refs: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node, aliases)
            if func_name not in ("setup", "setuptools.setup"):
                continue
            for kw in node.keywords:
                if kw.arg != "cmdclass":
                    continue
                # cmdclass value should be a dict literal
                if not isinstance(kw.value, ast.Dict):
                    continue
                for val in kw.value.values:
                    name = ""
                    if isinstance(val, ast.Name):
                        name = val.id
                    elif isinstance(val, ast.Attribute):
                        name = val.attr
                    if name in suspicious_class_names:
                        cmdclass_refs.add(name)

        if not cmdclass_refs:
            return findings

        # For each referenced class, check its body for dangerous behavior
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name not in cmdclass_refs:
                continue
            # Extract source lines for this class body only
            try:
                class_source_lines = source.splitlines()
                end_line = node.end_lineno if hasattr(node, "end_lineno") else len(class_source_lines)
                class_source = "\n".join(class_source_lines[node.lineno - 1:end_line])
            except Exception:
                class_source = source

            try:
                class_tree = ast.parse(class_source)
            except (SyntaxError, ValueError):
                class_tree = tree  # fall back to whole tree

            _, net, creds, calls = self._ast_has_dangerous_or_network(
                class_tree, class_source, aliases
            )

            has_exfil = any(p.search(class_source) for p in _EXFIL_PATTERNS)

            if has_exfil or (creds and net):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg_name,
                    title=f"Custom build class '{node.name}' contains exfiltration pattern",
                    detail=(
                        f"setup(cmdclass={{...}}) references '{node.name}' which subclasses "
                        f"a build hook and contains credential access + network activity."
                    ),
                    metadata={
                        "file": str(setup_path),
                        "class": node.name,
                        "check": "preinstall_cmdclass_exfil",
                    },
                ))
            elif calls and net:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg_name,
                    title=f"Custom build class '{node.name}' executes commands and accesses network",
                    detail=(
                        f"setup(cmdclass={{...}}) references '{node.name}' which subclasses "
                        f"a build hook and calls {', '.join(calls[:3])} with network access."
                    ),
                    metadata={
                        "file": str(setup_path),
                        "class": node.name,
                        "calls": calls,
                        "check": "preinstall_cmdclass_exec",
                    },
                ))
            elif calls:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.MEDIUM,
                    package=pkg_name,
                    title=f"Custom build class '{node.name}' uses dangerous calls",
                    detail=(
                        f"setup(cmdclass={{...}}) references '{node.name}' which subclasses "
                        f"a build hook and calls {', '.join(calls[:5])}."
                    ),
                    metadata={
                        "file": str(setup_path),
                        "class": node.name,
                        "calls": calls,
                        "check": "preinstall_cmdclass",
                    },
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

        for hook in (
            "preinstall", "install", "postinstall",
            "preuninstall", "postuninstall",
            "prepare", "prepack", "postpack",
            "prepublish", "prepublishOnly", "prestart",
        ):
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

    async def scan_pyproject(self, project_dir: Path) -> list[Finding]:
        """PLC-01: Scan pyproject.toml for dangerous in-tree build backends and dynamic entries."""
        findings: list[Finding] = []
        pyproject_path = project_dir / "pyproject.toml"
        if not pyproject_path.is_file():
            return findings

        pkg_name = project_dir.name

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomllib  # type: ignore[no-redef]
            except ImportError:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError:
                    return findings  # no TOML parser available

        try:
            data = tomllib.loads(pyproject_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return findings

        build_system = data.get("build-system", {})
        backend = build_system.get("build-backend", "")
        backend_path = build_system.get("backend-path", None)

        # Determine whether this is an in-tree (local) backend
        is_in_tree = False
        resolved_backend_file: Path | None = None

        if backend_path is not None:
            # backend-path present → explicitly in-tree
            is_in_tree = True
            if backend:
                # backend module name → try to find the .py file
                module_file = backend.replace(".", "/") + ".py"
                for bp in (backend_path if isinstance(backend_path, list) else [backend_path]):
                    candidate = project_dir / str(bp) / module_file
                    if candidate.is_file():
                        resolved_backend_file = candidate
                        break
                    # also try the module root directly
                    root_candidate = project_dir / str(bp) / backend.split(".")[0] / "__init__.py"
                    if root_candidate.is_file():
                        resolved_backend_file = root_candidate
                        break
        elif backend and backend not in _KNOWN_BACKENDS:
            # No backend-path but backend module not in the known-safe list.
            # Check if it resolves as a local .py file in the repo.
            module_file = backend.replace(".", "/") + ".py"
            candidate = project_dir / module_file
            if candidate.is_file():
                is_in_tree = True
                resolved_backend_file = candidate
            else:
                # Also check top-level package __init__.py
                init_candidate = project_dir / backend.split(".")[0] / "__init__.py"
                if init_candidate.is_file():
                    is_in_tree = True
                    resolved_backend_file = init_candidate

        if not is_in_tree:
            # Not in-tree; also check [tool.setuptools.cmdclass] / dynamic entries
            # which can inject local callables even with a standard backend.
            pass
        else:
            # In-tree backend found — scan the backend file if we can resolve it
            if resolved_backend_file is not None:
                backend_findings = await self.scan_setup_py(resolved_backend_file)
                # Escalate any findings to HIGH at minimum since it's a build backend
                for f in backend_findings:
                    if f.severity.value < Severity.HIGH.value:
                        f = Finding(
                            finding_type=f.finding_type,
                            severity=Severity.HIGH,
                            package=f.package,
                            title=f.title,
                            detail=f.detail,
                            metadata=f.metadata,
                        )
                    findings.append(f)

                if not backend_findings:
                    # Backend is in-tree but didn't trigger any findings — still warn
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH,
                        package=pkg_name,
                        title="pyproject.toml uses an in-tree build backend",
                        detail=(
                            f"[build-system] backend '{backend}' is resolved from a local "
                            f"file ({resolved_backend_file.relative_to(project_dir)}), "
                            f"not a published PyPI package. Code in this file runs during "
                            f"build without isolation."
                        ),
                        metadata={
                            "file": str(pyproject_path),
                            "backend": backend,
                            "backend_file": str(resolved_backend_file),
                            "check": "preinstall_intree_backend",
                        },
                    ))
            else:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg_name,
                    title="pyproject.toml uses an in-tree build backend (unresolved)",
                    detail=(
                        f"[build-system] specifies backend-path with backend '{backend}', "
                        f"indicating a local build backend. The backend module could not be "
                        f"resolved to a specific file for deeper analysis."
                    ),
                    metadata={
                        "file": str(pyproject_path),
                        "backend": backend,
                        "check": "preinstall_intree_backend_unresolved",
                    },
                ))

        # Check [tool.setuptools.cmdclass] and dynamic build entries pointing at local callables
        tool_setuptools = data.get("tool", {}).get("setuptools", {})
        cmdclass = tool_setuptools.get("cmdclass", {})
        if cmdclass:
            # cmdclass values are dotted paths like "mypackage.hooks:CustomInstall"
            local_entries = []
            for cmd, ref in cmdclass.items():
                if isinstance(ref, str) and not ref.startswith(tuple(_KNOWN_BACKENDS)):
                    local_entries.append(f"{cmd}={ref}")
            if local_entries:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg_name,
                    title="pyproject.toml [tool.setuptools.cmdclass] references local callables",
                    detail=(
                        f"Custom build command classes are registered: {', '.join(local_entries[:5])}. "
                        f"These run during build/install and may contain arbitrary code."
                    ),
                    metadata={
                        "file": str(pyproject_path),
                        "cmdclass": dict(list(cmdclass.items())[:10]),
                        "check": "preinstall_pyproject_cmdclass",
                    },
                ))

        dynamic = tool_setuptools.get("dynamic", {})
        if isinstance(dynamic, dict):
            for field, ref in dynamic.items():
                if isinstance(ref, dict) and "attr" in ref:
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        package=pkg_name,
                        title=f"pyproject.toml dynamic '{field}' references a module attribute",
                        detail=(
                            f"[tool.setuptools.dynamic].{field} uses attr={ref['attr']!r}, "
                            f"which imports and evaluates a local module attribute at build time."
                        ),
                        metadata={
                            "file": str(pyproject_path),
                            "field": field,
                            "attr": ref["attr"],
                            "check": "preinstall_pyproject_dynamic_attr",
                        },
                    ))

        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        setup_py = project_dir / "setup.py"
        if setup_py.exists():
            findings.extend(await self.scan_setup_py(setup_py))

        findings.extend(await self.scan_pyproject(project_dir))

        package_json = project_dir / "package.json"
        if package_json.exists():
            findings.extend(await self.scan_npm_scripts(package_json))

        for setup in project_dir.rglob("setup.py"):
            if "node_modules" in str(setup) or ".venv" in str(setup):
                continue
            if setup != setup_py:
                findings.extend(await self.scan_setup_py(setup))

        findings.extend(self._check_phantom_gyp(project_dir))

        return findings

    def _check_phantom_gyp(self, project_dir: Path) -> list[Finding]:
        """Cross-reference: flag binding.gyp as an alternate hook vector."""
        gyp_file = project_dir / "binding.gyp"
        if not gyp_file.is_file():
            return []
        pkg_json = project_dir / "package.json"
        if not pkg_json.is_file():
            return []
        try:
            import json
            data = json.loads(pkg_json.read_text())
            scripts = data.get("scripts", {})
        except (OSError, json.JSONDecodeError):
            return []

        has_install_hook = any(
            scripts.get(h) for h in ("preinstall", "postinstall", "install", "prepare")
        )
        if has_install_hook:
            return []

        has_native_ext = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
        has_native = any(
            f.suffix in has_native_ext
            for f in project_dir.rglob("*")
            if f.is_file() and "node_modules" not in f.parts
        )
        if has_native:
            return []

        pkg_name = data.get("name", project_dir.name)
        return [Finding(
            finding_type=FindingType.INSTALL_SCRIPT,
            severity=Severity.HIGH,
            package=pkg_name,
            title="binding.gyp as alternate install hook (Phantom Gyp)",
            detail=(
                "Package has binding.gyp but no explicit install scripts and no "
                "native C/C++ sources. node-gyp will execute binding.gyp during "
                "npm install, providing an alternate code execution vector that "
                "bypasses standard preinstall/postinstall hook detection."
            ),
            metadata={"file": "binding.gyp", "check": "preinstall_phantom_gyp"},
        )]

    def _get_call_name(self, node: ast.Call, aliases: dict[str, str] | None = None) -> str:
        """Return a canonical call name, resolving import aliases when provided.

        aliases maps local name -> canonical name, e.g. {'s': 'os.system'}.
        """
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if aliases and name in aliases:
                return aliases[name]
            return name
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                obj = node.func.value.id
                attr = node.func.attr
                # Resolve aliased module, e.g. `import subprocess as sp` → sp.Popen
                if aliases and obj in aliases:
                    obj = aliases[obj]
                return f"{obj}.{attr}"
        return ""

    def _build_alias_map(self, tree: ast.AST) -> dict[str, str]:
        """Walk AST and build a map of local name → canonical name for imports."""
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    aliases[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    # e.g. `from os import system as s` → s -> os.system
                    canonical = f"{module}.{alias.name}" if module else alias.name
                    aliases[local] = canonical
        return aliases

    def _ast_has_dangerous_or_network(
        self, tree: ast.AST, source: str, aliases: dict[str, str]
    ) -> tuple[bool, bool, bool, list[str]]:
        """Return (has_dangerous_calls, network_access, credential_access, call_names)."""
        dangerous_calls: list[str] = []
        network_access = False
        credential_access = False

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node, aliases)
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

        return bool(dangerous_calls), network_access, credential_access, dangerous_calls
