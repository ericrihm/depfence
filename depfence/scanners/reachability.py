"""Reachability scanner — determines whether vulnerable functions in flagged packages
are actually called by the user's code.

Only ~18% of critical CVEs are reachable in production. This scanner reduces alert
fatigue by filtering findings based on actual import and call-site evidence.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageId, Severity

_VULNERABLE_CALLS: dict[str, set[str]] = {
    "pydantic": {"parse_raw", "parse_obj", "model_validate_json"},
    "yaml": {"load", "unsafe_load"},
    "pickle": {"loads", "load"},
    "jinja2": {"from_string", "Template"},
    "subprocess": {"call", "Popen", "run"},
    "eval": set(),
    "exec": set(),
    "xml.etree": {"parse", "fromstring"},
    "lxml": {"parse", "fromstring"},
    "sqlite3": {"execute"},
    "requests": {"get", "post", "put", "delete"},
    "urllib": {"urlopen", "Request"},
    "torch": {"load"},
    "transformers": {"from_pretrained"},
}

_SEVERITY_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


class ReachabilityScanner:
    name = "reachability"
    ecosystems = ["pypi"]

    async def scan(self, packages: list) -> list:
        """Delegate to scan_project() on the current working directory."""
        return await self.scan_project(Path("."))

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        py_files = list(project_dir.rglob("*.py"))
        if not py_files:
            return []

        all_imports: set[str] = set()
        # module -> list of (fn_name, line, source_file)
        all_calls: dict[str, list[tuple[str, int, str]]] = {}

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            all_imports |= _extract_imports(source)

            for module in _VULNERABLE_CALLS:
                sites = _extract_calls(source, module)
                if sites:
                    rel = str(py_file.relative_to(project_dir))
                    all_calls.setdefault(module, []).extend(
                        (fn, line, rel) for fn, line in sites
                    )

        findings: list[Finding] = []
        for package_name in _VULNERABLE_CALLS:
            verdict, call_sites = _check_reachability(package_name, all_imports, all_calls)
            finding = _make_finding(package_name, verdict, call_sites)
            if finding is not None:
                findings.append(finding)

        return findings


def _extract_imports(source: str) -> set[str]:
    """Return all top-level module names imported in source."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # "import xml.etree.ElementTree" → add "xml.etree" and "xml"
                parts = alias.name.split(".")
                names.add(alias.name)
                if len(parts) > 1:
                    names.add(".".join(parts[:2]))
                    names.add(parts[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
                parts = node.module.split(".")
                if len(parts) > 1:
                    names.add(".".join(parts[:2]))
                    names.add(parts[0])
            # "from yaml import load" also adds "yaml"
            for alias in node.names:
                names.add(alias.name)
    return names


def _extract_calls(source: str, module: str) -> list[tuple[str, int]]:
    """Return (function_name, line_number) for calls to vulnerable functions of module."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    vulnerable = _VULNERABLE_CALLS.get(module, set())
    # For builtins like eval/exec the module IS the function name
    is_builtin = not vulnerable

    results: list[tuple[str, int]] = []
    short_name = module.split(".")[-1]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        fn = node.func
        if is_builtin:
            # eval() or exec() — bare name call
            if isinstance(fn, ast.Name) and fn.id == module:
                results.append((module, node.lineno))
        else:
            # attr call: yaml.load(...), torch.load(...)
            if isinstance(fn, ast.Attribute):
                if fn.attr in vulnerable:
                    obj = fn.value
                    if isinstance(obj, ast.Name) and obj.id in (module, short_name):
                        results.append((fn.attr, node.lineno))
                    # e.g. xml.etree.ElementTree.parse via aliased import
                    elif isinstance(obj, ast.Attribute):
                        results.append((fn.attr, node.lineno))
            # bare name call after "from yaml import load"
            elif isinstance(fn, ast.Name) and fn.id in vulnerable:
                results.append((fn.id, node.lineno))

    return results


def _check_reachability(
    package_name: str,
    all_imports: set[str],
    all_calls: dict[str, list[tuple[str, int, str]]],
) -> tuple[str, list[dict]]:
    """Return (verdict, call_sites).

    verdict is one of: "reachable", "imported_not_called", "not_reachable"
    """
    short = package_name.split(".")[-1]
    imported = package_name in all_imports or short in all_imports

    raw_sites = all_calls.get(package_name, [])
    call_sites = [
        {"function": fn, "line": line, "file": src_file}
        for fn, line, src_file in raw_sites
    ]

    if not imported and not call_sites:
        return "not_reachable", []
    if call_sites:
        return "reachable", call_sites
    return "imported_not_called", []


def _make_finding(
    package_name: str,
    verdict: str,
    call_sites: list[dict],
) -> Finding | None:
    pkg = PackageId("pypi", package_name)
    first_site = call_sites[0] if call_sites else {}

    if verdict == "reachable":
        return Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package=pkg,
            title=f"Vulnerable function in {package_name} is called by your code",
            detail=(
                f"Your code calls vulnerable function(s) from '{package_name}'. "
                f"This vulnerability is reachable in production."
            ),
            confidence=0.9,
            metadata={
                "reachability": "reachable",
                "call_sites": call_sites,
                "source_file": first_site.get("file", ""),
                "line": first_site.get("line", 0),
            },
        )

    if verdict == "imported_not_called":
        return Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.LOW,
            package=pkg,
            title=f"{package_name} is imported but vulnerable functions are not called",
            detail=(
                f"'{package_name}' is imported but no vulnerable function calls were "
                "detected. Severity reduced — verify manually if dynamic dispatch is used."
            ),
            confidence=0.7,
            metadata={
                "reachability": "imported_not_called",
                "call_sites": [],
                "source_file": "",
                "line": 0,
            },
        )

    # not_reachable
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=Severity.LOW,
        package=pkg,
        title="Vulnerability present but not reachable in your code",
        detail=(
            f"'{package_name}' has known vulnerabilities but is not imported or called "
            "anywhere in this project. No action required unless you plan to use it."
        ),
        confidence=1.0,
        metadata={
            "reachability": "not_reachable",
            "call_sites": [],
            "source_file": "",
            "line": 0,
        },
    )
