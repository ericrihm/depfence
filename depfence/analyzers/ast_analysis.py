"""AST-based analysis of package source code for suspicious patterns."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_JS_SUSPICIOUS = [
    (r"\beval\s*\(", "eval() call", Severity.HIGH),
    (r"\bFunction\s*\(", "Function constructor", Severity.HIGH),
    (r"Buffer\.from\s*\([^)]*['\"]base64['\"]", "Base64 decode", Severity.MEDIUM),
    (r"require\s*\(\s*['\"]child_process['\"]\s*\)", "child_process import", Severity.HIGH),
    (r"require\s*\(\s*['\"]fs['\"]\s*\)", "fs import in unexpected context", Severity.LOW),
    (r"require\s*\(\s*['\"]net['\"]\s*\)", "net module import", Severity.MEDIUM),
    (r"require\s*\(\s*['\"]dgram['\"]\s*\)", "UDP socket import", Severity.MEDIUM),
    (r"process\.env\[", "Environment variable access", Severity.LOW),
    (r"\.postinstall|\.preinstall", "Install hook reference", Severity.MEDIUM),
    (r"https?://\d+\.\d+\.\d+\.\d+", "Hardcoded IP URL", Severity.HIGH),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}", "Long hex escape sequence", Severity.MEDIUM),
    (r"String\.fromCharCode\s*\((?:\s*\d+\s*,){5,}", "Long fromCharCode chain", Severity.HIGH),
    (r"atob\s*\(|btoa\s*\(", "Base64 encoding/decoding", Severity.LOW),
]

_PY_DANGEROUS_CALLS = {
    "exec", "eval", "compile", "__import__",
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output",
}


class AstAnalyzer:
    name = "ast_analyzer"

    async def analyze(self, package: PackageMeta, source_path: Path | None) -> list[Finding]:
        if source_path is None or not source_path.exists():
            return []

        findings: list[Finding] = []
        for py_file in source_path.rglob("*.py"):
            findings.extend(self._analyze_python(package.pkg, py_file))
        for js_file in list(source_path.rglob("*.js")) + list(source_path.rglob("*.mjs")):
            findings.extend(self._analyze_javascript(package.pkg, js_file))
        return findings

    def _analyze_python(self, pkg: PackageId, filepath: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            source = filepath.read_text(errors="replace")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name in _PY_DANGEROUS_CALLS:
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH if call_name in ("exec", "eval") else Severity.MEDIUM,
                        package=pkg,
                        title=f"Dangerous call: {call_name}()",
                        detail=f"Found {call_name}() at {filepath.name}:{node.lineno}",
                        confidence=0.6,
                        metadata={"file": str(filepath), "line": node.lineno},
                    ))

        obfuscation_score = self._python_obfuscation_score(source)
        if obfuscation_score > 0.6:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg,
                title=f"Possible obfuscation in {filepath.name}",
                detail=f"Obfuscation score: {obfuscation_score:.2f}",
                confidence=obfuscation_score,
                metadata={"file": str(filepath), "obfuscation_score": obfuscation_score},
            ))

        return findings

    def _analyze_javascript(self, pkg: PackageId, filepath: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            source = filepath.read_text(errors="replace")
        except Exception:
            return findings

        if len(source) > 500_000:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Unusually large JS file: {filepath.name} ({len(source):,} bytes)",
                detail="Very large JavaScript files can hide obfuscated payloads.",
                confidence=0.5,
                metadata={"file": str(filepath), "size": len(source)},
            ))

        for pattern, desc, severity in _JS_SUSPICIOUS:
            matches = re.findall(pattern, source)
            if matches:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=severity,
                    package=pkg,
                    title=f"{desc} in {filepath.name}",
                    detail=f"Found {len(matches)} occurrence(s) of suspicious pattern.",
                    confidence=0.5,
                    metadata={"file": str(filepath), "pattern": pattern, "count": len(matches)},
                ))

        return findings

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _python_obfuscation_score(self, source: str) -> float:
        signals = 0.0
        total = 0.0

        total += 1
        if re.search(r"exec\s*\(\s*compile\s*\(", source):
            signals += 1

        total += 1
        hex_sequences = re.findall(r"\\x[0-9a-fA-F]{2}", source)
        if len(hex_sequences) > 20:
            signals += 1

        total += 1
        long_strings = re.findall(r"['\"][^'\"]{500,}['\"]", source)
        if long_strings:
            signals += 1

        total += 1
        chr_calls = re.findall(r"chr\s*\(\s*\d+\s*\)", source)
        if len(chr_calls) > 10:
            signals += 1

        total += 1
        lines = source.splitlines()
        if lines:
            avg_len = sum(len(l) for l in lines) / len(lines)
            if avg_len > 200:
                signals += 1

        return signals / total if total > 0 else 0.0
