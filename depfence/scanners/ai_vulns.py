"""AI framework vulnerability patterns — known-dangerous usage of AI libraries.

Detects:
1. Unsafe deserialization in PyTorch/TensorFlow
2. Prompt injection vectors in LangChain/LlamaIndex
3. Unvalidated model loading from untrusted sources
4. Known-vulnerable versions of AI frameworks
5. Unsafe default configurations in AI pipelines
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity

_KNOWN_VULNS: list[dict] = [
    {
        "package": "langchain",
        "versions": ["<0.0.325"],
        "severity": Severity.CRITICAL,
        "title": "Arbitrary code execution via LCEL",
        "cve": "CVE-2023-44467",
    },
    {
        "package": "langchain",
        "versions": ["<0.0.312"],
        "severity": Severity.CRITICAL,
        "title": "Prompt injection via PALChain",
        "cve": "CVE-2023-36188",
    },
    {
        "package": "transformers",
        "versions": ["<4.36.0"],
        "severity": Severity.HIGH,
        "title": "Unsafe pickle deserialization in model loading",
        "cve": "CVE-2023-7018",
    },
    {
        "package": "torch",
        "versions": ["<2.1.0"],
        "severity": Severity.HIGH,
        "title": "Arbitrary code execution via torch.load",
        "cve": "CVE-2024-5480",
    },
    {
        "package": "llama-index",
        "versions": ["<0.9.0"],
        "severity": Severity.HIGH,
        "title": "Server-side request forgery in data connectors",
        "cve": "CVE-2024-1455",
    },
    {
        "package": "gradio",
        "versions": ["<4.0"],
        "severity": Severity.HIGH,
        "title": "Path traversal allows arbitrary file read",
        "cve": "CVE-2023-51449",
    },
    {
        "package": "tensorflow",
        "versions": ["<2.14.0"],
        "severity": Severity.HIGH,
        "title": "Multiple memory corruption vulnerabilities",
        "cve": "CVE-2023-25668",
    },
    {
        "package": "onnx",
        "versions": ["<1.14.0"],
        "severity": Severity.MEDIUM,
        "title": "Directory traversal in model path handling",
        "cve": "CVE-2023-32577",
    },
    {
        "package": "mlflow",
        "versions": ["<2.9.0"],
        "severity": Severity.CRITICAL,
        "title": "Remote code execution via crafted model artifact",
        "cve": "CVE-2023-6831",
    },
    {
        "package": "ray",
        "versions": ["<2.8.1"],
        "severity": Severity.CRITICAL,
        "title": "Unauthenticated RCE on Ray dashboard",
        "cve": "CVE-2023-48022",
    },
]

_UNSAFE_PATTERNS: list[dict] = [
    {
        "pattern": re.compile(r"torch\.load\s*\((?!.*weights_only)[^)]*\)"),
        "title": "Unsafe torch.load without weights_only=True",
        "detail": "torch.load uses pickle by default and can execute arbitrary code. "
                  "Use weights_only=True or switch to safetensors.",
        "severity": Severity.HIGH,
    },
    {
        "pattern": re.compile(r"pickle\.loads?\s*\("),
        "title": "Pickle deserialization of model data",
        "detail": "pickle.load/loads can execute arbitrary code. If loading model weights, "
                  "use safetensors or torch.load(weights_only=True).",
        "severity": Severity.HIGH,
    },
    {
        "pattern": re.compile(r"from_pretrained\s*\(\s*['\"][^'\"]*['\"].*trust_remote_code\s*=\s*True"),
        "title": "trust_remote_code=True enables arbitrary code execution",
        "detail": "This flag allows the model repo to execute arbitrary Python code during loading. "
                  "Only use with models you fully trust.",
        "severity": Severity.HIGH,
    },
    {
        "pattern": re.compile(r"eval\s*\(\s*(?:response|output|result|completion|answer)"),
        "title": "eval() called on LLM output",
        "detail": "Evaluating LLM-generated code without sandboxing enables prompt injection attacks. "
                  "Use a restricted execution environment.",
        "severity": Severity.CRITICAL,
    },
    {
        "pattern": re.compile(r"exec\s*\(\s*(?:response|output|result|completion|answer)"),
        "title": "exec() called on LLM output",
        "detail": "Executing LLM-generated code without sandboxing is critically dangerous. "
                  "An attacker can craft prompts that exfiltrate data or compromise the system.",
        "severity": Severity.CRITICAL,
    },
    {
        "pattern": re.compile(r"subprocess\.(?:run|call|Popen)\s*\([^)]*(?:response|output|result|completion)"),
        "title": "LLM output passed to subprocess",
        "detail": "Passing LLM-generated content to subprocess enables command injection via prompt injection.",
        "severity": Severity.CRITICAL,
    },
    {
        "pattern": re.compile(r"(?:os\.system|os\.popen)\s*\([^)]*(?:response|output|result)"),
        "title": "LLM output passed to os.system/popen",
        "detail": "Direct shell execution of LLM output — trivially exploitable via prompt injection.",
        "severity": Severity.CRITICAL,
    },
]


class AiVulnScanner:
    ecosystems = ["pypi"]

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan project for AI-specific vulnerabilities."""
        findings: list[Finding] = []
        findings.extend(self._scan_patterns(project_dir))
        return findings

    def check_package_version(self, name: str, version: str) -> list[Finding]:
        """Check if a specific AI package version has known vulns."""
        findings = []
        for vuln in _KNOWN_VULNS:
            if vuln["package"] == name.lower():
                if self._version_matches(version, vuln["versions"]):
                    findings.append(Finding(
                        finding_type=FindingType.KNOWN_VULN,
                        severity=vuln["severity"],
                        package=f"pypi:{name}@{version}",
                        title=vuln["title"],
                        detail=f"Upgrade to a version that fixes {vuln.get('cve', 'this issue')}.",
                        cve=vuln.get("cve"),
                        fix_version=self._extract_fix_version(vuln["versions"][0]),
                    ))
        return findings

    def _scan_patterns(self, project_dir: Path) -> list[Finding]:
        """Scan Python files for unsafe AI patterns."""
        findings = []
        py_files = list(project_dir.rglob("*.py"))
        py_files = [f for f in py_files if ".venv" not in str(f) and "node_modules" not in str(f)]

        for fpath in py_files[:200]:
            try:
                content = fpath.read_text(errors="ignore")
            except OSError:
                continue

            rel_path = str(fpath.relative_to(project_dir))
            for pattern_info in _UNSAFE_PATTERNS:
                if pattern_info["pattern"].search(content):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=pattern_info["severity"],
                        package=f"file:{rel_path}",
                        title=pattern_info["title"],
                        detail=pattern_info["detail"],
                    ))

        return findings

    @staticmethod
    def _version_matches(current: str, constraints: list[str]) -> bool:
        """Simple version constraint checking."""
        from depfence.core.sbom_diff import _version_tuple

        current_t = _version_tuple(current)
        for constraint in constraints:
            if constraint.startswith("<"):
                target = constraint[1:]
                target_t = _version_tuple(target)
                if current_t < target_t:
                    return True
            elif constraint.startswith(">="):
                target = constraint[2:]
                target_t = _version_tuple(target)
                if current_t >= target_t:
                    return True
        return False

    @staticmethod
    def _extract_fix_version(constraint: str) -> str | None:
        """Extract the minimum safe version from a constraint like '<0.0.325'."""
        if constraint.startswith("<"):
            return constraint[1:]
        return None
