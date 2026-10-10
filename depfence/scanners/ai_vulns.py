"""AI framework vulnerability patterns — known-dangerous usage of AI libraries.

Detects:
1. Unsafe deserialization in PyTorch/TensorFlow
2. Prompt injection vectors in LangChain/LlamaIndex
3. Unvalidated model loading from untrusted sources
4. Known-vulnerable versions of AI frameworks
5. Unsafe default configurations in AI pipelines
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depfence.core.models import Finding, FindingType, Severity

# Source-pinned adjudication of every original row is in the W1 section of
# docs/2026-07-01-gap-analysis-simply-cyber-audit.md. Unsupported rows are
# quarantined there, not promoted to runtime findings.
_KNOWN_VULNS: list[dict] = [
    {
        "package": "langchain-experimental",
        "versions": ["<=0.0.14"],
        "severity": Severity.CRITICAL,
        "title": "PALChain arbitrary code execution via __import__",
        "cve": "CVE-2023-44467",
        "fix_version": None,
        "references": ["https://github.com/advisories/GHSA-gjjr-63x4-v8cq"],
    },
    {
        "package": "langchain",
        "versions": ["<0.0.247"],
        "severity": Severity.CRITICAL,
        "title": "Arbitrary code execution via PALChain",
        "cve": "CVE-2023-36188",
        "fix_version": "0.0.247",
        "references": ["https://github.com/advisories/GHSA-57fc-8q82-gfp3"],
    },
    {
        "package": "transformers",
        "versions": ["<4.36.0"],
        "severity": Severity.CRITICAL,
        "title": "Deserialization of untrusted data in model loading",
        "cve": "CVE-2023-7018",
        "fix_version": "4.36.0",
        "references": ["https://cveawg.mitre.org/api/cve/CVE-2023-7018"],
    },
    {
        "package": "langchain-core",
        "versions": ["<0.1.35"],
        "severity": Severity.MEDIUM,
        "title": "XML entity expansion in XMLOutputParser",
        "cve": "CVE-2024-1455",
        "fix_version": "0.1.35",
        "references": ["https://github.com/advisories/GHSA-q84m-rmw3-4382"],
    },
    {
        "package": "gradio",
        "versions": ["<4.11.0"],
        "severity": Severity.MEDIUM,
        "title": "File traversal in the /file route",
        "cve": "CVE-2023-51449",
        "fix_version": "4.11.0",
        "references": ["https://cveawg.mitre.org/api/cve/CVE-2023-51449"],
    },
    {
        "package": "tensorflow",
        "versions": ["<2.11.1"],
        "severity": Severity.MEDIUM,
        "title": "Heap out-of-bounds read in QuantizeAndDequantize",
        "cve": "CVE-2023-25668",
        "fix_version": "2.11.1",
        "references": [
            "https://github.com/tensorflow/tensorflow/security/advisories/GHSA-gw97-ff7c-9v96",
            "https://cveawg.mitre.org/api/cve/CVE-2023-25668",
        ],
    },
    {
        "package": "mlflow",
        "versions": ["<2.9.2"],
        "severity": Severity.HIGH,
        "title": "Path traversal in MLflow",
        "cve": "CVE-2023-6831",
        "fix_version": "2.9.2",
        "references": ["https://cveawg.mitre.org/api/cve/CVE-2023-6831"],
    },
    {
        "package": "ray",
        "versions": ["==2.6.3", "==2.8.0"],
        "severity": Severity.CRITICAL,
        "title": "Disputed: arbitrary code execution via Ray job submission API",
        "cve": "CVE-2023-48022",
        "fix_version": None,
        "detail": "The CVE names Ray 2.6.3 and 2.8.0 and is disputed by the vendor. "
                  "Ray requires a controlled network and trusted clients. No patched "
                  "version is established; optional token authentication in 2.52.0 "
                  "is defense in depth, not a replacement for network isolation.",
        "references": [
            "https://cveawg.mitre.org/api/cve/CVE-2023-48022",
            "https://docs.ray.io/en/latest/ray-security/index.html",
        ],
    },
    {
        "package": "lerobot",
        "versions": [">=0,<=0.5.1"],
        "severity": Severity.CRITICAL,
        "title": "Unsafe deserialization over unauthenticated gRPC in LeRobot",
        "cve": "CVE-2026-25874",
        "fix_version": None,
        "references": ["https://cveawg.mitre.org/api/cve/CVE-2026-25874"],
    },
    {
        "package": "onnx",
        "versions": ["<=1.20.1"],
        "severity": Severity.MEDIUM,
        "title": "Trust check bypass in onnx.hub.load via silent=True",
        "cve": "CVE-2026-28500",
        "fix_version": "1.21.0",
        "references": [
            "https://github.com/onnx/onnx/security/advisories/GHSA-hqmj-h5c6-369m",
        ],
    },
    {
        "package": "gradio",
        "versions": ["<5.6.0"],
        "severity": Severity.HIGH,
        "title": "Blocked path ACL bypass on case-insensitive file systems",
        "cve": "CVE-2025-23042",
        "fix_version": "5.6.0",
        "references": ["https://cveawg.mitre.org/api/cve/CVE-2025-23042"],
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
        """Match the reviewed local catalogue, not all known AI vulnerabilities."""
        findings = []
        package_name = canonicalize_name(name)
        for vuln in _KNOWN_VULNS:
            if vuln["package"] == package_name:
                if self._version_matches(version, vuln["versions"]):
                    fix_version = vuln["fix_version"]
                    remediation = (
                        f"The cited advisory identifies {fix_version} as a patched version."
                        if fix_version else "No patched version is established in the cited record."
                    )
                    findings.append(Finding(
                        finding_type=FindingType.KNOWN_VULN,
                        severity=vuln["severity"],
                        package=f"pypi:{name}@{version}",
                        title=vuln["title"],
                        detail=vuln.get("detail", f"Version matches {vuln['cve']}. "
                                        f"{remediation} Check the advisory for deployment applicability."),
                        cve=vuln["cve"],
                        fix_version=fix_version,
                        references=list(vuln["references"]),
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
        """Match any affected interval; comma-separated bounds intersect."""
        try:
            parsed = Version(current)
        except InvalidVersion:
            return False
        return any(SpecifierSet(constraint).contains(parsed, prereleases=True)
                   for constraint in constraints)
