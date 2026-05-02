"""Behavioral scanner — detects suspicious package behaviors via heuristics.

Checks install scripts, network access patterns, filesystem access,
obfuscation indicators, and other behavioral signals that indicate
a package may be malicious even without a known CVE.
"""

from __future__ import annotations

import re

from depfence.core.models import Finding, FindingType, PackageMeta, Severity

_SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"curl\s+.*\|\s*(sh|bash)", "Downloads and executes remote script"),
    (r"wget\s+.*\|\s*(sh|bash)", "Downloads and executes remote script"),
    (r"eval\s*\(", "Uses eval — potential code injection"),
    (r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]", "Decodes base64 payload"),
    (r"atob\s*\(", "Decodes base64 payload"),
    (r"child_process", "Spawns child processes"),
    (r"exec\s*\(", "Executes shell commands"),
    (r"execSync\s*\(", "Synchronously executes shell commands"),
    (r"\.env\b", "Accesses environment variables"),
    (r"process\.env", "Reads process environment"),
    (r"os\.environ", "Reads OS environment"),
    (r"/etc/passwd", "Accesses system password file"),
    (r"~/.ssh", "Accesses SSH keys"),
    (r"\.npmrc", "Accesses npm credentials"),
    (r"\.pypirc", "Accesses PyPI credentials"),
    (r"dns\.resolve", "Performs DNS resolution (potential exfiltration)"),
    (r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", "Contacts hardcoded IP address"),
    (r"webhook\.site|requestbin|pipedream|ngrok", "Contacts data exfiltration service"),
    (r"\\x[0-9a-f]{2}", "Contains hex-escaped strings (obfuscation)"),
    (r"String\.fromCharCode", "Constructs strings from char codes (obfuscation)"),
    (r"__import__\s*\(", "Dynamic Python import (potential obfuscation)"),
    (r"compile\s*\(.*exec", "Compiles and executes dynamic code"),
]

_NAME_TYPOSQUAT_INDICATORS = [
    (r"^[a-z]+-[a-z]+s$", 0.3),  # pluralized suffix
    (r"^(node|npm|pip|yarn|react|vue|angular|express|django|flask|torch|tensor)[-_]", 0.4),
    (r"[-_](cli|tool|util|helper|kit|lib|core|sdk)$", 0.2),
]


class BehavioralScanner:
    name = "behavioral"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for pkg_meta in packages:
            findings.extend(self._check_install_scripts(pkg_meta))
            findings.extend(self._check_metadata_signals(pkg_meta))
            findings.extend(self._check_name_patterns(pkg_meta))
        return findings

    def _check_install_scripts(self, meta: PackageMeta) -> list[Finding]:
        if not meta.has_install_scripts:
            return []
        return [Finding(
            finding_type=FindingType.INSTALL_SCRIPT,
            severity=Severity.MEDIUM,
            package=meta.pkg,
            title=f"{meta.pkg.name} has install scripts",
            detail=(
                "This package runs scripts during installation. "
                "Install scripts can execute arbitrary code on your system. "
                "Verify the scripts are legitimate before installing."
            ),
            confidence=0.6,
        )]

    def _check_metadata_signals(self, meta: PackageMeta) -> list[Finding]:
        findings: list[Finding] = []

        if meta.maintainers:
            for m in meta.maintainers:
                if m.recent_ownership_change:
                    findings.append(Finding(
                        finding_type=FindingType.MAINTAINER,
                        severity=Severity.HIGH,
                        package=meta.pkg,
                        title=f"{meta.pkg.name} has recent maintainer change",
                        detail=(
                            f"Maintainer '{m.username}' was recently added. "
                            "Recent ownership changes can indicate account takeover."
                        ),
                        confidence=0.7,
                    ))

        if not meta.has_provenance and meta.pkg.ecosystem == "npm":
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.LOW,
                package=meta.pkg,
                title=f"{meta.pkg.name} lacks provenance attestation",
                detail="No Sigstore provenance found. Cannot verify build origin.",
                confidence=1.0,
            ))

        if meta.dependency_count > 50:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.INFO,
                package=meta.pkg,
                title=f"{meta.pkg.name} has {meta.dependency_count} dependencies",
                detail="Large dependency tree increases supply chain attack surface.",
                confidence=0.5,
            ))

        return findings

    def _check_name_patterns(self, meta: PackageMeta) -> list[Finding]:
        findings: list[Finding] = []
        name = meta.pkg.name

        if len(name) <= 2:
            findings.append(Finding(
                finding_type=FindingType.TYPOSQUAT,
                severity=Severity.MEDIUM,
                package=meta.pkg,
                title=f"Very short package name: {name}",
                detail="Extremely short names are often registered for typosquatting.",
                confidence=0.4,
            ))

        return findings


def check_source_patterns(source: str) -> list[tuple[str, str]]:
    """Check source code for suspicious patterns. Returns list of (pattern, description)."""
    matches = []
    for pattern, desc in _SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, source, re.IGNORECASE):
            matches.append((pattern, desc))
    return matches
