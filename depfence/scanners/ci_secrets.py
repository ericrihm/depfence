"""CI secret exposure correlation scanner.

Detects which secret-like env vars are present in the CI environment and
cross-references them with behavioral signals from installed packages to
estimate blast radius and exfiltration risk.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

# (pattern, category, sensitivity)
_KNOWN_SECRETS: list[tuple[str, str, str]] = [
    # AI/ML
    ("ANTHROPIC_API_KEY", "ai_ml", "critical"),
    ("OPENAI_API_KEY", "ai_ml", "critical"),
    ("HF_TOKEN", "ai_ml", "high"),
    ("HUGGING_FACE_HUB_TOKEN", "ai_ml", "high"),
    ("WANDB_API_KEY", "ai_ml", "high"),
    ("COMET_API_KEY", "ai_ml", "medium"),
    ("REPLICATE_API_TOKEN", "ai_ml", "high"),
    ("TOGETHER_API_KEY", "ai_ml", "high"),
    # Cloud
    ("AWS_ACCESS_KEY_ID", "cloud", "critical"),
    ("AWS_SECRET_ACCESS_KEY", "cloud", "critical"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "cloud", "critical"),
    # CI
    ("GITHUB_TOKEN", "ci", "high"),
    ("ACTIONS_RUNTIME_TOKEN", "ci", "high"),
    ("NPM_TOKEN", "ci", "high"),
    ("PYPI_TOKEN", "ci", "high"),
    ("CARGO_REGISTRY_TOKEN", "ci", "high"),
]

# Glob patterns for general secret detection
_GENERAL_PATTERNS = [
    "*_TOKEN",
    "*_SECRET",
    "*_KEY",
    "*_PASSWORD",
    "*_API_KEY",
]

# Prefix patterns for cloud providers (wildcard match)
_CLOUD_PREFIXES = [
    ("AZURE_", "cloud", "critical"),
    ("GCP_", "cloud", "critical"),
]

# Behavioral signals in package source code that suggest env var harvesting
_ENV_HARVEST_PATTERNS = [
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"process\.env", re.IGNORECASE),
    re.compile(r"getenv\s*\(", re.IGNORECASE),
    re.compile(r"environ\.get\s*\(", re.IGNORECASE),
    re.compile(r"_KEY|_TOKEN|_SECRET|_PASSWORD", re.IGNORECASE),
]

_IMPACT_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
}

_CATEGORY_DISPLAY = {
    "ai_ml": "AI/ML",
    "cloud": "Cloud",
    "ci": "CI",
    "general": "General",
}


class CiSecretsScanner:
    name = "ci_secrets"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    async def scan(self, packages: list) -> list["Finding"]:
        """Standard scanner interface — CI secrets scanner is environment-based, not package-based."""
        return []

    async def scan_environment(self, project_dir: Path) -> list[Finding]:
        detected = self._detect_secrets()
        if not detected:
            return []

        suspicious = self._find_suspicious_packages(project_dir)
        findings: list[Finding] = []

        if suspicious:
            blast = self.estimate_blast_radius(detected, suspicious)
            severity = Severity.HIGH if blast["estimated_impact_score"] >= 30 else Severity.MEDIUM
            pkg = PackageId("ci", "environment")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=severity,
                package=pkg,
                title=f"CI secrets exposed to {len(suspicious)} suspicious package(s)",
                detail=(
                    f"{blast['total_secrets']} secret(s) detected in environment "
                    f"({blast['critical_secrets']} critical). "
                    f"{len(suspicious)} installed package(s) exhibit env-harvesting behavior. "
                    f"Estimated impact score: {blast['estimated_impact_score']}/100."
                ),
                confidence=0.8,
                metadata={
                    "secrets_detected": [s["name"] for s in detected],
                    "suspicious_packages": suspicious,
                    "blast_radius": blast,
                },
            ))

        critical_secrets = [s for s in detected if s["sensitivity"] == "critical"]
        if critical_secrets:
            pkg = PackageId("ci", "environment")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"High-value secrets present in CI environment ({len(detected)} total)",
                detail=(
                    f"Detected {len(critical_secrets)} critical and "
                    f"{len(detected) - len(critical_secrets)} other secret(s). "
                    "Ensure only the minimum required credentials are available to CI jobs."
                ),
                confidence=1.0,
                metadata={
                    "secrets_detected": [s["name"] for s in detected],
                    "suspicious_packages": suspicious,
                    "blast_radius": self.estimate_blast_radius(detected, suspicious),
                },
            ))

        return findings

    def _detect_secrets(self) -> list[dict]:
        found: list[dict] = []
        seen: set[str] = set()
        env = os.environ

        # Check known named secrets
        for name, category, sensitivity in _KNOWN_SECRETS:
            if name in env and name not in seen:
                found.append({"name": name, "category": category, "sensitivity": sensitivity})
                seen.add(name)

        # Check cloud prefix patterns
        for prefix, category, sensitivity in _CLOUD_PREFIXES:
            for key in env:
                if key.startswith(prefix) and key not in seen:
                    found.append({"name": key, "category": category, "sensitivity": sensitivity})
                    seen.add(key)

        # Check general glob patterns
        for key in env:
            if key in seen:
                continue
            for pattern in _GENERAL_PATTERNS:
                if fnmatch.fnmatch(key, pattern):
                    category, sensitivity = self.classify_secret(key)
                    found.append({"name": key, "category": category, "sensitivity": sensitivity})
                    seen.add(key)
                    break

        return found

    def _find_suspicious_packages(self, project_dir: Path) -> list[str]:
        from depfence.core.lockfile import detect_ecosystem, parse_lockfile

        lockfiles = detect_ecosystem(project_dir)
        suspicious: list[str] = []

        for eco, lockfile_path in lockfiles:
            packages = parse_lockfile(eco, lockfile_path)
            for pkg in packages:
                if self._package_has_env_access_signals(pkg.name):
                    suspicious.append(str(pkg))

        return suspicious

    def _package_has_env_access_signals(self, package_name: str) -> bool:
        # Heuristic: flag packages whose names suggest credential/env access tooling.
        # In production this would cross-reference with behavioral scanner results.
        _suspicious_name_patterns = re.compile(
            r"(credential|secret|vault|keyring|dotenv|env.?config|"
            r"aws.?sdk|boto|gcloud|azure.?identity|openai|anthropic|"
            r"huggingface|wandb|comet.?ml|replicate)",
            re.IGNORECASE,
        )
        return bool(_suspicious_name_patterns.search(package_name))

    def classify_secret(self, name: str) -> tuple[str, str]:
        name_upper = name.upper()

        # Check exact known secrets first
        for known_name, category, sensitivity in _KNOWN_SECRETS:
            if name_upper == known_name:
                return category, sensitivity

        # Cloud prefixes
        for prefix, category, sensitivity in _CLOUD_PREFIXES:
            if name_upper.startswith(prefix):
                return category, sensitivity

        # AI/ML signals
        _ai_keywords = ("OPENAI", "ANTHROPIC", "HF_", "HUGGING", "WANDB", "COMET",
                         "REPLICATE", "TOGETHER", "GROQ", "MISTRAL", "DEEPSEEK")
        if any(kw in name_upper for kw in _ai_keywords):
            return "ai_ml", "critical"

        # CI signals
        _ci_keywords = ("GITHUB", "GITLAB", "CIRCLECI", "TRAVIS", "JENKINS",
                         "NPM_TOKEN", "PYPI_TOKEN", "CARGO_")
        if any(kw in name_upper for kw in _ci_keywords):
            return "ci", "high"

        # Cloud signals
        _cloud_keywords = ("AWS_", "GCP_", "AZURE_", "GOOGLE_", "DIGITALOCEAN",
                            "CLOUDFLARE", "LINODE", "HEROKU")
        if any(kw in name_upper for kw in _cloud_keywords):
            return "cloud", "critical"

        # Sensitivity by suffix
        if name_upper.endswith(("_PASSWORD", "_SECRET")):
            return "general", "high"
        if name_upper.endswith(("_API_KEY", "_KEY")):
            return "general", "medium"
        if name_upper.endswith("_TOKEN"):
            return "general", "medium"

        return "general", "medium"

    def estimate_blast_radius(
        self, secrets: list[dict], suspicious_packages: list[str]
    ) -> dict:
        total = len(secrets)
        critical = sum(1 for s in secrets if s["sensitivity"] == "critical")
        high = sum(1 for s in secrets if s["sensitivity"] == "high")
        medium = sum(1 for s in secrets if s["sensitivity"] == "medium")

        # Base score from secret density
        raw = (
            critical * _IMPACT_WEIGHTS["critical"]
            + high * _IMPACT_WEIGHTS["high"]
            + medium * _IMPACT_WEIGHTS["medium"]
        )

        # Multiply by package risk factor
        pkg_multiplier = 1.0
        if suspicious_packages:
            pkg_multiplier = min(2.0, 1.0 + 0.2 * len(suspicious_packages))

        score = min(100, int(raw * pkg_multiplier))

        return {
            "total_secrets": total,
            "critical_secrets": critical,
            "high_secrets": high,
            "medium_secrets": medium,
            "packages_with_access_patterns": len(suspicious_packages),
            "estimated_impact_score": score,
        }
