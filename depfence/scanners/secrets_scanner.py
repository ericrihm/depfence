"""Secrets scanner — detects accidentally committed credentials in project files.

Scans for:
1. API keys (AWS, GCP, Azure, GitHub, Stripe, etc.)
2. Private keys (RSA, EC, PGP)
3. Database connection strings with passwords
4. JWT tokens
5. High-entropy strings that look like secrets
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity

_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
    (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "AWS Secret Access Key", Severity.CRITICAL),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.HIGH),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity.HIGH),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine-grained PAT", Severity.HIGH),
    # Google/GCP
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity.HIGH),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key", Severity.CRITICAL),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", Severity.HIGH),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity.CRITICAL),
    # Database URLs
    (r"(?:postgres|mysql|mongodb)://[^:]+:[^@\s]+@[^\s]+", "Database Connection String with Password", Severity.HIGH),
    # Generic tokens
    (r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9]{20,})['\"]?", "Generic API Key", Severity.MEDIUM),
    # Slack
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}", "Slack Token", Severity.HIGH),
    # JWT
    (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "JWT Token", Severity.MEDIUM),
    # Anthropic
    (r"sk-ant-[A-Za-z0-9\-_]{40,}", "Anthropic API Key", Severity.CRITICAL),
    # OpenAI
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", Severity.CRITICAL),
    # Azure
    (r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,}", "Azure Storage Key", Severity.HIGH),
    # NPM token
    (r"npm_[A-Za-z0-9]{36}", "NPM Access Token", Severity.HIGH),
    # PyPI token
    (r"pypi-[A-Za-z0-9\-_]{100,}", "PyPI API Token", Severity.HIGH),
]

_SCAN_EXTENSIONS = {
    ".json", ".yml", ".yaml", ".toml", ".env", ".cfg", ".conf", ".ini",
    ".properties", ".xml", ".tf", ".tfvars", ".sh", ".bash", ".zsh",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".tox", ".mypy_cache", ".pytest_cache",
}

_MAX_FILE_SIZE = 1024 * 1024  # 1MB


class SecretsScanner:
    ecosystems = ["all"]

    async def scan(self, packages: list) -> list:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for f in self._find_scannable_files(project_dir):
            try:
                if f.stat().st_size > _MAX_FILE_SIZE:
                    continue
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(f.relative_to(project_dir))
            findings.extend(self._scan_content(content, rel_path))
        return findings

    def _find_scannable_files(self, project_dir: Path) -> list[Path]:
        files = []
        for f in project_dir.rglob("*"):
            if any(skip in f.parts for skip in _SKIP_DIRS):
                continue
            if f.is_file() and (f.suffix in _SCAN_EXTENSIONS or f.name in (".env", ".env.local", ".env.production")):
                files.append(f)
        return files[:500]

    def _scan_content(self, content: str, path: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_titles: set[str] = set()

        for pattern, title, severity in _SECRET_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                if title in seen_titles:
                    break
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=severity,
                    package=f"secrets:{path}:L{line_num}",
                    title=f"{title} detected",
                    detail=f"A {title} was found in {path} at line {line_num}. "
                           f"Rotate this credential immediately and remove from source control.",
                ))
                seen_titles.add(title)
                break

        # High-entropy string detection in .env files
        if ".env" in path:
            findings.extend(self._check_env_entropy(content, path))

        return findings

    def _check_env_entropy(self, content: str, path: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip("'\"")
            if len(value) >= 20 and self._shannon_entropy(value) > 4.5:
                if not any(re.search(p, value) for p, _, _ in _SECRET_PATTERNS[:5]):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        package=f"secrets:{path}:L{i}",
                        title=f"High-entropy value in {key}",
                        detail=f"The value of {key} has high entropy ({self._shannon_entropy(value):.1f} bits) "
                               f"and may be a secret. Verify this is not a credential.",
                    ))
        return findings

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
