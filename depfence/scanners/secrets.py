"""Secrets and trade-secret leak detection scanner.

Detects:
1. API keys (AWS, GCP, Azure, GitHub, npm, PyPI, Stripe, Slack, Anthropic, OpenAI, etc.)
2. Private keys (RSA, EC, DSA, PGP)
3. JWT tokens
4. Database connection strings with credentials
5. High-entropy strings that look like secrets (Shannon entropy > 4.5 in strings > 20 chars)
6. Internal/private system references (configurable org-specific terms)
7. Hardcoded IPs and internal hostnames
8. .env file contents committed to git
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity


@dataclass
class SecretMatch:
    """A single secret match from scanning a file."""

    path: str
    line_num: int
    secret_type: str
    severity: Severity
    matched_text: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    masked_preview: str = ""

    def to_finding(self) -> Finding:
        preview = self.masked_preview or _mask(self.matched_text)
        return Finding(
            finding_type=FindingType.SECRET_EXPOSED,
            severity=self.severity,
            package=f"secrets:{self.path}:L{self.line_num}",
            title=f"{self.secret_type} detected",
            detail=(
                f"A {self.secret_type} was found in {self.path} at line {self.line_num}. "
                f"Preview: {preview}. "
                f"Rotate this credential immediately and remove from source control."
            ),
            metadata={
                "file": self.path,
                "line": self.line_num,
                "secret_type": self.secret_type,
                "masked_preview": preview,
                "context_before": self.context_before,
                "context_after": self.context_after,
            },
        )


# ---------------------------------------------------------------------------
# Pattern registry: (regex, label, severity, group_index_for_secret_value)
# group_index=0 means full match; 1+ means a capture group
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, str, Severity, int]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL, 0),
    (
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"\s]?([A-Za-z0-9/+=]{40})['\"\s]?",
        "AWS Secret Access Key",
        Severity.CRITICAL,
        1,
    ),
    (r"ASIA[0-9A-Z]{16}", "AWS Temporary Access Key", Severity.CRITICAL, 0),
    # GCP / Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity.HIGH, 0),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token", Severity.HIGH, 0),
    (
        r"""['"](\d+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)['"s]""",
        "Google Client ID",
        Severity.MEDIUM,
        1,
    ),
    # Azure
    (
        r"(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{44,})",
        "Azure Storage Key",
        Severity.CRITICAL,
        1,
    ),
    (
        r"(?:AZURE_CLIENT_SECRET|AzureWebJobsStorage)\s*[=:]\s*['\"\s]?([A-Za-z0-9+/=\-_]{30,})",
        "Azure Client Secret",
        Severity.CRITICAL,
        1,
    ),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.HIGH, 0),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity.HIGH, 0),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub Server Token", Severity.HIGH, 0),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine-grained PAT", Severity.HIGH, 0),
    # npm
    (r"npm_[A-Za-z0-9]{36}", "NPM Access Token", Severity.HIGH, 0),
    # PyPI
    (r"pypi-AgE[A-Za-z0-9\-_]{100,}", "PyPI API Token", Severity.HIGH, 0),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key", Severity.CRITICAL, 0),
    (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Restricted Key", Severity.HIGH, 0),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Key", Severity.MEDIUM, 0),
    # Slack
    (
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "Slack Token",
        Severity.HIGH,
        0,
    ),
    (
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        "Slack Webhook URL",
        Severity.HIGH,
        0,
    ),
    # Anthropic
    (r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93,}", "Anthropic API Key", Severity.CRITICAL, 0),
    (r"sk-ant-[A-Za-z0-9\-_]{40,}", "Anthropic API Key", Severity.CRITICAL, 0),
    # OpenAI
    (r"sk-proj-[A-Za-z0-9_\-]{80,}", "OpenAI API Key", Severity.CRITICAL, 0),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", Severity.CRITICAL, 0),
    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API Key", Severity.HIGH, 0),
    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key SID", Severity.HIGH, 0),
    # Private keys
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Private Key (PEM Header)",
        Severity.CRITICAL,
        0,
    ),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity.CRITICAL, 0),
    # Database connection strings
    (
        r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle|mariadb)://[^:\s]*:[^@\s]{3,}@[^\s]+",
        "Database Connection String",
        Severity.HIGH,
        0,
    ),
    (
        r"(?:DATABASE_URL|DB_URL|CONNECTION_STRING)\s*[=:]\s*['\"\s]?[^\s'\"]{20,}",
        "Database URL Variable",
        Severity.HIGH,
        0,
    ),
    # JWT tokens
    (
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}",
        "JWT Token",
        Severity.MEDIUM,
        0,
    ),
    # Generic credential patterns
    (
        r"(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?secret)\s*[=:]\s*['\"\s]?([A-Za-z0-9+/=\-_]{20,})['\"\s,]",
        "Generic API Key",
        Severity.MEDIUM,
        1,
    ),
    (
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "Hardcoded Password",
        Severity.HIGH,
        1,
    ),
    (
        r"(?:^|[\s,{])(?:secret|token)\s*[=:]\s*['\"]([A-Za-z0-9+/=\-_]{16,})['\"]",
        "Hardcoded Secret/Token",
        Severity.MEDIUM,
        1,
    ),
    # Internal IPs (RFC1918)
    (
        r"\b(?:10\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"|192\.168\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b",
        "Internal IP Address",
        Severity.LOW,
        0,
    ),
]

# Files/dirs to skip entirely
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".tox", ".mypy_cache", ".pytest_cache", ".eggs", "htmlcov",
    ".ruff_cache", "site-packages", "egg-info",
})

# Extensions to scan
_SCAN_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java",
    ".kt", ".scala", ".cs", ".rs",
    ".json", ".yml", ".yaml", ".toml", ".env", ".cfg", ".conf", ".ini",
    ".properties", ".xml", ".tf", ".tfvars", ".sh", ".bash", ".zsh",
    ".dockerfile", ".gradle",
    ".pem", ".key", ".crt", ".cer",
    ".txt",
})

# Files always scanned regardless of extension
_ALWAYS_SCAN_NAMES = frozenset({
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.test", ".env.staging", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".bashrc", ".zshrc", ".bash_profile",
})

_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
_CONTEXT_LINES = 2

# Known false-positive placeholder values (lowercase)
_FP_PLACEHOLDERS = frozenset({
    "your_secret_here", "changeme", "password", "example", "placeholder",
    "secret_key", "your-secret-key", "your_api_key", "xxxx", "aaaa",
    "none", "null", "undefined", "replace_me", "insert_here",
    "todo", "fixme", "my_secret", "my_key", "secret123",
    "test", "dummy", "fake", "mock", "sample", "demo",
    "your_password", "your_token", "your_key",
    "abc123", "1234567890", "0000000000", "xxxxxxxx",
})


def _mask(value: str) -> str:
    """Mask a secret value for safe display."""
    if not value:
        return "***"
    if len(value) <= 8:
        return "***"
    visible = max(4, len(value) // 6)
    return value[:visible] + "..." + value[-2:]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_likely_false_positive(matched: str, pattern_label: str) -> bool:
    """Heuristic filter to suppress known false positives."""
    stripped = matched.strip("'\"").strip()
    lower = stripped.lower()
    if lower in _FP_PLACEHOLDERS:
        return True
    if len(stripped) < 8:
        return True
    if len(set(stripped)) < 3:
        return True
    # Reject pure version strings (1.2.3) but NOT IPs (10.0.1.42 has 3 dots)
    if re.fullmatch(r"\d+\.\d+(\.\d+)?", stripped) and stripped.count(".") < 3:
        return True
    return False


class SecretsScanner:
    """Main secrets scanner: detects leaked credentials in source files.

    Compatible with the depfence scanner interface:
      - scan(packages, project_dir) -> list[Finding]   (for registry integration)
      - scan_project(project_dir) -> list[Finding]     (for project-level scan)
      - scan_file(path) -> list[SecretMatch]           (for standalone use / hooks)
    """

    ecosystems = ["all"]

    def __init__(self, org_terms: list[str] | None = None) -> None:
        self._org_terms: list[str] = org_terms or []
        self._compiled: list[tuple[re.Pattern[str], str, Severity, int]] = [
            (re.compile(pat), label, sev, grp)
            for pat, label, sev, grp in _SECRET_PATTERNS
        ]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def scan(self, packages: list, project_dir: Path | None = None) -> list[Finding]:
        """Scanner registry interface."""
        if project_dir is not None:
            return await self.scan_project(project_dir)
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan all relevant files in a project directory."""
        findings: list[Finding] = []
        for f in self._find_scannable_files(project_dir):
            try:
                if f.stat().st_size > _MAX_FILE_SIZE:
                    continue
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            rel_path = str(f.relative_to(project_dir))
            for match in self.scan_file_content(content, rel_path):
                findings.append(match.to_finding())
        return findings

    def scan_file(self, path: Path) -> list[SecretMatch]:
        """Scan a single file and return SecretMatch objects."""
        try:
            if path.stat().st_size > _MAX_FILE_SIZE:
                return []
            content = path.read_text(errors="ignore")
        except OSError:
            return []
        return self.scan_file_content(content, str(path))

    def scan_file_content(self, content: str, path: str = "<string>") -> list[SecretMatch]:
        """Scan raw content string and return SecretMatch objects."""
        matches: list[SecretMatch] = []
        lines = content.splitlines()
        seen: set[tuple[str, int]] = set()

        for compiled, label, severity, group_idx in self._compiled:
            for m in compiled.finditer(content):
                line_num = content[: m.start()].count("\n") + 1
                key = (label, line_num)
                if key in seen:
                    continue

                try:
                    raw_value = (
                        m.group(group_idx)
                        if group_idx and m.lastindex and m.lastindex >= group_idx
                        else m.group(0)
                    )
                except IndexError:
                    raw_value = m.group(0)

                if not raw_value:
                    raw_value = m.group(0)

                if _is_likely_false_positive(raw_value, label):
                    continue

                ctx_start = max(0, line_num - 1 - _CONTEXT_LINES)
                ctx_end = min(len(lines), line_num + _CONTEXT_LINES)
                ctx_before = lines[ctx_start: line_num - 1]
                ctx_after = lines[line_num:ctx_end]
                masked = _mask(raw_value)

                matches.append(
                    SecretMatch(
                        path=path,
                        line_num=line_num,
                        secret_type=label,
                        severity=severity,
                        matched_text=raw_value,
                        context_before=ctx_before,
                        context_after=ctx_after,
                        masked_preview=masked,
                    )
                )
                seen.add(key)

        # High-entropy string detection
        matches.extend(self._check_entropy(content, path, lines, seen))

        # Internal hostname / org-term detection
        if self._org_terms:
            matches.extend(self._check_org_terms(content, path, lines))

        return matches

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_scannable_files(self, project_dir: Path) -> list[Path]:
        files: list[Path] = []
        for f in project_dir.rglob("*"):
            if any(skip in f.parts for skip in _SKIP_DIRS):
                continue
            if not f.is_file():
                continue
            if f.name in _ALWAYS_SCAN_NAMES or f.suffix in _SCAN_EXTENSIONS:
                files.append(f)
        return files[:1000]

    def _check_entropy(
        self,
        content: str,
        path: str,
        lines: list[str],
        seen: set[tuple[str, int]],
    ) -> list[SecretMatch]:
        """Detect high-entropy strings that look like secrets."""
        matches: list[SecretMatch] = []
        token_pattern = re.compile(
            r"(?:"
            r"""['\"]([!-~]{20,})['\"]"""         # quoted strings
            r"|(?:[A-Z_]{3,})\s*=\s*([!-~]{20,})" # KEY=VALUE env style
            r")"
        )
        seen_lines: set[int] = set()
        for m in token_pattern.finditer(content):
            candidate = m.group(1) or m.group(2)
            if not candidate:
                continue
            candidate = candidate.strip()
            if len(candidate) < 20:
                continue
            if _shannon_entropy(candidate) <= 4.5:
                continue
            already_caught = any(cp.search(candidate) for cp, _, _, _ in self._compiled)
            if already_caught:
                continue
            if _is_likely_false_positive(candidate, "entropy"):
                continue
            line_num = content[: m.start()].count("\n") + 1
            key = ("High-Entropy String", line_num)
            if key in seen or line_num in seen_lines:
                continue
            seen_lines.add(line_num)
            ctx_start = max(0, line_num - 1 - _CONTEXT_LINES)
            ctx_end = min(len(lines), line_num + _CONTEXT_LINES)
            matches.append(
                SecretMatch(
                    path=path,
                    line_num=line_num,
                    secret_type="High-Entropy String",
                    severity=Severity.LOW,
                    matched_text=candidate,
                    context_before=lines[ctx_start: line_num - 1],
                    context_after=lines[line_num:ctx_end],
                    masked_preview=_mask(candidate),
                )
            )
        return matches

    def _check_org_terms(
        self, content: str, path: str, lines: list[str]
    ) -> list[SecretMatch]:
        """Flag references to internal org-specific terms."""
        matches: list[SecretMatch] = []
        for term in self._org_terms:
            pat = re.compile(re.escape(term), re.IGNORECASE)
            for m in pat.finditer(content):
                line_num = content[: m.start()].count("\n") + 1
                ctx_start = max(0, line_num - 1 - _CONTEXT_LINES)
                ctx_end = min(len(lines), line_num + _CONTEXT_LINES)
                matches.append(
                    SecretMatch(
                        path=path,
                        line_num=line_num,
                        secret_type=f"Internal Reference: {term}",
                        severity=Severity.MEDIUM,
                        matched_text=m.group(0),
                        context_before=lines[ctx_start: line_num - 1],
                        context_after=lines[line_num:ctx_end],
                        masked_preview=m.group(0),
                    )
                )
        return matches
