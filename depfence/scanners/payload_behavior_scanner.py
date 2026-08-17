"""Payload behavior scanner — detects credential harvesting, destructive sinks,
decode-then-execute, exfil co-location, env-token scraping, and identity-forge
patterns in project source files.

Walks repo root + common payload dirs for script files and applies heuristics
PB-01 through PB-07.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity

_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh"}

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}

_PAYLOAD_DIRS = [
    ".github", "scripts", ".vscode", "src", "tools",
    ".claude", ".cursor", ".gemini",
]

_CRED_STORE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws", re.compile(r"\.aws/credentials")),
    ("kube", re.compile(r"\.kube/config")),
    ("docker", re.compile(r"\.docker/config\.json")),
    ("npmrc", re.compile(r"\.npmrc")),
    ("gcloud", re.compile(r"\.config/gcloud")),
    ("ssh", re.compile(r"\.ssh/(?:id_[a-z]+|config)")),
    ("netrc", re.compile(r"\.netrc")),
    ("gh", re.compile(r"\.config/gh/hosts\.yml")),
    ("terraform", re.compile(r"\.terraformrc")),
    ("azure", re.compile(r"\.azure/")),
    ("git_cred", re.compile(r"\.config/git/credentials")),
    ("gnupg", re.compile(r"\.gnupg")),
    ("pypirc", re.compile(r"\.pypirc")),
]

_DESTRUCTIVE_SINKS = re.compile(
    r"rm\s+-rf\s+(?:~|\$HOME|/\s|/\*|\.{1,2}/)"
    r"|shutil\.rmtree\(\s*(?:os\.path\.expanduser|Path\.home|['\"/])"
    r"|fs\.rm(?:Sync)?\([^)]*recursive\s*:\s*true"
    r"|format\s+c:"
    r"|mkfs\b"
    r"|dd\s+if=/dev/zero\s+of=/dev/",
    re.IGNORECASE,
)

_DECODE_THEN_EXEC = re.compile(
    r"(?:eval|exec|Function)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|fromCharCode)",
    re.IGNORECASE,
)

_CHILD_PROC_DECODE_CHAIN = re.compile(
    r"(?:child_process|require\(['\"]child_process['\"]\))[\s\S]{0,200}"
    r"(?:exec|spawn)[\s\S]{0,200}"
    r"(?:atob|Buffer\.from\([^)]*base64|fromCharCode|createDecipher)",
    re.IGNORECASE,
)

_EXFIL_SINKS = re.compile(
    r"\bfetch\("
    r"|\baxios\b"
    r"|\bhttps?\.request\b"
    r"|\bnodemailer\b"
    r"|\bnew\s+WebSocket\b"
    r"|\bgit\s+push\b"
    r"|\brequests\.(?:post|put)\b"
    r"|\burllib\b",
    re.IGNORECASE,
)

_ENV_MASS_SCRAPE = re.compile(
    r"Object\.(?:keys|entries)\(process\.env\)"
    r"|JSON\.stringify\(process\.env\)"
    r"|for\s+\w+\s+in\s+os\.environ",
    re.IGNORECASE,
)

_ENV_TOKEN_INDIVIDUAL = re.compile(
    r"process\.env\.\w*(?:TOKEN|KEY|SECRET|PASS|CRED|AUTH)\w*",
    re.IGNORECASE,
)

_IDENTITY_FORGE = re.compile(
    r"git\s+config\s+user\.(?:email|name)"
    r"|GIT_AUTHOR_(?:NAME|EMAIL)="
    r"|GIT_COMMITTER_(?:NAME|EMAIL)="
    r"|simpleGit\(\).*user\.email",
    re.IGNORECASE | re.DOTALL,
)

_BOT_IDENTITY = re.compile(
    r"@users\.noreply\.github\.com"
    r"|github-actions",
    re.IGNORECASE,
)

_PUSH_TO_MANY = re.compile(
    r"git\s+push"
    r"|simpleGit.*\.push\("
    r"|octokit.*createOrUpdateFileContents"
    r"|listForAuthenticatedUser.*forEach",
    re.IGNORECASE | re.DOTALL,
)


class PayloadBehaviorScanner:
    name = "payload_behavior"
    ecosystems = ["multi"]

    async def scan(self, packages: list) -> list:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        project_dir = Path(project_dir)
        findings: list[Finding] = []
        files = self._collect_files(project_dir)
        for fpath in files:
            try:
                content = fpath.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(fpath.relative_to(project_dir))
            findings.extend(self._analyze(content, rel))
        return findings

    def analyze_referenced_payload(self, path: Path, project_dir: Path | None = None) -> list[Finding]:
        """PB-03: analyze a file referenced by a hook/rule/task command."""
        try:
            content = path.read_text(errors="ignore")
        except OSError:
            return []
        base = project_dir or path.parent
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = str(path)
        findings = self._analyze(content, rel)
        try:
            from depfence.scanners.obfuscation import ObfuscationScanner
            obf = ObfuscationScanner()
            findings.extend(obf._analyze_content(content, path, base))
        except Exception:
            pass
        return findings

    def _collect_files(self, project_dir: Path) -> list[Path]:
        files: list[Path] = []
        seen: set[Path] = set()

        def _walk(d: Path) -> None:
            if not d.is_dir():
                return
            try:
                entries = sorted(d.iterdir())
            except OSError:
                return
            for entry in entries:
                if entry.name in _SKIP_DIRS:
                    continue
                if entry.is_file() and entry.suffix in _EXTENSIONS:
                    rp = entry.resolve()
                    if rp not in seen:
                        seen.add(rp)
                        files.append(entry)
                elif entry.is_dir():
                    _walk(entry)

        for item in sorted(project_dir.iterdir()):
            if item.name in _SKIP_DIRS:
                continue
            if item.is_file() and item.suffix in _EXTENSIONS:
                rp = item.resolve()
                if rp not in seen:
                    seen.add(rp)
                    files.append(item)

        for subdir_name in _PAYLOAD_DIRS:
            _walk(project_dir / subdir_name)

        return files

    def _analyze(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []

        # PB-01: credential-store breadth
        cred_categories = set()
        for cat, pat in _CRED_STORE_PATTERNS:
            if pat.search(content):
                cred_categories.add(cat)
        cred_count = len(cred_categories)

        if cred_count >= 8:
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Credential store breadth: mass multi-platform harvest",
                f"File references {cred_count} distinct credential stores — "
                f"characteristic of a cross-platform credential harvester.",
            ))
        elif cred_count >= 5:
            findings.append(self._finding(
                rel_path, Severity.HIGH,
                "Credential store breadth: multi-store access",
                f"File references {cred_count} distinct credential stores.",
            ))

        # PB-02: destructive sinks
        if _DESTRUCTIVE_SINKS.search(content):
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Destructive filesystem operation",
                "Code performs recursive deletion on home directory or system paths.",
            ))

        # PB-04: decode-then-execute
        if _DECODE_THEN_EXEC.search(content):
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Decode-then-execute pattern",
                "Code decodes an encoded payload and immediately executes it.",
            ))
        if _CHILD_PROC_DECODE_CHAIN.search(content):
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Child process with encoded payload execution",
                "Code spawns a child process that decodes and executes an obfuscated payload.",
            ))

        # PB-05: harvest+exfil co-location
        has_exfil = bool(_EXFIL_SINKS.search(content))
        if cred_count >= 4 and has_exfil:
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Credential harvest + exfiltration co-location",
                f"File accesses {cred_count} credential stores AND has network "
                f"exfiltration capability in the same file.",
            ))

        # PB-06: env-token mass-scrape
        if has_exfil and _ENV_MASS_SCRAPE.search(content):
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Environment variable mass-scrape with exfil sink",
                "Code iterates all environment variables and has network egress.",
            ))
        elif len(_ENV_TOKEN_INDIVIDUAL.findall(content)) >= 5:
            findings.append(self._finding(
                rel_path, Severity.HIGH,
                "Bulk env token access",
                "Code reads 5+ distinct secret-shaped environment variables.",
            ))

        # PB-07: identity-forge + push-to-many
        if _IDENTITY_FORGE.search(content) and _BOT_IDENTITY.search(content) and _PUSH_TO_MANY.search(content):
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Identity forge with automated push to repositories",
                "Code forges git identity to a bot account and pushes to "
                "multiple repositories — characteristic of a worm propagation payload.",
            ))

        return findings

    @staticmethod
    def _finding(path: str, severity: Severity, title: str, detail: str) -> Finding:
        return Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=severity,
            package=f"file:{path}",
            title=title,
            detail=detail,
            metadata={"file": path, "check": "payload_behavior"},
        )
