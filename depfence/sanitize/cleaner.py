"""Automated sanitizer — replaces detected secrets with placeholders.

API:
  sanitize_file(path, findings) -> str          cleaned content string
  sanitize_repo(project_dir, config) -> SanitizeReport   full repo scan+clean
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depfence.sanitize.detector import DetectorConfig, SecretsDetector
from depfence.scanners.secrets import SecretMatch, SecretsScanner


# Placeholder templates by secret type
_PLACEHOLDERS: dict[str, str] = {
    "AWS Access Key ID": "AKIAXXXXXXXXXXXXXXXX",
    "AWS Secret Access Key": "REDACTED_AWS_SECRET",
    "AWS Temporary Access Key": "ASIAXXXXXXXXXXXXXXXX",
    "Google API Key": "REDACTED_GOOGLE_API_KEY",
    "Google OAuth Token": "REDACTED_GOOGLE_TOKEN",
    "Azure Storage Key": "REDACTED_AZURE_STORAGE_KEY",
    "Azure Client Secret": "REDACTED_AZURE_CLIENT_SECRET",
    "GitHub Personal Access Token": "ghp_REDACTED",
    "GitHub OAuth Token": "gho_REDACTED",
    "GitHub Server Token": "ghs_REDACTED",
    "GitHub Fine-grained PAT": "github_pat_REDACTED",
    "NPM Access Token": "npm_REDACTED",
    "PyPI API Token": "pypi-REDACTED",
    "Stripe Secret Key": "sk_live_REDACTED",
    "Stripe Restricted Key": "rk_live_REDACTED",
    "Stripe Test Key": "sk_test_REDACTED",
    "Slack Token": "xoxb-REDACTED",
    "Slack Webhook URL": "https://hooks.slack.com/services/REDACTED",
    "Anthropic API Key": "sk-ant-REDACTED",
    "OpenAI API Key": "sk-REDACTED",
    "SendGrid API Key": "SG.REDACTED",
    "Twilio API Key SID": "SKREDACTED",
    "Private Key (PEM Header)": "-----BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----",
    "PGP Private Key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nREDACTED\n-----END PGP PRIVATE KEY BLOCK-----",
    "Database Connection String": "DB_PROTOCOL://user:REDACTED@host/db",
    "Database URL Variable": "REDACTED_DATABASE_URL",
    "JWT Token": "REDACTED_JWT_TOKEN",
    "Generic API Key": "REDACTED_API_KEY",
    "Hardcoded Password": "REDACTED_PASSWORD",
    "Hardcoded Secret/Token": "REDACTED_SECRET",
    "High-Entropy String": "REDACTED_SECRET",
    "Internal IP Address": "REDACTED_INTERNAL_IP",
}

_DEFAULT_PLACEHOLDER = "REDACTED_SECRET"


@dataclass
class FileCleanResult:
    """Result of cleaning a single file."""

    path: str
    original_content: str
    cleaned_content: str
    replacements: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original_content != self.cleaned_content

    @property
    def replacement_count(self) -> int:
        return len(self.replacements)


@dataclass
class SanitizeReport:
    """Full report from sanitizing a repository."""

    project_dir: str
    files_scanned: int = 0
    files_modified: int = 0
    total_replacements: int = 0
    file_results: list[FileCleanResult] = field(default_factory=list)
    history_findings: list[dict[str, Any]] = field(default_factory=list)
    git_rewrite_needed: bool = False
    git_rewrite_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_dir": self.project_dir,
            "files_scanned": self.files_scanned,
            "files_modified": self.files_modified,
            "total_replacements": self.total_replacements,
            "git_rewrite_needed": self.git_rewrite_needed,
            "git_rewrite_commands": self.git_rewrite_commands,
            "files": [
                {
                    "path": r.path,
                    "replacements": r.replacements,
                }
                for r in self.file_results
                if r.changed
            ],
            "history_findings": self.history_findings,
        }

    def save(self, out_path: Path | None = None) -> Path:
        if out_path is None:
            out_path = Path(self.project_dir) / ".depfence-sanitize-report.json"
        out_path.write_text(json.dumps(self.to_dict(), indent=2))
        return out_path


class SanitizeCleaner:
    """Replaces detected secrets with safe placeholders."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self._config = config or DetectorConfig()
        self._detector = SecretsDetector(config=self._config)

    @classmethod
    def from_project(cls, project_dir: Path) -> "SanitizeCleaner":
        cfg = DetectorConfig.from_depfence_yml(project_dir)
        return cls(config=cfg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize_file(self, path: Path, findings: list[SecretMatch] | None = None) -> str:
        """Return cleaned content with secrets replaced by placeholders.

        If findings is None, the file is scanned first.
        """
        try:
            content = path.read_text(errors="ignore")
        except OSError:
            return ""
        if findings is None:
            findings = self._detector.scan_file(path)
        return self._apply_replacements(content, findings)

    def sanitize_content(self, content: str, findings: list[SecretMatch]) -> str:
        """Apply replacements to a content string given pre-computed findings."""
        return self._apply_replacements(content, findings)

    def sanitize_repo(self, project_dir: Path, write: bool = True) -> SanitizeReport:
        """Scan and optionally clean all files in a project directory.

        Args:
            project_dir: Root directory to scan.
            write: If True, write cleaned files in-place. If False, only report.

        Returns:
            SanitizeReport with everything found and cleaned.
        """
        report = SanitizeReport(project_dir=str(project_dir))
        scanner = SecretsScanner(org_terms=self._config.org_terms)

        files = scanner._find_scannable_files(project_dir)
        report.files_scanned = len(files)

        for f in files:
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(f.relative_to(project_dir))
            findings = scanner.scan_file_content(content, rel)
            if not findings:
                continue

            cleaned = self._apply_replacements(content, findings)
            replacements = [
                {
                    "line": m.line_num,
                    "secret_type": m.secret_type,
                    "severity": m.severity.value,
                    "placeholder": _PLACEHOLDERS.get(m.secret_type, _DEFAULT_PLACEHOLDER),
                }
                for m in findings
            ]
            result = FileCleanResult(
                path=rel,
                original_content=content,
                cleaned_content=cleaned,
                replacements=replacements,
            )
            report.file_results.append(result)

            if result.changed:
                report.files_modified += 1
                report.total_replacements += result.replacement_count
                if write:
                    f.write_text(cleaned)

        # Git history scan
        if self._config.scan_history:
            history = self._detector.scan_git_history(project_dir)
            if history:
                report.git_rewrite_needed = True
                report.history_findings = [
                    {
                        "commit": h.commit_hash,
                        "message": h.commit_message,
                        "file": h.file_path,
                        "secret_type": h.secret_type,
                        "severity": h.severity,
                    }
                    for h in history
                ]
                report.git_rewrite_commands = _git_rewrite_commands(project_dir, history)

        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _apply_replacements(self, content: str, findings: list[SecretMatch]) -> str:
        """Replace matched secret values with placeholders."""
        if not findings:
            return content

        # Sort by match position descending so offsets don't shift
        # We rebuild per-line to avoid offset drift
        lines = content.splitlines(keepends=True)
        changes_by_line: dict[int, list[tuple[str, str]]] = {}
        for m in findings:
            placeholder = _PLACEHOLDERS.get(m.secret_type, _DEFAULT_PLACEHOLDER)
            idx = m.line_num - 1
            if idx not in changes_by_line:
                changes_by_line[idx] = []
            changes_by_line[idx].append((re.escape(m.matched_text), placeholder))

        result_lines = list(lines)
        for idx, replacements in changes_by_line.items():
            if idx >= len(result_lines):
                continue
            line = result_lines[idx]
            for pattern, placeholder in replacements:
                try:
                    line = re.sub(pattern, placeholder, line, count=1)
                except re.error:
                    # Fallback: plain string replace
                    for m in findings:
                        if m.line_num - 1 == idx:
                            ph = _PLACEHOLDERS.get(m.secret_type, _DEFAULT_PLACEHOLDER)
                            line = line.replace(m.matched_text, ph, 1)
            result_lines[idx] = line

        return "".join(result_lines)


def _git_rewrite_commands(project_dir: Path, history_findings: list) -> list[str]:
    """Generate BFG/git-filter-repo recommendations for history rewriting."""
    affected_files = sorted({h.file_path for h in history_findings})
    cmds = [
        "# Git history contains leaked secrets. Options to rewrite history:",
        "",
        "# Option 1: BFG Repo Cleaner (recommended — faster)",
        "# Install: brew install bfg  OR  download from https://rtyley.github.io/bfg-repo-cleaner/",
        "",
        "# Replace specific secret strings (create passwords.txt with one secret per line):",
        "bfg --replace-text passwords.txt",
        "",
        "# Or delete specific files from history:",
    ]
    for f in affected_files:
        cmds.append(f"bfg --delete-files '{f}'")
    cmds += [
        "",
        "# After BFG:",
        f"git -C '{project_dir}' reflog expire --expire=now --all",
        f"git -C '{project_dir}' gc --prune=now --aggressive",
        f"git -C '{project_dir}' push --force",
        "",
        "# Option 2: git-filter-repo",
        "# pip install git-filter-repo",
        "# git filter-repo --sensitive-data-removal",
        "",
        "# IMPORTANT: All collaborators must re-clone after history rewrite.",
        "# Rotate all exposed credentials immediately regardless of history rewrite.",
    ]
    return cmds
