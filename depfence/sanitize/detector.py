"""Trade secret / sensitive info detector.

Reads configuration from depfence.yml under:
  secrets:
    patterns: [...]    # additional regex patterns
    org_terms: [...]   # internal hostname / term allowlist

Supports:
  - File content scanning with surrounding context
  - Git history scanning (check all commits for leaked secrets)
  - Severity classification
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depfence.scanners.secrets import SecretMatch, SecretsScanner, _shannon_entropy


@dataclass
class HistoryFinding:
    """A secret found in git history."""

    commit_hash: str
    commit_message: str
    file_path: str
    line_num: int
    secret_type: str
    masked_preview: str
    severity: str


@dataclass
class DetectorConfig:
    """Configuration for the secrets detector."""

    extra_patterns: list[tuple[str, str]] = field(default_factory=list)
    org_terms: list[str] = field(default_factory=list)
    scan_history: bool = True
    history_depth: int = 50  # max commits to scan
    entropy_threshold: float = 4.5
    min_secret_len: int = 20

    @classmethod
    def from_depfence_yml(cls, project_dir: Path) -> "DetectorConfig":
        """Load configuration from depfence.yml if present."""
        cfg_path = project_dir / "depfence.yml"
        if not cfg_path.exists():
            return cls()
        try:
            import yaml  # type: ignore[import]
            data = yaml.safe_load(cfg_path.read_text()) or {}
        except Exception:
            return cls()
        secrets_cfg = data.get("secrets", {}) or {}
        extra_pats: list[tuple[str, str]] = []
        for p in secrets_cfg.get("patterns", []) or []:
            if isinstance(p, dict):
                extra_pats.append((p.get("regex", ""), p.get("label", "Custom Pattern")))
            elif isinstance(p, str):
                extra_pats.append((p, "Custom Pattern"))
        return cls(
            extra_patterns=extra_pats,
            org_terms=secrets_cfg.get("org_terms", []) or [],
            scan_history=secrets_cfg.get("scan_history", True),
            history_depth=int(secrets_cfg.get("history_depth", 50)),
            entropy_threshold=float(secrets_cfg.get("entropy_threshold", 4.5)),
            min_secret_len=int(secrets_cfg.get("min_secret_len", 20)),
        )


class SecretsDetector:
    """High-level detector wrapping SecretsScanner with git history support."""

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self._config = config or DetectorConfig()
        self._scanner = SecretsScanner(org_terms=self._config.org_terms)
        # Register extra patterns
        for regex, label in self._config.extra_patterns:
            try:
                compiled = re.compile(regex)
                self._scanner._compiled.append((compiled, label, None, 0))  # type: ignore[arg-type]
            except re.error:
                pass

    @classmethod
    def from_project(cls, project_dir: Path) -> "SecretsDetector":
        """Create a detector configured from the project's depfence.yml."""
        cfg = DetectorConfig.from_depfence_yml(project_dir)
        return cls(config=cfg)

    # ------------------------------------------------------------------
    # File scanning
    # ------------------------------------------------------------------

    def scan_file(self, path: Path) -> list[SecretMatch]:
        """Scan a single file, returning findings with context."""
        return self._scanner.scan_file(path)

    def scan_content(self, content: str, path: str = "<string>") -> list[SecretMatch]:
        """Scan a string of content."""
        return self._scanner.scan_file_content(content, path)

    async def scan_project(self, project_dir: Path) -> list[SecretMatch]:
        """Scan all project files, returning SecretMatch objects."""
        all_matches: list[SecretMatch] = []
        for f in self._scanner._find_scannable_files(project_dir):
            try:
                content = f.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(f.relative_to(project_dir))
            all_matches.extend(self._scanner.scan_file_content(content, rel))
        return all_matches

    # ------------------------------------------------------------------
    # Git history scanning
    # ------------------------------------------------------------------

    def scan_git_history(self, project_dir: Path) -> list[HistoryFinding]:
        """Scan recent git commits for leaked secrets."""
        if not self._config.scan_history:
            return []

        git_dir = project_dir / ".git"
        if not git_dir.exists():
            return []

        findings: list[HistoryFinding] = []
        try:
            commits = self._get_recent_commits(project_dir, self._config.history_depth)
        except Exception:
            return []

        for commit_hash, commit_msg in commits:
            try:
                diff = self._get_commit_diff(project_dir, commit_hash)
            except Exception:
                continue
            current_file = "<unknown>"
            for line in diff.splitlines():
                if line.startswith("+++ b/"):
                    current_file = line[6:]
                elif line.startswith("+") and not line.startswith("+++"):
                    added_line = line[1:]
                    matches = self._scanner.scan_file_content(added_line, current_file)
                    for m in matches:
                        findings.append(
                            HistoryFinding(
                                commit_hash=commit_hash[:8],
                                commit_message=commit_msg[:80],
                                file_path=current_file,
                                line_num=m.line_num,
                                secret_type=m.secret_type,
                                masked_preview=m.masked_preview,
                                severity=m.severity.value,
                            )
                        )
        return findings

    # ------------------------------------------------------------------
    # Severity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def classify_severity(match: SecretMatch) -> str:
        """Return severity label for display."""
        return match.severity.value.upper()

    # ------------------------------------------------------------------
    # Internal git helpers
    # ------------------------------------------------------------------

    def _get_recent_commits(self, project_dir: Path, depth: int) -> list[tuple[str, str]]:
        result = subprocess.run(
            ["git", "log", f"--max-count={depth}", "--pretty=format:%H %s"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        commits: list[tuple[str, str]] = []
        for line in result.stdout.splitlines():
            if " " in line:
                h, _, msg = line.partition(" ")
                commits.append((h, msg))
        return commits

    def _get_commit_diff(self, project_dir: Path, commit_hash: str) -> str:
        result = subprocess.run(
            ["git", "show", "--no-color", commit_hash],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
