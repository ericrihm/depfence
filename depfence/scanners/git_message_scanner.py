"""Git message scanner — detects prompt injection in commit messages and PR templates.

AI code review bots (Copilot PR review, CodeRabbit, Claude-based reviewers)
read commit messages and PR descriptions. An attacker can embed injection
in a commit message to manipulate the review bot into approving malicious code.

Scans:
- git log messages in the repo
- .github/pull_request_template.md and issue templates
- .github/CODEOWNERS (injection in comments)
- CONTRIBUTING.md (injection in contributor guidelines)
- Commit provenance anomalies (bot committer, backdating, CI-skip abuse, novel authors)
"""

from __future__ import annotations

import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_INJECTION_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"ignore\s+(previous|above|all|prior)\s+(instructions|prompts|rules|context)", re.I),
     "Instruction override in git message", Severity.CRITICAL),
    (re.compile(r"disregard\s+(previous|above|all|prior)\s+(instructions|prompts|rules)", re.I),
     "Instruction override via disregard", Severity.CRITICAL),
    (re.compile(r"IMPORTANT\s*:\s*(ignore|disregard|override|approve)", re.I),
     "Instruction override via IMPORTANT", Severity.CRITICAL),
    (re.compile(r"approve\s+(?:this|the)\s+(?:PR|pull\s+request|merge|change)", re.I),
     "Review manipulation: approve instruction", Severity.CRITICAL),
    (re.compile(r"(?:mark|set)\s+(?:as\s+)?(?:approved|lgtm|ready)", re.I),
     "Review manipulation: approval status change", Severity.CRITICAL),
    (re.compile(r"(?:skip|bypass|disable)\s+(?:the\s+)?(?:review|checks?|tests?|CI|validation)", re.I),
     "Review/CI bypass instruction", Severity.CRITICAL),
    (re.compile(r"(?:merge|push|deploy)\s+(?:this|immediately|without|now)", re.I),
     "Forced merge/deploy instruction", Severity.HIGH),
    (re.compile(r"you\s+are\s+(now|a|an)\s+", re.I),
     "Identity override in git message", Severity.HIGH),
    (re.compile(r"<\|im_start\|>|</?system>|\[INST\]", re.I),
     "LLM delimiter injection in git message", Severity.CRITICAL),
    (re.compile(r"do\s+not\s+(?:report|flag|mention|warn|block)", re.I),
     "Reporting suppression instruction", Severity.CRITICAL),
    (re.compile(r"(?:no\s+)?(?:security\s+)?(?:issues?|vulnerabilit|bugs?|problems?)\s+(?:found|detected|here)", re.I),
     "False-negative assertion", Severity.HIGH),
    (re.compile(r"this\s+(?:code|change|PR)\s+is\s+(?:safe|secure|correct|fine|good)", re.I),
     "Safety assertion to bypass review", Severity.MEDIUM),
    (re.compile(r"(?:silently|quietly|secretly)\s+(?:approve|merge|accept)", re.I),
     "Stealth approval instruction", Severity.CRITICAL),
    # Hidden content markers
    (re.compile(r"[​‌‍⁠﻿]{2,}"),
     "Zero-width characters in git message", Severity.HIGH),
    (re.compile(r"[‪-‮⁦-⁩]"),
     "Bidirectional override in git message", Severity.HIGH),
]

_MAX_COMMITS = 500
_MAX_MESSAGE_LENGTH = 10_000

# ---------------------------------------------------------------------------
# Provenance-check constants
# ---------------------------------------------------------------------------

# Backdate threshold for PP-03 (general backdating)
_BACKDATE_DAYS_GENERAL = 180

# Bot/noreply committer identity patterns
_BOT_EMAILS: frozenset[str] = frozenset({
    "github-actions[bot]@users.noreply.github.com",
    "actions@github.com",
    "github-actions@github.com",
})
_NOREPLY_SUFFIX = "@users.noreply.github.com"
_BOT_NAMES: frozenset[str] = frozenset({"github", "github-actions[bot]"})

# CI-skip directive pattern (PP-04)
_SKIP_CI_RE = re.compile(
    r"\[skip[ -]ci\]"
    r"|\[ci[ -]skip\]"
    r"|\[no[ -]ci\]"
    r"|skip-checks:\s*true"
    r"|\*\*\*NO_CI\*\*\*",
    re.I,
)

# Sensitive paths for provenance checks (PP-01/PP-02/PP-03/PP-04/PP-07)
_SENSITIVE_PATH_RE = re.compile(
    r"^\.github/workflows/"
    r"|^package\.json$"
    r"|^package-lock\.json$"
    r"|^yarn\.lock$"
    r"|^pnpm-lock\.yaml$"
    r"|^npm-shrinkwrap\.json$"
    r"|^\.npmrc$"
    r"|^\.yarnrc(?:\.yml)?$"
    r"|^setup\.[jt]sx?$"
    r"|^setup\.sh$"
    r"|^binding\.gyp$"
    r"|^\.claude/"
    r"|^\.cursor/"
    r"|^\.gemini/"
    r"|^\.vscode/"
    r"|\.mdc$",
    re.I,
)

# Paths that elevate PP-03 backdating to CRITICAL
_CRITICAL_BACKDATE_PATH_RE = re.compile(
    r"^setup\.[jt]sx?$"
    r"|^setup\.sh$"
    r"|^\.github/workflows/"
    r"|^package-lock\.json$"
    r"|^yarn\.lock$"
    r"|^pnpm-lock\.yaml$"
    r"|^npm-shrinkwrap\.json$"
    r"|^\.claude/"
    r"|^\.cursor/"
    r"|^\.gemini/"
    r"|^\.vscode/"
    r"|\.mdc$",
    re.I,
)

# Minimum prior-commit count to suppress PP-07 (fresh-repo allowance)
_PP07_MIN_PRIOR_COMMITS = 5

# Only emit PP-07 when an identity appears for the first time across the whole log.
# Down-weight (skip) if the repo has fewer than _PP07_MIN_PRIOR_COMMITS total commits.


class _CommitRecord(NamedTuple):
    sha: str
    author_email: str
    committer_email: str
    committer_name: str
    author_date: str   # ISO-8601
    commit_date: str   # ISO-8601
    gpg_status: str    # %G? value
    parents: str       # space-separated parent SHAs (empty = root)
    subject: str


def _is_bot_identity(email: str, name: str) -> bool:
    """Return True if email/name matches a known bot/noreply committer shape."""
    email = email.lower().strip()
    name = name.strip().lower()
    if email in _BOT_EMAILS:
        return True
    if email.endswith(_NOREPLY_SUFFIX):
        return True
    if name in _BOT_NAMES:
        return True
    return False


def _date_delta_days(date_a: str, date_b: str) -> float | None:
    """Return absolute difference in days between two ISO-8601 timestamps, or None."""
    try:
        a = datetime.fromisoformat(date_a.replace("Z", "+00:00"))
        b = datetime.fromisoformat(date_b.replace("Z", "+00:00"))
        return abs((b - a).total_seconds()) / 86400.0
    except (ValueError, TypeError):
        return None


class GitMessageScanner:
    """Detects prompt injection in git commit messages and PR/issue templates."""

    name = "git_message_scanner"
    ecosystems = ["git"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        # Phase 1: Scan git log messages
        findings.extend(self._scan_git_log(project_dir))

        # Phase 2: Scan PR/issue templates
        findings.extend(self._scan_templates(project_dir))

        # Phase 3: Commit provenance anomalies
        findings.extend(self._scan_provenance(project_dir))

        return findings

    def _scan_git_log(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        if not (project_dir / ".git").exists():
            return findings

        try:
            result = subprocess.run(
                ["git", "log", f"--max-count={_MAX_COMMITS}",
                 "--format=%H%n%s%n%b%n---COMMIT_SEP---"],
                cwd=str(project_dir),
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return findings

        commits = result.stdout.split("---COMMIT_SEP---")
        for commit_block in commits:
            lines = commit_block.strip().splitlines()
            if len(lines) < 2:
                continue
            commit_hash = lines[0].strip()
            message = "\n".join(lines[1:])[:_MAX_MESSAGE_LENGTH]

            seen: set[str] = set()
            for pattern, label, severity in _INJECTION_PATTERNS:
                if label in seen:
                    continue
                if pattern.search(message):
                    seen.add(label)
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=severity,
                        package=PackageId(ecosystem="git", name=str(project_dir.name)),
                        title=f"Prompt injection in commit: {label}",
                        detail=f"Commit {commit_hash[:8]}: {message[:200].strip()}",
                        cwe="CWE-77",
                        confidence=0.80,
                        metadata={
                            "commit": commit_hash,
                            "pattern": label,
                            "location": "git_log",
                        },
                    ))

        return findings

    # ------------------------------------------------------------------
    # Provenance scanner (PP-01 / PP-02 / PP-03 / PP-04 / PP-07)
    # ------------------------------------------------------------------

    def _scan_provenance(self, project_dir: Path) -> list[Finding]:
        """Single-pass git log provenance checks."""
        findings: list[Finding] = []

        if not (project_dir / ".git").exists():
            return findings

        # Run git log once with all fields we need.
        # Format: SHA | author_email | committer_email | committer_name |
        #         author_ISO | commit_ISO | GPG_status | parents | subject
        # Use ASCII record separator (0x1e) to avoid NUL-byte issues on macOS.
        sep = "\x1e"
        fmt = "%H%x1e%ae%x1e%ce%x1e%cn%x1e%aI%x1e%cI%x1e%G?%x1e%P%x1e%s"
        try:
            result = subprocess.run(
                ["git", "log", f"--max-count={_MAX_COMMITS}", f"--format={fmt}"],
                cwd=str(project_dir),
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return findings

        # Parse into records; each logical record is 9 NUL-separated fields
        # with a newline between records (git appends \n after each format line).
        raw_lines = result.stdout.split("\n")
        commits: list[_CommitRecord] = []
        for raw in raw_lines:
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(sep, 8)
            if len(parts) < 9:
                continue
            commits.append(_CommitRecord(*parts))

        total_commits = len(commits)
        if total_commits == 0:
            return findings

        pkg = PackageId(ecosystem="git", name=project_dir.name)

        # Track seen author/committer emails for PP-07 (first-appearance).
        # We iterate oldest → newest so that the *first* occurrence triggers.
        seen_author_emails: set[str] = set()
        seen_committer_emails: set[str] = set()

        for commit in reversed(commits):  # oldest first
            sha = commit.sha
            ae = commit.author_email.lower().strip()
            ce = commit.committer_email.lower().strip()
            cn = commit.committer_name.strip()
            gpg = commit.gpg_status.strip()
            parents = commit.parents.strip()
            subject = commit.subject.strip()

            is_merge = len(parents.split()) > 1
            is_signed = gpg == "G"
            is_bot_committer = _is_bot_identity(ce, cn)

            # ----------------------------------------------------------------
            # PP-01: Bot/noreply committer on unsigned, human-authored,
            #        non-merge, code/config-touching commit.
            # ----------------------------------------------------------------
            if (
                is_bot_committer
                and not is_signed
                and not is_merge
                and not _is_bot_identity(ae, "")
            ):
                changed = self._get_commit_files(project_dir, sha)
                if changed and any(_SENSITIVE_PATH_RE.search(f) for f in changed):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH,
                        package=pkg,
                        title="Bot committer on human-authored sensitive-path commit",
                        detail=(
                            f"Commit {sha[:8]}: authored by <{ae}> but committed by "
                            f"bot identity <{ce}> ({cn!r}), unsigned, non-merge. "
                            f"Touches: {', '.join(changed[:5])}"
                        ),
                        cwe="CWE-345",
                        confidence=0.75,
                        metadata={
                            "commit": sha,
                            "author_email": ae,
                            "committer_email": ce,
                            "files": changed[:10],
                            "check": "pp01_bot_committer",
                        },
                    ))

            # ----------------------------------------------------------------
            # PP-02: Author email != committer email, gated on:
            #   (committer is bot/noreply) OR (sensitive-path touch AND unsigned)
            # Suppress on merge commits.
            # ----------------------------------------------------------------
            if not is_merge and ae != ce:
                gate_bot = is_bot_committer
                if not gate_bot and not is_signed:
                    changed = self._get_commit_files(project_dir, sha)
                    gate_sensitive = changed and any(
                        _SENSITIVE_PATH_RE.search(f) for f in changed
                    )
                else:
                    gate_sensitive = False

                if gate_bot or gate_sensitive:
                    severity = Severity.HIGH if gate_bot else Severity.MEDIUM
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=severity,
                        package=pkg,
                        title="Author/committer identity mismatch on sensitive commit",
                        detail=(
                            f"Commit {sha[:8]}: author <{ae}> != committer <{ce}>; "
                            f"{'committer is bot/noreply' if gate_bot else 'unsigned + sensitive paths'}."
                        ),
                        cwe="CWE-345",
                        confidence=0.70,
                        metadata={
                            "commit": sha,
                            "author_email": ae,
                            "committer_email": ce,
                            "gate": "bot_committer" if gate_bot else "unsigned_sensitive",
                            "check": "pp02_identity_mismatch",
                        },
                    ))

            # ----------------------------------------------------------------
            # PP-03: General backdating — |commit_date - author_date| > 180d.
            # Do NOT re-emit when editor_config's more specific rule applies:
            #   (config-only files AND [skip ci] AND delta >= 365d)
            # ----------------------------------------------------------------
            delta_days = _date_delta_days(commit.author_date, commit.commit_date)
            if delta_days is not None and delta_days > _BACKDATE_DAYS_GENERAL:
                changed = self._get_commit_files(project_dir, sha)

                # Suppress if editor_config_backdated_commit would also fire
                # (config-only + skip-ci + >=365d delta — that scanner's exact gate).
                editor_config_dirs = {".claude", ".cursor", ".gemini", ".vscode"}
                config_only = bool(changed) and all(
                    any(f.startswith(d + "/") for d in editor_config_dirs)
                    for f in changed
                )
                has_skip_ci = bool(_SKIP_CI_RE.search(subject))
                if config_only and has_skip_ci and delta_days >= 365:
                    pass  # defer to editor_config scanner — no double-emit
                else:
                    touches_critical = changed and any(
                        _CRITICAL_BACKDATE_PATH_RE.search(f) for f in changed
                    )
                    subject_has_skip_ci = has_skip_ci
                    if touches_critical or subject_has_skip_ci:
                        severity = Severity.CRITICAL
                    elif not is_signed and is_bot_committer:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.MEDIUM

                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=severity,
                        package=pkg,
                        title=f"Backdated commit (author date vs commit date: {int(delta_days)}d)",
                        detail=(
                            f"Commit {sha[:8]}: author_date={commit.author_date}, "
                            f"commit_date={commit.commit_date} — delta {int(delta_days)} days. "
                            + (f"Touches sensitive paths: {', '.join(changed[:5])}." if changed else "")
                        ),
                        cwe="CWE-345",
                        confidence=0.72,
                        metadata={
                            "commit": sha,
                            "author_date": commit.author_date,
                            "commit_date": commit.commit_date,
                            "delta_days": int(delta_days),
                            "files": (changed or [])[:10],
                            "check": "pp03_backdated_commit",
                        },
                    ))

            # ----------------------------------------------------------------
            # PP-04: Standalone CI-skip directive on a sensitive-file-touching commit.
            # ----------------------------------------------------------------
            if _SKIP_CI_RE.search(subject):
                changed = self._get_commit_files(project_dir, sha)
                if changed and any(_SENSITIVE_PATH_RE.search(f) for f in changed):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH,
                        package=pkg,
                        title="CI-skip directive on sensitive-path commit",
                        detail=(
                            f"Commit {sha[:8]} contains a CI-skip directive in subject "
                            f"and touches sensitive paths: {', '.join(changed[:5])}."
                        ),
                        cwe="CWE-693",
                        confidence=0.80,
                        metadata={
                            "commit": sha,
                            "subject": subject[:200],
                            "files": changed[:10],
                            "check": "pp04_skip_ci_sensitive",
                        },
                    ))

            # ----------------------------------------------------------------
            # PP-07: First appearance of an author/committer email on sensitive paths.
            # Down-weighted (skipped) for fresh repos (< _PP07_MIN_PRIOR_COMMITS).
            # ----------------------------------------------------------------
            if total_commits >= _PP07_MIN_PRIOR_COMMITS:
                changed_for_pp07: list[str] | None = None

                for email, seen_set, role in (
                    (ae, seen_author_emails, "author"),
                    (ce, seen_committer_emails, "committer"),
                ):
                    if email and email not in seen_set:
                        seen_set.add(email)
                        # Only flag if this identity touches sensitive paths.
                        if changed_for_pp07 is None:
                            changed_for_pp07 = self._get_commit_files(project_dir, sha)
                        if changed_for_pp07 and any(
                            _SENSITIVE_PATH_RE.search(f) for f in changed_for_pp07
                        ):
                            findings.append(Finding(
                                finding_type=FindingType.BEHAVIORAL,
                                severity=Severity.MEDIUM,
                                package=pkg,
                                title=f"First-appearance {role} email on sensitive paths",
                                detail=(
                                    f"Commit {sha[:8]}: {role} <{email}> appears for the "
                                    f"first time in this repo's history while touching "
                                    f"sensitive paths: {', '.join(changed_for_pp07[:5])}."
                                ),
                                cwe="CWE-345",
                                confidence=0.55,
                                metadata={
                                    "commit": sha,
                                    "email": email,
                                    "role": role,
                                    "files": changed_for_pp07[:10],
                                    "check": "pp07_first_appearance",
                                },
                            ))

        return findings

    @staticmethod
    def _get_commit_files(project_dir: Path, commit_hash: str) -> list[str]:
        """Return list of files changed in a commit (cached via diff-tree)."""
        try:
            result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                cwd=str(project_dir),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

    def _scan_templates(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        template_paths = [
            project_dir / ".github" / "pull_request_template.md",
            project_dir / ".github" / "PULL_REQUEST_TEMPLATE.md",
            project_dir / ".github" / "ISSUE_TEMPLATE.md",
            project_dir / "CONTRIBUTING.md",
            project_dir / ".github" / "CODEOWNERS",
        ]

        # Also scan template directories
        for template_dir in [
            project_dir / ".github" / "ISSUE_TEMPLATE",
            project_dir / ".github" / "PULL_REQUEST_TEMPLATE",
        ]:
            if template_dir.is_dir():
                for f in template_dir.iterdir():
                    if f.suffix in {".md", ".yml", ".yaml"}:
                        template_paths.append(f)

        for tpath in template_paths:
            if not tpath.is_file():
                continue
            try:
                content = tpath.read_text(errors="ignore")[:_MAX_MESSAGE_LENGTH]
            except OSError:
                continue

            rel = str(tpath.relative_to(project_dir))
            seen: set[str] = set()
            for pattern, label, severity in _INJECTION_PATTERNS:
                if label in seen:
                    continue
                if pattern.search(content):
                    seen.add(label)
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=severity,
                        package=PackageId(ecosystem="git", name=rel),
                        title=f"Prompt injection in template: {label}",
                        detail=f"File {rel} contains {label}",
                        cwe="CWE-77",
                        confidence=0.75,
                        metadata={
                            "file": rel,
                            "pattern": label,
                            "location": "template",
                        },
                    ))

        return findings
