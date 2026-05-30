"""Git message scanner — detects prompt injection in commit messages and PR templates.

AI code review bots (Copilot PR review, CodeRabbit, Claude-based reviewers)
read commit messages and PR descriptions. An attacker can embed injection
in a commit message to manipulate the review bot into approving malicious code.

Scans:
- git log messages in the repo
- .github/pull_request_template.md and issue templates
- .github/CODEOWNERS (injection in comments)
- CONTRIBUTING.md (injection in contributor guidelines)
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

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
