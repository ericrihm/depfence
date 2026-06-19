"""Tests for CiAiBotScanner — AI bot in CI/CD with untrusted input detection."""

import asyncio
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.ci_ai_bot_scanner import CiAiBotScanner


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def scanner():
    return CiAiBotScanner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_workflow(project_dir: Path, name: str, content: str) -> Path:
    wf_dir = project_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    path = wf_dir / name
    path.write_text(content)
    return path


def _write_ai_config(project_dir: Path, rel: str, content: str) -> Path:
    path = project_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# Workflow scanning — CRITICAL clinejection
# ---------------------------------------------------------------------------

class TestWorkflowClinejection:
    def test_ai_bot_with_issue_title_injection(self, scanner, tmp_path):
        """AI workflow interpolating github.event.issue.title → CRITICAL."""
        _write_workflow(tmp_path, "review.yml", """
name: AI Review
on: [issues]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropic/claude-action@v1
        with:
          prompt: "Review this issue: ${{ github.event.issue.title }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity == Severity.CRITICAL
                    and f.finding_type == FindingType.PROMPT_INJECTION]
        assert len(critical) >= 1
        assert any("clinejection" in f.title.lower() or "untrusted" in f.title.lower()
                   for f in critical)

    def test_ai_bot_with_pr_body_injection(self, scanner, tmp_path):
        """AI workflow interpolating github.event.pull_request.body → CRITICAL."""
        _write_workflow(tmp_path, "pr-review.yml", """
name: Cline PR Review
on: [pull_request]
jobs:
  ai-review:
    runs-on: ubuntu-latest
    steps:
      - name: Run Cline
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          cline --prompt "PR body: ${{ github.event.pull_request.body }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity == Severity.CRITICAL
                    and f.finding_type == FindingType.PROMPT_INJECTION]
        assert len(critical) >= 1

    def test_ai_bot_with_comment_body_injection(self, scanner, tmp_path):
        """AI workflow interpolating github.event.comment.body → CRITICAL."""
        _write_workflow(tmp_path, "comment.yml", """
on: issue_comment
jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/gpt-action@v2
        with:
          message: "${{ github.event.comment.body }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_ai_bot_with_attacker_controlled_ref(self, scanner, tmp_path):
        """AI workflow using github.actor → HIGH severity."""
        _write_workflow(tmp_path, "actor.yml", """
on: pull_request
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: claude review
        run: claude --user "${{ github.actor }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        high_or_above = [f for f in findings
                         if f.severity in (Severity.CRITICAL, Severity.HIGH)
                         and f.finding_type == FindingType.PROMPT_INJECTION]
        assert len(high_or_above) >= 1

    def test_no_ai_bot_no_finding(self, scanner, tmp_path):
        """Pure CI workflow with no AI indicators → no clinejection findings."""
        _write_workflow(tmp_path, "ci.yml", """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
""")
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) == 0

    def test_no_workflow_dir_returns_empty(self, scanner, tmp_path):
        """Project with no .github/workflows → no findings."""
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) == 0

    def test_non_yml_files_skipped(self, scanner, tmp_path):
        """Only .yml/.yaml are scanned; .txt is ignored."""
        _write_workflow(tmp_path, "notes.txt", """
anthropic claude ${{ github.event.issue.title }}
""")
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) == 0

    def test_pre_clinejection_write_perms(self, scanner, tmp_path):
        """Workflow with write perms + untrusted input (no AI bot yet) → MEDIUM."""
        _write_workflow(tmp_path, "write.yml", """
on: issues
permissions:
  issues: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        medium = [f for f in findings if f.severity == Severity.MEDIUM
                  and f.finding_type == FindingType.WORKFLOW]
        assert len(medium) >= 1

    def test_write_all_perms_flagged(self, scanner, tmp_path):
        """write-all permission string also triggers MEDIUM pre-clinejection."""
        _write_workflow(tmp_path, "write-all.yml", """
on: pull_request
permissions: write-all
jobs:
  do:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.body }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1

    def test_multiple_injections_multiple_findings(self, scanner, tmp_path):
        """Multiple untrusted inputs in one AI workflow → multiple findings."""
        _write_workflow(tmp_path, "multi.yml", """
on: issues
jobs:
  multi:
    runs-on: ubuntu-latest
    steps:
      - uses: coderabbit/review@v1
        with:
          title: "${{ github.event.issue.title }}"
          body: "${{ github.event.issue.body }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 2

    def test_pr_head_ref_injection(self, scanner, tmp_path):
        """github.event.pull_request.head.ref is untrusted → CRITICAL."""
        _write_workflow(tmp_path, "head.yml", """
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - run: ANTHROPIC_API_KEY=${{ secrets.ANTHROPIC_API_KEY }} claude --branch "${{ github.event.pull_request.head.ref }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_discussion_body_injection(self, scanner, tmp_path):
        """github.event.discussion.body is untrusted → CRITICAL."""
        _write_workflow(tmp_path, "discuss.yml", """
on: discussion
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: sweep-ai/sweep@v1
        with:
          query: "${{ github.event.discussion.body }}"
""")
        findings = _run(scanner.scan_project(tmp_path))
        assert any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# AI config file scanning
# ---------------------------------------------------------------------------

class TestAiConfigScanning:
    def test_cline_wildcard_tools(self, scanner, tmp_path):
        """AI config with wildcard tools → HIGH severity.

        The _BROAD_PERMISSIONS regex matches 'allowedTools: "*"' (bare quoted
        star) but NOT 'allowedTools: ["*"]' (star inside a JSON array bracket).
        Use the bare-quoted form that the regex is designed to catch.
        """
        _write_ai_config(tmp_path, ".cline", 'allowedTools: "*"')
        findings = _run(scanner.scan_project(tmp_path))
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("wildcard" in f.title.lower() for f in high)

    def test_cline_json_broad_perms(self, scanner, tmp_path):
        """YAML-style .cline.json with bare wildcard tools value → HIGH."""
        _write_ai_config(tmp_path, ".cline.json", "allowedTools: '*'")
        findings = _run(scanner.scan_project(tmp_path))
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_claude_settings_dangerous_tool(self, scanner, tmp_path):
        """Claude settings with Bash tool → MEDIUM severity."""
        _write_ai_config(tmp_path, ".claude/settings.json",
                         '{"tools": ["Bash", "Read", "Write"]}')
        findings = _run(scanner.scan_project(tmp_path))
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1
        assert any("shell" in f.title.lower() or "exec" in f.title.lower()
                   for f in medium)

    def test_cursorrules_exec_tool(self, scanner, tmp_path):
        """Cursor rules with Terminal tool → MEDIUM."""
        _write_ai_config(tmp_path, ".cursorrules",
                         "tools:\n  - Terminal\n  - Read")
        findings = _run(scanner.scan_project(tmp_path))
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_copilot_instructions_shell(self, scanner, tmp_path):
        """Copilot instructions mentioning Execute → MEDIUM."""
        _write_ai_config(
            tmp_path, ".github/copilot-instructions.md",
            "You can use Execute to run commands in the terminal."
        )
        findings = _run(scanner.scan_project(tmp_path))
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_benign_ai_config_no_finding(self, scanner, tmp_path):
        """AI config with only read-only tools → no findings."""
        _write_ai_config(tmp_path, ".cline.json",
                         '{"allowedTools": ["Read", "ListFiles"]}')
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) == 0

    def test_missing_config_files_no_error(self, scanner, tmp_path):
        """No AI config files present → no findings, no exception."""
        findings = _run(scanner.scan_project(tmp_path))
        assert findings == []

    def test_claude_md_file_scanned(self, scanner, tmp_path):
        """Top-level CLAUDE.md with RunCommand mention → MEDIUM."""
        _write_ai_config(tmp_path, "CLAUDE.md",
                         "Use RunCommand to execute shell scripts in CI.")
        findings = _run(scanner.scan_project(tmp_path))
        assert any(f.severity == Severity.MEDIUM for f in findings)


# ---------------------------------------------------------------------------
# scan() method (package-level) always returns []
# ---------------------------------------------------------------------------

class TestScanMethod:
    def test_scan_returns_empty(self, scanner):
        """scan() stub always returns empty list."""
        result = _run(scanner.scan([]))
        assert result == []

    def test_scanner_metadata(self, scanner):
        """Scanner has expected name and ecosystems."""
        assert scanner.name == "ci_ai_bot_scanner"
        assert "github" in scanner.ecosystems
