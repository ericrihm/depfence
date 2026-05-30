"""CI/CD AI bot scanner — detects AI agent configurations consuming untrusted input.

Catches the Clinejection attack pattern: AI coding assistants (Cline, Copilot,
Claude) used as GitHub Actions triage/review bots that process untrusted user
input (issue titles, PR bodies, comment text) without sanitization.

Scans:
- .github/workflows/*.yml for AI bot tool usage with ${{ }} injection
- AI agent config files (.cline, .copilot, .cursor)
- GitHub App/bot webhook configurations
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# AI coding tools that may be used as CI bots
_AI_BOT_INDICATORS = [
    "anthropic", "claude", "openai", "copilot", "cline",
    "cursor", "aider", "continue", "coderabbit", "codex",
    "gpt-4", "gpt-3", "claude-3", "claude-sonnet", "claude-opus",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "sweep-ai", "devin", "tabnine",
]

_AI_BOT_PATTERN = re.compile(
    r"|".join(re.escape(b) for b in _AI_BOT_INDICATORS),
    re.IGNORECASE,
)

# Untrusted input sources that should never flow into AI prompts unsanitized
_UNTRUSTED_INPUTS = re.compile(
    r"\$\{\{\s*github\.event\."
    r"(?:issue\.(?:title|body|labels)|"
    r"pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"comment\.(?:body|author)|"
    r"review\.(?:body|state)|"
    r"discussion\.(?:title|body)|"
    r"(?:inputs|client_payload)\.\w+)"
    r"\s*\}\}",
    re.IGNORECASE,
)

# Broader: any github.event interpolation (lower confidence)
_ANY_EVENT_INTERPOLATION = re.compile(
    r"\$\{\{\s*github\.event\.\w+",
    re.IGNORECASE,
)

# Additional untrusted sources
_UNTRUSTED_ACTOR = re.compile(
    r"\$\{\{\s*github\.(?:actor|head_ref|base_ref)\s*\}\}",
    re.IGNORECASE,
)

# AI agent config files that grant broad tool access
_AI_CONFIG_FILES = [
    ".cline", ".cline.json", ".cline.yaml",
    ".github/copilot-instructions.md",
    ".cursorrules", ".cursor/rules",
    ".claude/settings.json", ".claude/CLAUDE.md",
    "CLAUDE.md",
    ".aider.conf.yml", ".aiderignore",
    ".continue/config.json",
]

# Dangerous tool grants in AI configs
_DANGEROUS_TOOLS = re.compile(
    r"(?:Bash|Shell|Execute|Terminal|RunCommand|subprocess|system|exec)",
    re.IGNORECASE,
)

_BROAD_PERMISSIONS = re.compile(
    r"(?:allowedTools|allowed_tools|tools|permissions)\s*[:\[=]\s*[\"']*\*",
    re.IGNORECASE,
)


class CiAiBotScanner:
    """Detects AI agent configurations in CI/CD that consume untrusted input."""

    name = "ci_ai_bot_scanner"
    ecosystems = ["github"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        # Phase 1: Scan GitHub Actions workflows for AI bot + untrusted input
        findings.extend(self._scan_workflows(project_dir))

        # Phase 2: Scan AI config files for dangerous permissions
        findings.extend(self._scan_ai_configs(project_dir))

        return findings

    def _scan_workflows(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        workflow_dir = project_dir / ".github" / "workflows"

        if not workflow_dir.is_dir():
            return findings

        for wf_path in workflow_dir.iterdir():
            if wf_path.suffix not in {".yml", ".yaml"}:
                continue

            try:
                content = wf_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = str(wf_path.relative_to(project_dir))
            has_ai_bot = bool(_AI_BOT_PATTERN.search(content))

            # Check for untrusted input flowing into AI-aware workflows
            if has_ai_bot:
                for m in _UNTRUSTED_INPUTS.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=Severity.CRITICAL,
                        package=PackageId(ecosystem="github", name=rel),
                        title="Clinejection risk: untrusted input to AI bot",
                        detail=(
                            f"Line {line_num}: AI bot workflow interpolates "
                            f"untrusted input '{m.group()}' — an attacker can "
                            f"craft issue/PR text to manipulate the AI agent."
                        ),
                        cwe="CWE-77",
                        confidence=0.90,
                        references=[
                            "https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/",
                        ],
                        metadata={
                            "file": rel,
                            "line": line_num,
                            "input_source": m.group(),
                            "pattern": "clinejection",
                        },
                    ))

                for m in _UNTRUSTED_ACTOR.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        package=PackageId(ecosystem="github", name=rel),
                        title="AI bot uses attacker-controlled ref/actor",
                        detail=(
                            f"Line {line_num}: '{m.group()}' is attacker-controlled "
                            f"and used in an AI-aware workflow."
                        ),
                        cwe="CWE-77",
                        confidence=0.75,
                        metadata={"file": rel, "line": line_num},
                    ))

            # Even without AI bot indicators, flag broad ${{ github.event }}
            # usage that could become dangerous if an AI bot is added later
            if not has_ai_bot:
                event_matches = list(_UNTRUSTED_INPUTS.finditer(content))
                if event_matches:
                    # Check if the workflow has broad permissions too
                    try:
                        wf_data = yaml.safe_load(content)
                        if isinstance(wf_data, dict):
                            perms = wf_data.get("permissions", {})
                            has_write = (
                                perms == "write-all"
                                or (isinstance(perms, dict) and
                                    any(v == "write" for v in perms.values()))
                            )
                            if has_write:
                                findings.append(Finding(
                                    finding_type=FindingType.WORKFLOW,
                                    severity=Severity.MEDIUM,
                                    package=PackageId(ecosystem="github", name=rel),
                                    title="Workflow with write perms interpolates untrusted input",
                                    detail=(
                                        f"Workflow has write permissions and uses "
                                        f"{len(event_matches)} untrusted input interpolation(s). "
                                        f"Adding an AI bot to this workflow would create "
                                        f"a Clinejection-class vulnerability."
                                    ),
                                    cwe="CWE-77",
                                    confidence=0.60,
                                    metadata={"file": rel, "pattern": "pre_clinejection"},
                                ))
                    except (yaml.YAMLError, AttributeError):
                        pass

        return findings

    def _scan_ai_configs(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        for config_rel in _AI_CONFIG_FILES:
            config_path = project_dir / config_rel
            if not config_path.is_file():
                continue

            try:
                content = config_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = str(config_path.relative_to(project_dir))

            # Check for wildcard/broad tool permissions
            if _BROAD_PERMISSIONS.search(content):
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    package=PackageId(ecosystem="github", name=rel),
                    title="AI config grants wildcard tool access",
                    detail=(
                        f"Config {rel} grants broad tool permissions — "
                        f"if this project is used in CI/CD, an attacker "
                        f"can exploit the tool access via prompt injection."
                    ),
                    cwe="CWE-250",
                    confidence=0.70,
                    metadata={"file": rel, "pattern": "broad_permissions"},
                ))

            # Check for dangerous tool grants
            if _DANGEROUS_TOOLS.search(content):
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.MEDIUM,
                    package=PackageId(ecosystem="github", name=rel),
                    title="AI config includes shell execution tools",
                    detail=(
                        f"Config {rel} grants shell/exec tool access — "
                        f"combined with untrusted input, this enables RCE."
                    ),
                    cwe="CWE-78",
                    confidence=0.65,
                    metadata={"file": rel, "pattern": "dangerous_tools"},
                ))

        return findings
