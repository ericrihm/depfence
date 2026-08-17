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

_EVENT_FILE = re.compile(r"(?:\$GITHUB_EVENT_PATH|github\.event_path)", re.IGNORECASE)
_ARTIFACT_DOWNLOAD = re.compile(r"actions/download-artifact|gh\s+run\s+download", re.IGNORECASE)
_RETRIEVAL_SOURCE = re.compile(
    r"(?:curl|wget|gh\s+api|vector|embed(?:ding)?|retriev|memory|tool[_ -]?output)",
    re.IGNORECASE,
)
_SECRET_OR_WRITE = re.compile(
    r"\$\{\{\s*secrets\.|permissions\s*:\s*(?:write-all|[^\n]*write)|id-token\s*:\s*write",
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

            # Correlate within a step/job. Mere co-occurrence in different,
            # unconnected steps is not a source-to-sink flow.
            if has_ai_bot:
                findings.extend(self._workflow_flows(content, rel))

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

    def _workflow_flows(self, content: str, rel: str) -> list[Finding]:
        """Find bounded source→AI-sink→capability paths inside workflow jobs."""
        try:
            workflow = yaml.safe_load(content)
        except yaml.YAMLError:
            return []
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            return []

        findings: list[Finding] = []
        workflow_permissions = workflow.get("permissions")
        for job_id, job in workflow["jobs"].items():
            if not isinstance(job, dict):
                continue
            artifact_available = False
            job_permissions = job.get("permissions", workflow_permissions)
            for index, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    continue
                step_text = "\n".join(_strings(step))
                if _ARTIFACT_DOWNLOAD.search(step_text):
                    artifact_available = True
                if not _AI_BOT_PATTERN.search(step_text):
                    continue

                sources = [match.group() for match in _UNTRUSTED_INPUTS.finditer(step_text)]
                sources += [match.group() for match in _UNTRUSTED_ACTOR.finditer(step_text)]
                sources += [match.group() for match in _EVENT_FILE.finditer(step_text)]
                if artifact_available and (
                    _ARTIFACT_DOWNLOAD.search(step_text)
                    or _RETRIEVAL_SOURCE.search(step_text)
                    or "run" in step
                    or "with" in step
                ):
                    sources.append("downloaded workflow artifact")
                if not sources:
                    continue

                capability = _capability(job_permissions, step_text)
                for source in dict.fromkeys(sources):
                    actor_only = bool(_UNTRUSTED_ACTOR.fullmatch(source))
                    severity = Severity.HIGH if actor_only and capability == "network" else Severity.CRITICAL
                    title = (
                        "AI bot uses attacker-controlled ref/actor"
                        if actor_only
                        else "Untrusted CI data flows into an AI agent"
                    )
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=severity,
                        package=PackageId(ecosystem="github", name=rel),
                        title=title,
                        detail=(
                            f"Job '{job_id}' step {index + 1} passes {source!r} to an AI sink "
                            f"with {capability} capability. Review the shortest source-to-sink path."
                        ),
                        cwe="CWE-77",
                        confidence=0.90 if severity == Severity.CRITICAL else 0.75,
                        references=[
                            "https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/",
                        ],
                        metadata={
                            "file": rel,
                            "job": str(job_id),
                            "step": index + 1,
                            "input_source": source,
                            "sink": "ai_agent",
                            "capability": capability,
                            "pattern": "source_sink_capability",
                        },
                    ))
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


def _strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _capability(permissions: object, step_text: str) -> str:
    if permissions == "write-all":
        return "repository-write"
    if isinstance(permissions, dict) and any(value == "write" for value in permissions.values()):
        return "repository-write"
    if _SECRET_OR_WRITE.search(step_text):
        return "secret-or-identity"
    if "run" in step_text.lower():
        return "shell"
    return "network"
