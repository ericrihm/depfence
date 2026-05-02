"""GitHub Actions workflow YAML security scanner.

Detects insecure patterns directly in workflow YAML files:
1. Script injection   — ${{ github.event.* }} in run: blocks
2. Unpinned actions   — tag/branch refs instead of full SHA pins
3. Overly permissive  — write-all or missing permissions block
4. Secrets in logs    — echoing ${{ secrets.* }} in run: steps
5. pull_request_target with PR-head checkout (fork secrets leak)
6. Self-hosted runner usage (isolation risk)

This complements gha_scanner.py (which focuses on action dependency supply
chain) by analysing the workflow logic itself for misconfigurations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# Any ${{ github.event.* }} expression — user-controlled input
_INJECTION_RE = re.compile(
    r"\$\{\{\s*github\.event\."
    r"(?:issue\.(?:body|title)|pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|comment\.body|review\.body|review_comment\.body"
    r"|head_commit\.message|commits\[\d*\]\.message"
    r"|discussion\.body|discussion_comment\.body"
    r"|inputs\.[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\s*\}\}",
    re.IGNORECASE,
)

# Broader catch: any github.event.* not already matched (lower confidence)
_INJECTION_BROAD_RE = re.compile(
    r"\$\{\{\s*github\.event\.[a-zA-Z0-9_.[\]]+\s*\}\}",
    re.IGNORECASE,
)

# Secrets interpolated directly into a run: block
_SECRET_IN_RUN_RE = re.compile(
    r"\$\{\{\s*secrets\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}",
    re.IGNORECASE,
)

# echo / print commands followed by a secret expression on the same line
_SECRET_ECHO_RE = re.compile(
    r"(?:echo|printf|print|console\.log|::set-output|tee)\b[^\n]*"
    r"\$\{\{\s*secrets\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}",
    re.IGNORECASE,
)

# Full 40-char hex SHA
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# Triggers that indicate pull_request_target
_PRT_TRIGGER = "pull_request_target"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(workflow_path: Path) -> PackageId:
    return PackageId("github", workflow_path.name)


def _rel(workflow_path: Path) -> str:
    return str(workflow_path)


def _iter_jobs(workflow: dict[str, Any]):
    """Yield (job_id, job_dict) pairs."""
    for job_id, job in (workflow.get("jobs") or {}).items():
        if isinstance(job, dict):
            yield job_id, job


def _iter_steps(job: dict[str, Any]):
    """Yield step dicts from a job."""
    for step in job.get("steps") or []:
        if isinstance(step, dict):
            yield step


def _iter_run_blocks(workflow: dict[str, Any]):
    """Yield (job_id, step, run_text) for every run: step."""
    for job_id, job in _iter_jobs(workflow):
        for step in _iter_steps(job):
            run = step.get("run")
            if isinstance(run, str) and run.strip():
                yield job_id, step, run


def _is_sha_pinned(ref: str) -> bool:
    return bool(_SHA_RE.match(ref))


def _is_official_action(owner_repo: str) -> bool:
    return owner_repo.split("/")[0].lower() in ("actions", "github")


def _parse_uses(uses: str) -> tuple[str, str]:
    """Return (owner_repo, ref). ref is empty string if missing."""
    if "@" not in uses:
        return uses.strip(), ""
    owner_repo, _, ref = uses.partition("@")
    return owner_repo.strip(), ref.strip()


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_script_injection(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for job_id, step, run in _iter_run_blocks(workflow):
        matches_specific = _INJECTION_RE.findall(run)
        if matches_specific:
            key = (job_id, run[:80])
            if key in seen:
                continue
            seen.add(key)
            snippet = run[:400].replace("\n", " ")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.CRITICAL,
                package=pkg,
                title=f"Script injection via github.event in run: step [{workflow_path}]",
                detail=(
                    f"User-controlled expression(s) interpolated directly into a shell run: "
                    f"block in job '{job_id}'. An attacker who controls issue/PR content can "
                    f"execute arbitrary shell commands in CI.\n"
                    f"Matched: {', '.join(set(matches_specific))}\n"
                    f"Snippet: {snippet}"
                ),
                cwe="CWE-77",
                references=[
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                    "https://securitylab.github.com/research/github-actions-untrusted-input/",
                ],
                confidence=0.95,
                metadata={
                    "workflow": workflow_path,
                    "job": job_id,
                    "matched_expressions": list(set(matches_specific)),
                },
            ))
            continue

        # Lower-confidence broad catch for other github.event.* fields
        matches_broad = _INJECTION_BROAD_RE.findall(run)
        if matches_broad:
            key = (job_id, run[:80])
            if key in seen:
                continue
            seen.add(key)
            snippet = run[:400].replace("\n", " ")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg,
                title=f"Possible script injection via github.event in run: step [{workflow_path}]",
                detail=(
                    f"Unrecognised github.event.* expression(s) interpolated into a run: block "
                    f"in job '{job_id}'. Review whether these fields are user-controlled.\n"
                    f"Matched: {', '.join(set(matches_broad))}\n"
                    f"Snippet: {snippet}"
                ),
                cwe="CWE-77",
                references=[
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                ],
                confidence=0.65,
                metadata={
                    "workflow": workflow_path,
                    "job": job_id,
                    "matched_expressions": list(set(matches_broad)),
                },
            ))

    return findings


def _check_unpinned_actions(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for job_id, job in _iter_jobs(workflow):
        # Collect uses from steps and job-level (reusable workflows)
        candidates: list[str] = []
        for step in _iter_steps(job):
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                candidates.append(uses.strip())
        job_uses = job.get("uses")
        if isinstance(job_uses, str) and job_uses.strip():
            candidates.append(job_uses.strip())

        for uses in candidates:
            # Skip local path refs and Docker actions
            if uses.startswith(".") or uses.startswith("docker://"):
                continue

            owner_repo, ref = _parse_uses(uses)

            if not ref:
                # No ref at all
                severity = Severity.MEDIUM if _is_official_action(owner_repo) else Severity.HIGH
                findings.append(Finding(
                    finding_type=FindingType.PROVENANCE,
                    severity=severity,
                    package=PackageId("gha", owner_repo),
                    title=f"Action used without any version pin: {uses} [{workflow_path}]",
                    detail=(
                        f"Job '{job_id}' uses '{uses}' with no version ref. "
                        "Pin to a full commit SHA for reproducible, tamper-resistant builds."
                    ),
                    references=[
                        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                    ],
                    confidence=1.0,
                    metadata={"workflow": workflow_path, "job": job_id, "uses": uses},
                ))
                continue

            if _is_sha_pinned(ref):
                # Properly pinned — no finding
                continue

            # Has a tag or branch ref (mutable)
            is_official = _is_official_action(owner_repo)
            severity = Severity.MEDIUM if is_official else Severity.HIGH
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=severity,
                package=PackageId("gha", owner_repo, ref),
                title=f"Unpinned action ref (mutable tag/branch): {uses} [{workflow_path}]",
                detail=(
                    f"Job '{job_id}' uses '{uses}' pinned to mutable ref '{ref}'. "
                    "A compromised upstream can push malicious code to this ref and "
                    "inject it silently into your CI. "
                    "Pin to a full 40-character commit SHA instead "
                    "(e.g. uses: {owner_repo}@<sha>  # {ref}).".format(owner_repo=owner_repo, ref=ref)
                ),
                references=[
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                    "https://blog.pwnedlabs.io/github-actions-security/",
                ],
                confidence=0.95,
                metadata={"workflow": workflow_path, "job": job_id, "uses": uses, "ref": ref},
            ))

    return findings


def _check_permissions(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    top_perms = workflow.get("permissions")

    # Missing permissions block at top-level — defaults to write in many repos
    if top_perms is None:
        # Only flag if the workflow has on: triggers (i.e. is a real workflow, not a reusable)
        on_block = workflow.get("on") or workflow.get(True)  # YAML parses 'on' as True
        if on_block:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"No top-level permissions block [{workflow_path}]",
                detail=(
                    "Workflow lacks an explicit 'permissions:' block. "
                    "Depending on repository settings, GITHUB_TOKEN may default to "
                    "write access for all scopes. "
                    "Add 'permissions: read-all' at the top level and grant only the "
                    "minimum required write scopes per job."
                ),
                references=[
                    "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
                    "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions",
                ],
                confidence=0.8,
                metadata={"workflow": workflow_path, "permissions": None},
            ))
        return findings

    # write-all shorthand
    if isinstance(top_perms, str) and top_perms == "write-all":
        findings.append(Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.HIGH,
            package=pkg,
            title=f"Overly permissive: permissions: write-all [{workflow_path}]",
            detail=(
                "'permissions: write-all' grants the GITHUB_TOKEN full write access to "
                "all repository scopes. If a step runs malicious code (e.g. via a "
                "compromised action), it can push commits, modify releases, or exfiltrate data. "
                "Replace with explicit minimal scopes."
            ),
            references=[
                "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
            ],
            confidence=1.0,
            metadata={"workflow": workflow_path, "permissions": "write-all"},
        ))
        return findings

    # Granular write permissions — flag high-impact scopes
    if isinstance(top_perms, dict):
        _DANGEROUS_WRITE_SCOPES = {
            "contents": "push commits / create releases / delete branches",
            "packages": "publish or delete packages",
            "deployments": "create or delete deployments",
            "actions": "manage workflow runs and artifacts",
            "pull-requests": "approve or merge pull requests",
            "id-token": "request OIDC JWT tokens for cloud authentication",
        }
        for scope, description in _DANGEROUS_WRITE_SCOPES.items():
            if top_perms.get(scope) == "write":
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.MEDIUM,
                    package=pkg,
                    title=f"Broad write permission: {scope}: write [{workflow_path}]",
                    detail=(
                        f"The top-level permissions block grants write access to '{scope}' "
                        f"({description}). Ensure this is intentional and scoped to only "
                        "the jobs that require it."
                    ),
                    references=[
                        "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
                    ],
                    confidence=0.8,
                    metadata={"workflow": workflow_path, "scope": scope, "level": "write"},
                ))

    return findings


def _check_secrets_in_logs(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for job_id, step, run in _iter_run_blocks(workflow):
        # Direct echo/print of secret expression
        echo_matches = _SECRET_ECHO_RE.findall(run)
        if echo_matches:
            snippet = run[:400].replace("\n", " ")
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg,
                title=f"Secret value echoed to logs in job '{job_id}' [{workflow_path}]",
                detail=(
                    "A run: step appears to echo or print a ${{ secrets.* }} expression "
                    "directly to stdout, which will appear in CI logs and may persist in "
                    "log archives. Use GitHub's secret masking carefully and avoid printing "
                    "secret values at all.\n"
                    f"Snippet: {snippet}"
                ),
                cwe="CWE-532",
                references=[
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
                ],
                confidence=0.85,
                metadata={"workflow": workflow_path, "job": job_id},
            ))
            continue

        # Secret expression present in run block but not via echo — lower confidence
        secret_matches = _SECRET_IN_RUN_RE.findall(run)
        if secret_matches:
            # Acceptable usage: assigning to env var or using as arg is fine.
            # Flag only if the pattern looks like it's being embedded in a string
            # that would print it (heuristic: preceded by an echo-like command anywhere
            # in the block, or on a line that starts with echo/printf).
            for line in run.splitlines():
                line_stripped = line.strip()
                if _SECRET_ECHO_RE.search(line_stripped):
                    snippet = line_stripped[:300]
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH,
                        package=pkg,
                        title=f"Secret value may be printed in job '{job_id}' [{workflow_path}]",
                        detail=(
                            "A line in a run: block appears to output a ${{ secrets.* }} value "
                            "directly. GitHub automatically masks known secret values but this "
                            "is not reliable for derived or transformed values.\n"
                            f"Line: {snippet}"
                        ),
                        cwe="CWE-532",
                        references=[
                            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets",
                        ],
                        confidence=0.75,
                        metadata={"workflow": workflow_path, "job": job_id},
                    ))
                    break

    return findings


def _check_pull_request_target(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    """Detect pull_request_target + checkout of the PR head — allows fork PRs to access secrets."""
    findings: list[Finding] = []

    # Check if workflow is triggered by pull_request_target
    on_block = workflow.get("on") or workflow.get(True)
    if not on_block:
        return findings

    triggered_by_prt = False
    if isinstance(on_block, str):
        triggered_by_prt = on_block == _PRT_TRIGGER
    elif isinstance(on_block, list):
        triggered_by_prt = _PRT_TRIGGER in on_block
    elif isinstance(on_block, dict):
        triggered_by_prt = _PRT_TRIGGER in on_block

    if not triggered_by_prt:
        return findings

    # Look for checkout of the PR head ref
    _HEAD_REF_RE = re.compile(
        r"github\.event\.pull_request\.head\.(sha|ref)\b",
        re.IGNORECASE,
    )

    for job_id, job in _iter_jobs(workflow):
        for step in _iter_steps(job):
            uses = step.get("uses", "") or ""
            with_block = step.get("with") or {}

            # Detect actions/checkout with ref pointing to PR head
            is_checkout = "actions/checkout" in uses
            if not is_checkout:
                continue

            ref_val = str(with_block.get("ref", ""))
            if _HEAD_REF_RE.search(ref_val):
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=(
                        f"pull_request_target + PR head checkout in job '{job_id}' "
                        f"[{workflow_path}] — allows fork PRs to access secrets"
                    ),
                    detail=(
                        "The workflow is triggered by 'pull_request_target' (which runs in the "
                        "context of the base repo and has access to secrets) and checks out the "
                        "PR head commit. An attacker can send a fork PR containing malicious "
                        "workflow modifications that execute with full secret access.\n"
                        f"Checkout ref: {ref_val}"
                    ),
                    cwe="CWE-829",
                    references=[
                        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                    ],
                    confidence=0.95,
                    metadata={
                        "workflow": workflow_path,
                        "job": job_id,
                        "trigger": _PRT_TRIGGER,
                        "checkout_ref": ref_val,
                    },
                ))

    # Also flag pull_request_target without any checkout as a lower-confidence advisory
    if not findings:
        findings.append(Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.MEDIUM,
            package=pkg,
            title=f"Workflow uses pull_request_target trigger [{workflow_path}]",
            detail=(
                "The 'pull_request_target' trigger runs in the base repo's context with "
                "access to secrets. This is safe only if the workflow never checks out or "
                "executes code from the fork. Carefully review all steps to ensure no "
                "untrusted code is executed."
            ),
            references=[
                "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            ],
            confidence=0.7,
            metadata={"workflow": workflow_path, "trigger": _PRT_TRIGGER},
        ))

    return findings


def _check_self_hosted_runners(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []

    for job_id, job in _iter_jobs(workflow):
        runs_on = job.get("runs-on")
        if runs_on is None:
            continue

        # runs-on can be a string, list, or dict (group/labels format)
        is_self_hosted = False
        runner_value: Any = runs_on

        if isinstance(runs_on, str):
            is_self_hosted = "self-hosted" in runs_on.lower()
        elif isinstance(runs_on, list):
            is_self_hosted = any(
                isinstance(r, str) and "self-hosted" in r.lower() for r in runs_on
            )
        elif isinstance(runs_on, dict):
            # GitHub new group/labels syntax
            labels = runs_on.get("labels") or []
            if isinstance(labels, list):
                is_self_hosted = any(
                    isinstance(l, str) and "self-hosted" in l.lower() for l in labels
                )
            elif isinstance(labels, str):
                is_self_hosted = "self-hosted" in labels.lower()

        if is_self_hosted:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Self-hosted runner in job '{job_id}' [{workflow_path}]",
                detail=(
                    f"Job '{job_id}' uses a self-hosted runner (runs-on: {runner_value}). "
                    "Self-hosted runners persist state between runs and may be accessible to "
                    "fork pull requests. Risks include:\n"
                    "• Environment poisoning across runs (lingering files, env vars, processes)\n"
                    "• Fork PRs executing code on internal infrastructure if 'pull_request' "
                    "  trigger is used without restrictions\n"
                    "• Lateral movement to other internal services reachable from the runner\n"
                    "Mitigations: use ephemeral runners, restrict to trusted contributors, "
                    "enable 'Require approval for all outside collaborators'."
                ),
                references=[
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
                    "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
                ],
                confidence=0.9,
                metadata={
                    "workflow": workflow_path,
                    "job": job_id,
                    "runs_on": str(runner_value),
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class GhaWorkflowScanner:
    """Scan GitHub Actions workflow YAML files for security misconfigurations."""

    name = "gha_workflow_scanner"
    ecosystems = ["github"]

    async def scan(self, packages: list) -> list[Finding]:  # type: ignore[type-arg]
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Find .github/workflows/*.yml|yaml and analyse each for insecure patterns."""
        findings: list[Finding] = []
        workflows_dir = project_dir / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return findings

        workflow_files = sorted(
            list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        )
        for workflow_file in workflow_files:
            findings.extend(self._scan_workflow(workflow_file))

        return findings

    def _scan_workflow(self, workflow_path: Path) -> list[Finding]:
        try:
            text = workflow_path.read_text(encoding="utf-8", errors="replace")
            workflow: dict[str, Any] = yaml.safe_load(text) or {}
        except (yaml.YAMLError, OSError):
            return []

        if not isinstance(workflow, dict):
            return []

        pkg = _pkg(workflow_path)
        rel = _rel(workflow_path)
        findings: list[Finding] = []

        findings.extend(_check_script_injection(workflow, pkg, rel))
        findings.extend(_check_unpinned_actions(workflow, pkg, rel))
        findings.extend(_check_permissions(workflow, pkg, rel))
        findings.extend(_check_secrets_in_logs(workflow, pkg, rel))
        findings.extend(_check_pull_request_target(workflow, pkg, rel))
        findings.extend(_check_self_hosted_runners(workflow, pkg, rel))

        return findings
