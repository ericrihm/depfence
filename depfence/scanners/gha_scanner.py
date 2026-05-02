"""GitHub Actions workflow security scanner.

Detects supply chain risks in .github/workflows/*.yml:
unpinned action refs, known-compromised actions, script injection,
and excessive permissions.

The tj-actions/changed-files incident (March 2025) compromised 23,000+
repos — no existing Python dep scanner catches this class of risk.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from depfence.core.models import Finding, FindingType, PackageId, Severity

# Actions with confirmed supply chain compromises
_KNOWN_COMPROMISED: dict[str, str] = {
    "tj-actions/changed-files": "Compromised March 2025; malicious commit injected secrets exfiltration into 23,000+ repos.",
    "reviewdog/action-setup": "Compromised; malicious tag pushed to steal CI secrets.",
    "codecov/codecov-action": "Compromised 2024; supply chain attack via tampered uploader script.",
}

# Known-bad commit SHAs (add as incidents are discovered)
_KNOWN_BAD_SHAS: set[str] = {
    # tj-actions/changed-files malicious commit
    "0e58b082a0b29f1e77f58c0b987ae24e3f9d39a1",
}

# Regex for a full 40-char SHA pin
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# User-controlled GitHub event properties that enable script injection
_INJECTION_SOURCES = re.compile(
    r"\$\{\{\s*github\.event\."
    r"(issue\.body|issue\.title|pull_request\.title|pull_request\.body"
    r"|comment\.body|review\.body|review_comment\.body"
    r"|head_commit\.message|commits\[\d*\]\.message"
    r"|discussion\.body|discussion_comment\.body"
    r"|inputs\.[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\s*\}\}",
    re.IGNORECASE,
)


def _parse_action_ref(uses: str) -> tuple[str, str, str]:
    """Return (owner_repo, ref, full_uses). ref is the part after '@'."""
    if "@" not in uses:
        return uses, "", uses
    owner_repo, _, ref = uses.partition("@")
    return owner_repo.strip(), ref.strip(), uses


def _is_sha_pinned(ref: str) -> bool:
    return bool(_SHA_RE.match(ref))


def _is_official(owner_repo: str) -> bool:
    owner = owner_repo.split("/")[0].lower()
    return owner == "actions"


def _walk_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return job.get("steps") or []


def _collect_run_blocks(workflow: dict[str, Any]) -> list[str]:
    blocks: list[str] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in _walk_steps(job):
            run = step.get("run")
            if isinstance(run, str):
                blocks.append(run)
    return blocks


def _collect_uses(workflow: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in _walk_steps(job):
            uses = step.get("uses")
            if isinstance(uses, str) and uses.strip():
                refs.append(uses.strip())
        # reusable workflow call at job level
        uses = job.get("uses")
        if isinstance(uses, str) and uses.strip():
            refs.append(uses.strip())
    return refs


def _permissions_findings(
    workflow: dict[str, Any], pkg: PackageId, workflow_path: str
) -> list[Finding]:
    findings: list[Finding] = []
    perms = workflow.get("permissions")
    if perms is None:
        return findings

    flagged = False
    if isinstance(perms, str) and perms in ("write-all", "read-all"):
        if perms == "write-all":
            flagged = True
    elif isinstance(perms, dict):
        for scope, level in perms.items():
            if level == "write" and scope in ("contents", "packages", "deployments", "actions"):
                flagged = True
                break

    if flagged:
        findings.append(Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.MEDIUM,
            package=pkg,
            title=f"Workflow has broad write permissions: {workflow_path}",
            detail=(
                f"Permissions '{perms}' grant broad write access. "
                "Prefer minimal scopes and explicit per-job permission blocks."
            ),
            references=["https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"],
            confidence=0.8,
            metadata={"workflow": workflow_path, "permissions": str(perms)},
        ))
    return findings


class GhaScanner:
    name = "gha_scanner"
    ecosystems = ["gha"]

    async def scan(self, packages: list) -> list[Finding]:  # type: ignore[type-arg]
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        workflows_dir = project_dir / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return findings

        for workflow_file in sorted(workflows_dir.glob("*.yml")):
            findings.extend(self._scan_workflow(workflow_file))
        for workflow_file in sorted(workflows_dir.glob("*.yaml")):
            findings.extend(self._scan_workflow(workflow_file))

        return findings

    def _scan_workflow(self, workflow_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            workflow: dict[str, Any] = yaml.safe_load(workflow_path.read_text()) or {}
        except (yaml.YAMLError, OSError):
            return findings

        rel = str(workflow_path)
        pkg = PackageId("gha", workflow_path.name)

        findings.extend(_permissions_findings(workflow, pkg, rel))
        findings.extend(self._check_uses(workflow, pkg, rel))
        findings.extend(self._check_injection(workflow, pkg, rel))

        return findings

    def _check_uses(
        self, workflow: dict[str, Any], pkg: PackageId, workflow_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for uses in _collect_uses(workflow):
            owner_repo, ref, full_uses = _parse_action_ref(uses)

            # Skip local path actions and Docker actions
            if owner_repo.startswith(".") or owner_repo.startswith("docker://"):
                continue

            action_pkg = PackageId("gha", owner_repo, ref or None)

            # Known-compromised check (highest priority)
            if owner_repo in _KNOWN_COMPROMISED:
                findings.append(Finding(
                    finding_type=FindingType.KNOWN_VULN,
                    severity=Severity.CRITICAL,
                    package=action_pkg,
                    title=f"Known-compromised action: {owner_repo}",
                    detail=_KNOWN_COMPROMISED[owner_repo],
                    references=[
                        "https://github.com/advisories",
                        f"https://github.com/{owner_repo}",
                    ],
                    confidence=1.0,
                    metadata={"workflow": workflow_path, "uses": full_uses},
                ))
                continue

            # Known-bad SHA check
            if ref and ref in _KNOWN_BAD_SHAS:
                findings.append(Finding(
                    finding_type=FindingType.KNOWN_VULN,
                    severity=Severity.CRITICAL,
                    package=action_pkg,
                    title=f"Action pinned to known-malicious SHA: {full_uses}",
                    detail=f"SHA {ref} is associated with a confirmed supply chain compromise.",
                    confidence=1.0,
                    metadata={"workflow": workflow_path, "uses": full_uses, "sha": ref},
                ))
                continue

            sha_pinned = _is_sha_pinned(ref)

            if sha_pinned:
                # SHA-pinned: clean, no finding
                continue

            if not ref:
                # No ref at all — treat like unpinned tag
                if _is_official(owner_repo):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        package=action_pkg,
                        title=f"Unpinned official action (no ref): {owner_repo}",
                        detail=(
                            f"Action '{full_uses}' has no version pin. "
                            "Pin to a full commit SHA for reproducibility."
                        ),
                        confidence=0.9,
                        metadata={"workflow": workflow_path, "uses": full_uses},
                    ))
                else:
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.HIGH,
                        package=action_pkg,
                        title=f"Third-party action without SHA pin: {owner_repo}",
                        detail=(
                            f"Third-party action '{full_uses}' has no SHA pin. "
                            "Mutable tags can be silently overwritten in a supply chain attack."
                        ),
                        references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
                        confidence=0.9,
                        metadata={"workflow": workflow_path, "uses": full_uses},
                    ))
                continue

            # Has a tag/branch ref but not a SHA
            if _is_official(owner_repo):
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.MEDIUM,
                    package=action_pkg,
                    title=f"Unpinned official action: {full_uses}",
                    detail=(
                        f"Action '{full_uses}' is pinned to a mutable tag '{ref}'. "
                        "Pin to a full commit SHA (e.g. actions/checkout@<sha> # v4) for supply chain safety."
                    ),
                    confidence=0.85,
                    metadata={"workflow": workflow_path, "uses": full_uses, "ref": ref},
                ))
            else:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=action_pkg,
                    title=f"Third-party action without SHA pin: {full_uses}",
                    detail=(
                        f"Third-party action '{full_uses}' is pinned to mutable ref '{ref}'. "
                        "Any push to that tag can silently inject malicious code into your CI. "
                        "Pin to a full commit SHA."
                    ),
                    references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
                    confidence=0.9,
                    metadata={"workflow": workflow_path, "uses": full_uses, "ref": ref},
                ))

        return findings

    def _check_injection(
        self, workflow: dict[str, Any], pkg: PackageId, workflow_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for run_block in _collect_run_blocks(workflow):
            matches = _INJECTION_SOURCES.findall(run_block)
            if matches:
                snippet = run_block[:300].replace("\n", " ")
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"Script injection risk in workflow: {workflow_path}",
                    detail=(
                        f"User-controlled input ({', '.join(matches)}) interpolated directly "
                        f"into a run: step. An attacker controlling issue/PR content can execute "
                        f"arbitrary commands. Use an intermediate env var instead.\n"
                        f"Snippet: {snippet}"
                    ),
                    references=[
                        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
                        "https://securitylab.github.com/research/github-actions-untrusted-input/",
                    ],
                    confidence=0.95,
                    metadata={"workflow": workflow_path, "matched_inputs": matches},
                ))

        return findings
