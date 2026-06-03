"""Claude Code PreToolUse hook: block agents from WRITING fabricated action SHAs.

This is the author-gate layer of "resolve-never-predict": when an agent (or human)
uses Write/Edit/MultiEdit to put a `uses: owner/repo@<40hex>` pin into a GitHub Actions
workflow, this hook resolves each NEW pin against GitHub and reacts to fabricated /
hallucinated SHAs (the exact failure that motivated depfence's resolve_existence
scanner) *before the edit lands*, rather than catching it later in CI.

Warn-first and reversible by design:
- Default: WARN only — emits a `systemMessage`, never a permission decision, so the
  edit proceeds and a human/agent can see the warning. (This is the documented way to
  surface info from PreToolUse without auto-approving: do NOT emit permissionDecision
  'allow' — that bypasses the normal permission flow.)
- ``DEPFENCE_PRETOOLUSE_BLOCK=1`` escalates to ``permissionDecision: deny`` so the write
  is refused and the reason is fed back to the agent to fix.
- ``DEPFENCE_PRETOOLUSE=0`` (or false/no/off) disables the hook entirely.

Self-contained: resolution goes through the ``gh`` CLI (already authenticated in the
fleet) so the hook does not need depfence importable in the hook's Python. Network /
auth failures degrade to an informational note and never block (fail-open). The hook
always exits 0; it influences the tool only via its JSON stdout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

_USES_PIN_RE = re.compile(
    r"""uses:\s*["']?
        (?P<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)
        (?:/[A-Za-z0-9._/-]+)?
        @(?P<sha>[0-9a-fA-F]{40})
    """,
    re.VERBOSE,
)
_WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")
_DISABLE = {"0", "false", "no", "off"}
_FILE_TOOLS = {"Write", "Edit", "MultiEdit"}


def _gh_api(path: str) -> tuple[int, str | None]:
    """Call `gh api <path>`. Returns (returncode, api_status_string_or_None).

    On an API error gh prints a JSON body with a "status" field (e.g. "422", "404");
    we parse that structured field rather than scanning for substrings.
    """
    try:
        r = subprocess.run(
            ["gh", "api", path], capture_output=True, text=True, timeout=8
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return (-1, None)
    if r.returncode == 0:
        return (0, "200")
    status = None
    for blob in (r.stdout, r.stderr):
        if not blob:
            continue
        try:
            status = str(json.loads(blob).get("status") or "") or status
        except (ValueError, TypeError):
            continue
    return (r.returncode, status)


def _resolve(repo: str, sha: str) -> str:
    """exists | fabricated_commit | fabricated_repo | unverified."""
    rc, status = _gh_api(f"repos/{repo}/commits/{sha}")
    if rc == 0:
        return "exists"
    if status == "422":
        return "fabricated_commit"
    if status == "404":
        rc2, status2 = _gh_api(f"repos/{repo}")
        if status2 == "404":
            return "fabricated_repo"
        if status2 in ("401", "403", "429") or rc2 == -1:
            return "unverified"
        return "fabricated_commit"
    if status in ("401", "403", "429") or rc == -1:
        return "unverified"
    return "unverified"


def _new_content(tool_name: str, tool_input: dict) -> str:
    """Extract the text being WRITTEN, using the correct field per tool."""
    if tool_name == "Write":
        return tool_input.get("content", "") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string", "") or ""
    if tool_name == "MultiEdit":
        return "\n".join(e.get("new_string", "") or "" for e in tool_input.get("edits", []))
    return ""


def main(data: dict) -> dict:
    """Return the hook's JSON output (empty dict = no-op, exit 0)."""
    if os.environ.get("DEPFENCE_PRETOOLUSE", "1").lower() in _DISABLE:
        return {}

    tool_name = data.get("tool_name", "")
    if tool_name not in _FILE_TOOLS:
        return {}

    tool_input = data.get("tool_input", {}) or {}
    file_path = tool_input.get("file_path", "") or ""
    if not _WORKFLOW_RE.search(file_path):
        return {}

    content = _new_content(tool_name, tool_input)
    pins = {(m.group("repo"), m.group("sha").lower()) for m in _USES_PIN_RE.finditer(content)}
    if not pins:
        return {}

    fabricated: list[str] = []
    unverified = 0
    for repo, sha in sorted(pins):
        kind = _resolve(repo, sha)
        if kind == "fabricated_commit":
            fabricated.append(f"{repo}@{sha[:10]} — no such commit (fabricated/typo'd/hallucinated)")
        elif kind == "fabricated_repo":
            fabricated.append(f"{repo}@{sha[:10]} — repository does not exist")
        elif kind == "unverified":
            unverified += 1

    if not fabricated:
        if unverified:
            return {"systemMessage": (
                f"depfence: could not verify {unverified} action pin(s) in {file_path} "
                "(gh unauth / rate-limited). Pin existence was NOT confirmed."
            )}
        return {}

    detail = (
        "depfence resolve-never-predict: this edit introduces GitHub Action pin(s) that "
        "do not resolve to a real commit:\n  - " + "\n  - ".join(fabricated)
        + "\nNever hand-write a SHA — emit a tag (e.g. @v4) and let `ratchet pin` resolve it."
    )

    if os.environ.get("DEPFENCE_PRETOOLUSE_BLOCK", "").lower() in ("1", "true", "yes", "on"):
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": detail,
        }}
    # Warn-only default: surface the message, do NOT emit a permission decision.
    return {"systemMessage": detail}


def _run() -> int:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    try:
        out = main(data)
    except Exception:  # noqa: BLE001 — a hook must never crash the tool call
        return 0
    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(_run())
