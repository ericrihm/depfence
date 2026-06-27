"""Claude Code PostToolUse hook: detect accidentally written secrets.

Fires AFTER Write/Edit/MultiEdit completes and scans the written content for
accidentally committed credentials. Because the write already happened this
hook can only emit ``systemMessage`` — no ``permissionDecision`` is valid here.

The message never includes the raw secret value, only a type label and a
redacted hint (e.g. ``AWS access key AKIAIOSF****MPLE``). Any full scan hits
are also forwarded to the depfence signal bus for fleet-wide observability.

Disable: ``DEPFENCE_SECRETS_LEAK=0``  (also accepts ``false`` / ``no`` / ``off``)
Signal bus: ``~/.depfence/signals/pending.jsonl``
"""

from __future__ import annotations

import json
import os
import re
import sys
import time as _time

_DISABLE = {"0", "false", "no", "off"}
_FILE_TOOLS = {"Write", "Edit", "MultiEdit"}

_SIGNAL_BUS_PENDING = os.environ.get(
    "DEPFENCE_SIGNAL_BUS", os.path.expanduser("~/.depfence/signals/pending.jsonl")
)

# ---------------------------------------------------------------------------
# Exempt file types — expected to hold secrets intentionally.
# ---------------------------------------------------------------------------
_SKIP_EXT = {".pem", ".key"}
_SKIP_BASENAME_RE = re.compile(r"^\.env(\..+)?$")


def _is_exempt(file_path: str) -> bool:
    """Return True for files that are expected to contain secrets by design."""
    basename = os.path.basename(file_path)
    _root, ext = os.path.splitext(basename)
    if ext.lower() in _SKIP_EXT:
        return True
    if _SKIP_BASENAME_RE.match(basename):
        return True
    return False


# ---------------------------------------------------------------------------
# Secret patterns — all inline, no depfence.scanners imports.
#
# Two categories:
#   _TOKEN_PATTERNS  — the entire regex match IS the secret; redact the whole match.
#   _KEYED_PATTERNS  — match captures a key name + value; only the value is redacted.
# ---------------------------------------------------------------------------

_TOKEN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key",               re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub personal access token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth token",           re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("GitHub Actions/app token",     re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained PAT",      re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("Stripe live secret key",       re.compile(r"sk_live_[A-Za-z0-9]{24,}")),
    ("Slack token",                  re.compile(r"xox[bpras]-[A-Za-z0-9-]{10,}")),
    ("Google API key",               re.compile(r"AIza[A-Za-z0-9_\-]{35}")),
]

# PEM private key block header — the header line itself is not sensitive.
_PEM_RE = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

# Keyed patterns: named group 'key' holds the variable/field name (safe to show),
# named group 'value' holds the secret (redacted).
_KEYED_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS secret access key", re.compile(
        r"(?i)(?P<key>aws_secret_access_key)\s*=\s*(?P<value>[A-Za-z0-9/+=]{40})"
    )),
    ("Generic API/secret key", re.compile(
        r"(?i)(?P<key>api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_\-]{20,})[\"']?"
    )),
]


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

def _redact(value: str, prefix: int = 8, suffix: int = 4) -> str:
    """Mask the middle of a secret value.

    Shows enough of the start and end to let the operator identify *which*
    credential this is, without exposing enough to use it.

    For values too short to split safely (≤ prefix + suffix chars) the entire
    value is replaced with ``****`` — in practice our patterns all have minimum
    match lengths well above this threshold.
    """
    if len(value) <= prefix + suffix:
        return "****"
    return value[:prefix] + "****" + value[-suffix:]


def _redact_keyed(key_name: str, value: str, suffix: int = 4) -> str:
    """Produce a redacted display for a key=value style secret."""
    if len(value) <= suffix:
        tail = ""
    else:
        tail = value[-suffix:]
    return f"{key_name}=****{tail}"


# ---------------------------------------------------------------------------
# Content extraction (mirrors pretooluse_hook._new_content)
# ---------------------------------------------------------------------------

def _new_content(tool_name: str, tool_input: dict) -> str:
    """Extract the text being written, using the correct field per tool."""
    if tool_name == "Write":
        return tool_input.get("content", "") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string", "") or ""
    if tool_name == "MultiEdit":
        return "\n".join(
            e.get("new_string", "") or "" for e in tool_input.get("edits", [])
        )
    return ""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _scan(content: str) -> list[str]:
    """Return a list of human-readable, redacted finding strings.

    The returned strings NEVER contain the raw secret value — only a label
    and a masked hint are included.
    """
    findings: list[tuple[str, str]] = []  # (label, redacted_display)
    seen: set[tuple[str, str]] = set()

    # Token patterns: whole match is the secret.
    for label, pattern in _TOKEN_PATTERNS:
        for m in pattern.finditer(content):
            raw = m.group(0)
            redacted = _redact(raw)
            key = (label, redacted)
            if key not in seen:
                seen.add(key)
                findings.append((label, redacted))

    # Private key PEM blocks.
    for m in _PEM_RE.finditer(content):
        key_type = (m.group(1) or "").strip() or "unknown type"
        label = f"Private key ({key_type})"
        display = "PEM block"
        key = (label, display)
        if key not in seen:
            seen.add(key)
            findings.append((label, display))

    # Keyed patterns: only the 'value' group is sensitive.
    for label, pattern in _KEYED_PATTERNS:
        for m in pattern.finditer(content):
            key_name = m.group("key")
            value = m.group("value")
            display = _redact_keyed(key_name, value)
            key = (label, display)
            if key not in seen:
                seen.add(key)
                findings.append((label, display))

    return [f"{label}: {display}" for label, display in findings]


# ---------------------------------------------------------------------------
# Signal bus
# ---------------------------------------------------------------------------

def _emit_signal(findings: list[str], file_path: str) -> None:
    """Best-effort write a depfence_secrets_leak signal to the signal bus."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(_SIGNAL_BUS_PENDING)), exist_ok=True)
        sig = json.dumps({
            "name": "depfence_secrets_leak",
            "value": {
                "findings": findings,
                "file": file_path,
                "count": len(findings),
            },
            "source": "depfence_secrets_leak_detector",
            "timestamp": _time.time(),
        })
        with open(_SIGNAL_BUS_PENDING, "a") as f:
            f.write(sig + "\n")
    except OSError:
        pass  # best-effort — a hook must never crash the tool call


# ---------------------------------------------------------------------------
# Hook entry point
# ---------------------------------------------------------------------------

def main(data: dict) -> dict:
    """Return the PostToolUse hook's JSON output.

    PostToolUse hooks may only emit ``systemMessage`` — ``permissionDecision``
    is not valid here because the tool has already executed.
    """
    if os.environ.get("DEPFENCE_SECRETS_LEAK", "1").lower() in _DISABLE:
        return {}

    tool_name = data.get("tool_name", "")
    if tool_name not in _FILE_TOOLS:
        return {}

    tool_input = data.get("tool_input", {}) or {}
    file_path = tool_input.get("file_path", "") or ""

    if _is_exempt(file_path):
        return {}

    content = _new_content(tool_name, tool_input)
    if not content:
        return {}

    findings = _scan(content)
    if not findings:
        return {}

    _emit_signal(findings, file_path)

    bullet_list = "\n  - ".join(findings)
    msg = (
        f"depfence secrets-leak: {len(findings)} potential secret(s) detected in {file_path or '(no path)'}:\n"
        f"  - {bullet_list}\n"
        "Rotate any exposed credentials immediately. "
        "If these are test/placeholder values, use non-secret-pattern names or move them to a .env file."
    )
    return {"systemMessage": msg}


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
