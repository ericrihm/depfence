"""Claude Code PreToolUse hook: intercept Bash install commands and typosquat-check packages.

Intercepts Bash tool calls that contain package install commands (pip, npm, yarn, pnpm,
cargo, go, gem, bundle, composer) and runs depfence's typosquat detector against each
extracted package name before the command executes.

Warn-first by design:
- Default: WARN only — emits a ``systemMessage``, never a permission decision.
- ``DEPFENCE_INSTALL_GATE_BLOCK=1`` escalates to ``permissionDecision: deny``.
- ``DEPFENCE_INSTALL_GATE=0`` (or false/no/off) disables the hook entirely.

Always exits 0 — never crashes the tool call.
Performance target: < 2ms for the fast path (non-Bash tool or no install keyword);
< 50ms for the full typosquat scan (no network calls).
"""

from __future__ import annotations

import json
import os
import re
import sys

from depfence.core.signal_bus import emit_signal

_DISABLE_VALUES = {"0", "false", "no", "off"}

# ---------------------------------------------------------------------------
# Fast pre-check: exit early when there is clearly no install invocation.
# Precompiled at module load so repeated calls pay only the re.search cost.
# ---------------------------------------------------------------------------

_FAST_RE = re.compile(
    r"\b(?:pip3?|npm|yarn|pnpm|cargo|gem|bundle|composer)\b"
    r"|python3?\s+-m\s+pip"
    r"|\bgo\s+(?:get|install)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Install command patterns
# Each entry: (compiled_regex, ecosystem_string).
# The named group ``args`` captures everything after the subcommand keyword,
# up to a shell command boundary (newline, semicolon, pipe, ampersand).
# ---------------------------------------------------------------------------

_INSTALL_RES: list[tuple[re.Pattern[str], str]] = [
    # pip / pip3 / python -m pip / python3 -m pip
    (
        re.compile(
            r"(?:pip3?|python3?\s+-m\s+pip)\s+install\s+(?P<args>[^\n;|&]+)",
            re.IGNORECASE,
        ),
        "pypi",
    ),
    # npm install <pkg> / npm i <pkg>  — NOT npm ci (ci matches neither install nor i)
    (
        re.compile(r"\bnpm\s+(?:install|i)\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "npm",
    ),
    # yarn add
    (
        re.compile(r"\byarn\s+add\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "npm",
    ),
    # pnpm add / pnpm install
    (
        re.compile(r"\bpnpm\s+(?:add|install)\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "npm",
    ),
    # cargo add / cargo install
    (
        re.compile(r"\bcargo\s+(?:add|install)\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "cargo",
    ),
    # go get / go install
    (
        re.compile(r"\bgo\s+(?:get|install)\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "go",
    ),
    # gem install
    (
        re.compile(r"\bgem\s+install\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "gem",
    ),
    # bundle add
    (
        re.compile(r"\bbundle\s+add\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "gem",
    ),
    # composer require
    (
        re.compile(r"\bcomposer\s+require\s+(?P<args>[^\n;|&]+)", re.IGNORECASE),
        "composer",
    ),
]

# Flags whose next token is a value, not a package name.
_FLAGS_CONSUMING_VALUE: frozenset[str] = frozenset({
    # pip
    "-r", "--requirement",
    "-c", "--constraint",
    "-t", "--target",
    "-e", "--editable",
    "-i", "--index-url",
    "--extra-index-url",
    "--trusted-host",
    "--prefix",
    "--root",
    "--install-option",
    "--global-option",
    # npm / pnpm
    "--workspace", "-w",
    # cargo
    "--version",
    # gem
    "--source",
    "--install-dir",
})


def _strip_version(token: str, ecosystem: str) -> str:
    """Strip a version specifier from *token*, returning the bare package name.

    Handles npm scoped packages (``@scope/name@version``) and standard
    specifiers (``requests>=2.0``, ``serde@1.0``, ``pkg[extra]``).
    """
    if ecosystem == "npm" and token.startswith("@"):
        # Scoped package: @scope/name  or  @scope/name@version
        rest = token[1:]  # drop leading @
        second_at = rest.find("@")
        if second_at != -1:
            return "@" + rest[:second_at]
        return token
    # General: everything up to the first version operator or bracket.
    # Allow `/` so that composer (`vendor/package`) and go module paths
    # (`github.com/user/repo`) are preserved intact.
    m = re.match(r"^([A-Za-z0-9][\w./\-]*)", token)
    return m.group(1) if m else token


def _extract_packages(args: str, ecosystem: str) -> list[str]:
    """Extract bare package names from the *args* string of an install command.

    Rules:
    - Flags (``-``-prefixed) are skipped; flags in ``_FLAGS_CONSUMING_VALUE``
      also consume the following token.
    - Local paths (``./``, ``../``, ``/``, bare ``.``/``..``) are skipped.
    - URLs and VCS references (``://``, ``file:``, ``git+``) are skipped.
    - Requirement files (``.txt``, ``.cfg``, ``.toml``) are skipped.
    - Version specifiers are stripped before returning.
    """
    tokens = args.split()
    packages: list[str] = []
    skip_next = False

    for token in tokens:
        if skip_next:
            skip_next = False
            continue

        if token.startswith("-"):
            if token in _FLAGS_CONSUMING_VALUE:
                skip_next = True
            continue

        # Local paths
        if token in (".", "..") or token.startswith("./") or token.startswith("../") or token.startswith("/"):
            continue

        # URLs / VCS references
        if "://" in token or token.startswith("file:") or token.startswith("git+"):
            continue

        # Bare requirement files accidentally given without the -r flag
        lower = token.lower()
        if lower.endswith(".txt") or lower.endswith(".cfg") or lower.endswith(".toml"):
            continue

        pkg = _strip_version(token, ecosystem)
        if pkg:
            packages.append(pkg)

    return packages


def _scan_command(command: str) -> list[tuple[str, str]]:
    """Return (package_name, ecosystem) pairs found in *command*.

    Runs all install patterns and extracts package names from each match.
    Duplicates within the same pattern are preserved here; deduplication
    happens in ``main`` before calling the typosquat detector.
    """
    results: list[tuple[str, str]] = []
    for pattern, ecosystem in _INSTALL_RES:
        for m in pattern.finditer(command):
            args = m.group("args").strip()
            for pkg in _extract_packages(args, ecosystem):
                results.append((pkg, ecosystem))
    return results


def _emit_signal(findings: list[dict]) -> str | None:
    """Write a bounded private signal and report degraded observability."""
    return emit_signal(
        name="depfence_typosquat_install",
        value={"findings": findings, "count": len(findings)},
        source="depfence_bash_install_gate",
    )


def main(data: dict) -> dict:
    """Return the hook's JSON output (empty dict = no-op, exit 0)."""
    # --- Env gate ---
    if os.environ.get("DEPFENCE_INSTALL_GATE", "1").lower() in _DISABLE_VALUES:
        return {}

    # --- Fast path: not a Bash tool call ---
    if data.get("tool_name") != "Bash":
        return {}

    tool_input = data.get("tool_input") or {}
    command = tool_input.get("command") or ""
    if not command:
        return {}

    # --- Fast pre-check: no install keywords at all → exit in < 2ms ---
    if not _FAST_RE.search(command):
        return {}

    # --- Full scan (still local-only, no network) ---
    try:
        from depfence.analyzers.typosquat_detector import check_against_popular
    except ImportError:
        return {}  # depfence not importable in this environment — fail open

    raw = _scan_command(command)
    if not raw:
        return {}

    # Deduplicate by (name_lower, ecosystem) before hitting the detector
    seen: set[tuple[str, str]] = set()
    flagged: list[dict] = []

    for pkg, ecosystem in raw:
        key = (pkg.lower(), ecosystem)
        if key in seen:
            continue
        seen.add(key)

        try:
            match = check_against_popular(pkg, ecosystem)
        except Exception:  # noqa: BLE001
            continue

        if match is not None and match.confidence > 0.5:
            flagged.append({
                "suspect": pkg,
                "target": match.target,
                "confidence": match.confidence,
                "attack_type": match.attack_type,
                "ecosystem": ecosystem,
            })

    if not flagged:
        return {}

    signal_error = _emit_signal(flagged)

    lines = [
        "depfence install-gate: possible typosquat package(s) detected in install command:"
    ]
    for f in flagged:
        lines.append(
            f"  - {f['suspect']!r} looks like a typosquat of {f['target']!r} "
            f"(confidence {f['confidence']:.0%}, attack: {f['attack_type']})"
        )
    lines.append("Verify the package name before installing.")
    if signal_error:
        lines.append(f"Local observability: {signal_error}.")
    detail = "\n".join(lines)

    if os.environ.get("DEPFENCE_INSTALL_GATE_BLOCK", "").lower() in ("1", "true", "yes", "on"):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": detail,
            }
        }

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
