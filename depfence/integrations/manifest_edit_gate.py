"""Claude Code PreToolUse hook: intercept manifest edits and check for typosquat packages.

When an agent or human uses Write/Edit/MultiEdit to add packages to a dependency
manifest, this hook checks newly-added package names against the typosquat detector
*before the edit lands* — catching malicious package substitutions at author time.

Warn-first and reversible by design:
- Default: WARN only — emits a ``systemMessage`` without a permissionDecision, so
  the edit proceeds and the agent/human sees the warning.  (Do NOT emit
  permissionDecision 'allow' — that bypasses the normal permission flow.)
- ``DEPFENCE_MANIFEST_GATE_BLOCK=1`` escalates to ``permissionDecision: deny`` so the
  write is refused and the reason is fed back to the agent to fix.
- ``DEPFENCE_MANIFEST_GATE=0`` (or false/no/off) disables the hook entirely.

Self-contained: all detection is offline (no network calls).  Typosquat checking
uses the embedded popular-package lists in depfence.analyzers.typosquat_detector.
The hook always exits 0; it influences the tool only via its JSON stdout.

Performance guarantee: the manifest basename check is O(1) dict lookup so non-
matching files exit in < 1 ms without importing the typosquat detector.
"""

from __future__ import annotations

import json
import os
import re
import sys

from depfence.core.signal_bus import emit_signal

_DISABLE = {"0", "false", "no", "off"}
_BLOCK_VALUES = {"1", "true", "yes", "on"}
_FILE_TOOLS = {"Write", "Edit", "MultiEdit"}

# Flag matches above this confidence threshold.
# check_against_popular internally filters at > 0.7, so this is a belt-and-
# suspenders guard for any future callers with lower-confidence matches.
_CONFIDENCE_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Package extraction — one function per manifest format
# ---------------------------------------------------------------------------

# package.json: non-package top-level keys to skip
_NPM_SKIP_KEYS = frozenset({
    "name", "version", "description", "license", "author", "main", "module",
    "types", "typings", "browser", "bin", "files", "keywords", "private",
    "homepage", "bugs", "repository", "funding", "engines", "os", "cpu",
    "scripts", "workspaces", "publishConfig", "man", "directories",
    "contributors", "maintainers",
})

# Match: "package-name": "^1.2.3"  /  "^1.0"  /  "*"  /  ">=2.0"
_NPM_DEP_RE = re.compile(
    r'"(@?[a-zA-Z0-9][a-zA-Z0-9._\-/@]*)"\s*:\s*"[\^~>=<\*\d]'
)


def _extract_npm(content: str) -> list[str]:
    """Extract bare package names from package.json content or a snippet."""
    names: list[str] = []
    for m in _NPM_DEP_RE.finditer(content):
        raw = m.group(1)
        # For scoped packages like @babel/core, check the package portion
        bare = raw.split("/")[-1] if "/" in raw else raw
        if bare.lower() not in _NPM_SKIP_KEYS and raw.lower() not in _NPM_SKIP_KEYS:
            names.append(bare)
    return names


def _extract_requirements(content: str) -> list[str]:
    """Extract package names from requirements.txt content or snippet.

    Skips comment lines (#), flag lines (-r, -i, -e, --index-url, …), and
    VCS/URL references (contain ://).
    """
    names: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-") or "://" in line:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            names.append(m.group(1))
    return names


# pyproject.toml dependency section headers
_PYPROJECT_SECTION_RE = re.compile(
    r"^\[(?:project\.dependencies|tool\.poetry\.dependencies)\]",
    re.MULTILINE,
)
# First word on each line inside a dependency section
_PYPROJECT_DEP_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", re.MULTILINE)


def _extract_pyproject(content: str) -> list[str]:
    """Extract package names from pyproject.toml dependency sections.

    Falls back to scanning all name-like lines when no section header is
    present (e.g. Edit supplying just the new dependency lines).
    """
    names: list[str] = []
    found_section = False
    for sec_m in _PYPROJECT_SECTION_RE.finditer(content):
        found_section = True
        start = sec_m.end()
        next_sec = re.search(r"^\[", content[start:], re.MULTILINE)
        end = start + next_sec.start() if next_sec else len(content)
        for dep_m in _PYPROJECT_DEP_RE.finditer(content[start:end]):
            name = dep_m.group(1)
            if name.lower() != "python":
                names.append(name)
    if not found_section:
        # Partial edit: treat every leading name-like token as a candidate
        for dep_m in _PYPROJECT_DEP_RE.finditer(content):
            name = dep_m.group(1)
            if name.lower() != "python":
                names.append(name)
    return names


# Cargo.toml dependency section headers ([dependencies] or [dev-dependencies])
_CARGO_SECTION_RE = re.compile(r"^\[(?:dev-)?dependencies\]", re.MULTILINE)
# crate-name = ...
_CARGO_DEP_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9_-]*)\s*=", re.MULTILINE)


def _extract_cargo(content: str) -> list[str]:
    """Extract crate names from Cargo.toml dependency sections.

    Falls back to scanning all name = ... lines when no section header is
    present (e.g. Edit supplying just the new dependency lines).
    """
    names: list[str] = []
    found_section = False
    for sec_m in _CARGO_SECTION_RE.finditer(content):
        found_section = True
        start = sec_m.end()
        next_sec = re.search(r"^\[", content[start:], re.MULTILINE)
        end = start + next_sec.start() if next_sec else len(content)
        for dep_m in _CARGO_DEP_RE.finditer(content[start:end]):
            names.append(dep_m.group(1))
    if not found_section:
        for dep_m in _CARGO_DEP_RE.finditer(content):
            names.append(dep_m.group(1))
    return names


# go.mod block require ( ... ) and single-line require module v...
_GOMOD_BLOCK_RE = re.compile(r"require\s*\(([^)]*)\)", re.DOTALL)
_GOMOD_INLINE_RE = re.compile(r"^require\s+(\S+)", re.MULTILINE)
_GOMOD_MODULE_LINE_RE = re.compile(r"^\s*(\S+)\s+v", re.MULTILINE)


def _extract_gomod(content: str) -> list[str]:
    """Extract the last path component of each module path in go.mod."""
    names: list[str] = []
    for block_m in _GOMOD_BLOCK_RE.finditer(content):
        for dep_m in _GOMOD_MODULE_LINE_RE.finditer(block_m.group(1)):
            names.append(dep_m.group(1).split("/")[-1])
    for line_m in _GOMOD_INLINE_RE.finditer(content):
        names.append(line_m.group(1).split("/")[-1])
    return names


# Gemfile: gem "name" or gem 'name'
_GEMFILE_GEM_RE = re.compile(r"""gem\s+['"]([^'"]+)['"]""")


def _extract_gemfile(content: str) -> list[str]:
    return [m.group(1) for m in _GEMFILE_GEM_RE.finditer(content)]


# composer.json: "vendor/package": "^version"
_COMPOSER_DEP_RE = re.compile(
    r'"([a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+)"\s*:\s*"[^\d"]*[\d^~>=<\*]'
)
_COMPOSER_SKIP = frozenset({"php", "ext-json", "ext-mbstring", "ext-curl", "ext-pdo"})


def _extract_composer(content: str) -> list[str]:
    """Extract the package portion of vendor/package entries in composer.json."""
    names: list[str] = []
    for m in _COMPOSER_DEP_RE.finditer(content):
        vendor_pkg = m.group(1)
        if vendor_pkg not in _COMPOSER_SKIP:
            names.append(vendor_pkg.split("/")[-1])
    return names


# pubspec.yaml: dependencies: block, indented entries
_PUBSPEC_DEP_SECTION_RE = re.compile(r"^dependencies\s*:", re.MULTILINE)
_PUBSPEC_PKG_RE = re.compile(r"^\s{2,4}([a-zA-Z0-9_][a-zA-Z0-9_-]*)\s*:", re.MULTILINE)
_PUBSPEC_SKIP = frozenset({"flutter", "sdk"})


def _extract_pubspec(content: str) -> list[str]:
    """Extract package names from the dependencies: block in pubspec.yaml."""
    names: list[str] = []
    for sec_m in _PUBSPEC_DEP_SECTION_RE.finditer(content):
        start = sec_m.end()
        # Next top-level key (no leading whitespace)
        next_sec = re.search(r"^\S", content[start:], re.MULTILINE)
        end = start + next_sec.start() if next_sec else len(content)
        for pkg_m in _PUBSPEC_PKG_RE.finditer(content[start:end]):
            name = pkg_m.group(1)
            if name not in _PUBSPEC_SKIP:
                names.append(name)
    return names


# ---------------------------------------------------------------------------
# Dispatch table: basename → (ecosystem, extractor)
# ---------------------------------------------------------------------------

_EXTRACTORS: dict[str, tuple[str, object]] = {
    "package.json":    ("npm",   _extract_npm),
    "requirements.txt": ("pypi", _extract_requirements),
    "pyproject.toml":  ("pypi",  _extract_pyproject),
    "Cargo.toml":      ("cargo", _extract_cargo),
    "go.mod":          ("go",    _extract_gomod),
    "Gemfile":         ("ruby",  _extract_gemfile),
    "composer.json":   ("php",   _extract_composer),
    "pubspec.yaml":    ("dart",  _extract_pubspec),
}


# ---------------------------------------------------------------------------
# Content extraction from tool input
# ---------------------------------------------------------------------------

def _new_content(tool_name: str, tool_input: dict) -> str:
    """Return the text being written, using the correct field per tool."""
    if tool_name == "Write":
        return tool_input.get("content", "") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string", "") or ""
    if tool_name == "MultiEdit":
        return "\n".join(
            e.get("new_string", "") or ""
            for e in tool_input.get("edits", [])
        )
    return ""


# ---------------------------------------------------------------------------
# Signal bus
# ---------------------------------------------------------------------------

def _emit_signal(findings: list[dict], file_path: str) -> str | None:
    """Write a bounded private signal and report degraded observability."""
    return emit_signal(
        name="depfence_typosquat_manifest",
        value={"findings": findings, "count": len(findings)},
        source="depfence_manifest_edit_gate",
        file_path=file_path,
    )


# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------

def main(data: dict) -> dict:
    """Return the hook's JSON output (empty dict = no-op, exit 0)."""
    if os.environ.get("DEPFENCE_MANIFEST_GATE", "1").lower() in _DISABLE:
        return {}

    tool_name = data.get("tool_name", "")
    if tool_name not in _FILE_TOOLS:
        return {}

    tool_input = data.get("tool_input", {}) or {}
    file_path = tool_input.get("file_path", "") or ""

    # O(1) dict lookup — fast exit for non-manifest files (< 5 ms guarantee)
    basename = os.path.basename(file_path)
    entry = _EXTRACTORS.get(basename)
    if entry is None:
        return {}

    content = _new_content(tool_name, tool_input)
    if not content:
        return {}

    ecosystem, extractor = entry  # type: ignore[misc]
    package_names = extractor(content)  # type: ignore[operator]
    if not package_names:
        return {}

    # Lazy import: keep it after the path check so non-manifest files exit
    # in < 5 ms without the module load cost.
    from depfence.analyzers.typosquat_detector import check_against_popular

    findings: list[dict] = []
    seen: set[str] = set()
    for name in package_names:
        if name in seen:
            continue
        seen.add(name)
        match = check_against_popular(name, ecosystem)
        if match is not None and match.confidence > _CONFIDENCE_THRESHOLD:
            findings.append({
                "suspect": match.suspect,
                "target": match.target,
                "confidence": match.confidence,
                "attack_type": match.attack_type,
            })

    if not findings:
        return {}

    lines = [
        f'  - "{fi["suspect"]}" looks like a typosquat of "{fi["target"]}"'
        f' ({fi["attack_type"]}, confidence={fi["confidence"]:.0%})'
        for fi in findings
    ]
    detail = (
        f"depfence manifest-gate: {file_path!r} introduces package(s) that look "
        "like typosquats:\n" + "\n".join(lines) +
        "\nVerify these package names are correct before proceeding."
    )

    signal_error = _emit_signal(findings, file_path)
    if signal_error:
        detail += f"\nLocal observability: {signal_error}."

    if os.environ.get("DEPFENCE_MANIFEST_GATE_BLOCK", "").lower() in _BLOCK_VALUES:
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
