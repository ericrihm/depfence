"""Package version diff analyzer — detects suspicious code changes between versions."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DiffSignal:
    signal_type: str  # "network_added", "eval_added", "obfuscation_added", "credential_access", "binary_added", "postinstall_added"
    file_path: str
    line: int
    snippet: str  # up to 100 chars of the suspicious line
    severity: str  # "critical", "high", "medium"


@dataclass
class VersionDiffResult:
    package: str
    old_version: str
    new_version: str
    signals: list[DiffSignal]
    risk_score: float  # 0-10
    files_added: int
    files_modified: int
    lines_added: int


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# (compiled_regex, signal_type, severity)
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Network calls
    (re.compile(r"fetch\s*\("), "network_added", "high"),
    (re.compile(r"http\.get\s*\("), "network_added", "high"),
    (re.compile(r"XMLHttpRequest"), "network_added", "high"),
    (re.compile(r"\burllib\b"), "network_added", "medium"),
    (re.compile(r"requests\."), "network_added", "medium"),
    (re.compile(r"httpx\."), "network_added", "medium"),
    (re.compile(r"socket\.connect\s*\("), "network_added", "high"),
    # Eval / exec / code execution
    (re.compile(r"\beval\s*\("), "eval_added", "critical"),
    (re.compile(r"\bexec\s*\("), "eval_added", "critical"),
    (re.compile(r"\bFunction\s*\("), "eval_added", "high"),
    (re.compile(r"\bchild_process\b"), "eval_added", "critical"),
    (re.compile(r"\bsubprocess\b"), "eval_added", "high"),
    (re.compile(r"\bos\.system\s*\("), "eval_added", "critical"),
    # Obfuscation
    (re.compile(r"(?:base64|b64).*(?:exec|eval)", re.IGNORECASE), "obfuscation_added", "critical"),
    (re.compile(r"Buffer\.from\s*\([^)]*\)\s*.*eval", re.IGNORECASE), "obfuscation_added", "critical"),
    (re.compile(r"[0-9a-fA-F]{51,}"), "obfuscation_added", "high"),
    # Credential access
    (re.compile(r"process\.env"), "credential_access", "medium"),
    (re.compile(r"os\.environ"), "credential_access", "medium"),
    (re.compile(r"~/\.ssh"), "credential_access", "critical"),
    (re.compile(r"~/\.aws"), "credential_access", "critical"),
    (re.compile(r"\bkeychain\b", re.IGNORECASE), "credential_access", "high"),
]

# Severity weights for risk scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.0,
    "medium": 1.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_binary(content: str) -> bool:
    """Heuristic: presence of null bytes indicates a binary file."""
    return "\x00" in content


def _new_lines(old_text: str | None, new_text: str) -> list[tuple[int, str]]:
    """Return (1-based line number, line text) pairs that are new in new_text.

    A line is considered new if it does not appear in the old version of the
    same file (simple set membership — good enough for security signals).
    """
    old_lines: set[str] = set()
    if old_text is not None:
        old_lines = set(old_text.splitlines())

    result: list[tuple[int, str]] = []
    for lineno, line in enumerate(new_text.splitlines(), start=1):
        if line not in old_lines:
            result.append((lineno, line))
    return result


def _check_postinstall(file_path: str, content: str, old_content: str | None) -> list[DiffSignal]:
    """Check package.json for newly-added pre/postinstall scripts."""
    signals: list[DiffSignal] = []
    try:
        new_pkg = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return signals

    new_scripts: dict[str, str] = new_pkg.get("scripts", {})
    old_scripts: dict[str, str] = {}
    if old_content:
        try:
            old_pkg = json.loads(old_content)
            old_scripts = old_pkg.get("scripts", {})
        except (json.JSONDecodeError, ValueError):
            pass

    for hook in ("preinstall", "postinstall", "install"):
        if hook in new_scripts and hook not in old_scripts:
            snippet = new_scripts[hook][:100]
            signals.append(DiffSignal(
                signal_type="postinstall_added",
                file_path=file_path,
                line=0,
                snippet=snippet,
                severity="critical",
            ))
    return signals


def _scan_new_lines(file_path: str, new_lines: list[tuple[int, str]]) -> list[DiffSignal]:
    """Scan newly-added lines for suspicious patterns."""
    signals: list[DiffSignal] = []
    for lineno, line in new_lines:
        for pattern, signal_type, severity in _PATTERNS:
            if pattern.search(line):
                signals.append(DiffSignal(
                    signal_type=signal_type,
                    file_path=file_path,
                    line=lineno,
                    snippet=line.strip()[:100],
                    severity=severity,
                ))
                # One signal per line per pattern is fine; continue to catch
                # multiple different signal types on the same line.
    return signals


def _compute_risk_score(signals: list[DiffSignal]) -> float:
    if not signals:
        return 0.0
    total = sum(_SEVERITY_WEIGHTS.get(s.severity, 1.0) for s in signals)
    return min(round(total, 2), 10.0)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_diff(
    old_content: dict[str, str],
    new_content: dict[str, str],
    package_name: str,
    old_version: str,
    new_version: str,
) -> VersionDiffResult:
    """Analyze suspicious changes introduced between two package versions.

    Parameters
    ----------
    old_content:
        Mapping of filepath -> file content for the old version.
    new_content:
        Mapping of filepath -> file content for the new version.
    package_name, old_version, new_version:
        Metadata for the result object.

    Returns
    -------
    VersionDiffResult
    """
    signals: list[DiffSignal] = []
    files_added = 0
    files_modified = 0
    lines_added_total = 0

    for file_path, new_text in new_content.items():
        old_text: str | None = old_content.get(file_path)
        is_new_file = old_text is None

        if is_new_file:
            files_added += 1
        else:
            files_modified += 1

        # --- Binary file detection ---
        if _is_binary(new_text):
            if is_new_file or not _is_binary(old_text or ""):
                signals.append(DiffSignal(
                    signal_type="binary_added",
                    file_path=file_path,
                    line=0,
                    snippet="<binary file>",
                    severity="high",
                ))
            # Don't try to text-scan binary blobs
            continue

        # --- package.json postinstall detection ---
        if file_path.endswith("package.json") or file_path == "package.json":
            signals.extend(_check_postinstall(file_path, new_text, old_text))

        # --- Compute new lines and count them ---
        new_line_list = _new_lines(old_text, new_text)
        lines_added_total += len(new_line_list)

        # --- Scan new lines for suspicious patterns ---
        signals.extend(_scan_new_lines(file_path, new_line_list))

    return VersionDiffResult(
        package=package_name,
        old_version=old_version,
        new_version=new_version,
        signals=signals,
        risk_score=_compute_risk_score(signals),
        files_added=files_added,
        files_modified=files_modified,
        lines_added=lines_added_total,
    )
