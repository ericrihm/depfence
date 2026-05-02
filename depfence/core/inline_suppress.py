"""Inline suppression support for depfence.

Allows users to annotate lines in their lockfiles/manifests with
``depfence:ignore`` comments to suppress specific findings without
touching a separate baseline file.

Supported syntax
----------------
* ``# depfence:ignore``            — suppress all findings for this package
* ``# depfence:ignore CVE-2024-1234`` — suppress a specific CVE
* ``# depfence:ignore typosquat``  — suppress by finding type (FindingType value)
* Multiple tokens: ``# depfence:ignore CVE-2024-1234 typosquat``

Supported file formats
-----------------------
* requirements.txt   (``#`` comments)
* Cargo.toml         (``#`` comments)
* package.json       (``//`` comments)

The comment style is detected per-line so the same parser handles all formats.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding

# Matches the depfence:ignore token and optional suppression targets that follow.
# Group 1: everything after "depfence:ignore" on the same line (stripped).
_DIRECTIVE_RE = re.compile(
    r"(?:#|//)\s*depfence:ignore\s*(.*?)(?:\s*(?:#|//).*)?$"
)

# Regex to extract a package name from a requirements.txt-style line.
# Handles: requests==2.28.0, flask>=2.0, numpy~=1.26.0, django[rest]>=4.0
_REQUIREMENTS_PKG_RE = re.compile(
    r"^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
)

# Regex for package.json dependency line: "lodash": "^4.17.0"
_PACKAGE_JSON_PKG_RE = re.compile(
    r'^\s*"(@?[A-Za-z0-9][\w.@/-]*)"\s*:\s*"'
)

# Regex for Cargo.toml dependency line: serde = "1.0" or serde = { version = "1.0" }
_CARGO_PKG_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_-]*)\s*="
)


def _extract_package_name(line: str, file_suffix: str) -> str | None:
    """Return the package name from a manifest line, or None if not parseable."""
    # Strip inline comment before trying to identify the package.
    code_part = re.split(r"\s*(?:#|//)", line)[0].strip()
    if not code_part:
        return None

    if file_suffix in (".txt",):
        # requirements.txt style
        m = _REQUIREMENTS_PKG_RE.match(code_part)
        return m.group(1).lower() if m else None

    if file_suffix in (".json",):
        m = _PACKAGE_JSON_PKG_RE.match(code_part)
        return m.group(1).lower() if m else None

    if file_suffix in (".toml",):
        m = _CARGO_PKG_RE.match(code_part)
        return m.group(1).lower() if m else None

    # Fallback: try requirements.txt heuristic for unknown suffixes.
    m = _REQUIREMENTS_PKG_RE.match(code_part)
    return m.group(1).lower() if m else None


def _parse_targets(raw: str) -> list[str]:
    """Parse the token(s) after ``depfence:ignore``.

    Returns an empty list when the directive has no arguments, meaning
    *all* findings for the package are suppressed (wildcard).
    Tokens are normalised to lower-case for case-insensitive matching.
    """
    tokens = raw.strip().split()
    return [t.lower() for t in tokens if t]


def parse_suppressions(file_path: Path) -> dict[str, list[str]]:
    """Parse *file_path* for ``depfence:ignore`` comments.

    Returns a mapping of ``{package_name_lower: [suppression_tokens]}``.

    * An empty list of tokens means "suppress everything" (wildcard).
    * Tokens are either CVE IDs (e.g. ``"cve-2024-1234"``) or finding-type
      values (e.g. ``"typosquat"``, ``"known_vulnerability"``).
    * The special key ``"*"`` is used when the package name cannot be
      determined from the line (best-effort fallback).

    Lines without a ``depfence:ignore`` directive are ignored entirely.
    """
    suppressions: dict[str, list[str]] = {}

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return suppressions

    suffix = file_path.suffix.lower()

    for line in text.splitlines():
        m = _DIRECTIVE_RE.search(line)
        if m is None:
            continue

        targets = _parse_targets(m.group(1))
        pkg_name = _extract_package_name(line, suffix)

        if pkg_name is None:
            # Cannot identify the package; use wildcard key.
            key = suppressions.get("*")
            if key is None:
                suppressions["*"] = targets
            else:
                # Merge: empty list (wildcard) dominates.
                if not key or not targets:
                    suppressions["*"] = []
                else:
                    suppressions["*"] = list(dict.fromkeys(key + targets))
        else:
            existing = suppressions.get(pkg_name)
            if existing is None:
                suppressions[pkg_name] = targets
            else:
                # Merge: empty list (wildcard) dominates.
                if not existing or not targets:
                    suppressions[pkg_name] = []
                else:
                    suppressions[pkg_name] = list(dict.fromkeys(existing + targets))

    return suppressions


def _is_suppressed_by(finding: Finding, tokens: list[str]) -> bool:
    """Return True if *finding* is suppressed by *tokens*.

    An empty *tokens* list is a wildcard — it suppresses everything.
    Otherwise each token is matched against:
    * The finding's CVE id (case-insensitive).
    * The finding's finding_type value (e.g. ``"typosquat"``).
    """
    if not tokens:
        # Wildcard: suppress all findings for this package.
        return True

    for token in tokens:
        # CVE match
        if finding.cve and token == finding.cve.lower():
            return True
        # Finding-type match
        if token == finding.finding_type.value.lower():
            return True

    return False


def filter_findings(
    findings: list[Finding],
    suppressions: dict[str, list[str]],
) -> tuple[list[Finding], list[Finding]]:
    """Apply inline suppressions to *findings*.

    Parameters
    ----------
    findings:
        The full list of findings produced by the scanner.
    suppressions:
        The mapping returned by :func:`parse_suppressions`.

    Returns
    -------
    (active, suppressed)
        *active* — findings that are **not** suppressed and should be reported.
        *suppressed* — findings that matched a suppression directive.
    """
    active: list[Finding] = []
    suppressed: list[Finding] = []

    # Pre-compute wildcard tokens once.
    wildcard_tokens: list[str] | None = suppressions.get("*")

    for finding in findings:
        pkg_name = finding.package.name.lower() if hasattr(finding.package, "name") else str(finding.package).lower()

        # Check package-specific suppression first.
        pkg_tokens = suppressions.get(pkg_name)
        if pkg_tokens is not None and _is_suppressed_by(finding, pkg_tokens):
            suppressed.append(finding)
            continue

        # Fall back to wildcard suppression.
        if wildcard_tokens is not None and _is_suppressed_by(finding, wildcard_tokens):
            suppressed.append(finding)
            continue

        active.append(finding)

    return active, suppressed
