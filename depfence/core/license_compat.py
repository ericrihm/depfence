"""License compatibility detection module.

Checks whether dependency licenses are compatible with the project's own license
and generates Finding objects for conflicts.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-declared-type]


# ---------------------------------------------------------------------------
# License classification sets
# ---------------------------------------------------------------------------

# Licenses that are fully permissive — compatible with everything.
_PERMISSIVE_CLEAN: frozenset[str] = frozenset(
    {
        "MIT",
        "ISC",
        "BSD-2-Clause",
        "BSD-2-Clause-Patent",
        "Unlicense",
        "CC0-1.0",
        "0BSD",
        "WTFPL",
        "Zlib",
        "CDDL-1.0",
    }
)

# Permissive but carry a notable clause (patent grant / attribution).
# These are still compatible with most things but are worth a LOW note.
_PERMISSIVE_LOW: frozenset[str] = frozenset(
    {
        "Apache-2.0",
        "BSD-3-Clause",
        "BSD-4-Clause",
        "PSF-2.0",
        "Python-2.0",
    }
)

# File-level or weak copyleft — "warning" tier only.
_COPYLEFT_WEAK: frozenset[str] = frozenset(
    {
        "MPL-2.0",
        "MPL-1.1",
        "EUPL-1.2",
        "EUPL-1.1",
        "EPL-1.0",
        "EPL-2.0",
        "CDDL-1.1",
    }
)

# Library copyleft — dynamic-link exception means warning, not hard error.
_COPYLEFT_LGPL: frozenset[str] = frozenset(
    {
        "LGPL-2.0",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
    }
)

# Strong copyleft — hard conflict with permissive / proprietary projects.
_COPYLEFT_STRONG: frozenset[str] = frozenset(
    {
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
    }
)

# Network copyleft — requires source even for SaaS; always a hard conflict.
_COPYLEFT_NETWORK: frozenset[str] = frozenset(
    {
        "AGPL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
        "BUSL-1.1",
    }
)

# Copyleft project licenses — can consume anything (copyleft absorbs permissive).
_COPYLEFT_ANY: frozenset[str] = (
    _COPYLEFT_LGPL | _COPYLEFT_WEAK | _COPYLEFT_STRONG | _COPYLEFT_NETWORK
)

# All permissive project licenses.
_PERMISSIVE_ANY: frozenset[str] = _PERMISSIVE_CLEAN | _PERMISSIVE_LOW

# Proprietary / source-available synonyms recognised in project license fields.
_PROPRIETARY_SIGNALS: tuple[str, ...] = (
    "proprietary",
    "commercial",
    "all rights reserved",
    "unlicensed",
    "private",
    "source-available",
)

# ---------------------------------------------------------------------------
# Human-readable normalisation map  (fragment → canonical SPDX)
# ---------------------------------------------------------------------------

_FUZZY_MAP: list[tuple[tuple[str, ...], str]] = [
    # AGPL
    (("agpl-3", "agpl3", "agplv3", "gnu agpl", "affero gpl", "affero general public"), "AGPL-3.0"),
    # GPL 3
    (("gpl-3", "gpl3", "gplv3", "gpl v3", "gnu gpl v3", "gnu general public license v3",
      "general public license 3", "gpl version 3"), "GPL-3.0"),
    # GPL 2
    (("gpl-2", "gpl2", "gplv2", "gpl v2", "gnu gpl v2", "gnu general public license v2",
      "general public license 2", "gpl version 2"), "GPL-2.0"),
    # LGPL 3
    (("lgpl-3", "lgpl3", "lgplv3", "lgpl v3", "gnu lgpl v3"), "LGPL-3.0"),
    # LGPL 2.1
    (("lgpl-2.1", "lgpl2.1", "lgplv2.1", "lgpl v2.1", "gnu lesser general public license v2.1"), "LGPL-2.1"),
    # LGPL 2
    (("lgpl-2", "lgpl2", "lgplv2", "lgpl v2", "gnu lesser general public license v2"), "LGPL-2.0"),
    # MPL
    (("mpl-2", "mpl2", "mplv2", "mozilla public license 2"), "MPL-2.0"),
    (("mpl-1.1", "mpl1.1", "mozilla public license 1.1"), "MPL-1.1"),
    # Apache
    (("apache-2", "apache2", "apache 2", "apache license 2", "apache license, version 2",
      "apache 2.0", "apache-2.0"), "Apache-2.0"),
    # MIT
    (("mit license", "the mit license", "mit-license"), "MIT"),
    # BSD
    (("bsd-2", "bsd2", "2-clause bsd", "bsd 2-clause"), "BSD-2-Clause"),
    (("bsd-3", "bsd3", "3-clause bsd", "bsd 3-clause", "new bsd", "modified bsd"), "BSD-3-Clause"),
    # ISC
    (("isc license",), "ISC"),
    # Unlicense
    (("unlicensed", "the unlicense", "public domain"), "Unlicense"),
    # CC0
    (("creative commons zero", "cc-zero", "cc 0", "cc0"), "CC0-1.0"),
    # SSPL
    (("sspl-1", "sspl1", "server side public license"), "SSPL-1.0"),
    # EPL
    (("epl-2", "epl2", "eclipse public license 2"), "EPL-2.0"),
    (("epl-1", "epl1", "eclipse public license 1"), "EPL-1.0"),
    # EUPL
    (("eupl-1.2", "eupl1.2", "european union public license 1.2"), "EUPL-1.2"),
    # WTFPL
    (("wtfpl",), "WTFPL"),
]


def _normalise(raw: str) -> str:
    """Return a canonical SPDX-like identifier for *raw*, or the stripped original."""
    stripped = raw.strip()
    lower = stripped.lower()

    # Direct hit in known sets — return as-is (already SPDX).
    all_known = (
        _PERMISSIVE_CLEAN | _PERMISSIVE_LOW | _COPYLEFT_WEAK
        | _COPYLEFT_LGPL | _COPYLEFT_STRONG | _COPYLEFT_NETWORK
    )
    if stripped in all_known:
        return stripped

    # Fuzzy matching.
    for fragments, canonical in _FUZZY_MAP:
        for frag in fragments:
            if frag in lower:
                return canonical

    return stripped


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------


@dataclass
class LicenseConflict:
    """Represents a license incompatibility between a dependency and the project."""

    package: str
    package_license: str
    project_license: str
    reason: str
    severity: str  # "error" or "warning"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_project_license(raw: str) -> str:
    """Return 'permissive', 'copyleft', 'proprietary', or 'unknown'."""
    norm = _normalise(raw)
    if norm in _PERMISSIVE_ANY:
        return "permissive"
    if norm in _COPYLEFT_ANY:
        return "copyleft"
    lower = norm.lower()
    if any(sig in lower for sig in _PROPRIETARY_SIGNALS):
        return "proprietary"
    return "unknown"


def _classify_dep_license(raw: str) -> str:
    """Return the tier of a dependency licence: 'clean', 'low', 'weak', 'lgpl',
    'strong', 'network', or 'unknown'."""
    norm = _normalise(raw)
    if norm in _PERMISSIVE_CLEAN:
        return "clean"
    if norm in _PERMISSIVE_LOW:
        return "low"
    if norm in _COPYLEFT_WEAK:
        return "weak"
    if norm in _COPYLEFT_LGPL:
        return "lgpl"
    if norm in _COPYLEFT_STRONG:
        return "strong"
    if norm in _COPYLEFT_NETWORK:
        return "network"
    return "unknown"


# ---------------------------------------------------------------------------
# Core public functions
# ---------------------------------------------------------------------------


def check_license_compatibility(
    project_license: str,
    dependencies: list[dict],
) -> list[LicenseConflict]:
    """Check all deps for license compatibility with the project license.

    Parameters
    ----------
    project_license:
        SPDX identifier (or human-readable string) for the project's own license.
    dependencies:
        Each dict must contain at least ``"name"`` and ``"license"``; ``"ecosystem"``
        is optional context.

    Returns
    -------
    list[LicenseConflict]
        One entry per incompatible dependency; empty when all deps are compatible.
    """
    conflicts: list[LicenseConflict] = []

    proj_norm = _normalise(project_license)
    proj_class = _classify_project_license(project_license)

    for dep in dependencies:
        name = dep.get("name", "<unknown>")
        dep_lic_raw = dep.get("license", "") or ""
        dep_norm = _normalise(dep_lic_raw)
        tier = _classify_dep_license(dep_lic_raw)

        if not dep_lic_raw or dep_lic_raw.upper() in ("UNKNOWN", "NOASSERTION", ""):
            conflicts.append(
                LicenseConflict(
                    package=name,
                    package_license=dep_lic_raw or "UNKNOWN",
                    project_license=project_license,
                    reason=(
                        "Dependency license is unknown or unspecified — "
                        "compatibility cannot be verified."
                    ),
                    severity="warning",
                )
            )
            continue

        # Copyleft projects can consume any open-source license freely.
        if proj_class == "copyleft":
            continue

        # --- Network copyleft (AGPL, SSPL, BUSL) ---
        if tier == "network":
            # Conflict with everything except the same or compatible copyleft project.
            if proj_class in ("permissive", "proprietary", "unknown"):
                conflicts.append(
                    LicenseConflict(
                        package=name,
                        package_license=dep_lic_raw,
                        project_license=project_license,
                        reason=(
                            f"{dep_norm} requires that source code be made available even "
                            "for network-accessed services (AGPL/SSPL network copyleft). "
                            f"This is incompatible with a {proj_norm} project."
                        ),
                        severity="error",
                    )
                )
            continue

        # --- Strong copyleft (GPL) ---
        if tier == "strong":
            # GPL-2.0 cannot be combined with Apache-2.0 (patent termination clause clash).
            # GPL in any permissive or proprietary project is a hard conflict.
            if proj_class in ("permissive", "proprietary", "unknown"):
                reason = (
                    f"{dep_norm} is a strong copyleft license. Distributing it as part "
                    f"of a {proj_norm} project requires the entire project to be released "
                    f"under {dep_norm} as well."
                )
                if dep_norm == "GPL-2.0" and proj_norm == "Apache-2.0":
                    reason += (
                        " Additionally, GPL-2.0 and Apache-2.0 are specifically "
                        "incompatible due to additional restrictions in GPL-2.0."
                    )
                conflicts.append(
                    LicenseConflict(
                        package=name,
                        package_license=dep_lic_raw,
                        project_license=project_license,
                        reason=reason,
                        severity="error",
                    )
                )
            continue

        # --- LGPL (weak copyleft with dynamic-link exception) ---
        if tier == "lgpl":
            if proj_class in ("proprietary",):
                conflicts.append(
                    LicenseConflict(
                        package=name,
                        package_license=dep_lic_raw,
                        project_license=project_license,
                        reason=(
                            f"{dep_norm} requires that modifications to the library itself "
                            "be released as LGPL. Dynamic linking is typically acceptable; "
                            "static linking or modifications may require source disclosure."
                        ),
                        severity="warning",
                    )
                )
            elif proj_class in ("permissive", "unknown"):
                # Soft warning — dynamic link is usually fine, but flag it.
                conflicts.append(
                    LicenseConflict(
                        package=name,
                        package_license=dep_lic_raw,
                        project_license=project_license,
                        reason=(
                            f"{dep_norm} is a library copyleft license. Dynamic linking "
                            f"with a {proj_norm} project is generally allowed, but any "
                            "modifications to the LGPL library must be released under LGPL."
                        ),
                        severity="warning",
                    )
                )
            continue

        # --- File-level / weak copyleft (MPL, EPL, EUPL) ---
        if tier == "weak":
            # Warning for permissive/proprietary — file-level copyleft only.
            if proj_class in ("permissive", "proprietary", "unknown"):
                conflicts.append(
                    LicenseConflict(
                        package=name,
                        package_license=dep_lic_raw,
                        project_license=project_license,
                        reason=(
                            f"{dep_norm} is a file-level copyleft license. Files from "
                            "this dependency that are modified must be kept under "
                            f"{dep_norm}, but the rest of your {proj_norm} project is "
                            "not affected."
                        ),
                        severity="warning",
                    )
                )
            continue

        # Permissive tiers (clean, low) are compatible with everything — no conflict.

    return conflicts


def detect_project_license(project_dir: Path) -> str | None:
    """Detect the project's license from common metadata files.

    Checks in priority order:
    1. ``pyproject.toml`` → ``[project] license``
    2. ``package.json`` → ``license``
    3. ``LICENSE`` / ``LICENSE.txt`` / ``LICENSE.md`` → first non-empty line

    Returns
    -------
    str | None
        The detected license string, or *None* if no information was found.
    """
    # 1. pyproject.toml
    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            proj = data.get("project", {})
            lic = proj.get("license")
            if isinstance(lic, str) and lic:
                return lic
            # PEP 639 / new format: {text = "..."} or {file = "..."}
            if isinstance(lic, dict):
                if "text" in lic and lic["text"]:
                    return lic["text"]
                # If it's {file = "..."}, fall through to LICENSE file check below.
        except Exception:  # noqa: BLE001
            pass

    # 2. package.json
    pkg_json = project_dir / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            lic = data.get("license")
            if isinstance(lic, str) and lic:
                return lic
        except Exception:  # noqa: BLE001
            pass

    # 3. LICENSE file variants (first non-blank line)
    for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt"):
        lic_file = project_dir / candidate
        if lic_file.is_file():
            try:
                for line in lic_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line:
                        return line
            except Exception:  # noqa: BLE001
                pass

    return None


def generate_license_findings(
    project_dir: Path,
    dependencies: list[dict],
) -> list[Finding]:
    """Generate Finding objects for license conflicts.

    Detects the project license from *project_dir*, then calls
    :func:`check_license_compatibility` and converts each
    :class:`LicenseConflict` into a :class:`~depfence.core.models.Finding`.

    Parameters
    ----------
    project_dir:
        Root directory of the project being scanned.
    dependencies:
        List of dicts with at least ``"name"``, ``"license"``, and optionally
        ``"ecosystem"`` and ``"version"``.

    Returns
    -------
    list[Finding]
        One Finding per conflict; empty when everything is compatible or the
        project license cannot be detected.
    """
    project_license = detect_project_license(project_dir)
    if not project_license:
        return []

    conflicts = check_license_compatibility(project_license, dependencies)
    findings: list[Finding] = []

    for conflict in conflicts:
        # Map severity string → Severity enum and choose appropriate level.
        if conflict.severity == "error":
            severity = Severity.HIGH
        elif conflict.severity == "warning":
            # Distinguish between unknown-license (LOW) and soft copyleft (MEDIUM).
            dep_lic_upper = conflict.package_license.upper()
            if dep_lic_upper in ("UNKNOWN", "NOASSERTION", ""):
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Build a PackageId from what we have; look up ecosystem/version from deps.
        dep_meta = next(
            (d for d in dependencies if d.get("name") == conflict.package),
            {},
        )
        ecosystem = dep_meta.get("ecosystem", "unknown")
        version = dep_meta.get("version")

        pkg_id = PackageId(
            ecosystem=ecosystem,
            name=conflict.package,
            version=version,
        )

        title = (
            f"License conflict: {conflict.package_license} dependency "
            f"in {conflict.project_license} project"
        )

        finding = Finding(
            finding_type=FindingType.PROVENANCE,
            severity=severity,
            package=pkg_id,
            title=title,
            detail=conflict.reason,
            metadata={
                "package_license": conflict.package_license,
                "project_license": conflict.project_license,
                "conflict_severity": conflict.severity,
            },
        )
        findings.append(finding)

    return findings
