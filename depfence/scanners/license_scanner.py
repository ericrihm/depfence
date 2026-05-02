"""License compliance scanner — detects dependency licenses incompatible with commercial use.

Classifies each package's SPDX license into risk tiers (CRITICAL → CLEAN) and
emits findings for anything that could block shipping a commercial product.
Handles common non-SPDX variations like "MIT License", "GPLv3", "Apache 2.0".

Risk tiers
----------
CRITICAL  — copyleft/viral: AGPL-3.0, SSPL-1.0, RPL-1.5, OSL-3.0
HIGH      — strong copyleft: GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, MPL-2.0 (static link),
            CC-BY-SA, EUPL
MEDIUM    — weak copyleft / restrictive: MPL-2.0, Artistic-2.0, EPL-2.0, CC-BY-NC
LOW       — permissive with conditions: Apache-2.0 (patent clause), BSD-3-Clause (attribution)
CLEAN     — fully permissive: MIT, ISC, BSD-2-Clause, Unlicense, 0BSD, CC0-1.0, WTFPL
UNKNOWN   — empty / unrecognised → MEDIUM (treat unknown as risky)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-reuse-declared-type]

from depfence.core.models import Finding, FindingType, PackageMeta, Severity

# ---------------------------------------------------------------------------
# License classification tables
# ---------------------------------------------------------------------------

# Tier → (Severity | None, commercial_use_ok, human label)
_TIERS: dict[str, tuple[Severity | None, bool, str]] = {
    "CRITICAL": (Severity.CRITICAL, False, "Viral copyleft — incompatible with commercial use"),
    "HIGH":     (Severity.HIGH,     False, "Strong copyleft — commercial use likely blocked"),
    "MEDIUM":   (Severity.MEDIUM,   True,  "Weak copyleft / restrictive conditions"),
    "LOW":      (Severity.LOW,      True,  "Permissive with notable conditions"),
    "CLEAN":    (None,              True,  "Permissive — no commercial restrictions"),
    "UNKNOWN":  (Severity.MEDIUM,   False, "License unknown — treat as risky"),
}

# Canonical SPDX identifiers  →  tier
_SPDX_TIER: dict[str, str] = {
    # CRITICAL — viral / network copyleft
    "AGPL-3.0":            "CRITICAL",
    "AGPL-3.0-only":       "CRITICAL",
    "AGPL-3.0-or-later":   "CRITICAL",
    "SSPL-1.0":            "CRITICAL",
    "RPL-1.5":             "CRITICAL",
    "OSL-3.0":             "CRITICAL",

    # HIGH — strong copyleft
    "GPL-2.0":             "HIGH",
    "GPL-2.0-only":        "HIGH",
    "GPL-2.0-or-later":    "HIGH",
    "GPL-3.0":             "HIGH",
    "GPL-3.0-only":        "HIGH",
    "GPL-3.0-or-later":    "HIGH",
    "LGPL-2.1":            "HIGH",
    "LGPL-2.1-only":       "HIGH",
    "LGPL-2.1-or-later":   "HIGH",
    "LGPL-3.0":            "HIGH",
    "LGPL-3.0-only":       "HIGH",
    "LGPL-3.0-or-later":   "HIGH",
    "CC-BY-SA-4.0":        "HIGH",
    "CC-BY-SA-3.0":        "HIGH",
    "EUPL-1.2":            "HIGH",
    "EUPL-1.1":            "HIGH",

    # MEDIUM — weak copyleft / non-commercial restrictions
    "MPL-2.0":             "MEDIUM",
    "Artistic-2.0":        "MEDIUM",
    "EPL-2.0":             "MEDIUM",
    "EPL-1.0":             "MEDIUM",
    "CC-BY-NC-4.0":        "MEDIUM",
    "CC-BY-NC-3.0":        "MEDIUM",
    "CC-BY-NC-SA-4.0":     "MEDIUM",

    # LOW — permissive with conditions worth noting
    "Apache-2.0":          "LOW",
    "BSD-3-Clause":        "LOW",

    # CLEAN — fully permissive
    "MIT":                 "CLEAN",
    "ISC":                 "CLEAN",
    "BSD-2-Clause":        "CLEAN",
    "Unlicense":           "CLEAN",
    "0BSD":                "CLEAN",
    "CC0-1.0":             "CLEAN",
    "WTFPL":               "CLEAN",
    "Zlib":                "CLEAN",
    "PSF-2.0":             "CLEAN",
    "Python-2.0":          "CLEAN",
}

# ---------------------------------------------------------------------------
# Variation → canonical SPDX mapping  (case-insensitive keys applied below)
# ---------------------------------------------------------------------------

_VARIATIONS: list[tuple[re.Pattern[str], str]] = [
    # MIT
    (re.compile(r"(?:^|\bthe\s+)mit\b", re.I),              "MIT"),
    # ISC
    (re.compile(r"^isc\b", re.I),                             "ISC"),
    # Apache
    (re.compile(r"apache[\s\-]*(license[\s,]*)?(2\.0|2)", re.I), "Apache-2.0"),
    # BSD-3
    (re.compile(r"bsd[\s\-]*(3[\s\-]clause|3)", re.I),        "BSD-3-Clause"),
    # BSD-2
    (re.compile(r"bsd[\s\-]*(2[\s\-]clause|2)", re.I),        "BSD-2-Clause"),
    # BSD generic (no clause count) → treat as BSD-2
    (re.compile(r"^bsd$", re.I),                              "BSD-2-Clause"),
    # AGPL (before GPL to prevent substring match)
    (re.compile(r"agpl[\s\-]*v?3|affero\s+gpl[\s\-]*v?3|gnu\s+affero|^agpl$|gnu\s+agpl", re.I), "AGPL-3.0"),
    # GPL-3
    (re.compile(r"gpl[\s\-]*v?3|gnu\s+gpl[\s\-]*v?3|gnu\s+general\s+public\s+license[\s,]*v?3", re.I), "GPL-3.0"),
    # GPL-2
    (re.compile(r"gpl[\s\-]*v?2|gnu\s+gpl[\s\-]*v?2|gnu\s+general\s+public\s+license[\s,]*v?2", re.I), "GPL-2.0"),
    # GPL generic (no version) → GPL-2.0 (conservative)
    (re.compile(r"^gpl$|^gnu\s+gpl$|^gnu\s+general\s+public\s+license$", re.I), "GPL-2.0"),
    # LGPL-3
    (re.compile(r"lgpl[\s\-]*v?3|gnu\s+lgpl[\s\-]*v?3|lesser\s+general\s+public\s+license[\s,]*v?3", re.I), "LGPL-3.0"),
    # LGPL-2.1
    (re.compile(r"lgpl[\s\-]*v?2\.?1|gnu\s+lgpl[\s\-]*v?2|lesser\s+general\s+public\s+license[\s,]*v?2", re.I), "LGPL-2.1"),
    # MPL
    (re.compile(r"mpl[\s\-]*2|mozilla\s+public\s+license[\s,]*2", re.I),      "MPL-2.0"),
    # SSPL
    (re.compile(r"sspl", re.I),                               "SSPL-1.0"),
    # EPL
    (re.compile(r"epl[\s\-]*2|eclipse\s+public\s+license[\s,]*2", re.I),      "EPL-2.0"),
    (re.compile(r"epl[\s\-]*1|eclipse\s+public\s+license[\s,]*1", re.I),      "EPL-1.0"),
    # CC0
    (re.compile(r"cc0|creative\s+commons\s+zero", re.I),      "CC0-1.0"),
    # Unlicense
    (re.compile(r"unlicen[sc]e", re.I),                       "Unlicense"),
    # WTFPL
    (re.compile(r"wtfpl", re.I),                              "WTFPL"),
    # PSF
    (re.compile(r"psf|python\s+software\s+foundation", re.I), "PSF-2.0"),
]

# Projects whose license allows them to consume copyleft dependencies
_COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class LicenseScanner:
    """Scan packages for license compliance risks.

    Usage::

        scanner = LicenseScanner()
        findings = await scanner.scan(packages)
    """

    name = "license"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        """Return a Finding for every package with a non-CLEAN license."""
        findings: list[Finding] = []
        for meta in packages:
            finding = self._check_package(meta)
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------
    # Core classification helpers
    # ------------------------------------------------------------------

    def classify_license(self, license_str: str) -> tuple[str, Severity | None]:
        """Return ``(tier_name, severity_or_none)`` for a license string.

        Handles:
        - Exact SPDX identifiers  (e.g. "MIT", "GPL-3.0-only")
        - Common human variations  (e.g. "MIT License", "GPLv3", "Apache 2.0")
        - Empty / ``"UNKNOWN"`` / ``None`` → ``("UNKNOWN", Severity.MEDIUM)``
        """
        if not license_str or license_str.strip().upper() in ("UNKNOWN", "NONE", "PROPRIETARY"):
            tier = "UNKNOWN" if not license_str or license_str.strip().upper() == "UNKNOWN" else "CRITICAL"
            # Proprietary means commercial use is defined by the owner, treat as CRITICAL.
            if license_str and license_str.strip().upper() == "PROPRIETARY":
                return ("CRITICAL", Severity.CRITICAL)
            return ("UNKNOWN", Severity.MEDIUM)

        normalized = license_str.strip()

        # 1. Exact SPDX match (case-sensitive first, then case-folded)
        if normalized in _SPDX_TIER:
            tier = _SPDX_TIER[normalized]
            return (tier, _TIERS[tier][0])

        # 2. Case-folded SPDX match
        upper = normalized.upper()
        for spdx, tier in _SPDX_TIER.items():
            if spdx.upper() == upper:
                return (tier, _TIERS[tier][0])

        # 3. Variation regex matching → resolve to canonical SPDX, then look up tier
        for pattern, canonical in _VARIATIONS:
            if pattern.search(normalized):
                tier = _SPDX_TIER.get(canonical, "UNKNOWN")
                return (tier, _TIERS[tier][0])

        # 4. Unrecognised → treat as UNKNOWN / MEDIUM
        return ("UNKNOWN", Severity.MEDIUM)

    def check_compatibility(
        self,
        project_license: str,
        dep_licenses: list[str],
    ) -> list[str]:
        """Return list of dep license strings that are incompatible with *project_license*.

        Rules:
        - If the project is copyleft (GPL family) it can consume anything.
        - Permissive project (MIT, Apache, BSD, …) cannot include strong/viral copyleft deps.
        """
        proj_canonical = self._to_canonical(project_license)
        if proj_canonical in _COPYLEFT_LICENSES:
            # GPL project can consume any license
            return []

        incompatible = []
        for dep_lic in dep_licenses:
            tier, _ = self.classify_license(dep_lic)
            if tier in ("CRITICAL", "HIGH"):
                incompatible.append(dep_lic)
        return incompatible

    # ------------------------------------------------------------------
    # Project license detection
    # ------------------------------------------------------------------

    def detect_project_license(self, project_root: str | Path) -> str | None:
        """Detect the project's own license from well-known locations.

        Searches (in order):
        1. ``pyproject.toml`` → ``[project] license``
        2. ``package.json``   → ``license`` field
        3. ``LICENSE`` / ``LICENSE.txt`` / ``LICENSE.md`` first line
        """
        root = Path(project_root)

        # pyproject.toml
        ppt = root / "pyproject.toml"
        if ppt.exists():
            try:
                with open(ppt, "rb") as fh:
                    data = tomllib.load(fh)
                lic = data.get("project", {}).get("license")
                if isinstance(lic, str) and lic:
                    return lic
                # PEP 621 table form: {text = "..."} or {file = "..."}
                if isinstance(lic, dict):
                    if "text" in lic:
                        return str(lic["text"])
            except Exception:
                pass

        # package.json
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                import json
                with open(pkg_json) as fh:
                    data = json.load(fh)
                lic = data.get("license")
                if isinstance(lic, str) and lic:
                    return lic
            except Exception:
                pass

        # LICENSE file (first non-blank line gives a hint)
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt"):
            lic_file = root / name
            if lic_file.exists():
                try:
                    text = lic_file.read_text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if line:
                            return line  # return the first meaningful line as a hint
                except Exception:
                    pass

        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_package(self, meta: PackageMeta) -> Finding | None:
        """Produce a Finding for *meta* if its license is not CLEAN."""
        license_str = meta.license or ""
        tier, severity = self.classify_license(license_str)

        if tier == "CLEAN":
            return None  # No finding for permissive licenses

        tier_info = _TIERS[tier]
        _, commercial_ok, tier_label = tier_info

        display_license = license_str if license_str else "UNKNOWN"

        if tier == "UNKNOWN":
            title = f"{meta.pkg.name} has an unknown or missing license"
            detail = (
                f"No recognisable license was found for {meta.pkg.name}. "
                "Without a clear license, legal use is uncertain and commercial deployment "
                "may be blocked. Check the package repository and contact the maintainer."
            )
        elif tier == "CRITICAL":
            title = f"{meta.pkg.name} uses {display_license} — viral copyleft"
            detail = (
                f"{meta.pkg.name} is licensed under {display_license}, which is a viral "
                "copyleft license. Including this package in a commercial product may require "
                "you to open-source your entire codebase under the same terms. "
                f"({tier_label})"
            )
        elif tier == "HIGH":
            title = f"{meta.pkg.name} uses {display_license} — strong copyleft"
            detail = (
                f"{meta.pkg.name} is licensed under {display_license}, a strong copyleft "
                "license. Distribution of software that includes or links against this "
                "package may trigger copyleft obligations. Review with legal counsel before "
                f"shipping. ({tier_label})"
            )
        elif tier == "MEDIUM":
            title = f"{meta.pkg.name} uses {display_license} — restricted conditions"
            detail = (
                f"{meta.pkg.name} is licensed under {display_license}. This license has "
                "conditions that may restrict commercial use or require specific compliance "
                f"steps. ({tier_label})"
            )
        else:  # LOW
            title = f"{meta.pkg.name} uses {display_license} — note conditions"
            detail = (
                f"{meta.pkg.name} is licensed under {display_license}. This is generally "
                "permissive, but contains conditions worth noting (e.g. patent clauses, "
                f"attribution requirements). ({tier_label})"
            )

        assert severity is not None  # CLEAN is handled above; all other tiers have a severity
        return Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=severity,
            package=meta.pkg,
            title=title,
            detail=detail,
            confidence=1.0,
            metadata={
                "license": display_license,
                "risk_tier": tier,
                "commercial_use": commercial_ok,
            },
        )

    def _to_canonical(self, license_str: str) -> str:
        """Best-effort resolve *license_str* to a canonical SPDX identifier."""
        if not license_str:
            return ""
        # Exact match
        if license_str in _SPDX_TIER:
            return license_str
        # Case-folded exact
        upper = license_str.upper()
        for spdx in _SPDX_TIER:
            if spdx.upper() == upper:
                return spdx
        # Variation
        for pattern, canonical in _VARIATIONS:
            if pattern.search(license_str):
                return canonical
        return license_str
