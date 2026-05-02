"""License compliance scanner with policy enforcement.

Detects dependency licenses incompatible with your product licensing policy.
Reads policy from ``depfence.yml`` (``licenses:`` section) and evaluates each
package against allow/deny lists and per-package exceptions.

Policy format (depfence.yml)::

    licenses:
      allow: [permissive, weak_copyleft]
      deny: [strong_copyleft, non_commercial]
      exceptions:
        - package: "linux-headers"
          reason: "System dependency, not distributed"

Categories (based on depfence/data/license_db.json)
----------------------------------------------------
permissive      — MIT, BSD-*, Apache-2.0, ISC, Unlicense, CC0, Zlib, PSF, …
weak_copyleft   — LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-1.0, EPL-2.0, …
strong_copyleft — GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, …
non_commercial  — CC-BY-NC-*, PolyForm-Noncommercial, …
unknown         — no license detected (treated as HIGH risk)

SPDX expression parsing
-----------------------
Handles compound expressions such as:
- ``MIT OR Apache-2.0``          → best-case (most permissive wins)
- ``GPL-2.0-only WITH Classpath-exception-2.0``  → treated as base license
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LICENSE_DB_PATH = Path(__file__).parent.parent / "data" / "license_db.json"

# Category → severity for policy violations (packages with NO policy override)
_CATEGORY_SEVERITY: dict[str, Severity] = {
    "permissive":     Severity.LOW,
    "weak_copyleft":  Severity.MEDIUM,
    "strong_copyleft": Severity.HIGH,
    "non_commercial": Severity.HIGH,
    "unknown":        Severity.HIGH,
}

# Default policy when no depfence.yml is present
_DEFAULT_POLICY: dict[str, Any] = {
    "allow": ["permissive"],
    "deny": ["strong_copyleft", "non_commercial"],
    "exceptions": [],
}

# Human-readable category labels
_CATEGORY_LABELS: dict[str, str] = {
    "permissive":     "Permissive",
    "weak_copyleft":  "Weak Copyleft",
    "strong_copyleft": "Strong Copyleft",
    "non_commercial": "Non-Commercial",
    "unknown":        "Unknown",
}

# SPDX identifiers that have permissive-override exceptions commonly used
_WITH_EXCEPTIONS: dict[str, str] = {
    "Classpath-exception-2.0": "permissive",  # GPL + Classpath = effectively permissive in JVM
    "FOSS-exception-2.0": "permissive",
}


# ---------------------------------------------------------------------------
# License DB loader
# ---------------------------------------------------------------------------

def _load_db() -> dict[str, dict[str, Any]]:
    """Load the SPDX license database."""
    try:
        with open(_LICENSE_DB_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


_LICENSE_DB: dict[str, dict[str, Any]] = _load_db()

# Build case-folded lookup for the DB
_LICENSE_DB_UPPER: dict[str, str] = {k.upper(): k for k in _LICENSE_DB}


# ---------------------------------------------------------------------------
# SPDX expression parser
# ---------------------------------------------------------------------------

def parse_spdx_expression(expr: str) -> list[str]:
    """Parse an SPDX license expression into a flat list of license identifiers.

    Rules:
    - ``MIT OR Apache-2.0``                  → ["MIT", "Apache-2.0"]
    - ``GPL-2.0-only AND Classpath-exception-2.0`` → ["GPL-2.0-only"]  (WITH handled)
    - ``GPL-2.0-only WITH Classpath-exception-2.0`` → ["GPL-2.0-only"]
    - Parentheses are stripped; operators AND/OR/WITH stripped.
    - Returns at minimum ["UNKNOWN"] if expression is empty.
    """
    if not expr or not expr.strip():
        return ["UNKNOWN"]

    # Strip parens
    expr = expr.replace("(", " ").replace(")", " ")

    # Split on operators (case-insensitive)
    tokens = re.split(r"\b(?:AND|OR|WITH)\b", expr, flags=re.IGNORECASE)
    tokens = [t.strip() for t in tokens if t.strip()]

    # Remove known exception identifiers (they modify, not replace the license)
    exception_ids = {
        "Classpath-exception-2.0",
        "FOSS-exception-2.0",
        "OpenSSL-exception",
        "Bison-exception-2.2",
        "GCC-exception-3.1",
        "Font-exception-2.0",
    }
    tokens = [t for t in tokens if t not in exception_ids]

    return tokens if tokens else ["UNKNOWN"]


def _category_for_spdx(spdx_id: str) -> str:
    """Return the license category for a canonical SPDX identifier."""
    # Exact match
    if spdx_id in _LICENSE_DB:
        return _LICENSE_DB[spdx_id].get("category", "unknown")
    # Case-folded match
    upper = spdx_id.upper()
    if upper in _LICENSE_DB_UPPER:
        canonical = _LICENSE_DB_UPPER[upper]
        return _LICENSE_DB[canonical].get("category", "unknown")
    # Known SPDX variants (e.g. "GPL-2.0-only" not in DB but pattern-match)
    if re.match(r"(AGPL|GPL|SSPL|OSL|RPL|CPAL|Sleepycat|ODbL|SPL)", spdx_id, re.I):
        return "strong_copyleft"
    if re.match(r"(LGPL|MPL|EPL|EUPL|APSL|MS-RL|CDDL|CPL|OFL|SimPL)", spdx_id, re.I):
        return "weak_copyleft"
    if re.match(r"(CC-BY-NC)", spdx_id, re.I):
        return "non_commercial"
    if re.match(r"(MIT|BSD|Apache|ISC|Zlib|PSF|Unlicense|CC0|WTFPL|0BSD|Artistic-1|BSL|AFL"
                r"|NCSA|PHP|Ruby|W3C|PostgreSQL|HPND|FTL|OpenSSL|curl|MS-PL|NIST|Fair"
                r"|Entessa|Xnet|EUDatagrid)", spdx_id, re.I):
        return "permissive"
    return "unknown"


def resolve_spdx_expression_category(expr: str) -> str:
    """Resolve an SPDX expression (possibly compound) to a single risk category.

    For OR expressions, takes the *most permissive* category (best case).
    For AND/WITH expressions, takes the *most restrictive* category (worst case).
    In practice this function simplifies to: take the worst category of all
    identifiers found, which is the conservative safe approach for compliance.
    """
    ids = parse_spdx_expression(expr)
    if ids == ["UNKNOWN"]:
        return "unknown"

    _ORDER = ["permissive", "weak_copyleft", "strong_copyleft", "non_commercial", "unknown"]

    # Check if this is an OR expression — pick most permissive
    is_or = bool(re.search(r"\bOR\b", expr, re.IGNORECASE))

    categories = [_category_for_spdx(sid) for sid in ids]

    if is_or:
        # Pick the most permissive (lowest index in _ORDER)
        return min(categories, key=lambda c: _ORDER.index(c) if c in _ORDER else len(_ORDER))
    else:
        # Pick most restrictive (highest index)
        return max(categories, key=lambda c: _ORDER.index(c) if c in _ORDER else len(_ORDER))


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------

def _load_policy(project_dir: Path) -> dict[str, Any]:
    """Load the ``licenses:`` section from depfence.yml in *project_dir*."""
    for config_name in ("depfence.yml", "depfence.yaml", ".depfence.yml"):
        cfg_path = project_dir / config_name
        if cfg_path.exists():
            try:
                import yaml  # type: ignore[import]
                raw = yaml.safe_load(cfg_path.read_text()) or {}
                return raw.get("licenses", _DEFAULT_POLICY)
            except Exception:
                pass
    return _DEFAULT_POLICY


# ---------------------------------------------------------------------------
# PolicyResult
# ---------------------------------------------------------------------------

@dataclass
class LicensePolicyResult:
    """Result of evaluating a single package against the license policy."""
    package_name: str
    version: str | None
    license_str: str
    category: str
    status: str  # "allowed", "denied", "exception", "unknown"
    reason: str = ""


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class LicenseScanner:
    """Policy-aware license compliance scanner.

    Usage::

        scanner = LicenseScanner()
        findings = scanner.scan(packages, project_dir=Path("."))
    """

    name = "license_compliance"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    def scan(
        self,
        packages: list[PackageMeta | PackageId],
        project_dir: Path | str = ".",
    ) -> list[Finding]:
        """Scan *packages* for license compliance against the project policy.

        Parameters
        ----------
        packages:
            List of :class:`~depfence.core.models.PackageMeta` or
            :class:`~depfence.core.models.PackageId` objects.
        project_dir:
            Directory containing ``depfence.yml`` with the ``licenses:`` section.

        Returns
        -------
        list[Finding]
            One finding per package that violates the policy or has unknown/risky
            license. Packages that are explicitly allowed produce no findings.
        """
        project_dir = Path(project_dir)
        policy = _load_policy(project_dir)

        allow_cats: set[str] = set(policy.get("allow", _DEFAULT_POLICY["allow"]))
        deny_cats: set[str] = set(policy.get("deny", _DEFAULT_POLICY["deny"]))
        exceptions: list[dict[str, str]] = policy.get("exceptions", [])
        exception_names: set[str] = {e["package"] for e in exceptions if "package" in e}

        findings: list[Finding] = []
        for pkg_obj in packages:
            if isinstance(pkg_obj, PackageMeta):
                pkg = pkg_obj.pkg
                license_str = pkg_obj.license or ""
            elif isinstance(pkg_obj, PackageId):
                pkg = pkg_obj
                license_str = ""
            else:
                continue

            finding = self._evaluate_package(
                pkg, license_str, allow_cats, deny_cats, exception_names
            )
            if finding is not None:
                findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_license_info(self, license_str: str) -> dict[str, Any]:
        """Return category and OSI-approval status for a license string."""
        category = resolve_spdx_expression_category(license_str)
        # Try exact lookup in DB for osi_approved
        osi_approved: bool | None = None
        ids = parse_spdx_expression(license_str)
        for sid in ids:
            if sid in _LICENSE_DB:
                osi_approved = _LICENSE_DB[sid].get("osi_approved")
                break
            upper = sid.upper()
            if upper in _LICENSE_DB_UPPER:
                canonical = _LICENSE_DB_UPPER[upper]
                osi_approved = _LICENSE_DB[canonical].get("osi_approved")
                break
        return {
            "category": category,
            "osi_approved": osi_approved,
            "label": _CATEGORY_LABELS.get(category, category),
        }

    def evaluate_policy(
        self,
        packages: list[PackageMeta | PackageId],
        project_dir: Path | str = ".",
    ) -> list[LicensePolicyResult]:
        """Return structured policy results (for table rendering) without Finding objects."""
        project_dir = Path(project_dir)
        policy = _load_policy(project_dir)
        allow_cats = set(policy.get("allow", _DEFAULT_POLICY["allow"]))
        deny_cats = set(policy.get("deny", _DEFAULT_POLICY["deny"]))
        exceptions_list = policy.get("exceptions", [])
        exception_names = {e["package"] for e in exceptions_list if "package" in e}

        results: list[LicensePolicyResult] = []
        for pkg_obj in packages:
            if isinstance(pkg_obj, PackageMeta):
                pkg = pkg_obj.pkg
                license_str = pkg_obj.license or ""
            elif isinstance(pkg_obj, PackageId):
                pkg = pkg_obj
                license_str = ""
            else:
                continue

            category = resolve_spdx_expression_category(license_str) if license_str else "unknown"

            # Check exceptions first
            if pkg.name in exception_names:
                exc = next((e for e in exceptions_list if e.get("package") == pkg.name), {})
                results.append(LicensePolicyResult(
                    package_name=pkg.name,
                    version=pkg.version,
                    license_str=license_str or "UNKNOWN",
                    category=category,
                    status="exception",
                    reason=exc.get("reason", ""),
                ))
                continue

            if not license_str:
                status = "unknown"
            elif category in deny_cats:
                status = "denied"
            elif category in allow_cats:
                status = "allowed"
            else:
                status = "unknown"

            results.append(LicensePolicyResult(
                package_name=pkg.name,
                version=pkg.version,
                license_str=license_str or "UNKNOWN",
                category=category,
                status=status,
            ))

        return results

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _evaluate_package(
        self,
        pkg: PackageId,
        license_str: str,
        allow_cats: set[str],
        deny_cats: set[str],
        exception_names: set[str],
    ) -> Finding | None:
        """Return a Finding if this package violates policy, else None."""
        # Exceptions are always allowed — skip
        if pkg.name in exception_names:
            return None

        # No license at all → HIGH risk
        if not license_str or not license_str.strip():
            return Finding(
                finding_type=FindingType.LICENSE,
                severity=Severity.HIGH,
                package=pkg,
                title=f"{pkg.name} has no license (legal risk)",
                detail=(
                    f"No license was detected for {pkg.name}. Without a clear license "
                    "this package cannot legally be used in most commercial products. "
                    "Review the package repository and contact the maintainer."
                ),
                confidence=1.0,
                metadata={
                    "license": "UNKNOWN",
                    "category": "unknown",
                    "status": "denied",
                    "osi_approved": None,
                },
            )

        category = resolve_spdx_expression_category(license_str)

        # Explicitly denied categories always produce a finding
        if category in deny_cats:
            severity = _CATEGORY_SEVERITY.get(category, Severity.HIGH)
            return Finding(
                finding_type=FindingType.LICENSE,
                severity=severity,
                package=pkg,
                title=f"{pkg.name} uses {license_str} ({_CATEGORY_LABELS.get(category, category)}) — policy violation",
                detail=(
                    f"{pkg.name} is licensed under {license_str!r}. This falls into the "
                    f"{_CATEGORY_LABELS.get(category, category)!r} category which is "
                    "denied by your license policy. Review and either replace the package "
                    "or add an exception in depfence.yml."
                ),
                confidence=1.0,
                metadata={
                    "license": license_str,
                    "category": category,
                    "status": "denied",
                    "osi_approved": self.get_license_info(license_str).get("osi_approved"),
                },
            )

        # Explicitly allowed → no finding
        if category in allow_cats:
            return None

        # Neither allowed nor denied → unknown/warn
        if category == "unknown":
            return Finding(
                finding_type=FindingType.LICENSE,
                severity=Severity.HIGH,
                package=pkg,
                title=f"{pkg.name} has unrecognised license {license_str!r}",
                detail=(
                    f"The license {license_str!r} for {pkg.name} is not recognised. "
                    "Unrecognised licenses may carry legal risk. Verify the license "
                    "manually and add it to your policy."
                ),
                confidence=0.8,
                metadata={
                    "license": license_str,
                    "category": "unknown",
                    "status": "unknown",
                    "osi_approved": None,
                },
            )

        # Category exists but is not in allow or deny — produce a LOW advisory
        return Finding(
            finding_type=FindingType.LICENSE,
            severity=Severity.LOW,
            package=pkg,
            title=f"{pkg.name} uses {license_str} ({_CATEGORY_LABELS.get(category, category)}) — review required",
            detail=(
                f"{pkg.name} is licensed under {license_str!r} "
                f"({_CATEGORY_LABELS.get(category, category)}). This category is not "
                "explicitly allowed or denied in your policy. Review and update depfence.yml."
            ),
            confidence=0.9,
            metadata={
                "license": license_str,
                "category": category,
                "status": "unknown",
                "osi_approved": self.get_license_info(license_str).get("osi_approved"),
            },
        )
