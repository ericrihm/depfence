"""Tool implementations for the depfence MCP server.

Each tool takes typed parameters and returns structured, JSON-serialisable
results. Tools are designed to be fast — they prefer cached data and
short-circuit expensive network calls when possible.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    """A single advisory / CVE for a package."""
    id: str
    summary: str
    severity: str
    fixed_version: str | None
    references: list[str] = field(default_factory=list)
    published: str = ""


@dataclass
class CheckResult:
    """Structured result returned by check_package and similar tools."""
    package: str
    ecosystem: str
    version: str | None
    safe: bool
    risk_score: int          # 0 – 100
    findings: list[dict[str, Any]] = field(default_factory=list)
    advisories: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProjectScanResult:
    """Aggregated result returned by scan_project."""
    path: str
    packages_scanned: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TyposquatResult:
    """Result of a typosquat check."""
    package: str
    ecosystem: str
    is_typosquat: bool
    confidence: float
    similar_to: str | None
    reason: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LicenseResult:
    """Result of a license compliance check."""
    package: str
    ecosystem: str
    license: str
    tier: str
    severity: str | None
    commercial_use_ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AlternativeResult:
    """Suggested safer alternatives for a package."""
    package: str
    ecosystem: str
    alternatives: list[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Severity conversion helpers
# ---------------------------------------------------------------------------

def _severity_to_score(severity: Severity) -> int:
    """Map Severity enum to a 0-100 risk contribution."""
    return {
        Severity.CRITICAL: 90,
        Severity.HIGH: 70,
        Severity.MEDIUM: 40,
        Severity.LOW: 15,
        Severity.INFO: 5,
    }.get(severity, 10)


def _compute_risk_score(findings: list[Finding]) -> int:
    """Compute an overall risk score 0-100 from a list of findings."""
    if not findings:
        return 0
    max_score = max(_severity_to_score(f.severity) for f in findings)
    # Accumulate extra points for multiple findings (capped)
    extra = min(len(findings) - 1, 5) * 3
    return min(max_score + extra, 100)


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "type": f.finding_type.value,
        "severity": f.severity.value,
        "title": f.title,
        "detail": f.detail,
        "cve": f.cve,
        "fix_version": f.fix_version,
        "confidence": f.confidence,
        "references": f.references,
    }


def _build_recommendation(findings: list[Finding], safe: bool) -> str:
    if safe:
        return "No issues found. Package appears safe to use."
    types = {f.finding_type for f in findings}
    if FindingType.MALICIOUS in types:
        return "DO NOT USE — package flagged as malicious."
    if FindingType.TYPOSQUAT in types:
        return "Possible typosquat — verify the package name carefully before installing."
    if FindingType.KNOWN_VULN in types:
        cve_finding = next((f for f in findings if f.cve), None)
        if cve_finding and cve_finding.fix_version:
            return f"Vulnerability found — upgrade to {cve_finding.fix_version} or later."
        return "Known vulnerabilities found — review and upgrade if a fix is available."
    if FindingType.DEP_CONFUSION in types:
        return "Dependency confusion risk — verify registry configuration."
    if FindingType.LICENSE in types:
        lic_finding = next((f for f in findings if f.finding_type == FindingType.LICENSE), None)
        return f"License issue detected: {lic_finding.title if lic_finding else 'review required'}."
    severities = sorted({f.severity for f in findings}, key=lambda s: _severity_to_score(s), reverse=True)
    return f"Issues found ({severities[0].value} severity) — review before using."


# ---------------------------------------------------------------------------
# Alternatives database (lightweight, no network required)
# ---------------------------------------------------------------------------

_ALTERNATIVES: dict[str, dict[str, list[str]]] = {
    "npm": {
        "request": ["axios", "got", "node-fetch", "undici"],
        "lodash": ["lodash-es", "radash", "just"],
        "moment": ["date-fns", "dayjs", "luxon"],
        "chalk": ["kleur", "colorette", "picocolors"],
        "uuid": ["nanoid", "crypto.randomUUID (built-in)"],
        "colors": ["chalk", "kleur", "colorette"],
        "left-pad": ["String.prototype.padStart (built-in)"],
        "is": ["type-fest"],
    },
    "pypi": {
        "requests": ["httpx", "aiohttp", "urllib.request (stdlib)"],
        "pyyaml": ["ruamel.yaml", "strictyaml"],
        "pickle": ["json (stdlib)", "msgpack", "cloudpickle"],
        "simplejson": ["json (stdlib)", "orjson", "ujson"],
        "nose": ["pytest", "unittest (stdlib)"],
        "mock": ["unittest.mock (stdlib)"],
    },
}


# ---------------------------------------------------------------------------
# McpTools — the actual tool implementations
# ---------------------------------------------------------------------------

class McpTools:
    """Container for all MCP tool implementations.

    Designed for fast, low-latency use: prefers cached advisories, does
    minimal network I/O where possible.
    """

    # ------------------------------------------------------------------
    # check_package
    # ------------------------------------------------------------------

    async def check_package(
        self,
        name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> CheckResult:
        """Security check for a single package.

        Runs reputation, typosquat, depconfusion, and OSV checks. Results
        from OSV are cached so repeated queries are instant.
        """
        ecosystem = ecosystem.lower()
        pkg = PackageId(ecosystem=ecosystem, name=name, version=version)

        findings: list[Finding] = []
        advisories: list[Advisory] = []
        cached = False

        # 1. Reputation + typosquat (synchronous, no network)
        try:
            from depfence.scanners.reputation import ReputationScanner
            rep = ReputationScanner()
            meta = PackageMeta(pkg=pkg)
            rep_findings = rep.analyze(meta)
            findings.extend(rep_findings)
        except Exception as exc:  # noqa: BLE001
            log.debug("reputation scan error for %s: %s", name, exc)

        # 2. Dep-confusion (synchronous analysis, no network needed for basic check)
        try:
            from depfence.scanners.depconfusion import DepConfusionScanner
            dc = DepConfusionScanner()
            meta = PackageMeta(pkg=pkg)
            dc_findings = await dc.scan([meta])
            findings.extend(dc_findings)
        except Exception as exc:  # noqa: BLE001
            log.debug("depconfusion scan error for %s: %s", name, exc)

        # 3. OSV advisories (network, but uses cache)
        try:
            from depfence.core.osv_client import OsvClient
            async with OsvClient() as client:
                result = await client.query_package(
                    name=name,
                    ecosystem=ecosystem,
                    version=version,
                )
            for vuln in result:
                advisories.append(Advisory(
                    id=vuln.id,
                    summary=vuln.summary,
                    severity=vuln.severity,
                    fixed_version=vuln.fixed_version,
                    references=vuln.references,
                    published=vuln.published,
                ))
                # Also add as a Finding for unified scoring
                from depfence.scanners.osv_scanner import _vuln_to_finding
                findings.append(_vuln_to_finding(pkg, vuln))
            cached = False  # OSV client caches internally; we can't easily tell
        except Exception as exc:  # noqa: BLE001
            log.debug("OSV query error for %s: %s", name, exc)

        risk_score = _compute_risk_score(findings)
        safe = risk_score == 0

        return CheckResult(
            package=name,
            ecosystem=ecosystem,
            version=version,
            safe=safe,
            risk_score=risk_score,
            findings=[_finding_to_dict(f) for f in findings],
            advisories=[{
                "id": a.id,
                "summary": a.summary,
                "severity": a.severity,
                "fixed_version": a.fixed_version,
                "references": a.references,
                "published": a.published,
            } for a in advisories],
            recommendation=_build_recommendation(findings, safe),
            cached=cached,
        )

    # ------------------------------------------------------------------
    # scan_project
    # ------------------------------------------------------------------

    async def scan_project(self, path: str | None = None) -> ProjectScanResult:
        """Full project scan — discovers lockfiles and runs all scanners."""
        from depfence.core.engine import scan_directory
        from depfence.core.models import Severity as Sev

        project_dir = Path(path or ".").resolve()

        try:
            result = await scan_directory(
                project_dir,
                skip_advisory=False,
                skip_behavioral=False,
                skip_reputation=False,
                fetch_metadata=True,
                project_scanners=True,
                enrich=False,   # skip EPSS/KEV enrichment for speed
                use_cache=True,
            )
        except Exception as exc:  # noqa: BLE001
            return ProjectScanResult(
                path=str(project_dir),
                packages_scanned=0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                errors=[str(exc)],
            )

        return ProjectScanResult(
            path=str(project_dir),
            packages_scanned=result.packages_scanned,
            findings_count=len(result.findings),
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=sum(1 for f in result.findings if f.severity == Sev.MEDIUM),
            low_count=sum(1 for f in result.findings if f.severity == Sev.LOW),
            findings=[_finding_to_dict(f) for f in result.findings],
            errors=result.errors,
        )

    # ------------------------------------------------------------------
    # is_typosquat
    # ------------------------------------------------------------------

    async def is_typosquat(self, name: str, ecosystem: str) -> TyposquatResult:
        """Check if a package name looks like a typosquat of a popular package."""
        ecosystem = ecosystem.lower()
        pkg = PackageId(ecosystem=ecosystem, name=name)
        meta = PackageMeta(pkg=pkg)

        try:
            from depfence.scanners.reputation import ReputationScanner
            rep = ReputationScanner()
            findings = rep._check_typosquat(meta)
        except Exception as exc:  # noqa: BLE001
            log.debug("typosquat check error: %s", exc)
            findings = []

        if findings:
            f = findings[0]
            return TyposquatResult(
                package=name,
                ecosystem=ecosystem,
                is_typosquat=True,
                confidence=f.confidence,
                similar_to=str(f.metadata.get("similar_to", "")),
                reason=str(f.metadata.get("reason", f.detail)),
                severity=f.severity.value,
            )

        return TyposquatResult(
            package=name,
            ecosystem=ecosystem,
            is_typosquat=False,
            confidence=0.0,
            similar_to=None,
            reason="No similar popular packages found.",
            severity="none",
        )

    # ------------------------------------------------------------------
    # get_advisories
    # ------------------------------------------------------------------

    async def get_advisories(
        self,
        package: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get known CVEs / advisories for a package from OSV.dev."""
        ecosystem = ecosystem.lower()
        advisories: list[dict[str, Any]] = []

        try:
            from depfence.core.osv_client import OsvClient
            async with OsvClient() as client:
                vulns = await client.query_package(
                    name=package,
                    ecosystem=ecosystem,
                    version=version,
                )
            for v in vulns:
                advisories.append({
                    "id": v.id,
                    "summary": v.summary,
                    "severity": v.severity,
                    "fixed_version": v.fixed_version,
                    "affected_versions": v.affected_versions,
                    "references": v.references,
                    "published": v.published,
                })
        except Exception as exc:  # noqa: BLE001
            log.debug("get_advisories error for %s/%s: %s", ecosystem, package, exc)

        return advisories

    # ------------------------------------------------------------------
    # suggest_alternative
    # ------------------------------------------------------------------

    async def suggest_alternative(
        self,
        package: str,
        ecosystem: str,
    ) -> AlternativeResult:
        """Suggest safer or better-maintained alternatives for a package."""
        ecosystem = ecosystem.lower()
        eco_alts = _ALTERNATIVES.get(ecosystem, {})
        alternatives = eco_alts.get(package.lower(), [])

        if alternatives:
            reason = f"'{package}' has well-maintained alternatives with better security track records."
        else:
            reason = (
                f"No specific alternatives indexed for '{package}' in {ecosystem}. "
                "Search the registry for actively maintained packages with similar functionality."
            )

        return AlternativeResult(
            package=package,
            ecosystem=ecosystem,
            alternatives=alternatives,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # check_license
    # ------------------------------------------------------------------

    async def check_license(
        self,
        package: str,
        ecosystem: str,
        version: str | None = None,
    ) -> LicenseResult:
        """License compliance check for a package."""
        ecosystem = ecosystem.lower()
        pkg = PackageId(ecosystem=ecosystem, name=package, version=version)

        # Try to fetch real license from registry
        license_str = ""
        try:
            from depfence.core.fetcher import fetch_meta
            meta = await fetch_meta(pkg)
            license_str = meta.license or ""
        except Exception as exc:  # noqa: BLE001
            log.debug("fetch_meta error for license check %s: %s", package, exc)
            meta = PackageMeta(pkg=pkg)

        if not license_str:
            license_str = "UNKNOWN"

        # Classify using the license scanner
        try:
            from depfence.scanners.license_scanner import LicenseScanner
            ls = LicenseScanner()
            tier, severity = ls.classify_license(license_str)
        except Exception as exc:  # noqa: BLE001
            log.debug("license classify error: %s", exc)
            tier = "UNKNOWN"
            severity = Severity.MEDIUM

        _tier_labels = {
            "CRITICAL": "Viral copyleft — incompatible with commercial use",
            "HIGH": "Strong copyleft — commercial use likely blocked",
            "MEDIUM": "Weak copyleft / restrictive conditions",
            "LOW": "Permissive with notable conditions",
            "CLEAN": "Permissive — no commercial restrictions",
            "UNKNOWN": "License unknown — treat as risky",
        }
        commercial_ok = tier in ("CLEAN", "LOW", "MEDIUM")
        detail = _tier_labels.get(tier, "Unknown tier")

        return LicenseResult(
            package=package,
            ecosystem=ecosystem,
            license=license_str,
            tier=tier,
            severity=severity.value if severity else None,
            commercial_use_ok=commercial_ok,
            detail=detail,
        )
