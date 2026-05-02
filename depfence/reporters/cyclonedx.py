"""CycloneDX 1.5 SBOM generator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_ECOSYSTEM_TO_PURL_TYPE: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "go": "golang",
    "maven": "maven",
    "nuget": "nuget",
}

# Severity enum value -> CycloneDX severity string
_SEVERITY_MAP: dict[str, str] = {
    Severity.CRITICAL.value: "critical",
    Severity.HIGH.value: "high",
    Severity.MEDIUM.value: "medium",
    Severity.LOW.value: "low",
    Severity.INFO.value: "info",
}

_SOURCE = {"name": "depfence", "url": "https://github.com/ericrihm/depfence"}


def _purl_type(ecosystem: str) -> str:
    return _ECOSYSTEM_TO_PURL_TYPE.get(ecosystem.lower(), ecosystem.lower())


def _bom_ref(pkg: PackageId) -> str:
    version = pkg.version or ""
    return f"{pkg.ecosystem}:{pkg.name}@{version}"


def _purl(pkg: PackageId) -> str:
    ptype = _purl_type(pkg.ecosystem)
    version = pkg.version or ""
    return f"pkg:{ptype}/{pkg.name}@{version}"


def _build_component(pkg: PackageId) -> dict:
    return {
        "type": "library",
        "name": pkg.name,
        "version": pkg.version or "",
        "purl": _purl(pkg),
        "bom-ref": _bom_ref(pkg),
    }


def _build_vulnerability(finding: Finding) -> dict | None:
    """Return a CycloneDX VEX vulnerability entry for a KNOWN_VULN finding, or None.

    Only findings with a CVE identifier are included; findings without a CVE
    fall back to the title for the ``id`` field.  Non-KNOWN_VULN findings are
    excluded entirely.
    """
    if finding.finding_type != FindingType.KNOWN_VULN:
        return None

    # Require a CVE; use the title as a fallback only when cve is absent.
    vuln_id = finding.cve or finding.title

    severity_str = _SEVERITY_MAP.get(finding.severity.value, "unknown")

    vuln: dict = {
        "id": vuln_id,
        "source": _SOURCE,
        "ratings": [{"severity": severity_str, "method": "other"}],
        "description": finding.detail,
        "affects": [{"ref": _bom_ref(finding.package)}],
    }

    # Recommendation: include only when a fix version is known.
    if finding.fix_version:
        vuln["recommendation"] = f"Upgrade to {finding.fix_version}"

    # VEX analysis block.
    epss_score = finding.metadata.get("epss_score")
    analysis_detail = f"EPSS score: {epss_score}" if epss_score is not None else None

    # Determine exploitability state: use EPSS score as a signal when available.
    if epss_score is not None and float(epss_score) > 0:
        state = "exploitable"
    else:
        state = "in_triage"

    analysis: dict = {"state": state}
    if analysis_detail:
        analysis["detail"] = analysis_detail

    vuln["analysis"] = analysis

    return vuln


def generate_sbom(
    packages: list[PackageId],
    findings: list[Finding],
    project_name: str = "",
    project_version: str = "",
) -> dict:
    """Generate a CycloneDX 1.5 compliant SBOM as a dict.

    Args:
        packages: List of packages to include as components.
        findings: List of scan findings; only KNOWN_VULN findings are mapped to
                  CycloneDX vulnerabilities.
        project_name: Name of the scanned project (used in metadata.component).
        project_version: Version of the scanned project.

    Returns:
        CycloneDX 1.5 SBOM as a Python dict suitable for JSON serialisation.
    """
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    components = [_build_component(pkg) for pkg in packages]

    vulnerabilities = []
    for finding in findings:
        vuln = _build_vulnerability(finding)
        if vuln is not None:
            vulnerabilities.append(vuln)

    # Minimal dependency entries — each component depends on nothing by default.
    dependencies = [{"ref": _bom_ref(pkg), "dependsOn": []} for pkg in packages]

    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": serial_number,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "depfence",
                    "name": "depfence",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
        "dependencies": dependencies,
    }
    return sbom


def write_sbom(sbom: dict, output: Path) -> None:
    """Write a CycloneDX SBOM dict to *output* as indented JSON.

    Args:
        sbom: SBOM dict produced by :func:`generate_sbom`.
        output: Destination file path.
    """
    output.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
