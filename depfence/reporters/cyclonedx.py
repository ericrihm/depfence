"""CycloneDX 1.7 (and compatibility 1.5) SBOM generator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from depfence import __version__
from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.reporters.package_id import coerce_package_id, package_key, package_purl

SUPPORTED_SPEC_VERSIONS = ("1.7", "1.5")

_SEVERITY_MAP = {severity.value: severity.value for severity in Severity}
_SOURCE = {"name": "depfence", "url": "https://github.com/ericrihm/depfence"}


def _purl(pkg: PackageId) -> str:
    return cast(str, package_purl(pkg))


def _bom_ref(pkg: PackageId) -> str:
    return cast(str, package_purl(pkg))


def _build_component(pkg: PackageId) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": pkg.name,
        "purl": package_purl(pkg),
        "bom-ref": _bom_ref(pkg),
    }
    if pkg.version:
        component["version"] = pkg.version
    return component


def _explicitly_exploitable(finding: Finding) -> bool:
    """Only direct exploitability evidence can produce a VEX exploitable state."""
    return any(
        finding.metadata.get(key) is True
        for key in ("exploitable", "known_exploited", "kev", "cisa_kev", "in_kev")
    )


def _build_vulnerability(finding: Finding) -> dict[str, Any] | None:
    if finding.finding_type != FindingType.KNOWN_VULN:
        return None

    package = coerce_package_id(finding.package)
    vuln: dict[str, Any] = {
        "id": finding.cve or finding.title,
        "source": _SOURCE,
        "ratings": [{"severity": _SEVERITY_MAP.get(finding.severity.value, "unknown"), "method": "other"}],
        "description": finding.detail,
        "affects": [{"ref": _bom_ref(package)}],
        "analysis": {"state": "exploitable" if _explicitly_exploitable(finding) else "in_triage"},
    }
    if finding.fix_version:
        vuln["recommendation"] = f"Upgrade to {finding.fix_version}"
    epss_score = finding.metadata.get("epss_score")
    if epss_score is not None:
        vuln["analysis"]["detail"] = f"EPSS score: {epss_score}"
    return vuln


def generate_sbom(
    packages: list[PackageId],
    findings: list[Finding],
    project_name: str = "",
    project_version: str = "",
    spec_version: str = "1.7",
) -> dict[str, Any]:
    """Generate a CycloneDX SBOM; 1.7 is default and 1.5 is supported explicitly."""
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise ValueError(
            f"unsupported CycloneDX version {spec_version!r}; choose one of {SUPPORTED_SPEC_VERSIONS}"
        )

    unique_packages = list({package_key(pkg): pkg for pkg in packages}.values())
    components = [_build_component(pkg) for pkg in unique_packages]

    vulnerabilities: list[dict[str, Any]] = []
    vulnerability_keys: set[tuple[str, str]] = set()
    for finding in findings:
        vuln = _build_vulnerability(finding)
        if vuln is None:
            continue
        key = (str(vuln["id"]), str(vuln["affects"][0]["ref"]))
        if key not in vulnerability_keys:
            vulnerability_keys.add(key)
            vulnerabilities.append(vuln)

    tool_component = {
        "type": "application",
        "manufacturer": {"name": "depfence"},
        "name": "depfence",
        "version": __version__,
    }
    tools: Any
    if spec_version == "1.5":
        tools = [{"vendor": "depfence", "name": "depfence", "version": __version__}]
    else:
        tools = {"components": [tool_component]}

    project_component: dict[str, Any] = {
        "type": "application",
        "name": project_name or "depfence-scan",
    }
    if project_version:
        project_component["version"] = project_version

    return {
        "$schema": f"https://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": tools,
            "component": project_component,
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
        "dependencies": [{"ref": component["bom-ref"], "dependsOn": []} for component in components],
    }


def write_sbom(sbom: dict[str, Any], output: Path) -> None:
    output.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
