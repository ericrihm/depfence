"""SPDX 2.3 SBOM generator."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from depfence.core.models import PackageId, ScanResult

_ECOSYSTEM_TO_PURL_TYPE: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "go": "golang",
    "maven": "maven",
    "nuget": "nuget",
}

_TOOL_VERSION = "depfence-0.4.0"
_NAMESPACE_BASE = "https://depfence.dev/spdx"


def _purl_type(ecosystem: str) -> str:
    return _ECOSYSTEM_TO_PURL_TYPE.get(ecosystem.lower(), ecosystem.lower())


def _purl(pkg: PackageId) -> str:
    ptype = _purl_type(pkg.ecosystem)
    version = pkg.version or ""
    return f"pkg:{ptype}/{pkg.name}@{version}"


def _spdx_id(pkg: PackageId) -> str:
    """Return a valid SPDX element ID for a package (SPDXRef-<sanitised>)."""
    safe = f"{pkg.ecosystem}-{pkg.name}-{pkg.version or 'unversioned'}"
    # Replace chars that are not alphanumeric, hyphen, or dot
    safe = "".join(c if c.isalnum() or c in "-." else "-" for c in safe)
    return f"SPDXRef-{safe}"


def _build_package(pkg: PackageId) -> dict:
    return {
        "SPDXID": _spdx_id(pkg),
        "name": pkg.name,
        "versionInfo": pkg.version or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "supplier": "NOASSERTION",
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl(pkg),
            }
        ],
    }


def _assemble_doc(pkg_list: list[PackageId], project_name: str) -> dict:
    """Build the SPDX 2.3 document dict from a resolved package list."""
    name = project_name or "depfence-scan"
    doc_uuid = uuid.uuid4()
    namespace = f"{_NAMESPACE_BASE}/{name}/{doc_uuid}"
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    spdx_packages = [_build_package(pkg) for pkg in pkg_list]

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": _spdx_id(pkg),
        }
        for pkg in pkg_list
    ]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [f"Tool: {_TOOL_VERSION}"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def generate_spdx(result: ScanResult, project_name: str = "") -> dict:
    """Generate a valid SPDX 2.3 JSON document from a scan result.

    Package list is derived from the findings on *result*. For full package
    coverage (including packages without findings) use
    :func:`generate_spdx_with_packages`.

    Args:
        result: Scan result whose findings are used to enumerate packages.
        project_name: Document name. Defaults to ``"depfence-scan"``.

    Returns:
        SPDX 2.3 document as a Python dict ready for JSON serialisation.
    """
    packages_seen: dict[str, PackageId] = {}
    for finding in result.findings:
        pkg = finding.package
        key = str(pkg)
        if key not in packages_seen:
            packages_seen[key] = pkg

    return _assemble_doc(list(packages_seen.values()), project_name)


def generate_spdx_with_packages(
    result: ScanResult,
    packages: list[PackageId],
    project_name: str = "",
) -> dict:
    """Generate a valid SPDX 2.3 JSON document from an explicit package list.

    Preferred entry-point for the CLI ``sbom --format spdx`` command where the
    full lockfile package list is already available independently of findings.

    Args:
        result: Scan result (findings are ignored).
        packages: Explicit list of packages to include as SPDX packages.
        project_name: Document name. Defaults to ``"depfence-scan"``.

    Returns:
        SPDX 2.3 document as a Python dict ready for JSON serialisation.
    """
    seen: dict[str, PackageId] = {}
    for pkg in packages:
        key = str(pkg)
        if key not in seen:
            seen[key] = pkg

    return _assemble_doc(list(seen.values()), project_name)
