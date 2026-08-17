"""SPDX 2.3 SBOM generator."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from depfence import __version__
from depfence.core.models import PackageId, ScanResult
from depfence.reporters.package_id import coerce_package_id, package_key, package_purl

_TOOL_VERSION = f"depfence-{__version__}"
_NAMESPACE_BASE = "https://github.com/ericrihm/depfence/spdx"


def _purl(pkg: PackageId) -> str:
    return package_purl(pkg)


def _spdx_id(pkg: PackageId) -> str:
    """Return a valid SPDX element ID for a package (SPDXRef-<sanitised>)."""
    safe = f"{pkg.ecosystem}-{pkg.name}-{pkg.version or 'unversioned'}"
    # Replace chars that are not alphanumeric, hyphen, or dot
    safe = "".join(c if c.isalnum() or c in "-." else "-" for c in safe)
    digest = hashlib.sha256(package_purl(pkg).encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{safe}-{digest}"


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


def _assemble_doc(pkg_list: list[PackageId], project_name: str, spec_version: str = "2.3") -> dict:
    """Build the SPDX 2.3 document dict from a resolved package list."""
    if spec_version != "2.3":
        raise ValueError("DepFence supports SPDX 2.3 JSON only")
    name = project_name or "depfence-scan"
    doc_uuid = uuid.uuid4()
    namespace = f"{_NAMESPACE_BASE}/{quote(name, safe='')}/{doc_uuid}"
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


def generate_spdx(result: ScanResult, project_name: str = "", spec_version: str = "2.3") -> dict:
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
        pkg = coerce_package_id(finding.package)
        key = str(pkg)
        if key not in packages_seen:
            packages_seen[key] = pkg

    return _assemble_doc(list(packages_seen.values()), project_name, spec_version)


def generate_spdx_with_packages(
    result: ScanResult,
    packages: list[PackageId],
    project_name: str = "",
    spec_version: str = "2.3",
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
    seen: dict[tuple[str, str, str], PackageId] = {}
    for pkg in packages:
        key = package_key(pkg)
        if key not in seen:
            seen[key] = pkg

    return _assemble_doc(list(seen.values()), project_name, spec_version)
