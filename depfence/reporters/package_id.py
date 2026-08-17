"""Standards-compliant package identity helpers shared by SBOM reporters."""

from __future__ import annotations

from packageurl import PackageURL

from depfence.core.models import PackageId

_PURL_TYPES = {
    "npm": "npm",
    "pypi": "pypi",
    "cargo": "cargo",
    "go": "golang",
    "golang": "golang",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "gem",
    "gem": "gem",
    "composer": "composer",
    "swift": "swift",
    "dart": "pub",
    "pub": "pub",
}


def package_purl(pkg: PackageId) -> str:
    """Build a canonical Package URL, including ecosystem-specific namespaces."""
    ptype = _PURL_TYPES.get(pkg.ecosystem.lower(), pkg.ecosystem.lower())
    raw_name = pkg.name.strip()
    namespace: str | None = None
    name = raw_name

    if ptype == "npm" and raw_name.startswith("@") and "/" in raw_name:
        namespace, name = raw_name.split("/", 1)
    elif ptype == "maven" and ":" in raw_name:
        namespace, name = raw_name.split(":", 1)
    elif ptype in {"golang", "composer", "swift"} and "/" in raw_name:
        namespace, name = raw_name.rsplit("/", 1)

    return str(
        PackageURL(
            type=ptype,
            namespace=namespace,
            name=name,
            version=pkg.version or None,
        ).to_string()
    )


def package_key(pkg: PackageId) -> tuple[str, str, str]:
    return (pkg.ecosystem.lower(), pkg.name, pkg.version or "")


def coerce_package_id(value: PackageId | str) -> PackageId:
    """Normalize legacy scanners that still return string package identities."""
    if isinstance(value, PackageId):
        return value
    raw = str(value)
    ecosystem, separator, remainder = raw.partition(":")
    if not separator:
        return PackageId("unknown", raw)
    name, version_separator, version = remainder.rpartition("@")
    if version_separator and name:
        return PackageId(ecosystem or "unknown", name, version or None)
    return PackageId(ecosystem or "unknown", remainder)
