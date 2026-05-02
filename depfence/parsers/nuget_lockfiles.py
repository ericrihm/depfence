"""Parsers for NuGet ecosystem lockfiles (packages.lock.json and packages.config)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from depfence.core.models import PackageId


def parse_packages_lock_json(path: Path) -> list[PackageId]:
    """Parse .NET packages.lock.json and return a list of PackageId instances.

    The lockfile groups dependencies by target framework (e.g. ``net8.0``).
    Both Direct and Transitive dependencies are included.  Duplicate
    ``(name, version)`` pairs that appear in multiple target frameworks are
    deduplicated so each package is reported only once.

    Args:
        path: Absolute path to a ``packages.lock.json`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='nuget'``.
    """
    data = json.loads(path.read_text(encoding="utf-8"))

    seen: set[tuple[str, str | None]] = set()
    packages: list[PackageId] = []

    dependencies = data.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return packages

    for _framework, pkgs in dependencies.items():
        if not isinstance(pkgs, dict):
            continue
        for name, info in pkgs.items():
            if not isinstance(info, dict):
                continue
            version: str | None = info.get("resolved") or None
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            packages.append(
                PackageId(
                    ecosystem="nuget",
                    name=name,
                    version=version,
                )
            )

    return packages


def parse_packages_config(path: Path) -> list[PackageId]:
    """Parse a legacy NuGet packages.config XML file.

    Each ``<package id="..." version="..." />`` element becomes one
    :class:`~depfence.core.models.PackageId`.  Elements missing the ``id``
    attribute are skipped.

    Args:
        path: Absolute path to a ``packages.config`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='nuget'``.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    # The root element is <packages>; child elements are <package>.
    # ElementTree uses the local tag name directly because packages.config
    # carries no XML namespace.
    packages: list[PackageId] = []

    # Support both the root being <packages> (standard) and the file
    # being a bare list with <package> as the root (non-standard but seen
    # in the wild).
    if root.tag == "package":
        package_elems = [root]
    else:
        package_elems = root.findall("package")

    for pkg in package_elems:
        name = pkg.get("id", "").strip()
        if not name:
            continue
        version: str | None = (pkg.get("version") or "").strip() or None
        packages.append(
            PackageId(
                ecosystem="nuget",
                name=name,
                version=version,
            )
        )

    return packages


def detect_nuget_lockfiles(project_dir: Path) -> list[tuple[str, Path]]:
    """Find NuGet lockfiles in *project_dir* recursively.

    Searches for:

    * ``packages.lock.json`` — .NET SDK lockfile (any depth).
    * ``packages.config`` — Legacy NuGet package reference file (any depth).

    Args:
        project_dir: Root directory to search.

    Returns:
        List of ``(file_type, absolute_path)`` tuples where *file_type* is one
        of ``"packages.lock.json"`` or ``"packages.config"``.
    """
    results: list[tuple[str, Path]] = []

    for lockfile in project_dir.rglob("packages.lock.json"):
        results.append(("packages.lock.json", lockfile))

    for config in project_dir.rglob("packages.config"):
        results.append(("packages.config", config))

    return results
