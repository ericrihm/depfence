"""Parsers for JVM ecosystem lockfiles (Maven pom.xml and Gradle lockfile)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from depfence.core.models import PackageId

# Maven XML namespace used in POM 4.0 files
_MAVEN_NS = "http://maven.apache.org/POM/4.0.0"

# Scopes that should be excluded from runtime dependency analysis
_EXCLUDED_SCOPES = {"test", "provided"}


def parse_pom_xml(path: Path) -> list[PackageId]:
    """Parse Maven pom.xml and return a list of PackageId instances.

    Only runtime/compile-scoped dependencies are returned; dependencies with
    ``<scope>test</scope>`` or ``<scope>provided</scope>`` are skipped.

    Both ``<dependencies>`` and ``<dependencyManagement><dependencies>``
    sections are searched.

    Args:
        path: Absolute path to a ``pom.xml`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='maven'`` and ``name='groupId:artifactId'``.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    # Support files both with and without the Maven namespace declaration.
    ns = _MAVEN_NS if root.tag.startswith("{") else ""
    prefix = f"{{{ns}}}" if ns else ""

    def _tag(local: str) -> str:
        return f"{prefix}{local}"

    def _text(elem: ET.Element | None) -> str:
        if elem is None:
            return ""
        return (elem.text or "").strip()

    def _collect(deps_elem: ET.Element | None) -> list[PackageId]:
        if deps_elem is None:
            return []
        results: list[PackageId] = []
        for dep in deps_elem.findall(_tag("dependency")):
            scope = _text(dep.find(_tag("scope")))
            if scope.lower() in _EXCLUDED_SCOPES:
                continue
            group_id = _text(dep.find(_tag("groupId")))
            artifact_id = _text(dep.find(_tag("artifactId")))
            version = _text(dep.find(_tag("version"))) or None
            if not group_id or not artifact_id:
                continue
            results.append(
                PackageId(
                    ecosystem="maven",
                    name=f"{group_id}:{artifact_id}",
                    version=version if version else None,
                )
            )
        return results

    packages: list[PackageId] = []

    # <dependencies> at the top level
    packages.extend(_collect(root.find(_tag("dependencies"))))

    # <dependencyManagement><dependencies>
    dep_mgmt = root.find(_tag("dependencyManagement"))
    if dep_mgmt is not None:
        packages.extend(_collect(dep_mgmt.find(_tag("dependencies"))))

    return packages


def parse_gradle_lockfile(path: Path) -> list[PackageId]:
    """Parse a Gradle native lockfile and return a list of PackageId instances.

    The lockfile format is one dependency per line::

        com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath

    Lines starting with ``#`` are comments. The sentinel line ``empty=``
    signals the end of dependency entries and is skipped, as are any other
    blank lines.

    Args:
        path: Absolute path to a ``gradle.lockfile``.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='maven'`` and ``name='groupId:artifactId'``.
    """
    packages: list[PackageId] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        # Skip comments and blank lines
        if not line or line.startswith("#"):
            continue

        # The sentinel "empty=" line marks the end of real dependencies
        if line == "empty=":
            continue

        # Format: group:artifact:version=configurations
        # Split off the configurations part first
        dep_part, _, _configs = line.partition("=")
        parts = dep_part.split(":")
        if len(parts) < 3:
            # Malformed line; skip gracefully
            continue

        group_id = parts[0].strip()
        artifact_id = parts[1].strip()
        version = parts[2].strip() or None

        if not group_id or not artifact_id:
            continue

        packages.append(
            PackageId(
                ecosystem="maven",
                name=f"{group_id}:{artifact_id}",
                version=version,
            )
        )

    return packages


def detect_jvm_lockfiles(project_dir: Path) -> list[tuple[str, Path]]:
    """Detect JVM lockfiles in *project_dir* (non-recursively and recursively).

    Searches for:

    * ``pom.xml`` — Maven project descriptor (up to 3 levels deep to capture
      multi-module layouts without being too broad).
    * ``gradle.lockfile`` — Gradle native lockfile (any depth).
    * ``buildscript-gradle.lockfile`` — Gradle buildscript lockfile variant.

    Args:
        project_dir: Root directory to search.

    Returns:
        List of ``(file_type, absolute_path)`` tuples where *file_type* is one
        of ``"pom.xml"``, ``"gradle.lockfile"``, or
        ``"buildscript-gradle.lockfile"``.
    """
    results: list[tuple[str, Path]] = []

    # pom.xml — search up to depth 3 (root + two levels of sub-modules)
    for pom in project_dir.rglob("pom.xml"):
        # Depth guard: count path components relative to project_dir
        rel_parts = pom.relative_to(project_dir).parts
        if len(rel_parts) <= 3:  # file itself counts as one part
            results.append(("pom.xml", pom))

    # Gradle native lockfiles — any depth
    for lockfile in project_dir.rglob("gradle.lockfile"):
        results.append(("gradle.lockfile", lockfile))

    for lockfile in project_dir.rglob("buildscript-gradle.lockfile"):
        results.append(("buildscript-gradle.lockfile", lockfile))

    return results
