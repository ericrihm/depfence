"""Parsers for Gradle dependency files (lockfile and version catalogs)."""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import PackageId


def parse_gradle_lockfile(path: Path) -> list[PackageId]:
    """Parse a Gradle native lockfile and return a list of PackageId instances.

    The lockfile format is one dependency per line::

        com.google.code.gson:gson:2.10.1=compileClasspath,runtimeClasspath

    Lines starting with ``#`` are comments. The sentinel line ``empty=``
    signals the end of dependency entries and is skipped, as are blank lines.

    Args:
        path: Absolute path to a ``gradle.lockfile``.

    Returns:
        List of PackageId with ``ecosystem='maven'`` and
        ``name='groupId:artifactId'``.
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


def parse_gradle_version_catalog(path: Path) -> list[PackageId]:
    """Parse a Gradle version catalog (``gradle/libs.versions.toml``).

    Supports the standard TOML format with ``[versions]`` and ``[libraries]``
    sections. Version references (``version.ref``) are resolved against the
    ``[versions]`` table. Inline versions (``version = "x.y.z"``) are used
    directly. Libraries without a resolvable version are included with
    ``version=None``.

    No external TOML library is required — parsing is done with regex.

    Args:
        path: Absolute path to ``libs.versions.toml`` (or any TOML version
            catalog file).

    Returns:
        List of PackageId with ``ecosystem='maven'`` and
        ``name='groupId:artifactId'``.
    """
    content = path.read_text(encoding="utf-8")

    # -----------------------------------------------------------------------
    # Split content into sections by [section] headers
    # -----------------------------------------------------------------------
    sections: dict[str, str] = {}
    current_section = ""
    section_lines: list[str] = []

    for line in content.splitlines():
        header_match = re.match(r"^\[([^\]]+)\]", line.strip())
        if header_match:
            if current_section:
                sections[current_section] = "\n".join(section_lines)
            current_section = header_match.group(1).strip()
            section_lines = []
        else:
            if current_section:
                section_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(section_lines)

    # -----------------------------------------------------------------------
    # Parse [versions]
    # -----------------------------------------------------------------------
    version_refs: dict[str, str] = {}
    versions_text = sections.get("versions", "")
    for line in versions_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*"([^"]+)"', line)
        if m:
            version_refs[m.group(1)] = m.group(2)

    # -----------------------------------------------------------------------
    # Parse [libraries]
    # -----------------------------------------------------------------------
    packages: list[PackageId] = []
    libraries_text = sections.get("libraries", "")

    for line in libraries_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Extract module = "group:artifact"
        module_match = re.search(r'module\s*=\s*"([^"]+)"', line)
        if not module_match:
            continue
        module = module_match.group(1)

        # Resolve version
        version: str | None = None

        # version.ref = "someRef"
        ref_match = re.search(r'version\.ref\s*=\s*"([^"]+)"', line)
        if ref_match:
            ref_key = ref_match.group(1)
            version = version_refs.get(ref_key)
        else:
            # version = "x.y.z" (inline)
            ver_match = re.search(r'(?<!\.)version\s*=\s*"([^"]+)"', line)
            if ver_match:
                version = ver_match.group(1)

        packages.append(PackageId(ecosystem="maven", name=module, version=version))

    return packages
