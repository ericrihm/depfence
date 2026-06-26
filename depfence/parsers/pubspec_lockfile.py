"""Parsers for Dart/Flutter dependency files (pubspec.lock and pubspec.yaml)."""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import PackageId


def parse_pubspec_lock(path: Path) -> list[PackageId]:
    """Parse a Flutter/Dart pubspec.lock file.

    The format is YAML with a ``packages:`` mapping where each entry has
    ``dependency``, ``description``, ``source``, and ``version`` fields::

        packages:
          http:
            dependency: "direct main"
            description:
              name: http
              ...
            source: hosted
            version: "1.2.0"
    """
    packages: list[PackageId] = []
    content = path.read_text(encoding="utf-8")

    current_pkg: str = ""
    for line in content.splitlines():
        stripped = line.rstrip()

        if stripped == "packages:":
            continue

        # Top-level package name (2-space indent, no further indent)
        if re.match(r"^  [a-zA-Z_]", stripped) and stripped.endswith(":"):
            current_pkg = stripped.strip().rstrip(":")
            continue

        if current_pkg and stripped.strip().startswith("version:"):
            raw = stripped.split("version:", 1)[1].strip().strip('"').strip("'")
            if raw:
                packages.append(PackageId("dart", current_pkg, raw))
            current_pkg = ""

    return packages


def parse_pubspec_yaml(path: Path) -> list[PackageId]:
    """Parse a pubspec.yaml for declared dependencies (no versions from lockfile).

    Extracts packages from ``dependencies:`` and ``dev_dependencies:``
    sections. Version constraints are captured as-is (e.g. ``^1.2.0``).
    """
    packages: list[PackageId] = []
    content = path.read_text(encoding="utf-8")

    in_deps = False
    for line in content.splitlines():
        stripped = line.rstrip()

        if re.match(r"^(dependencies|dev_dependencies)\s*:", stripped):
            in_deps = True
            continue

        if in_deps and stripped and not stripped[0].isspace():
            in_deps = False
            continue

        if not in_deps:
            continue

        # "  package_name: ^1.2.0" or "  package_name: any"
        m = re.match(r"^  ([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+)?", stripped)
        if m:
            name = m.group(1)
            version_raw = (m.group(2) or "").strip().strip('"').strip("'")
            # Skip SDK deps (multiline "sdk: flutter") and complex deps
            if version_raw == "" or any(c in version_raw for c in ["{", "/"]):
                continue
            if version_raw in ("any",) or version_raw.startswith(("^", ">", "<", "=")):
                version = version_raw.lstrip("^>=<! ").split(",")[0].strip() or None
                packages.append(PackageId("dart", name, version))
            elif ":" not in version_raw:
                packages.append(PackageId("dart", name, version_raw))

    return packages
