"""Parsers for Swift ecosystem lockfiles (Package.resolved and Podfile.lock)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import PackageId


def parse_package_resolved(path: Path) -> list[PackageId]:
    """Parse a Swift Package Manager ``Package.resolved`` file.

    Supports both v1 and v2 formats:

    * **v2** (SPM >= 5.6): top-level ``"pins"`` array; each pin has
      ``"identity"`` and ``"state": {"version": "..."}`` keys.
    * **v1** (older SPM): ``"object": {"pins": [...]}`` structure; each pin
      has ``"package"`` (name) and ``"state": {"version": "..."}`` keys.

    Pins whose state does not contain a ``"version"`` key (e.g. branch or
    commit-only pins) are included with ``version=None``.

    Args:
        path: Absolute path to a ``Package.resolved`` file.

    Returns:
        List of PackageId with ``ecosystem='swift'``.
    """
    packages: list[PackageId] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return packages

    if not isinstance(data, dict):
        return packages

    file_version = data.get("version", 2)

    if file_version == 1:
        # v1: {"object": {"pins": [...]}}
        pins = data.get("object", {}).get("pins", [])
        name_key = "package"
    else:
        # v2+: {"pins": [...]}
        pins = data.get("pins", [])
        name_key = "identity"

    for pin in pins:
        if not isinstance(pin, dict):
            continue
        name = pin.get(name_key, "")
        if not name:
            continue
        state = pin.get("state", {})
        version: str | None = state.get("version") if isinstance(state, dict) else None
        packages.append(PackageId(ecosystem="swift", name=name, version=version))

    return packages


def parse_podfile_lock(path: Path) -> list[PackageId]:
    """Parse a CocoaPods ``Podfile.lock`` file.

    Only top-level pod entries in the ``PODS:`` section are extracted.
    Dependency sub-entries (indented further under a pod) are ignored.

    Format example::

        PODS:
          - Alamofire (5.8.1)
          - Moya (15.0.0):
            - Alamofire (~> 5.0)

    Args:
        path: Absolute path to a ``Podfile.lock`` file.

    Returns:
        List of PackageId with ``ecosystem='swift'``.
    """
    packages: list[PackageId] = []

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return packages

    in_pods_section = False
    # Top-level pod lines are indented with exactly 2 spaces: "  - Name (version)"
    pod_line_re = re.compile(r"^  - ([A-Za-z0-9_\-\.\/]+)\s+\(([^)]+)\)")

    for line in content.splitlines():
        # Detect section headers (no leading spaces)
        if not line.startswith(" "):
            in_pods_section = line.rstrip(":").strip() == "PODS"
            continue

        if not in_pods_section:
            continue

        m = pod_line_re.match(line)
        if m:
            name = m.group(1)
            version = m.group(2)
            packages.append(PackageId(ecosystem="swift", name=name, version=version))

    return packages
