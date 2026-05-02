"""Parser for PHP Composer lockfiles (composer.lock)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from depfence.core.models import PackageId

log = logging.getLogger(__name__)


def parse_composer_lock(path: Path) -> list[PackageId]:
    """Parse composer.lock and return PackageId list.

    composer.lock contains two arrays: "packages" (production) and
    "packages-dev" (development). Each entry has "name" and "version".
    """
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        log.debug("Failed to parse %s", path, exc_info=True)
        return []

    packages: list[PackageId] = []
    seen: set[str] = set()

    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            # Strip 'v' prefix common in composer versions
            if version.startswith("v"):
                version = version[1:]

            if not name or name in seen:
                continue
            seen.add(name)
            packages.append(PackageId(
                ecosystem="packagist",
                name=name,
                version=version or None,
            ))

    return packages
