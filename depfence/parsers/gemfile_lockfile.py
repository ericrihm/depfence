"""Parser for Ruby Bundler lockfiles (Gemfile.lock)."""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import PackageId

# Matches a gem entry under a specs: block.
# Format (4-space indent): "    rails (7.1.3)"
# or with platform:        "    rails-dom-testing (2.2.0)"
_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9_\-\.]+) \(([^)]+)\)\s*$")

# Section headers with no leading whitespace that end with a colon, e.g. "GEM:" or "GIT:"
_SECTION_RE = re.compile(r"^([A-Z]+)\s*$")


def parse_gemfile_lock(path: Path) -> list[PackageId]:
    """Parse a Bundler ``Gemfile.lock`` file and return locked gems.

    The lockfile is divided into sections (GEM, GIT, PATH, BUNDLED WITH …).
    Each section may contain a ``specs:`` block listing gems at a 4-space indent
    with their version in parentheses::

        GEM
          remote: https://rubygems.org/
          specs:
            rails (7.1.3)
            rake (13.1.0)

        GIT
          remote: https://github.com/rack/rack.git
          specs:
            rack (3.0.8)

    Only the first ``name (version)`` entry per gem name is kept (deduplication
    across GEM/GIT/PATH sections).

    Args:
        path: Absolute path to a ``Gemfile.lock`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='rubygems'``.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return []

    packages: list[PackageId] = []
    seen: set[str] = set()

    in_specs = False

    for line in content.splitlines():
        # Detect "  specs:" (2-space indent)
        if line.rstrip() == "  specs:":
            in_specs = True
            continue

        # Any non-indented or 2-space-indented non-specs line ends the specs block
        if in_specs and not line.startswith("    "):
            in_specs = False

        if not in_specs:
            continue

        m = _GEM_SPEC_RE.match(line)
        if m:
            name = m.group(1)
            version = m.group(2)
            # Skip sub-dependency lines (would be at 6-space indent, not matched)
            if name not in seen:
                seen.add(name)
                packages.append(PackageId(ecosystem="rubygems", name=name, version=version))

    return packages
