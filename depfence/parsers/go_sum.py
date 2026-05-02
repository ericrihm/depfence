"""Parsers for Go module files (go.sum and go.mod)."""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import PackageId

# go.sum line format: <module> <version>[/go.mod] <hash>
# The version must start with 'v' (standard Go semver / pseudo-version).
# We require all three whitespace-separated fields to be present and non-empty.
_GO_SUM_LINE = re.compile(
    r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s]*)\s+\S+"
)

# go.mod require block: lines of the form "    <module> <version>"
# inside a `require ( ... )` block.
_REQUIRE_BLOCK = re.compile(
    r"\brequire\s*\((?P<block>[^)]*)\)", re.DOTALL
)
# Single-line require: `require <module> <version>`
_REQUIRE_SINGLE = re.compile(
    r"^\s*require\s+(?P<module>[^\s(][^\s]*)\s+(?P<version>[^\s]+)",
    re.MULTILINE,
)
# A dependency line inside a require block (not a comment, not blank)
_REQUIRE_ENTRY = re.compile(
    r"^\s+(?P<module>[^\s/][^\s]*)\s+(?P<version>[^\s]+)",
    re.MULTILINE,
)


def parse_go_sum(path: Path) -> list[PackageId]:
    """Parse a ``go.sum`` file and return the unique set of Go modules.

    Each line in ``go.sum`` has the form::

        github.com/foo/bar v1.2.3 h1:...
        github.com/foo/bar v1.2.3/go.mod h1:...

    The ``/go.mod`` suffix is stripped so that each ``(module, version)`` pair
    is reported only once.  Blank lines and lines that do not match the
    expected format are silently skipped.

    Args:
        path: Absolute path to a ``go.sum`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='go'``.
    """
    seen: set[tuple[str, str | None]] = set()
    packages: list[PackageId] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = _GO_SUM_LINE.match(line)
        if not m:
            continue

        module = m.group("module").strip()
        raw_version = m.group("version").strip()

        # Strip the /go.mod suffix that appears on the second hash line.
        version = raw_version.removesuffix("/go.mod")

        key = (module, version)
        if key in seen:
            continue
        seen.add(key)

        packages.append(PackageId(ecosystem="go", name=module, version=version))

    return packages


def parse_go_mod(path: Path) -> list[PackageId]:
    """Parse a ``go.mod`` file and return the direct and indirect dependencies.

    Both multi-line ``require ( ... )`` blocks and single-line
    ``require module version`` statements are supported.  The ``// indirect``
    comment that Go appends to transitive dependencies is ignored — all
    entries are returned.

    Lines starting with ``//`` inside require blocks are treated as comments
    and skipped.  The pseudo-module ``go`` (which carries the Go toolchain
    version) is also skipped.

    Args:
        path: Absolute path to a ``go.mod`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='go'``.
    """
    text = path.read_text(encoding="utf-8")
    seen: set[tuple[str, str | None]] = set()
    packages: list[PackageId] = []

    def _add(module: str, raw_version: str) -> None:
        module = module.strip()
        # Strip inline comments that appear after the version token
        version = raw_version.split("//")[0].strip() or None
        if not module or module == "go":
            return
        key = (module, version)
        if key in seen:
            return
        seen.add(key)
        packages.append(PackageId(ecosystem="go", name=module, version=version))

    # Multi-line require blocks
    for block_match in _REQUIRE_BLOCK.finditer(text):
        block_text = block_match.group("block")
        for entry in _REQUIRE_ENTRY.finditer(block_text):
            line_text = entry.group(0).lstrip()
            if line_text.startswith("//"):
                continue
            _add(entry.group("module"), entry.group("version"))

    # Single-line require directives
    for m in _REQUIRE_SINGLE.finditer(text):
        _add(m.group("module"), m.group("version"))

    return packages
