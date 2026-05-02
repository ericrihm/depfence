"""Parser for Cargo lockfiles (Cargo.lock)."""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import PackageId

# Matches a [[package]] section header.
_PACKAGE_HEADER = re.compile(r"^\[\[package\]\]", re.MULTILINE)

# Matches a key = "value" line inside a [[package]] block.
_KV_RE = re.compile(r'^(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)


def _parse_blocks(text: str) -> list[dict[str, str]]:
    """Split *text* into [[package]] blocks and extract key/value pairs.

    Returns a list of dicts, one per [[package]] block, containing only the
    string-valued keys (name, version, source, checksum).  Array-valued keys
    such as ``dependencies`` are ignored because they are not needed for
    package identification.
    """
    # Find the start position of every [[package]] header.
    header_positions = [m.start() for m in _PACKAGE_HEADER.finditer(text)]

    blocks: list[dict[str, str]] = []
    for i, start in enumerate(header_positions):
        end = header_positions[i + 1] if i + 1 < len(header_positions) else len(text)
        block_text = text[start:end]
        kv: dict[str, str] = {}
        for m in _KV_RE.finditer(block_text):
            key, value = m.group(1), m.group(2)
            # Keep only the first occurrence of each key within the block
            # (array-valued entries like dependencies use a different syntax
            # and are not matched by _KV_RE anyway).
            if key not in kv:
                kv[key] = value
        blocks.append(kv)

    return blocks


def parse_cargo_lock(path: Path) -> list[PackageId]:
    """Parse a ``Cargo.lock`` file and return the list of locked packages.

    Supports both the v1 format (no top-level ``version`` key) and the v3
    format (``version = 3`` at the top of the file).  In both cases every
    ``[[package]]`` entry is returned, including the root crate(s) of the
    workspace.

    Args:
        path: Absolute path to a ``Cargo.lock`` file.

    Returns:
        List of :class:`~depfence.core.models.PackageId` with
        ``ecosystem='cargo'``.  Entries without a ``name`` key are silently
        skipped.
    """
    text = path.read_text(encoding="utf-8")
    blocks = _parse_blocks(text)

    packages: list[PackageId] = []
    for block in blocks:
        name = block.get("name", "").strip()
        if not name:
            continue
        version: str | None = block.get("version", "").strip() or None
        packages.append(PackageId(ecosystem="cargo", name=name, version=version))

    return packages
