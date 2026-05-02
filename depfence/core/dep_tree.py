"""Dependency tree resolver — parses lockfiles into a proper tree structure.

Provides:
- DepNode: tree node dataclass with children, depth, and dev flag
- build_tree_from_package_lock: parse package-lock.json v2/v3 into a tree
- build_tree_from_poetry_lock: parse poetry.lock into a tree
- find_paths_to: trace which direct deps transitively pull in a target package
- tree_to_text: render the tree like ``npm ls`` output with box-drawing chars
- count_transitive: count total transitive deps for each root node
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import PackageId


@dataclass
class DepNode:
    package: PackageId
    children: list["DepNode"] = field(default_factory=list)
    depth: int = 0
    is_dev: bool = False


# ---------------------------------------------------------------------------
# package-lock.json (v2/v3) parser
# ---------------------------------------------------------------------------

def build_tree_from_package_lock(lockfile_path: Path) -> list[DepNode]:
    """Parse a package-lock.json (v2/v3) into a list of root DepNode trees.

    The v2/v3 format uses a flat "packages" dict where the root project is
    stored under the empty-string key "".  Root dependencies are listed in
    ``packages[""]["dependencies"]`` and ``packages[""]["devDependencies"]``.
    Each package entry may have its own ``"dependencies"`` sub-key that maps
    dep names to version constraints (the actual resolved version lives in the
    matching ``"node_modules/<name>"`` entry).

    Args:
        lockfile_path: Absolute path to ``package-lock.json``.

    Returns:
        List of root :class:`DepNode` objects with children populated
        recursively.  Returns an empty list when the file is missing or
        malformed.
    """
    if not lockfile_path.exists():
        return []

    try:
        data = json.loads(lockfile_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    packages: dict[str, dict] = data.get("packages", {})
    root_entry: dict = packages.get("", {})

    root_deps: dict[str, str] = root_entry.get("dependencies", {})
    root_dev_deps: dict[str, str] = root_entry.get("devDependencies", {})

    # Build a lookup: package-name → {version, dependencies, ...}
    # "node_modules/foo" → "foo" for simple packages
    # "node_modules/foo/node_modules/bar" → nested, keyed by full path
    pkg_by_name: dict[str, dict] = {}  # simple name → info (last writer wins for nesting)
    pkg_by_path: dict[str, dict] = {}  # full key → info

    for key, info in packages.items():
        if not key:
            continue
        pkg_by_path[key] = info
        # Strip leading node_modules/ prefix and take the last component
        # e.g. "node_modules/foo" → "foo"
        # e.g. "node_modules/foo/node_modules/bar" → "bar" (nested override)
        parts = key.split("node_modules/")
        name = parts[-1] if parts else key
        if name:
            pkg_by_name[name] = info

    def _resolve_pkg(name: str, context_path: str = "") -> PackageId | None:
        """Resolve package name to a PackageId, preferring context-local nesting."""
        # Try context-local nested first (e.g. "node_modules/foo/node_modules/bar")
        if context_path:
            nested_key = f"{context_path}/node_modules/{name}"
            if nested_key in pkg_by_path:
                info = pkg_by_path[nested_key]
                version = info.get("version", "")
                return PackageId("npm", name, version or None)

        # Fall back to top-level
        top_key = f"node_modules/{name}"
        if top_key in pkg_by_path:
            info = pkg_by_path[top_key]
            version = info.get("version", "")
            return PackageId("npm", name, version or None)

        # Use pkg_by_name as last resort
        info = pkg_by_name.get(name)
        if info is not None:
            version = info.get("version", "")
            return PackageId("npm", name, version or None)

        return PackageId("npm", name, None)

    def _build_node(
        name: str,
        context_path: str,
        depth: int,
        is_dev: bool,
        visited: set[str],
    ) -> DepNode:
        pkg_id = _resolve_pkg(name, context_path)
        node = DepNode(package=pkg_id, depth=depth, is_dev=is_dev)

        # Determine the canonical path for this package
        nested_key = f"{context_path}/node_modules/{name}" if context_path else f"node_modules/{name}"
        canonical_key = nested_key if nested_key in pkg_by_path else f"node_modules/{name}"

        # Avoid infinite recursion from circular references
        cycle_key = f"{canonical_key}@{depth}"
        if canonical_key in visited or depth >= 50:
            return node

        visited = visited | {canonical_key}

        info = pkg_by_path.get(canonical_key, pkg_by_name.get(name, {}))
        child_deps: dict[str, str] = info.get("dependencies", {})

        for child_name in child_deps:
            child_node = _build_node(
                child_name,
                canonical_key,
                depth + 1,
                is_dev,
                visited,
            )
            node.children.append(child_node)

        return node

    roots: list[DepNode] = []

    for name in root_deps:
        node = _build_node(name, "", 0, is_dev=False, visited=set())
        roots.append(node)

    for name in root_dev_deps:
        node = _build_node(name, "", 0, is_dev=True, visited=set())
        roots.append(node)

    return roots


# ---------------------------------------------------------------------------
# poetry.lock parser
# ---------------------------------------------------------------------------

def build_tree_from_poetry_lock(lockfile_path: Path) -> list[DepNode]:
    """Parse a ``poetry.lock`` file into a list of root DepNode trees.

    poetry.lock is TOML but we parse it with regex to avoid a third-party
    dependency, following the same approach as other parsers in this project.

    A ``[[package]]`` block looks like::

        [[package]]
        name = "requests"
        version = "2.31.0"
        category = "main"   # or "dev"

        [package.dependencies]
        certifi = ">=2017.4.17"
        charset-normalizer = ">=2,<4"

    Root packages are those NOT listed as a dependency of any other package.

    Args:
        lockfile_path: Absolute path to ``poetry.lock``.

    Returns:
        List of root :class:`DepNode` objects with children populated
        recursively.  Returns an empty list when the file is missing or
        malformed.
    """
    if not lockfile_path.exists():
        return []

    try:
        content = lockfile_path.read_text()
    except OSError:
        return []

    # Split into [[package]] blocks
    block_pattern = re.compile(r"\[\[package\]\]", re.MULTILINE)
    block_starts = [m.start() for m in block_pattern.finditer(content)]

    if not block_starts:
        return []

    # Each block runs from its start to the next block start (or EOF)
    blocks: list[str] = []
    for i, start in enumerate(block_starts):
        end = block_starts[i + 1] if i + 1 < len(block_starts) else len(content)
        blocks.append(content[start:end])

    # Parse each block into a dict: name → {version, is_dev, deps: {name: spec}}
    packages: dict[str, dict] = {}  # normalised name → info

    _kv = re.compile(r'^(\w[\w-]*)\s*=\s*"([^"]*)"', re.MULTILINE)
    _dep_section = re.compile(r"\[package\.dependencies\](.*?)(?=\[|\Z)", re.DOTALL)
    _dep_line = re.compile(r'^([\w][\w.-]*)\s*=', re.MULTILINE)

    def _normalise(name: str) -> str:
        """Normalise package name: lowercase, hyphens/underscores unified."""
        return name.lower().replace("-", "_")

    for block in blocks:
        info: dict[str, str] = {}
        for m in _kv.finditer(block):
            key, val = m.group(1).lower(), m.group(2)
            if key in ("name", "version", "category"):
                info[key] = val

        name = info.get("name", "")
        version = info.get("version", "")
        category = info.get("category", "main")

        if not name:
            continue

        # Parse [package.dependencies] sub-section
        dep_names: list[str] = []
        dep_match = _dep_section.search(block)
        if dep_match:
            dep_body = dep_match.group(1)
            for dm in _dep_line.finditer(dep_body):
                dep_names.append(dm.group(1))

        normalised = _normalise(name)
        packages[normalised] = {
            "name": name,
            "version": version,
            "is_dev": category == "dev",
            "deps": [_normalise(d) for d in dep_names],
        }

    if not packages:
        return []

    # Identify roots: packages not listed as a dep of any other package
    all_dep_targets: set[str] = set()
    for info in packages.values():
        all_dep_targets.update(info["deps"])

    root_names = [n for n in packages if n not in all_dep_targets]

    def _build_node(norm_name: str, depth: int, is_dev: bool, visited: frozenset[str]) -> DepNode:
        info = packages.get(norm_name, {})
        pkg_id = PackageId("pypi", info.get("name", norm_name), info.get("version") or None)
        effective_dev = is_dev or info.get("is_dev", False)
        node = DepNode(package=pkg_id, depth=depth, is_dev=effective_dev)

        if norm_name in visited or depth >= 50:
            return node

        new_visited = visited | {norm_name}
        for child_norm in info.get("deps", []):
            if child_norm in packages:
                child_node = _build_node(child_norm, depth + 1, effective_dev, new_visited)
                node.children.append(child_node)

        return node

    roots: list[DepNode] = []
    for norm_name in root_names:
        info = packages[norm_name]
        node = _build_node(norm_name, 0, info["is_dev"], frozenset())
        roots.append(node)

    return roots


# ---------------------------------------------------------------------------
# Tree query helpers
# ---------------------------------------------------------------------------

def find_paths_to(tree: list[DepNode], target_name: str) -> list[list[PackageId]]:
    """Return all dependency paths from a root node to a package named ``target_name``.

    Useful for answering "why is this vulnerable package in my tree?"

    Args:
        tree: List of root :class:`DepNode` objects.
        target_name: The package name to search for (case-insensitive).

    Returns:
        List of paths, where each path is a list of :class:`PackageId` from
        the root (inclusive) down to (and including) the target package.
    """
    target_lower = target_name.lower()
    paths: list[list[PackageId]] = []

    def _dfs(node: DepNode, current_path: list[PackageId]) -> None:
        current_path = current_path + [node.package]
        if node.package.name.lower() == target_lower:
            paths.append(current_path)
        else:
            for child in node.children:
                _dfs(child, current_path)

    for root in tree:
        _dfs(root, [])

    return paths


def tree_to_text(tree: list[DepNode], max_depth: int = 5) -> str:
    """Render the dependency tree as text, like ``npm ls`` output.

    Uses box-drawing characters (├──, └──, │) for visual hierarchy.

    Args:
        tree: List of root :class:`DepNode` objects.
        max_depth: Maximum depth to render (default 5).

    Returns:
        Multi-line string representation of the tree.
    """
    lines: list[str] = []

    def _render(node: DepNode, prefix: str, is_last: bool) -> None:
        if node.depth > max_depth:
            return

        connector = "└── " if is_last else "├── "
        pkg = node.package
        label = f"{pkg.name}@{pkg.version}" if pkg.version else pkg.name
        if node.is_dev:
            label += " (dev)"
        lines.append(f"{prefix}{connector}{label}")

        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, child in enumerate(node.children):
            if child.depth > max_depth:
                continue
            _render(child, child_prefix, i == len(node.children) - 1)

    for i, root in enumerate(tree):
        pkg = root.package
        label = f"{pkg.name}@{pkg.version}" if pkg.version else pkg.name
        if root.is_dev:
            label += " (dev)"
        lines.append(label)
        for j, child in enumerate(root.children):
            _render(child, "", j == len(root.children) - 1)

    return "\n".join(lines)


def count_transitive(tree: list[DepNode]) -> dict[str, int]:
    """Count total transitive dependencies for each root node.

    Packages appearing multiple times in the subtree are counted once per
    unique (name, version) pair to avoid inflation from diamond dependencies.

    Args:
        tree: List of root :class:`DepNode` objects.

    Returns:
        Dict mapping each root package's name to the count of unique
        transitive (non-root) packages beneath it.
    """
    result: dict[str, int] = {}

    def _collect(node: DepNode, seen: set[str]) -> None:
        for child in node.children:
            key = f"{child.package.name}@{child.package.version}"
            if key not in seen:
                seen.add(key)
                _collect(child, seen)

    for root in tree:
        seen: set[str] = set()
        _collect(root, seen)
        result[root.package.name] = len(seen)

    return result
