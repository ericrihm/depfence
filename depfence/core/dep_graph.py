"""Dependency graph analysis — transitive risk paths and blast radius.

Builds a directed graph from lockfile dependency relationships and computes:
1. Transitive dependency chains (how deeply a vulnerable pkg is nested)
2. Blast radius (how many packages depend on a given package)
3. Critical path identification (shortest path from root to vulnerable pkg)
4. Concentration risk (single points of failure in the dep tree)
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import PackageId


@dataclass
class DepNode:
    pkg: PackageId
    dependents: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    depth: int = 0
    is_direct: bool = False


@dataclass
class BlastRadius:
    package: str
    direct_dependents: int
    transitive_dependents: int
    depth_from_root: int
    risk_score: int

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "direct_dependents": self.direct_dependents,
            "transitive_dependents": self.transitive_dependents,
            "depth": self.depth_from_root,
            "risk_score": self.risk_score,
        }


class DependencyGraph:
    """Directed acyclic graph of package dependencies."""

    def __init__(self) -> None:
        self._nodes: dict[str, DepNode] = {}
        self._edges: dict[str, set[str]] = defaultdict(set)
        self._reverse_edges: dict[str, set[str]] = defaultdict(set)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def add_package(self, pkg: PackageId, is_direct: bool = False) -> None:
        key = self._key(pkg)
        if key not in self._nodes:
            self._nodes[key] = DepNode(pkg=pkg, is_direct=is_direct)
        elif is_direct:
            self._nodes[key].is_direct = True

    def add_dependency(self, parent: PackageId, child: PackageId) -> None:
        parent_key = self._key(parent)
        child_key = self._key(child)
        self.add_package(parent)
        self.add_package(child)
        self._edges[parent_key].add(child_key)
        self._reverse_edges[child_key].add(parent_key)

    def get_dependents(self, pkg: PackageId) -> list[str]:
        """Get all packages that directly depend on pkg."""
        key = self._key(pkg)
        return list(self._reverse_edges.get(key, set()))

    def get_transitive_dependents(self, pkg: PackageId) -> set[str]:
        """Get all packages that transitively depend on pkg."""
        key = self._key(pkg)
        visited: set[str] = set()
        queue = deque([key])

        while queue:
            current = queue.popleft()
            for parent in self._reverse_edges.get(current, set()):
                if parent not in visited:
                    visited.add(parent)
                    queue.append(parent)

        return visited

    def get_dependencies(self, pkg: PackageId) -> list[str]:
        """Get direct dependencies of pkg."""
        key = self._key(pkg)
        return list(self._edges.get(key, set()))

    def get_transitive_dependencies(self, pkg: PackageId) -> set[str]:
        """Get all transitive dependencies of pkg."""
        key = self._key(pkg)
        visited: set[str] = set()
        queue = deque([key])

        while queue:
            current = queue.popleft()
            for child in self._edges.get(current, set()):
                if child not in visited:
                    visited.add(child)
                    queue.append(child)

        return visited

    def compute_blast_radius(self, pkg: PackageId) -> BlastRadius:
        """Compute how much damage a compromise of pkg would cause."""
        key = self._key(pkg)
        direct = list(self._reverse_edges.get(key, set()))
        transitive = self.get_transitive_dependents(pkg)
        depth = self._depth_from_root(key)

        total_nodes = max(self.node_count, 1)
        reach_pct = len(transitive) / total_nodes * 100
        risk_score = min(int(reach_pct * 2 + len(direct) * 5), 100)

        return BlastRadius(
            package=key,
            direct_dependents=len(direct),
            transitive_dependents=len(transitive),
            depth_from_root=depth,
            risk_score=risk_score,
        )

    def find_concentration_risks(self, threshold: int = 5) -> list[BlastRadius]:
        """Find packages that many others depend on (single points of failure)."""
        risks = []
        for key in self._nodes:
            dependents = self._reverse_edges.get(key, set())
            if len(dependents) >= threshold:
                pkg = self._nodes[key].pkg
                br = self.compute_blast_radius(pkg)
                risks.append(br)

        return sorted(risks, key=lambda r: r.risk_score, reverse=True)

    def shortest_path(self, start: PackageId, end: PackageId) -> list[str] | None:
        """Find shortest dependency path between two packages."""
        start_key = self._key(start)
        end_key = self._key(end)

        if start_key not in self._nodes or end_key not in self._nodes:
            return None

        visited: set[str] = set()
        queue: deque[list[str]] = deque([[start_key]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == end_key:
                return path

            if current in visited:
                continue
            visited.add(current)

            for child in self._edges.get(current, set()):
                if child not in visited:
                    queue.append(path + [child])

        return None

    def get_direct_packages(self) -> list[str]:
        """Get all direct (root-level) dependencies."""
        return [k for k, n in self._nodes.items() if n.is_direct]

    def to_dict(self) -> dict:
        """Serialize graph for JSON output."""
        return {
            "nodes": len(self._nodes),
            "edges": sum(len(deps) for deps in self._edges.values()),
            "direct_deps": len(self.get_direct_packages()),
            "packages": [
                {
                    "key": k,
                    "ecosystem": n.pkg.ecosystem,
                    "name": n.pkg.name,
                    "version": n.pkg.version,
                    "is_direct": n.is_direct,
                    "dependents": len(self._reverse_edges.get(k, set())),
                    "dependencies": len(self._edges.get(k, set())),
                }
                for k, n in sorted(self._nodes.items())
            ],
        }

    def _depth_from_root(self, key: str) -> int:
        """BFS depth from any root node to key."""
        roots = [k for k, n in self._nodes.items() if n.is_direct]
        if not roots:
            return 0
        if key in roots:
            return 0

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(r, 0) for r in roots])

        while queue:
            current, depth = queue.popleft()
            if current == key:
                return depth
            if current in visited:
                continue
            visited.add(current)
            for child in self._edges.get(current, set()):
                if child not in visited:
                    queue.append((child, depth + 1))

        return -1

    @staticmethod
    def _key(pkg: PackageId) -> str:
        return f"{pkg.ecosystem}:{pkg.name}@{pkg.version or 'any'}"


def build_graph_from_package_lock(path: Path) -> DependencyGraph:
    """Build a DependencyGraph from a package-lock.json."""
    graph = DependencyGraph()
    data = json.loads(path.read_text())

    # lockfileVersion 2/3
    if "packages" in data:
        root_deps = set()
        pkg_json = path.parent / "package.json"
        if pkg_json.exists():
            pj = json.loads(pkg_json.read_text())
            root_deps = set(pj.get("dependencies", {}).keys()) | set(pj.get("devDependencies", {}).keys())

        for key, info in data["packages"].items():
            if not key:
                continue
            name = key.split("node_modules/")[-1]
            version = info.get("version", "")
            if not name or not version:
                continue

            pkg = PackageId("npm", name, version)
            is_direct = name in root_deps
            graph.add_package(pkg, is_direct=is_direct)

            for dep_name in info.get("dependencies", {}).keys():
                dep_pkg = PackageId("npm", dep_name, None)
                graph.add_dependency(pkg, dep_pkg)

    return graph
