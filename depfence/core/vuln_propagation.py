"""Vulnerability propagation analysis — traces how deep transitive vulns reach your code.

Given a dependency graph and a set of vulnerable packages, this module computes:
1. Attack paths: shortest path from each vuln to a direct dependency
2. Exposure score: how many of YOUR imports are reachable from the vuln
3. Upgrade priority: which direct dep upgrade eliminates the most vulns
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class AttackPath:
    vulnerable_package: str
    direct_dependency: str
    path: list[str]
    depth: int
    severity: str

    @property
    def summary(self) -> str:
        return " → ".join(self.path)


@dataclass
class UpgradePriority:
    package: str
    vulns_eliminated: int
    affected_paths: list[AttackPath] = field(default_factory=list)


def trace_attack_paths(
    graph: dict[str, set[str]],
    vulnerable_packages: set[str],
    direct_deps: set[str],
) -> list[AttackPath]:
    """Trace how each vulnerable package reaches your direct dependencies.

    Args:
        graph: adjacency list mapping package -> set of packages it depends on
        vulnerable_packages: set of package keys known to be vulnerable
        direct_deps: set of packages that are your direct dependencies

    Returns:
        List of AttackPath objects sorted by depth (shortest first)
    """
    reverse_graph: dict[str, set[str]] = defaultdict(set)
    for parent, children in graph.items():
        for child in children:
            reverse_graph[child].add(parent)

    paths: list[AttackPath] = []

    for vuln_pkg in vulnerable_packages:
        if vuln_pkg not in reverse_graph and vuln_pkg not in graph:
            continue

        # BFS from vulnerable package up toward direct deps
        visited: set[str] = set()
        queue: deque[list[str]] = deque([[vuln_pkg]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current in visited:
                continue
            visited.add(current)

            if current in direct_deps and len(path) > 1:
                paths.append(AttackPath(
                    vulnerable_package=vuln_pkg,
                    direct_dependency=current,
                    path=list(reversed(path)),
                    depth=len(path) - 1,
                    severity="",
                ))
                continue

            for parent in reverse_graph.get(current, set()):
                if parent not in visited:
                    queue.append(path + [parent])

    paths.sort(key=lambda p: p.depth)
    return paths


def compute_upgrade_priorities(
    paths: list[AttackPath],
) -> list[UpgradePriority]:
    """Determine which direct dependency upgrades eliminate the most vulnerabilities.

    Returns:
        Sorted list of UpgradePriority (highest impact first)
    """
    by_direct: dict[str, list[AttackPath]] = defaultdict(list)
    for path in paths:
        by_direct[path.direct_dependency].append(path)

    priorities = []
    for pkg, pkg_paths in by_direct.items():
        unique_vulns = set(p.vulnerable_package for p in pkg_paths)
        priorities.append(UpgradePriority(
            package=pkg,
            vulns_eliminated=len(unique_vulns),
            affected_paths=pkg_paths,
        ))

    priorities.sort(key=lambda p: p.vulns_eliminated, reverse=True)
    return priorities


def exposure_summary(paths: list[AttackPath]) -> dict:
    """Generate a summary of vulnerability exposure."""
    if not paths:
        return {"total_paths": 0, "unique_vulns": 0, "max_depth": 0, "direct_deps_affected": 0}

    unique_vulns = set(p.vulnerable_package for p in paths)
    direct_affected = set(p.direct_dependency for p in paths)

    return {
        "total_paths": len(paths),
        "unique_vulns": len(unique_vulns),
        "max_depth": max(p.depth for p in paths),
        "avg_depth": round(sum(p.depth for p in paths) / len(paths), 1),
        "direct_deps_affected": len(direct_affected),
        "deepest_path": max(paths, key=lambda p: p.depth).summary if paths else "",
    }
