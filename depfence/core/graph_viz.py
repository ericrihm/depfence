"""Dependency graph visualization — generates Mermaid and DOT format graphs.

Produces visual dependency trees with vulnerability annotations,
color-coded by risk level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import Finding, Severity


@dataclass
class GraphNode:
    name: str
    version: str | None = None
    severity: Severity | None = None
    is_direct: bool = False
    findings_count: int = 0


def generate_mermaid(
    graph: dict[str, set[str]],
    findings: list[Finding] | None = None,
    direct_deps: set[str] | None = None,
    max_nodes: int = 50,
) -> str:
    """Generate a Mermaid flowchart from a dependency graph.

    Args:
        graph: adjacency list {parent: {child1, child2, ...}}
        findings: optional findings to annotate vulnerable nodes
        direct_deps: optional set of direct dependency names
        max_nodes: limit graph size for readability
    """
    vuln_map = _build_vuln_map(findings) if findings else {}
    direct = direct_deps or set()

    lines = ["graph TD"]

    # Collect all nodes
    all_nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    for parent, children in graph.items():
        all_nodes.add(parent)
        for child in children:
            all_nodes.add(child)
            edges.append((parent, child))

    # Limit nodes
    nodes_list = sorted(all_nodes)[:max_nodes]
    node_set = set(nodes_list)

    # Define node styles
    for node in nodes_list:
        safe_id = _safe_id(node)
        label = node.split("@")[0] if "@" in node else node

        if node in vuln_map:
            sev = vuln_map[node]
            if sev in (Severity.CRITICAL, Severity.HIGH):
                lines.append(f"    {safe_id}[/{label}\\]:::danger")
            else:
                lines.append(f"    {safe_id}[/{label}\\]:::warning")
        elif node in direct:
            lines.append(f"    {safe_id}[{label}]:::direct")
        else:
            lines.append(f"    {safe_id}({label})")

    # Add edges
    for parent, child in edges:
        if parent in node_set and child in node_set:
            lines.append(f"    {_safe_id(parent)} --> {_safe_id(child)}")

    # Style classes
    lines.append("")
    lines.append("    classDef danger fill:#ff4444,stroke:#cc0000,color:#fff")
    lines.append("    classDef warning fill:#ffaa00,stroke:#cc8800,color:#000")
    lines.append("    classDef direct fill:#4488ff,stroke:#2266cc,color:#fff")

    return "\n".join(lines)


def generate_dot(
    graph: dict[str, set[str]],
    findings: list[Finding] | None = None,
    direct_deps: set[str] | None = None,
    max_nodes: int = 100,
) -> str:
    """Generate a Graphviz DOT format graph."""
    vuln_map = _build_vuln_map(findings) if findings else {}
    direct = direct_deps or set()

    lines = ["digraph dependencies {"]
    lines.append("    rankdir=LR;")
    lines.append("    node [shape=box, style=rounded, fontname=\"Helvetica\"];")
    lines.append("")

    all_nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    for parent, children in graph.items():
        all_nodes.add(parent)
        for child in children:
            all_nodes.add(child)
            edges.append((parent, child))

    nodes_list = sorted(all_nodes)[:max_nodes]
    node_set = set(nodes_list)

    for node in nodes_list:
        safe_id = _safe_id(node)
        label = node.split("@")[0] if "@" in node else node
        attrs = [f'label="{label}"']

        if node in vuln_map:
            sev = vuln_map[node]
            if sev in (Severity.CRITICAL, Severity.HIGH):
                attrs.append('fillcolor="#ff4444"')
                attrs.append("style=filled")
                attrs.append('fontcolor="white"')
            else:
                attrs.append('fillcolor="#ffaa00"')
                attrs.append("style=filled")
        elif node in direct:
            attrs.append('fillcolor="#4488ff"')
            attrs.append("style=filled")
            attrs.append('fontcolor="white"')

        lines.append(f"    {safe_id} [{', '.join(attrs)}];")

    lines.append("")
    for parent, child in edges:
        if parent in node_set and child in node_set:
            lines.append(f"    {_safe_id(parent)} -> {_safe_id(child)};")

    lines.append("}")
    return "\n".join(lines)


def generate_tree(
    graph: dict[str, set[str]],
    root: str,
    findings: list[Finding] | None = None,
    max_depth: int = 5,
) -> str:
    """Generate a text-based tree view (like `npm ls`)."""
    vuln_map = _build_vuln_map(findings) if findings else {}
    lines: list[str] = []
    visited: set[str] = set()

    def _walk(node: str, prefix: str, depth: int) -> None:
        if depth > max_depth or node in visited:
            return
        visited.add(node)

        marker = ""
        if node in vuln_map:
            sev = vuln_map[node]
            marker = f" [{sev.name}]"

        lines.append(f"{prefix}{node}{marker}")

        children = sorted(graph.get(node, set()))
        for i, child in enumerate(children):
            is_last = i == len(children) - 1
            child_prefix = prefix + ("    " if is_last else "│   ")
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{child}{' [' + vuln_map[child].name + ']' if child in vuln_map else ''}")
            _walk(child, child_prefix, depth + 1)

    _walk(root, "", 0)
    return "\n".join(lines)


def _build_vuln_map(findings: list[Finding]) -> dict[str, Severity]:
    """Map package names to their highest severity finding."""
    vuln_map: dict[str, Severity] = {}
    for f in findings:
        pkg = f.package
        if pkg not in vuln_map or f.severity.value < vuln_map[pkg].value:
            vuln_map[pkg] = f.severity
    return vuln_map


def _safe_id(name: str) -> str:
    """Convert package name to a safe graph node ID."""
    return name.replace("@", "_").replace("/", "_").replace("-", "_").replace(".", "_")
