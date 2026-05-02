"""Tests for dependency graph visualization."""

import pytest

from depfence.core.graph_viz import generate_dot, generate_mermaid, generate_tree
from depfence.core.models import Finding, FindingType, Severity


@pytest.fixture
def sample_graph():
    return {
        "my-app": {"express", "lodash"},
        "express": {"body-parser", "qs"},
        "body-parser": {"qs"},
        "qs": set(),
        "lodash": set(),
    }


@pytest.fixture
def sample_findings():
    return [
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package="qs",
            title="Prototype pollution",
            detail="detail",
        ),
    ]


class TestMermaid:
    def test_basic_output(self, sample_graph):
        output = generate_mermaid(sample_graph)
        assert "graph TD" in output
        assert "-->" in output
        assert "express" in output

    def test_vuln_annotation(self, sample_graph, sample_findings):
        output = generate_mermaid(sample_graph, findings=sample_findings)
        assert "danger" in output
        assert "qs" in output

    def test_direct_deps_styled(self, sample_graph):
        output = generate_mermaid(sample_graph, direct_deps={"express", "lodash"})
        assert "direct" in output

    def test_max_nodes_limit(self, sample_graph):
        output = generate_mermaid(sample_graph, max_nodes=3)
        assert output.count("-->") <= 10  # Limited edges


class TestDot:
    def test_basic_output(self, sample_graph):
        output = generate_dot(sample_graph)
        assert "digraph dependencies" in output
        assert "->" in output
        assert "express" in output

    def test_vuln_annotation(self, sample_graph, sample_findings):
        output = generate_dot(sample_graph, findings=sample_findings)
        assert "ff4444" in output  # Red for high severity

    def test_direct_deps_styled(self, sample_graph):
        output = generate_dot(sample_graph, direct_deps={"express"})
        assert "4488ff" in output  # Blue for direct


class TestTree:
    def test_basic_tree(self, sample_graph):
        output = generate_tree(sample_graph, "my-app")
        assert "my-app" in output
        assert "express" in output

    def test_vuln_in_tree(self, sample_graph, sample_findings):
        output = generate_tree(sample_graph, "my-app", findings=sample_findings)
        assert "HIGH" in output

    def test_max_depth(self, sample_graph):
        output = generate_tree(sample_graph, "my-app", max_depth=1)
        lines = output.strip().split("\n")
        assert len(lines) <= 10  # Shallow tree
