"""Tests for vulnerability propagation analysis."""

import pytest

from depfence.core.vuln_propagation import (
    AttackPath,
    compute_upgrade_priorities,
    exposure_summary,
    trace_attack_paths,
)


@pytest.fixture
def sample_graph():
    return {
        "my-app": {"express", "lodash"},
        "express": {"body-parser", "qs"},
        "body-parser": {"qs", "raw-body"},
        "qs": {"side-channel"},
        "lodash": set(),
        "side-channel": set(),
        "raw-body": set(),
    }


@pytest.fixture
def direct_deps():
    return {"express", "lodash"}


def test_trace_direct_vuln(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"lodash"}, direct_deps)
    assert len(paths) == 0  # lodash IS a direct dep with no transitive path


def test_trace_transitive_vuln(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"side-channel"}, direct_deps)
    assert len(paths) >= 1
    assert paths[0].vulnerable_package == "side-channel"
    assert paths[0].direct_dependency == "express"
    assert "side-channel" in paths[0].path
    assert "express" in paths[0].path


def test_trace_depth(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"side-channel"}, direct_deps)
    assert paths[0].depth >= 2  # side-channel -> qs -> express (or via body-parser)


def test_multiple_vulns(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"side-channel", "raw-body"}, direct_deps)
    vuln_pkgs = set(p.vulnerable_package for p in paths)
    assert "side-channel" in vuln_pkgs
    assert "raw-body" in vuln_pkgs


def test_upgrade_priorities(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"side-channel", "raw-body", "qs"}, direct_deps)
    priorities = compute_upgrade_priorities(paths)
    assert len(priorities) >= 1
    assert priorities[0].package == "express"
    assert priorities[0].vulns_eliminated >= 2


def test_exposure_summary_empty():
    summary = exposure_summary([])
    assert summary["total_paths"] == 0
    assert summary["unique_vulns"] == 0


def test_exposure_summary(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"side-channel", "raw-body"}, direct_deps)
    summary = exposure_summary(paths)
    assert summary["total_paths"] > 0
    assert summary["unique_vulns"] == 2
    assert summary["direct_deps_affected"] >= 1
    assert "deepest_path" in summary


def test_nonexistent_vuln(sample_graph, direct_deps):
    paths = trace_attack_paths(sample_graph, {"nonexistent-pkg"}, direct_deps)
    assert paths == []


def test_attack_path_summary():
    path = AttackPath(
        vulnerable_package="evil",
        direct_dependency="express",
        path=["express", "qs", "evil"],
        depth=2,
        severity="HIGH",
    )
    assert path.summary == "express → qs → evil"
