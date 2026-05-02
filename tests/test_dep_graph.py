"""Tests for dependency graph analysis."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.dep_graph import DependencyGraph, build_graph_from_package_lock
from depfence.core.models import PackageId


def _make_pkg(name, version="1.0.0", eco="npm"):
    return PackageId(eco, name, version)


def test_basic_graph():
    g = DependencyGraph()
    root = _make_pkg("my-app")
    lodash = _make_pkg("lodash", "4.17.21")
    g.add_package(root, is_direct=True)
    g.add_dependency(root, lodash)
    assert g.node_count == 2
    assert g.get_dependencies(root) == ["npm:lodash@4.17.21"]


def test_transitive_dependents():
    g = DependencyGraph()
    app = _make_pkg("app")
    express = _make_pkg("express")
    body_parser = _make_pkg("body-parser")
    raw_body = _make_pkg("raw-body")

    g.add_package(app, is_direct=True)
    g.add_dependency(app, express)
    g.add_dependency(express, body_parser)
    g.add_dependency(body_parser, raw_body)

    dependents = g.get_transitive_dependents(raw_body)
    assert "npm:body-parser@1.0.0" in dependents
    assert "npm:express@1.0.0" in dependents
    assert "npm:app@1.0.0" in dependents


def test_blast_radius():
    g = DependencyGraph()
    app = _make_pkg("app")
    core = _make_pkg("core-lib")
    a = _make_pkg("dep-a")
    b = _make_pkg("dep-b")
    c = _make_pkg("dep-c")

    g.add_package(app, is_direct=True)
    g.add_dependency(app, core)
    g.add_dependency(a, core)
    g.add_dependency(b, core)
    g.add_dependency(c, core)

    br = g.compute_blast_radius(core)
    assert br.direct_dependents == 4
    assert br.risk_score > 0


def test_shortest_path():
    g = DependencyGraph()
    app = _make_pkg("app")
    a = _make_pkg("a")
    b = _make_pkg("b")
    c = _make_pkg("c")

    g.add_dependency(app, a)
    g.add_dependency(a, b)
    g.add_dependency(b, c)
    g.add_dependency(app, c)  # shortcut

    path = g.shortest_path(app, c)
    assert path is not None
    assert len(path) == 2  # direct edge app -> c


def test_concentration_risks():
    g = DependencyGraph()
    shared = _make_pkg("shared-util")
    for i in range(10):
        dep = _make_pkg(f"dep-{i}")
        g.add_dependency(dep, shared)

    risks = g.find_concentration_risks(threshold=5)
    assert len(risks) >= 1
    assert risks[0].direct_dependents >= 10


def test_direct_packages():
    g = DependencyGraph()
    a = _make_pkg("direct-dep")
    b = _make_pkg("transitive-dep")
    g.add_package(a, is_direct=True)
    g.add_package(b, is_direct=False)
    assert "npm:direct-dep@1.0.0" in g.get_direct_packages()
    assert "npm:transitive-dep@1.0.0" not in g.get_direct_packages()


def test_to_dict():
    g = DependencyGraph()
    g.add_package(_make_pkg("a"), is_direct=True)
    g.add_dependency(_make_pkg("a"), _make_pkg("b"))
    d = g.to_dict()
    assert d["nodes"] == 2
    assert d["edges"] == 1
    assert d["direct_deps"] == 1


def test_build_from_package_lock():
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "my-app", "version": "1.0.0"},
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {"body-parser": "^1.20.0"},
            },
            "node_modules/body-parser": {
                "version": "1.20.2",
                "dependencies": {"raw-body": "^2.5.0"},
            },
            "node_modules/raw-body": {"version": "2.5.2"},
        },
    }
    with tempfile.TemporaryDirectory() as d:
        lock_path = Path(d) / "package-lock.json"
        lock_path.write_text(json.dumps(lock))
        pkg_json = Path(d) / "package.json"
        pkg_json.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))

        graph = build_graph_from_package_lock(lock_path)
        assert graph.node_count >= 3  # includes dependency refs
        deps = graph.get_dependencies(PackageId("npm", "express", "4.18.2"))
        assert any("body-parser" in d for d in deps)


def test_no_path_returns_none():
    g = DependencyGraph()
    a = _make_pkg("a")
    b = _make_pkg("b")
    g.add_package(a)
    g.add_package(b)
    assert g.shortest_path(a, b) is None
