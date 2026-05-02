"""Tests for the dependency tree resolver (dep_tree.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depfence.core.dep_tree import (
    DepNode,
    build_tree_from_package_lock,
    build_tree_from_poetry_lock,
    count_transitive,
    find_paths_to,
    tree_to_text,
)
from depfence.core.models import PackageId


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PACKAGE_LOCK_V3 = {
    "name": "myapp",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "myapp",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "^4.17.21",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            },
        },
        "node_modules/express": {
            "version": "4.18.2",
            "dependencies": {
                "body-parser": "^1.20.0",
                "qs": "^6.11.0",
            },
        },
        "node_modules/body-parser": {
            "version": "1.20.2",
            "dependencies": {
                "qs": "^6.11.0",
            },
        },
        "node_modules/qs": {
            "version": "6.11.2",
        },
        "node_modules/lodash": {
            "version": "4.17.21",
        },
        "node_modules/jest": {
            "version": "29.7.0",
            "dependencies": {
                "jest-cli": "^29.7.0",
            },
        },
        "node_modules/jest-cli": {
            "version": "29.7.0",
        },
    },
}

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[package.dependencies]
certifi = ">=2017.4.17"
charset-normalizer = ">=2,<4"
urllib3 = ">=1.21.1,<3"

[[package]]
name = "certifi"
version = "2023.7.22"
category = "main"

[[package]]
name = "charset-normalizer"
version = "3.3.0"
category = "main"

[[package]]
name = "urllib3"
version = "2.0.7"
category = "main"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[package.dependencies]
pluggy = ">=0.12,<2"

[[package]]
name = "pluggy"
version = "1.3.0"
category = "dev"
"""


# ---------------------------------------------------------------------------
# package-lock.json v3 tests
# ---------------------------------------------------------------------------

class TestBuildTreeFromPackageLock:
    def test_returns_root_nodes(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        root_names = {n.package.name for n in tree}
        assert "express" in root_names
        assert "lodash" in root_names
        assert "jest" in root_names
        # Internal packages should not be roots
        assert "body-parser" not in root_names

    def test_root_node_versions(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        express_node = next(n for n in tree if n.package.name == "express")
        assert express_node.package.version == "4.18.2"
        lodash_node = next(n for n in tree if n.package.name == "lodash")
        assert lodash_node.package.version == "4.17.21"

    def test_dev_flag(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        jest_node = next(n for n in tree if n.package.name == "jest")
        assert jest_node.is_dev is True
        express_node = next(n for n in tree if n.package.name == "express")
        assert express_node.is_dev is False

    def test_children_populated(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        express_node = next(n for n in tree if n.package.name == "express")
        child_names = {c.package.name for c in express_node.children}
        assert "body-parser" in child_names
        assert "qs" in child_names

    def test_depth_increments(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        express_node = next(n for n in tree if n.package.name == "express")
        assert express_node.depth == 0
        for child in express_node.children:
            assert child.depth == 1

    def test_ecosystem_is_npm(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        for node in tree:
            assert node.package.ecosystem == "npm"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = build_tree_from_package_lock(tmp_path / "nonexistent.json")
        assert result == []

    def test_malformed_json_returns_empty(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text("this is not json {{{")
        result = build_tree_from_package_lock(lock)
        assert result == []

    def test_empty_packages_returns_empty(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
        result = build_tree_from_package_lock(lock)
        assert result == []

    def test_no_packages_key(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({"lockfileVersion": 3}))
        result = build_tree_from_package_lock(lock)
        assert result == []

    def test_circular_deps_dont_hang(self, tmp_path: Path) -> None:
        """Mutually dependent packages should not cause infinite recursion."""
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "app",
                    "dependencies": {"alpha": "^1.0.0"},
                },
                "node_modules/alpha": {
                    "version": "1.0.0",
                    "dependencies": {"beta": "^1.0.0"},
                },
                "node_modules/beta": {
                    "version": "1.0.0",
                    "dependencies": {"alpha": "^1.0.0"},
                },
            },
        }
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(data))
        # Must not raise or hang
        tree = build_tree_from_package_lock(lock)
        assert len(tree) == 1
        assert tree[0].package.name == "alpha"


# ---------------------------------------------------------------------------
# poetry.lock tests
# ---------------------------------------------------------------------------

class TestBuildTreeFromPoetryLock:
    def test_returns_root_nodes(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        root_names = {n.package.name for n in tree}
        # requests and pytest are roots (nothing depends on them)
        assert "requests" in root_names
        assert "pytest" in root_names

    def test_non_root_not_in_roots(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        root_names = {n.package.name for n in tree}
        # certifi, charset-normalizer, urllib3 are deps of requests
        assert "certifi" not in root_names
        assert "urllib3" not in root_names

    def test_versions_parsed(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        requests_node = next(n for n in tree if n.package.name == "requests")
        assert requests_node.package.version == "2.31.0"

    def test_children_populated(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        requests_node = next(n for n in tree if n.package.name == "requests")
        child_names = {c.package.name for c in requests_node.children}
        assert "certifi" in child_names
        assert "urllib3" in child_names

    def test_dev_flag_marked(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        pytest_node = next(n for n in tree if n.package.name == "pytest")
        assert pytest_node.is_dev is True
        requests_node = next(n for n in tree if n.package.name == "requests")
        assert requests_node.is_dev is False

    def test_ecosystem_is_pypi(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        for node in tree:
            assert node.package.ecosystem == "pypi"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = build_tree_from_poetry_lock(tmp_path / "poetry.lock")
        assert result == []

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text("")
        result = build_tree_from_poetry_lock(lock)
        assert result == []

    def test_dev_child_inherits_dev_flag(self, tmp_path: Path) -> None:
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK)
        tree = build_tree_from_poetry_lock(lock)
        pytest_node = next(n for n in tree if n.package.name == "pytest")
        # pluggy is a child of pytest (dev)
        pluggy_nodes = [c for c in pytest_node.children if c.package.name == "pluggy"]
        assert pluggy_nodes, "pluggy should be a child of pytest"
        assert pluggy_nodes[0].is_dev is True


# ---------------------------------------------------------------------------
# find_paths_to tests
# ---------------------------------------------------------------------------

class TestFindPathsTo:
    def _make_tree(self) -> list[DepNode]:
        """Construct a simple hand-built tree for path-finding tests."""
        qs = DepNode(package=PackageId("npm", "qs", "6.11.2"), depth=2)
        body_parser = DepNode(package=PackageId("npm", "body-parser", "1.20.2"), depth=1, children=[qs])
        express = DepNode(package=PackageId("npm", "express", "4.18.2"), depth=0, children=[body_parser])
        lodash = DepNode(package=PackageId("npm", "lodash", "4.17.21"), depth=0)
        return [express, lodash]

    def test_finds_direct_dep(self) -> None:
        tree = self._make_tree()
        paths = find_paths_to(tree, "express")
        assert len(paths) == 1
        assert paths[0][-1].name == "express"
        assert len(paths[0]) == 1  # root itself

    def test_finds_nested_dep(self) -> None:
        tree = self._make_tree()
        paths = find_paths_to(tree, "qs")
        assert len(paths) == 1
        path = paths[0]
        assert [p.name for p in path] == ["express", "body-parser", "qs"]

    def test_returns_empty_for_unknown(self) -> None:
        tree = self._make_tree()
        paths = find_paths_to(tree, "nonexistent-pkg")
        assert paths == []

    def test_case_insensitive(self) -> None:
        tree = self._make_tree()
        paths = find_paths_to(tree, "QS")
        assert len(paths) == 1

    def test_multiple_paths(self) -> None:
        """Package reachable via two roots should yield two paths."""
        shared = DepNode(package=PackageId("npm", "ms", "2.1.3"), depth=1)
        root_a = DepNode(package=PackageId("npm", "debug", "4.3.4"), depth=0, children=[shared])
        root_b = DepNode(package=PackageId("npm", "mocha", "10.2.0"), depth=0, children=[shared])
        paths = find_paths_to([root_a, root_b], "ms")
        assert len(paths) == 2
        roots_in_paths = {path[0].name for path in paths}
        assert "debug" in roots_in_paths
        assert "mocha" in roots_in_paths

    def test_empty_tree(self) -> None:
        assert find_paths_to([], "anything") == []

    def test_from_lockfile(self, tmp_path: Path) -> None:
        """Integration: parse lockfile then find a nested transitive dep."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        paths = find_paths_to(tree, "qs")
        # qs appears under express->qs and express->body-parser->qs
        assert len(paths) >= 1
        # At least one path should go through express
        express_paths = [p for p in paths if p[0].name == "express"]
        assert express_paths


# ---------------------------------------------------------------------------
# tree_to_text tests
# ---------------------------------------------------------------------------

class TestTreeToText:
    def _make_tree(self) -> list[DepNode]:
        qs = DepNode(package=PackageId("npm", "qs", "6.11.2"), depth=2)
        body_parser = DepNode(package=PackageId("npm", "body-parser", "1.20.2"), depth=1, children=[qs])
        express = DepNode(package=PackageId("npm", "express", "4.18.2"), depth=0, children=[body_parser])
        lodash = DepNode(package=PackageId("npm", "lodash", "4.17.21"), depth=0)
        return [express, lodash]

    def test_root_names_present(self) -> None:
        text = tree_to_text(self._make_tree())
        assert "express@4.18.2" in text
        assert "lodash@4.17.21" in text

    def test_children_present(self) -> None:
        text = tree_to_text(self._make_tree())
        assert "body-parser@1.20.2" in text
        assert "qs@6.11.2" in text

    def test_box_drawing_chars(self) -> None:
        text = tree_to_text(self._make_tree())
        assert "├──" in text or "└──" in text

    def test_last_child_uses_corner(self) -> None:
        """Single child should use └── not ├──."""
        child = DepNode(package=PackageId("npm", "child", "1.0.0"), depth=1)
        root = DepNode(package=PackageId("npm", "root", "1.0.0"), depth=0, children=[child])
        text = tree_to_text([root])
        assert "└──" in text
        assert "├──" not in text

    def test_max_depth_respected(self) -> None:
        # Build a 4-level chain: root → a → b → c → d
        d = DepNode(package=PackageId("npm", "d", "1.0"), depth=3)
        c = DepNode(package=PackageId("npm", "c", "1.0"), depth=2, children=[d])
        b = DepNode(package=PackageId("npm", "b", "1.0"), depth=1, children=[c])
        a = DepNode(package=PackageId("npm", "a", "1.0"), depth=0, children=[b])
        text = tree_to_text([a], max_depth=1)
        assert "b@1.0" in text
        assert "c@1.0" not in text
        assert "d@1.0" not in text

    def test_dev_label(self) -> None:
        node = DepNode(package=PackageId("npm", "jest", "29.0.0"), depth=0, is_dev=True)
        text = tree_to_text([node])
        assert "(dev)" in text

    def test_empty_tree(self) -> None:
        assert tree_to_text([]) == ""

    def test_no_version_renders_name_only(self) -> None:
        node = DepNode(package=PackageId("npm", "some-pkg", None), depth=0)
        text = tree_to_text([node])
        assert "some-pkg" in text
        assert "@" not in text


# ---------------------------------------------------------------------------
# count_transitive tests
# ---------------------------------------------------------------------------

class TestCountTransitive:
    def test_no_children(self) -> None:
        root = DepNode(package=PackageId("npm", "leaf", "1.0.0"), depth=0)
        result = count_transitive([root])
        assert result["leaf"] == 0

    def test_single_level_children(self) -> None:
        a = DepNode(package=PackageId("npm", "a", "1.0.0"), depth=1)
        b = DepNode(package=PackageId("npm", "b", "1.0.0"), depth=1)
        root = DepNode(package=PackageId("npm", "root", "1.0.0"), depth=0, children=[a, b])
        result = count_transitive([root])
        assert result["root"] == 2

    def test_nested_children(self) -> None:
        c = DepNode(package=PackageId("npm", "c", "1.0.0"), depth=2)
        b = DepNode(package=PackageId("npm", "b", "1.0.0"), depth=1, children=[c])
        a = DepNode(package=PackageId("npm", "a", "1.0.0"), depth=1)
        root = DepNode(package=PackageId("npm", "root", "1.0.0"), depth=0, children=[a, b])
        result = count_transitive([root])
        assert result["root"] == 3  # a, b, c

    def test_diamond_counted_once(self) -> None:
        """Shared dep reachable via two paths should be counted once."""
        shared = DepNode(package=PackageId("npm", "shared", "1.0.0"), depth=2)
        left = DepNode(package=PackageId("npm", "left", "1.0.0"), depth=1, children=[shared])
        right = DepNode(package=PackageId("npm", "right", "1.0.0"), depth=1, children=[shared])
        root = DepNode(package=PackageId("npm", "root", "1.0.0"), depth=0, children=[left, right])
        result = count_transitive([root])
        assert result["root"] == 3  # left, right, shared (not 4)

    def test_multiple_roots(self) -> None:
        child = DepNode(package=PackageId("npm", "child", "1.0.0"), depth=1)
        root_a = DepNode(package=PackageId("npm", "alpha", "1.0.0"), depth=0, children=[child])
        root_b = DepNode(package=PackageId("npm", "beta", "1.0.0"), depth=0)
        result = count_transitive([root_a, root_b])
        assert result["alpha"] == 1
        assert result["beta"] == 0

    def test_from_lockfile(self, tmp_path: Path) -> None:
        """Integration: parsed lockfile transitive counts are non-negative."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps(PACKAGE_LOCK_V3))
        tree = build_tree_from_package_lock(lock)
        result = count_transitive(tree)
        # express has body-parser, qs at minimum
        assert result.get("express", 0) >= 2
        # lodash has no deps
        assert result.get("lodash", 0) == 0

    def test_empty_tree(self) -> None:
        assert count_transitive([]) == {}
