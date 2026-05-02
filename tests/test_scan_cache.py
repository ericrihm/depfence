"""Tests for ScanCache diff scanning."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.core.scan_cache import ScanCache


def _cache(tmp_path: Path) -> ScanCache:
    return ScanCache(cache_dir=tmp_path / "cache")


def _pkg(name: str, version: str, ecosystem: str = "npm") -> PackageId:
    return PackageId(ecosystem, name, version)


def test_first_scan_returns_none(tmp_path):
    cache = _cache(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    assert cache.get_cached_packages(project_dir) is None


def test_save_and_retrieve(tmp_path):
    cache = _cache(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    packages = [_pkg("lodash", "4.17.21"), _pkg("express", "4.18.2")]
    cache.save_scan(project_dir, packages)

    retrieved = cache.get_cached_packages(project_dir)
    assert retrieved is not None
    assert "npm:lodash@4.17.21" in retrieved
    assert "npm:express@4.18.2" in retrieved


def test_diff_detects_additions(tmp_path):
    cache = _cache(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    initial = [_pkg("lodash", "4.17.21")]
    cache.save_scan(project_dir, initial)

    current = [_pkg("lodash", "4.17.21"), _pkg("axios", "1.6.0")]
    diff = cache.get_diff(project_dir, current)

    added_names = [p.name for p in diff["added"]]
    assert "axios" in added_names
    assert diff["removed"] == []
    assert diff["updated"] == []


def test_diff_detects_removals(tmp_path):
    cache = _cache(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    initial = [_pkg("lodash", "4.17.21"), _pkg("axios", "1.6.0")]
    cache.save_scan(project_dir, initial)

    current = [_pkg("lodash", "4.17.21")]
    diff = cache.get_diff(project_dir, current)

    removed_names = [p.name for p in diff["removed"]]
    assert "axios" in removed_names
    assert diff["added"] == []
    assert diff["updated"] == []


def test_diff_detects_updates(tmp_path):
    cache = _cache(tmp_path)
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    initial = [_pkg("lodash", "4.17.20")]
    cache.save_scan(project_dir, initial)

    current = [_pkg("lodash", "4.17.21")]
    diff = cache.get_diff(project_dir, current)

    updated_names = [p.name for p in diff["updated"]]
    assert "lodash" in updated_names
    assert diff["added"] == []
    assert diff["removed"] == []
