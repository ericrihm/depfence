"""Tests for depfence/parsers/composer_lockfile.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.parsers.composer_lockfile import parse_composer_lock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_lock(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "composer.lock"
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FULL_LOCK_DATA = {
    "_readme": ["This file locks the dependencies of your project"],
    "content-hash": "abc123def456",
    "packages": [
        {"name": "laravel/framework", "version": "v11.5.0"},
        {"name": "symfony/http-kernel", "version": "v7.0.5"},
        {"name": "guzzlehttp/guzzle", "version": "7.8.1"},
        {"name": "monolog/monolog", "version": "3.5.0"},
    ],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "v10.5.10"},
        {"name": "mockery/mockery", "version": "1.6.7"},
    ],
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseComposerLockBasic:
    def test_production_packages_included(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        names = {pkg.name for pkg in parse_composer_lock(p)}
        assert "laravel/framework" in names
        assert "symfony/http-kernel" in names
        assert "guzzlehttp/guzzle" in names
        assert "monolog/monolog" in names

    def test_dev_packages_included(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        names = {pkg.name for pkg in parse_composer_lock(p)}
        assert "phpunit/phpunit" in names
        assert "mockery/mockery" in names

    def test_total_count(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        assert len(parse_composer_lock(p)) == 6

    def test_ecosystem_is_packagist(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        assert all(pkg.ecosystem == "packagist" for pkg in parse_composer_lock(p))

    def test_v_prefix_stripped_from_version(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        by_name = {pkg.name: pkg for pkg in parse_composer_lock(p)}
        assert by_name["laravel/framework"].version == "11.5.0"
        assert by_name["symfony/http-kernel"].version == "7.0.5"
        assert by_name["phpunit/phpunit"].version == "10.5.10"

    def test_version_without_v_prefix_unchanged(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        by_name = {pkg.name: pkg for pkg in parse_composer_lock(p)}
        assert by_name["guzzlehttp/guzzle"].version == "7.8.1"
        assert by_name["monolog/monolog"].version == "3.5.0"

    def test_returns_package_id_instances(self, tmp_path: Path):
        p = _write_lock(tmp_path, FULL_LOCK_DATA)
        assert all(isinstance(pkg, PackageId) for pkg in parse_composer_lock(p))


class TestParseComposerLockEdgeCases:
    def test_empty_json_object_returns_empty(self, tmp_path: Path):
        p = _write_lock(tmp_path, {})
        assert parse_composer_lock(p) == []

    def test_invalid_json_returns_empty(self, tmp_path: Path):
        p = tmp_path / "composer.lock"
        p.write_text("this is not json { at all")
        assert parse_composer_lock(p) == []

    def test_missing_packages_key_returns_empty(self, tmp_path: Path):
        p = _write_lock(tmp_path, {"content-hash": "abc"})
        assert parse_composer_lock(p) == []

    def test_missing_name_entry_skipped(self, tmp_path: Path):
        data = {
            "packages": [
                {"version": "1.0.0"},  # no name
                {"name": "vendor/valid", "version": "2.0.0"},
            ],
            "packages-dev": [],
        }
        p = _write_lock(tmp_path, data)
        packages = parse_composer_lock(p)
        assert len(packages) == 1
        assert packages[0].name == "vendor/valid"

    def test_missing_version_produces_none(self, tmp_path: Path):
        data = {"packages": [{"name": "vendor/pkg"}], "packages-dev": []}
        p = _write_lock(tmp_path, data)
        packages = parse_composer_lock(p)
        assert len(packages) == 1
        assert packages[0].version is None

    def test_deduplication_across_sections(self, tmp_path: Path):
        data = {
            "packages": [{"name": "dup/pkg", "version": "1.0.0"}],
            "packages-dev": [{"name": "dup/pkg", "version": "1.0.0"}],
        }
        p = _write_lock(tmp_path, data)
        packages = parse_composer_lock(p)
        assert len(packages) == 1

    def test_only_dev_packages_parsed(self, tmp_path: Path):
        data = {
            "packages": [],
            "packages-dev": [{"name": "dev/only", "version": "0.1.0"}],
        }
        p = _write_lock(tmp_path, data)
        packages = parse_composer_lock(p)
        assert len(packages) == 1
        assert packages[0].name == "dev/only"

    def test_empty_packages_arrays(self, tmp_path: Path):
        data = {"packages": [], "packages-dev": []}
        p = _write_lock(tmp_path, data)
        assert parse_composer_lock(p) == []

    def test_large_composer_lock(self, tmp_path: Path):
        pkgs = [{"name": f"vendor/pkg-{i}", "version": f"{i}.0.0"} for i in range(50)]
        data = {"packages": pkgs, "packages-dev": []}
        p = _write_lock(tmp_path, data)
        packages = parse_composer_lock(p)
        assert len(packages) == 50
