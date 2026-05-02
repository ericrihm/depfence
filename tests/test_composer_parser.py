"""Tests for the PHP composer.lock parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depfence.parsers.composer_lockfile import parse_composer_lock


@pytest.fixture
def composer_lock(tmp_path):
    """Create a realistic composer.lock file."""
    data = {
        "_readme": ["This file locks the dependencies"],
        "content-hash": "abc123",
        "packages": [
            {
                "name": "laravel/framework",
                "version": "v11.5.0",
                "source": {"type": "git"},
            },
            {
                "name": "symfony/http-kernel",
                "version": "v7.0.5",
                "source": {"type": "git"},
            },
            {
                "name": "guzzlehttp/guzzle",
                "version": "7.8.1",
                "source": {"type": "git"},
            },
            {
                "name": "monolog/monolog",
                "version": "3.5.0",
                "source": {"type": "git"},
            },
        ],
        "packages-dev": [
            {
                "name": "phpunit/phpunit",
                "version": "v10.5.10",
                "source": {"type": "git"},
            },
            {
                "name": "mockery/mockery",
                "version": "1.6.7",
                "source": {"type": "git"},
            },
        ],
    }
    lock_path = tmp_path / "composer.lock"
    lock_path.write_text(json.dumps(data))
    return lock_path


class TestParseComposerLock:
    def test_parses_production_packages(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        names = [p.name for p in packages]
        assert "laravel/framework" in names
        assert "symfony/http-kernel" in names
        assert "guzzlehttp/guzzle" in names

    def test_parses_dev_packages(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        names = [p.name for p in packages]
        assert "phpunit/phpunit" in names
        assert "mockery/mockery" in names

    def test_ecosystem_is_packagist(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        assert all(p.ecosystem == "packagist" for p in packages)

    def test_strips_v_prefix_from_version(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        laravel = next(p for p in packages if p.name == "laravel/framework")
        assert laravel.version == "11.5.0"

    def test_preserves_version_without_v(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        guzzle = next(p for p in packages if p.name == "guzzlehttp/guzzle")
        assert guzzle.version == "7.8.1"

    def test_total_count(self, composer_lock):
        packages = parse_composer_lock(composer_lock)
        assert len(packages) == 6

    def test_deduplicates_across_sections(self, tmp_path):
        data = {
            "packages": [{"name": "dup/pkg", "version": "1.0.0"}],
            "packages-dev": [{"name": "dup/pkg", "version": "1.0.0"}],
        }
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps(data))
        packages = parse_composer_lock(lock_path)
        assert len(packages) == 1

    def test_empty_file(self, tmp_path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text("{}")
        packages = parse_composer_lock(lock_path)
        assert packages == []

    def test_invalid_json(self, tmp_path):
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text("not json at all")
        packages = parse_composer_lock(lock_path)
        assert packages == []

    def test_missing_version(self, tmp_path):
        data = {"packages": [{"name": "vendor/pkg"}]}
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps(data))
        packages = parse_composer_lock(lock_path)
        assert len(packages) == 1
        assert packages[0].version is None


class TestLockfileIntegration:
    def test_detect_ecosystem_finds_composer(self, tmp_path):
        from depfence.core.lockfile import detect_ecosystem
        (tmp_path / "composer.lock").write_text('{"packages": []}')
        lockfiles = detect_ecosystem(tmp_path)
        ecosystems = [eco for eco, _ in lockfiles]
        assert "packagist" in ecosystems

    def test_parse_lockfile_dispatches_to_composer(self, tmp_path):
        from depfence.core.lockfile import parse_lockfile
        data = {"packages": [{"name": "vendor/lib", "version": "2.0.0"}]}
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps(data))
        packages = parse_lockfile("packagist", lock_path)
        assert len(packages) == 1
        assert packages[0].name == "vendor/lib"
