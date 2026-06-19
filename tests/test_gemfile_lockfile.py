"""Tests for depfence/parsers/gemfile_lockfile.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.parsers.gemfile_lockfile import parse_gemfile_lock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GEMFILE_LOCK_FULL = """\
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.3)
      actionpack (= 7.1.3)
    actionpack (7.1.3)
      rack (~> 3.0)
    rails (7.1.3)
      actionpack (= 7.1.3)
    rake (13.1.0)

GIT
  remote: https://github.com/rack/rack.git
  revision: abc1234
  branch: main
  specs:
    rack (3.0.8)

PATH
  remote: .
  specs:
    myapp (0.1.0)

PLATFORMS
  arm64-darwin-23
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)
  rake

BUNDLED WITH
   2.5.4
"""

GEMFILE_LOCK_MINIMAL = """\
GEM
  remote: https://rubygems.org/
  specs:
    sinatra (3.2.0)

BUNDLED WITH
   2.4.0
"""

GEMFILE_LOCK_EMPTY = ""

GEMFILE_LOCK_NO_SPECS = """\
GEM
  remote: https://rubygems.org/

BUNDLED WITH
   2.5.0
"""

GEMFILE_LOCK_DEDUP = """\
GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.7)

GIT
  remote: https://github.com/rack/rack.git
  specs:
    rack (3.0.8)

BUNDLED WITH
   2.5.0
"""

GEMFILE_LOCK_WITH_PLATFORM_GEM = """\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.3-arm64-darwin)
    puma (6.4.2)

BUNDLED WITH
   2.5.4
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseGemfileLockBasic:
    def test_gem_section_packages_included(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        names = {p.name for p in parse_gemfile_lock(f)}
        assert "rails" in names
        assert "rake" in names
        assert "actioncable" in names
        assert "actionpack" in names

    def test_git_section_packages_included(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        names = {p.name for p in parse_gemfile_lock(f)}
        assert "rack" in names

    def test_path_section_packages_included(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        names = {p.name for p in parse_gemfile_lock(f)}
        assert "myapp" in names

    def test_ecosystem_is_rubygems(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        assert all(p.ecosystem == "rubygems" for p in parse_gemfile_lock(f))

    def test_versions_extracted(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        by_name = {p.name: p for p in parse_gemfile_lock(f)}
        assert by_name["rails"].version == "7.1.3"
        assert by_name["rake"].version == "13.1.0"
        assert by_name["rack"].version == "3.0.8"
        assert by_name["myapp"].version == "0.1.0"

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        assert all(isinstance(p, PackageId) for p in parse_gemfile_lock(f))


class TestParseGemfileLockSubDependencies:
    def test_sub_dependency_lines_not_top_level(self, tmp_path: Path):
        """Lines indented 6+ spaces (sub-deps under a gem) must not appear as top-level entries."""
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        packages = parse_gemfile_lock(f)
        # actionpack appears as sub-dep of actioncable AND as its own top-level spec
        # It must be present exactly once
        actionpack_entries = [p for p in packages if p.name == "actionpack"]
        assert len(actionpack_entries) == 1
        assert actionpack_entries[0].version == "7.1.3"

    def test_dependencies_section_not_parsed(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        names = {p.name for p in parse_gemfile_lock(f)}
        # "DEPENDENCIES" section lists constraint strings, not versioned gems
        assert "rails (~> 7.1)" not in names

    def test_bundled_with_not_parsed(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_FULL)
        names = {p.name for p in parse_gemfile_lock(f)}
        assert "BUNDLED" not in names
        assert "2.5.4" not in names


class TestParseGemfileLockDeduplication:
    def test_same_gem_across_sections_deduplicated(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_DEDUP)
        packages = parse_gemfile_lock(f)
        rack_entries = [p for p in packages if p.name == "rack"]
        assert len(rack_entries) == 1
        # First occurrence (GEM section 3.0.7) wins
        assert rack_entries[0].version == "3.0.7"


class TestParseGemfileLockEdgeCases:
    def test_empty_file_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_EMPTY)
        assert parse_gemfile_lock(f) == []

    def test_no_specs_blocks_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_NO_SPECS)
        assert parse_gemfile_lock(f) == []

    def test_minimal_one_gem(self, tmp_path: Path):
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_MINIMAL)
        packages = parse_gemfile_lock(f)
        assert len(packages) == 1
        assert packages[0].name == "sinatra"
        assert packages[0].version == "3.2.0"

    def test_platform_specific_gem_parsed(self, tmp_path: Path):
        """nokogiri (1.16.3-arm64-darwin) should be parsed — the version includes platform suffix."""
        f = tmp_path / "Gemfile.lock"
        f.write_text(GEMFILE_LOCK_WITH_PLATFORM_GEM)
        packages = parse_gemfile_lock(f)
        names = {p.name for p in packages}
        assert "nokogiri" in names
        assert "puma" in names

    def test_missing_file_returns_empty(self, tmp_path: Path):
        f = tmp_path / "DoesNotExist.lock"
        assert parse_gemfile_lock(f) == []
