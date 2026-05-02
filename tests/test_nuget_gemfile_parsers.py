"""Tests for NuGet (packages.lock.json) and Ruby (Gemfile.lock) lockfile parsers,
and for their integration with the core lockfile detection/dispatch layer.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from depfence.parsers.nuget_lockfiles import parse_packages_lock_json
from depfence.parsers.gemfile_lockfile import parse_gemfile_lock
from depfence.core.lockfile import detect_ecosystem, parse_lockfile


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

PACKAGES_LOCK_JSON_FIXTURE = {
    "version": 2,
    "dependencies": {
        "net8.0": {
            "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[13.0.3, )",
                "resolved": "13.0.3",
            },
            "Microsoft.Extensions.Logging": {
                "type": "Direct",
                "requested": "[8.0.0, )",
                "resolved": "8.0.0",
            },
            "System.Text.Json": {
                "type": "Transitive",
                "resolved": "8.0.0",
            },
        },
        "net6.0": {
            # Same package, same version — should be deduplicated
            "Newtonsoft.Json": {
                "type": "Direct",
                "resolved": "13.0.3",
            },
            # Different version of another package
            "Serilog": {
                "type": "Direct",
                "resolved": "3.1.1",
            },
        },
    },
}

GEMFILE_LOCK_FIXTURE = """GEM
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

GEMFILE_LOCK_MINIMAL = """GEM
  remote: https://rubygems.org/
  specs:
    sinatra (3.2.0)

BUNDLED WITH
   2.4.0
"""


# ---------------------------------------------------------------------------
# NuGet: parse_packages_lock_json
# ---------------------------------------------------------------------------

class TestParsePackagesLockJson:
    def test_returns_correct_ecosystem(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(PACKAGES_LOCK_JSON_FIXTURE, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        assert all(p.ecosystem == "nuget" for p in packages)

    def test_parses_expected_packages(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(PACKAGES_LOCK_JSON_FIXTURE, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        names = {p.name for p in packages}
        assert "Newtonsoft.Json" in names
        assert "Microsoft.Extensions.Logging" in names
        assert "System.Text.Json" in names
        assert "Serilog" in names

    def test_deduplicates_cross_framework(self):
        """Newtonsoft.Json 13.0.3 appears in both net8.0 and net6.0 — count once."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(PACKAGES_LOCK_JSON_FIXTURE, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        newtonsoft = [p for p in packages if p.name == "Newtonsoft.Json"]
        assert len(newtonsoft) == 1

    def test_version_is_resolved_value(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(PACKAGES_LOCK_JSON_FIXTURE, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        by_name = {p.name: p for p in packages}
        assert by_name["Newtonsoft.Json"].version == "13.0.3"
        assert by_name["Serilog"].version == "3.1.1"

    def test_empty_dependencies(self):
        data = {"version": 2, "dependencies": {}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        assert packages == []

    def test_missing_dependencies_key(self):
        data = {"version": 2}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        assert packages == []

    def test_package_without_resolved_has_none_version(self):
        data = {
            "version": 2,
            "dependencies": {
                "net8.0": {
                    "SomePackage": {"type": "Direct"},
                }
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        assert len(packages) == 1
        assert packages[0].version is None


# ---------------------------------------------------------------------------
# Ruby: parse_gemfile_lock
# ---------------------------------------------------------------------------

class TestParseGemfileLock:
    def test_returns_correct_ecosystem(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        assert all(p.ecosystem == "rubygems" for p in packages)

    def test_parses_gem_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        names = {p.name for p in packages}
        assert "rails" in names
        assert "rake" in names
        assert "actioncable" in names
        assert "actionpack" in names

    def test_parses_git_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        names = {p.name for p in packages}
        assert "rack" in names

    def test_parses_path_section(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        names = {p.name for p in packages}
        assert "myapp" in names

    def test_correct_versions(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        by_name = {p.name: p for p in packages}
        assert by_name["rails"].version == "7.1.3"
        assert by_name["rake"].version == "13.1.0"
        assert by_name["rack"].version == "3.0.8"

    def test_deduplication_across_sections(self):
        """rack appears in both GEM and GIT specs — only first occurrence kept."""
        content = """GEM
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
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(content)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        racks = [p for p in packages if p.name == "rack"]
        assert len(racks) == 1
        assert racks[0].version == "3.0.7"

    def test_minimal_lockfile(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_MINIMAL)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        assert len(packages) == 1
        assert packages[0].name == "sinatra"
        assert packages[0].version == "3.2.0"
        assert packages[0].ecosystem == "rubygems"

    def test_empty_lockfile(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write("")
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        assert packages == []

    def test_does_not_include_bundled_with(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        names = {p.name for p in packages}
        # "BUNDLED WITH" is not a gem
        assert "BUNDLED" not in names
        assert "2.5.4" not in names

    def test_does_not_include_sub_dependencies(self):
        """Lines like '      actionpack (= 7.1.3)' (6-space indent) should be ignored."""
        with tempfile.NamedTemporaryFile(mode="w", suffix="Gemfile.lock", delete=False) as f:
            f.write(GEMFILE_LOCK_FIXTURE)
            f.flush()
            packages = parse_gemfile_lock(Path(f.name))
        # The constraint "actionpack (= 7.1.3)" under actioncable is a sub-dep entry,
        # NOT a new gem entry — actionpack itself IS a top-level spec but with version 7.1.3
        by_name = {p.name: p for p in packages}
        # actionpack should be present once with version 7.1.3 from its own spec entry
        assert by_name["actionpack"].version == "7.1.3"


# ---------------------------------------------------------------------------
# Integration: detect_ecosystem + parse_lockfile
# ---------------------------------------------------------------------------

class TestDetectEcosystem:
    def test_detects_packages_lock_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "packages.lock.json").write_text(json.dumps({"version": 2, "dependencies": {}}))
            results = detect_ecosystem(p)
            ecosystems = {eco for eco, _ in results}
            assert "nuget" in ecosystems

    def test_detects_gemfile_lock(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Gemfile.lock").write_text(GEMFILE_LOCK_MINIMAL)
            results = detect_ecosystem(p)
            ecosystems = {eco for eco, _ in results}
            assert "rubygems" in ecosystems


class TestParseLockfileDispatch:
    def test_dispatches_nuget(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="packages.lock", delete=False
        ) as f:
            json.dump(PACKAGES_LOCK_JSON_FIXTURE, f)
            path = Path(f.name)
        # Rename to exact filename expected
        target = path.parent / "packages.lock.json"
        path.rename(target)
        packages = parse_lockfile("nuget", target)
        assert len(packages) > 0
        assert all(p.ecosystem == "nuget" for p in packages)

    def test_dispatches_rubygems(self):
        with tempfile.TemporaryDirectory() as d:
            lock = Path(d) / "Gemfile.lock"
            lock.write_text(GEMFILE_LOCK_FIXTURE)
            packages = parse_lockfile("rubygems", lock)
        assert len(packages) > 0
        assert all(p.ecosystem == "rubygems" for p in packages)

    def test_unknown_ecosystem_returns_empty(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            packages = parse_lockfile("unknown_eco", Path(f.name))
        assert packages == []
