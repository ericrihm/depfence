"""Tests for depfence/parsers/swift_lockfile.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.parsers.swift_lockfile import parse_package_resolved, parse_podfile_lock


# ---------------------------------------------------------------------------
# Fixtures — Package.resolved
# ---------------------------------------------------------------------------

PACKAGE_RESOLVED_V2 = {
    "pins": [
        {
            "identity": "alamofire",
            "kind": "remoteSourceControl",
            "location": "https://github.com/Alamofire/Alamofire.git",
            "state": {"revision": "abc123", "version": "5.8.1"},
        },
        {
            "identity": "swift-argument-parser",
            "kind": "remoteSourceControl",
            "location": "https://github.com/apple/swift-argument-parser.git",
            "state": {"revision": "def456", "version": "1.2.3"},
        },
    ],
    "version": 2,
}

PACKAGE_RESOLVED_V1 = {
    "object": {
        "pins": [
            {
                "package": "Alamofire",
                "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
                "state": {"branch": None, "revision": "abc123", "version": "5.8.1"},
            },
            {
                "package": "Kingfisher",
                "repositoryURL": "https://github.com/onevcat/Kingfisher.git",
                "state": {"branch": None, "revision": "xyz789", "version": "7.10.0"},
            },
        ]
    },
    "version": 1,
}

PACKAGE_RESOLVED_V2_NO_VERSION = {
    "pins": [
        {
            "identity": "some-branch-pkg",
            "kind": "remoteSourceControl",
            "location": "https://github.com/example/some-pkg.git",
            "state": {"branch": "main", "revision": "abc123"},
        },
    ],
    "version": 2,
}

PACKAGE_RESOLVED_EMPTY_PINS = {"pins": [], "version": 2}

PACKAGE_RESOLVED_V2_SINGLE = {
    "pins": [
        {
            "identity": "only-pkg",
            "kind": "remoteSourceControl",
            "location": "https://github.com/example/only-pkg.git",
            "state": {"revision": "aaa", "version": "0.0.1"},
        }
    ],
    "version": 2,
}

# ---------------------------------------------------------------------------
# Fixtures — Podfile.lock
# ---------------------------------------------------------------------------

PODFILE_LOCK_BASIC = """\
PODS:
  - Alamofire (5.8.1)
  - Moya (15.0.0):
    - Alamofire (~> 5.0)
  - SwiftyJSON (5.0.1)

DEPENDENCIES:
  - Alamofire
  - Moya
  - SwiftyJSON

SPEC CHECKSUMS:
  Alamofire: abc123
  Moya: def456
  SwiftyJSON: ghi789

PODFILE CHECKSUM: xyz999

COCOAPODS: 1.14.3
"""

PODFILE_LOCK_EMPTY_PODS = """\
PODS:

DEPENDENCIES:
  - SomeLib

PODFILE CHECKSUM: abc123
"""

PODFILE_LOCK_NO_PODS_SECTION = """\
DEPENDENCIES:
  - Alamofire
"""

PODFILE_LOCK_NESTED_DEPS = """\
PODS:
  - RxSwift (6.7.0)
  - RxCocoa (6.7.0):
    - RxSwift (= 6.7.0)
    - RxRelay (= 6.7.0)
  - RxRelay (6.7.0):
    - RxSwift (= 6.7.0)

DEPENDENCIES:
  - RxSwift
  - RxCocoa
  - RxRelay
"""


# ---------------------------------------------------------------------------
# Tests for parse_package_resolved
# ---------------------------------------------------------------------------

class TestParsePackageResolvedV2:
    def _write(self, tmp_path: Path, data: dict) -> Path:
        f = tmp_path / "Package.resolved"
        f.write_text(json.dumps(data))
        return f

    def test_package_count(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2)
        assert len(parse_package_resolved(f)) == 2

    def test_ecosystem_is_swift(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2)
        assert all(p.ecosystem == "swift" for p in parse_package_resolved(f))

    def test_names_from_identity_key(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2)
        names = {p.name for p in parse_package_resolved(f)}
        assert "alamofire" in names
        assert "swift-argument-parser" in names

    def test_versions_extracted(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2)
        by_name = {p.name: p for p in parse_package_resolved(f)}
        assert by_name["alamofire"].version == "5.8.1"
        assert by_name["swift-argument-parser"].version == "1.2.3"

    def test_pin_without_version_has_none(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2_NO_VERSION)
        packages = parse_package_resolved(f)
        assert len(packages) == 1
        assert packages[0].name == "some-branch-pkg"
        assert packages[0].version is None

    def test_empty_pins(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_EMPTY_PINS)
        assert parse_package_resolved(f) == []

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V2)
        assert all(isinstance(p, PackageId) for p in parse_package_resolved(f))


class TestParsePackageResolvedV1:
    def _write(self, tmp_path: Path, data: dict) -> Path:
        f = tmp_path / "Package.resolved"
        f.write_text(json.dumps(data))
        return f

    def test_package_count(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V1)
        assert len(parse_package_resolved(f)) == 2

    def test_names_from_package_key(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V1)
        names = {p.name for p in parse_package_resolved(f)}
        assert "Alamofire" in names
        assert "Kingfisher" in names

    def test_versions_extracted(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V1)
        by_name = {p.name: p for p in parse_package_resolved(f)}
        assert by_name["Alamofire"].version == "5.8.1"
        assert by_name["Kingfisher"].version == "7.10.0"

    def test_ecosystem_is_swift(self, tmp_path: Path):
        f = self._write(tmp_path, PACKAGE_RESOLVED_V1)
        assert all(p.ecosystem == "swift" for p in parse_package_resolved(f))


class TestParsePackageResolvedEdgeCases:
    def test_malformed_json_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Package.resolved"
        f.write_text("not json at all {{ }")
        assert parse_package_resolved(f) == []

    def test_empty_json_object_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Package.resolved"
        f.write_text("{}")
        assert parse_package_resolved(f) == []

    def test_json_array_at_root_returns_empty(self, tmp_path: Path):
        # Root must be a dict, not an array
        f = tmp_path / "Package.resolved"
        f.write_text("[]")
        assert parse_package_resolved(f) == []

    def test_single_package(self, tmp_path: Path):
        f = tmp_path / "Package.resolved"
        f.write_text(json.dumps(PACKAGE_RESOLVED_V2_SINGLE))
        packages = parse_package_resolved(f)
        assert len(packages) == 1
        assert packages[0].name == "only-pkg"
        assert packages[0].version == "0.0.1"


# ---------------------------------------------------------------------------
# Tests for parse_podfile_lock
# ---------------------------------------------------------------------------

class TestParsePodfileLockBasic:
    def test_package_count(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        assert len(parse_podfile_lock(f)) == 3

    def test_ecosystem_is_swift(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        assert all(p.ecosystem == "swift" for p in parse_podfile_lock(f))

    def test_names_extracted(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        names = {p.name for p in parse_podfile_lock(f)}
        assert "Alamofire" in names
        assert "Moya" in names
        assert "SwiftyJSON" in names

    def test_versions_extracted(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        by_name = {p.name: p for p in parse_podfile_lock(f)}
        assert by_name["Alamofire"].version == "5.8.1"
        assert by_name["Moya"].version == "15.0.0"
        assert by_name["SwiftyJSON"].version == "5.0.1"

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        assert all(isinstance(p, PackageId) for p in parse_podfile_lock(f))


class TestParsePodfileLockSubDependencies:
    def test_sub_dep_lines_excluded(self, tmp_path: Path):
        """Lines indented under a pod (its deps) must not appear as separate packages."""
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        names = {p.name for p in parse_podfile_lock(f)}
        # Alamofire is listed as a sub-dep of Moya but must only be counted as a top-level pod
        assert names == {"Alamofire", "Moya", "SwiftyJSON"}

    def test_nested_deps_all_pods_present(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_NESTED_DEPS)
        names = {p.name for p in parse_podfile_lock(f)}
        assert names == {"RxSwift", "RxCocoa", "RxRelay"}

    def test_dependencies_section_not_parsed(self, tmp_path: Path):
        """DEPENDENCIES: section lists unversioned names — must not appear as packages."""
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_BASIC)
        packages = parse_podfile_lock(f)
        # Verify none of the packages came from the DEPENDENCIES section (they'd have no version)
        # All packages in PODS: have versions, so check that no version is None
        assert all(p.version is not None for p in packages)


class TestParsePodfileLockEdgeCases:
    def test_empty_pods_section_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_EMPTY_PODS)
        assert parse_podfile_lock(f) == []

    def test_no_pods_section_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_NO_PODS_SECTION)
        assert parse_podfile_lock(f) == []

    def test_empty_file_returns_empty(self, tmp_path: Path):
        f = tmp_path / "Podfile.lock"
        f.write_text("")
        assert parse_podfile_lock(f) == []

    def test_missing_file_returns_empty(self, tmp_path: Path):
        f = tmp_path / "DoesNotExist.lock"
        assert parse_podfile_lock(f) == []
