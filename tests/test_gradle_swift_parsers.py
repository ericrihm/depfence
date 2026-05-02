"""Tests for Gradle and Swift lockfile parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.parsers.gradle_lockfile import (
    parse_gradle_lockfile,
    parse_gradle_version_catalog,
)
from depfence.parsers.swift_lockfile import (
    parse_package_resolved,
    parse_podfile_lock,
)
from depfence.core.lockfile import detect_ecosystem


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GRADLE_LOCKFILE_CONTENT = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can mess up the build, be careful.
com.google.code.gson:gson:2.10.1=compileClasspath,runtimeClasspath
com.squareup.okhttp3:okhttp:4.12.0=compileClasspath,runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.22=compileClasspath,runtimeClasspath
empty=
"""

GRADLE_LOCKFILE_MALFORMED = """\
# Comment
com.example:good:1.0.0=compileClasspath
this-is-malformed-no-colon
:missing-group:1.0.0=runtime
com.example:also-good:2.0.0=runtime
empty=
"""

GRADLE_LOCKFILE_EMPTY = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can mess up the build, be careful.
empty=
"""

GRADLE_VERSION_CATALOG = """\
[versions]
kotlin = "1.9.22"
okhttp = "4.12.0"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
gson = { module = "com.google.code.gson:gson", version = "2.10.1" }

[plugins]
android = { id = "com.android.application", version = "8.0.0" }
"""

GRADLE_VERSION_CATALOG_EMPTY_LIBS = """\
[versions]
foo = "1.0.0"

[libraries]
"""

PACKAGE_RESOLVED_V2 = """\
{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": { "revision": "abc123", "version": "5.8.1" }
    },
    {
      "identity": "swift-argument-parser",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-argument-parser.git",
      "state": { "revision": "def456", "version": "1.2.3" }
    }
  ],
  "version": 2
}
"""

PACKAGE_RESOLVED_V1 = """\
{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": { "branch": null, "revision": "abc123", "version": "5.8.1" }
      },
      {
        "package": "Kingfisher",
        "repositoryURL": "https://github.com/onevcat/Kingfisher.git",
        "state": { "branch": null, "revision": "xyz789", "version": "7.10.0" }
      }
    ]
  },
  "version": 1
}
"""

PACKAGE_RESOLVED_NO_VERSION = """\
{
  "pins": [
    {
      "identity": "some-pkg",
      "kind": "remoteSourceControl",
      "location": "https://github.com/example/some-pkg.git",
      "state": { "branch": "main", "revision": "abc123" }
    }
  ],
  "version": 2
}
"""

PODFILE_LOCK_CONTENT = """\
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
"""

PODFILE_LOCK_EMPTY_PODS = """\
PODS:

DEPENDENCIES:
  - SomeLib
"""


# ---------------------------------------------------------------------------
# TestGradleLockfile
# ---------------------------------------------------------------------------


class TestGradleLockfile:
    def test_basic_parsing(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        packages = parse_gradle_lockfile(f)
        assert len(packages) == 3

    def test_ecosystem_is_maven(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        packages = parse_gradle_lockfile(f)
        assert all(p.ecosystem == "maven" for p in packages)

    def test_names_and_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        by_name = {p.name: p for p in parse_gradle_lockfile(f)}
        assert by_name["com.google.code.gson:gson"].version == "2.10.1"
        assert by_name["com.squareup.okhttp3:okhttp"].version == "4.12.0"
        assert by_name["org.jetbrains.kotlin:kotlin-stdlib"].version == "1.9.22"

    def test_skips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        packages = parse_gradle_lockfile(f)
        assert not any(p.name.startswith("#") for p in packages)

    def test_skips_empty_sentinel(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        packages = parse_gradle_lockfile(f)
        assert not any(p.name == "empty" for p in packages)

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_EMPTY)
        assert parse_gradle_lockfile(f) == []

    def test_malformed_lines_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_MALFORMED)
        packages = parse_gradle_lockfile(f)
        names = {p.name for p in packages}
        assert "com.example:good" in names
        assert "com.example:also-good" in names
        # malformed lines must not appear
        assert not any("malformed" in n for n in names)

    def test_returns_package_id_type(self, tmp_path: Path) -> None:
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_CONTENT)
        packages = parse_gradle_lockfile(f)
        assert all(isinstance(p, PackageId) for p in packages)


# ---------------------------------------------------------------------------
# TestGradleVersionCatalog
# ---------------------------------------------------------------------------


class TestGradleVersionCatalog:
    def test_basic_parsing(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG)
        packages = parse_gradle_version_catalog(f)
        assert len(packages) == 3

    def test_ecosystem_is_maven(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG)
        packages = parse_gradle_version_catalog(f)
        assert all(p.ecosystem == "maven" for p in packages)

    def test_version_ref_resolved(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG)
        by_name = {p.name: p for p in parse_gradle_version_catalog(f)}
        assert by_name["org.jetbrains.kotlin:kotlin-stdlib"].version == "1.9.22"
        assert by_name["com.squareup.okhttp3:okhttp"].version == "4.12.0"

    def test_inline_version(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG)
        by_name = {p.name: p for p in parse_gradle_version_catalog(f)}
        assert by_name["com.google.code.gson:gson"].version == "2.10.1"

    def test_plugins_section_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG)
        packages = parse_gradle_version_catalog(f)
        # [plugins] entries have no module= key — none should appear
        assert not any("android" in p.name for p in packages)

    def test_empty_libraries_section(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_EMPTY_LIBS)
        assert parse_gradle_version_catalog(f) == []

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "libs.versions.toml"
        f.write_text("")
        assert parse_gradle_version_catalog(f) == []


# ---------------------------------------------------------------------------
# TestPackageResolved
# ---------------------------------------------------------------------------


class TestPackageResolved:
    def test_v2_basic_parsing(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V2)
        packages = parse_package_resolved(f)
        assert len(packages) == 2

    def test_v2_ecosystem(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V2)
        assert all(p.ecosystem == "swift" for p in parse_package_resolved(f))

    def test_v2_names_and_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V2)
        by_name = {p.name: p for p in parse_package_resolved(f)}
        assert by_name["alamofire"].version == "5.8.1"
        assert by_name["swift-argument-parser"].version == "1.2.3"

    def test_v1_basic_parsing(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V1)
        packages = parse_package_resolved(f)
        assert len(packages) == 2

    def test_v1_ecosystem(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V1)
        assert all(p.ecosystem == "swift" for p in parse_package_resolved(f))

    def test_v1_names_and_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_V1)
        by_name = {p.name: p for p in parse_package_resolved(f)}
        assert by_name["Alamofire"].version == "5.8.1"
        assert by_name["Kingfisher"].version == "7.10.0"

    def test_pin_without_version_is_included(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text(PACKAGE_RESOLVED_NO_VERSION)
        packages = parse_package_resolved(f)
        assert len(packages) == 1
        assert packages[0].name == "some-pkg"
        assert packages[0].version is None

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text("{}")
        assert parse_package_resolved(f) == []

    def test_malformed_json(self, tmp_path: Path) -> None:
        f = tmp_path / "Package.resolved"
        f.write_text("not json at all")
        assert parse_package_resolved(f) == []


# ---------------------------------------------------------------------------
# TestPodfileLock
# ---------------------------------------------------------------------------


class TestPodfileLock:
    def test_basic_parsing(self, tmp_path: Path) -> None:
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_CONTENT)
        packages = parse_podfile_lock(f)
        assert len(packages) == 3

    def test_ecosystem(self, tmp_path: Path) -> None:
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_CONTENT)
        assert all(p.ecosystem == "swift" for p in parse_podfile_lock(f))

    def test_names_and_versions(self, tmp_path: Path) -> None:
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_CONTENT)
        by_name = {p.name: p for p in parse_podfile_lock(f)}
        assert by_name["Alamofire"].version == "5.8.1"
        assert by_name["Moya"].version == "15.0.0"
        assert by_name["SwiftyJSON"].version == "5.0.1"

    def test_sub_dependencies_excluded(self, tmp_path: Path) -> None:
        """Entries indented under a pod (its deps) must not appear as top-level packages."""
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_CONTENT)
        names = {p.name for p in parse_podfile_lock(f)}
        # "Alamofire" appears as a sub-dep of Moya but should only be counted once
        # (as a top-level pod entry)
        assert names == {"Alamofire", "Moya", "SwiftyJSON"}

    def test_empty_pods_section(self, tmp_path: Path) -> None:
        f = tmp_path / "Podfile.lock"
        f.write_text(PODFILE_LOCK_EMPTY_PODS)
        assert parse_podfile_lock(f) == []

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "Podfile.lock"
        f.write_text("")
        assert parse_podfile_lock(f) == []


# ---------------------------------------------------------------------------
# TestDetectEcosystem
# ---------------------------------------------------------------------------


class TestDetectEcosystem:
    def test_detects_gradle_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "gradle.lockfile").write_text("empty=\n")
        results = detect_ecosystem(tmp_path)
        ecosystems = {eco for eco, _ in results}
        assert "maven" in ecosystems

    def test_detects_package_resolved(self, tmp_path: Path) -> None:
        (tmp_path / "Package.resolved").write_text('{"pins":[],"version":2}')
        results = detect_ecosystem(tmp_path)
        ecosystems = {eco for eco, _ in results}
        assert "swift" in ecosystems

    def test_detects_podfile_lock(self, tmp_path: Path) -> None:
        (tmp_path / "Podfile.lock").write_text("PODS:\n")
        results = detect_ecosystem(tmp_path)
        ecosystems = {eco for eco, _ in results}
        assert "swift" in ecosystems

    def test_returns_correct_path_for_gradle(self, tmp_path: Path) -> None:
        lockfile = tmp_path / "gradle.lockfile"
        lockfile.write_text("empty=\n")
        results = detect_ecosystem(tmp_path)
        paths = [p for _, p in results]
        assert lockfile in paths

    def test_multiple_lockfiles_detected(self, tmp_path: Path) -> None:
        (tmp_path / "gradle.lockfile").write_text("empty=\n")
        (tmp_path / "Package.resolved").write_text('{"pins":[],"version":2}')
        (tmp_path / "Podfile.lock").write_text("PODS:\n")
        results = detect_ecosystem(tmp_path)
        ecosystems = [eco for eco, _ in results]
        assert ecosystems.count("maven") >= 1
        assert ecosystems.count("swift") >= 2
