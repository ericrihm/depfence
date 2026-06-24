"""Tests for depfence/parsers/gradle_lockfile.py."""

from __future__ import annotations

from pathlib import Path

from depfence.core.models import PackageId
from depfence.parsers.gradle_lockfile import (
    parse_gradle_lockfile,
    parse_gradle_version_catalog,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GRADLE_LOCKFILE_BASIC = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can mess up the build, be careful.
com.google.code.gson:gson:2.10.1=compileClasspath,runtimeClasspath
com.squareup.okhttp3:okhttp:4.12.0=compileClasspath,runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.22=compileClasspath,runtimeClasspath
empty=
"""

GRADLE_LOCKFILE_EMPTY_SENTINEL_ONLY = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can mess up the build, be careful.
empty=
"""

GRADLE_LOCKFILE_MALFORMED = """\
# Comment
com.example:good:1.0.0=compileClasspath
this-is-malformed-no-colons
:missing-group:1.0.0=runtime
good:artifact-only-two-parts=runtime
com.example:also-good:2.0.0=runtime
empty=
"""

GRADLE_LOCKFILE_NO_CONFIGS = """\
com.example:lib:3.0.0=
empty=
"""

GRADLE_LOCKFILE_SINGLE_ENTRY = """\
com.example:single:0.0.1=compileClasspath
empty=
"""

GRADLE_VERSION_CATALOG_FULL = """\
[versions]
kotlin = "1.9.22"
okhttp = "4.12.0"
gson = "2.10.1"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
gson = { module = "com.google.code.gson:gson", version = "2.10.1" }
no-version = { module = "com.example:no-version" }

[plugins]
android = { id = "com.android.application", version = "8.0.0" }
"""

GRADLE_VERSION_CATALOG_UNRESOLVABLE_REF = """\
[versions]
# no refs here

[libraries]
broken = { module = "com.example:broken", version.ref = "nonexistent" }
"""

GRADLE_VERSION_CATALOG_EMPTY_LIBRARIES = """\
[versions]
foo = "1.0.0"

[libraries]
"""

GRADLE_VERSION_CATALOG_ONLY_PLUGINS = """\
[plugins]
android = { id = "com.android.application", version = "8.0.0" }
"""


# ---------------------------------------------------------------------------
# Tests for parse_gradle_lockfile
# ---------------------------------------------------------------------------

class TestParseGradleLockfileBasic:
    def test_package_count(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        packages = parse_gradle_lockfile(f)
        assert len(packages) == 3

    def test_ecosystem_is_maven(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        assert all(p.ecosystem == "maven" for p in parse_gradle_lockfile(f))

    def test_name_format_group_artifact(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        by_name = {p.name: p for p in parse_gradle_lockfile(f)}
        assert "com.google.code.gson:gson" in by_name
        assert "com.squareup.okhttp3:okhttp" in by_name
        assert "org.jetbrains.kotlin:kotlin-stdlib" in by_name

    def test_versions_extracted(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        by_name = {p.name: p for p in parse_gradle_lockfile(f)}
        assert by_name["com.google.code.gson:gson"].version == "2.10.1"
        assert by_name["com.squareup.okhttp3:okhttp"].version == "4.12.0"
        assert by_name["org.jetbrains.kotlin:kotlin-stdlib"].version == "1.9.22"

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        assert all(isinstance(p, PackageId) for p in parse_gradle_lockfile(f))


class TestParseGradleLockfileEdgeCases:
    def test_empty_file_only_sentinel(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_EMPTY_SENTINEL_ONLY)
        assert parse_gradle_lockfile(f) == []

    def test_comment_lines_skipped(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        packages = parse_gradle_lockfile(f)
        assert not any(p.name.startswith("#") for p in packages)

    def test_empty_sentinel_not_included(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_BASIC)
        packages = parse_gradle_lockfile(f)
        assert not any(p.name == "empty" for p in packages)

    def test_malformed_lines_skipped(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_MALFORMED)
        packages = parse_gradle_lockfile(f)
        names = {p.name for p in packages}
        assert "com.example:good" in names
        assert "com.example:also-good" in names
        # Lines without 3 colon-separated parts are skipped
        assert not any("malformed" in n for n in names)

    def test_no_configs_field_still_parses(self, tmp_path: Path):
        # "com.example:lib:3.0.0=" with empty configs field
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_NO_CONFIGS)
        packages = parse_gradle_lockfile(f)
        assert len(packages) == 1
        assert packages[0].name == "com.example:lib"
        assert packages[0].version == "3.0.0"

    def test_single_entry(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text(GRADLE_LOCKFILE_SINGLE_ENTRY)
        packages = parse_gradle_lockfile(f)
        assert len(packages) == 1
        assert packages[0].name == "com.example:single"
        assert packages[0].version == "0.0.1"

    def test_completely_blank_file(self, tmp_path: Path):
        f = tmp_path / "gradle.lockfile"
        f.write_text("")
        assert parse_gradle_lockfile(f) == []


# ---------------------------------------------------------------------------
# Tests for parse_gradle_version_catalog
# ---------------------------------------------------------------------------

class TestParseGradleVersionCatalogBasic:
    def test_library_count(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        packages = parse_gradle_version_catalog(f)
        # 4 [libraries] entries (including no-version one), plugins excluded
        assert len(packages) == 4

    def test_ecosystem_is_maven(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        assert all(p.ecosystem == "maven" for p in parse_gradle_version_catalog(f))

    def test_version_ref_resolved(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        by_name = {p.name: p for p in parse_gradle_version_catalog(f)}
        assert by_name["org.jetbrains.kotlin:kotlin-stdlib"].version == "1.9.22"
        assert by_name["com.squareup.okhttp3:okhttp"].version == "4.12.0"

    def test_inline_version(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        by_name = {p.name: p for p in parse_gradle_version_catalog(f)}
        assert by_name["com.google.code.gson:gson"].version == "2.10.1"

    def test_library_without_version_has_none(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        by_name = {p.name: p for p in parse_gradle_version_catalog(f)}
        assert by_name["com.example:no-version"].version is None

    def test_plugins_section_excluded(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        packages = parse_gradle_version_catalog(f)
        # No plugin entry should sneak through (they have id= not module=)
        assert not any("android" in p.name for p in packages)

    def test_returns_package_id_instances(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_FULL)
        assert all(isinstance(p, PackageId) for p in parse_gradle_version_catalog(f))


class TestParseGradleVersionCatalogEdgeCases:
    def test_unresolvable_ref_produces_none_version(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_UNRESOLVABLE_REF)
        packages = parse_gradle_version_catalog(f)
        assert len(packages) == 1
        assert packages[0].version is None

    def test_empty_libraries_section(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_EMPTY_LIBRARIES)
        assert parse_gradle_version_catalog(f) == []

    def test_only_plugins_no_libraries(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text(GRADLE_VERSION_CATALOG_ONLY_PLUGINS)
        assert parse_gradle_version_catalog(f) == []

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "libs.versions.toml"
        f.write_text("")
        assert parse_gradle_version_catalog(f) == []

    def test_no_versions_section_inline_version_used(self, tmp_path: Path):
        content = """\
[libraries]
mylib = { module = "com.example:mylib", version = "9.9.9" }
"""
        f = tmp_path / "libs.versions.toml"
        f.write_text(content)
        packages = parse_gradle_version_catalog(f)
        assert len(packages) == 1
        assert packages[0].version == "9.9.9"
