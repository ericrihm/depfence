"""Tests for FlutterPubspecScanner — risky Flutter dependency patterns."""

from __future__ import annotations

import asyncio

import pytest

from depfence.scanners.flutter_pubspec_scanner import FlutterPubspecScanner


@pytest.fixture
def scanner():
    return FlutterPubspecScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


PUBSPEC_WITH_OVERRIDES = """\
name: my_app
dependencies:
  http: ^1.2.0

dependency_overrides:
  http: 0.13.0
"""

PUBSPEC_WITH_GIT = """\
name: my_app
dependencies:
  custom_pkg:
    git:
      url: https://github.com/attacker/custom_pkg.git
"""

PUBSPEC_WITH_EXTERNAL_PATH = """\
name: my_app
dependencies:
  local_pkg:
    path: ../../outside_project/local_pkg
"""

PUBSPEC_WITH_CUSTOM_HOSTED = """\
name: my_app
dependencies:
  internal_pkg:
    hosted:
      name: internal_pkg
      url: https://private-registry.evil.com
"""

PUBSPEC_CLEAN = """\
name: my_app
dependencies:
  http: ^1.2.0
  provider: ^6.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
"""


class TestDependencyOverrides:
    def test_overrides_flagged(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_WITH_OVERRIDES)
        findings = run(scanner.scan_project(tmp_path))
        fl01 = [f for f in findings if "FL-01" in f.title]
        assert len(fl01) == 1
        assert fl01[0].severity.value == "high"

    def test_clean_pubspec_no_overrides(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_CLEAN)
        findings = run(scanner.scan_project(tmp_path))
        fl01 = [f for f in findings if "FL-01" in f.title]
        assert fl01 == []


class TestGitDeps:
    def test_git_dep_flagged(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_WITH_GIT)
        findings = run(scanner.scan_project(tmp_path))
        fl02 = [f for f in findings if "FL-02" in f.title]
        assert len(fl02) == 1
        assert "attacker" in fl02[0].detail


class TestPathDeps:
    def test_external_path_flagged(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_WITH_EXTERNAL_PATH)
        findings = run(scanner.scan_project(tmp_path))
        fl03 = [f for f in findings if "FL-03" in f.title]
        assert len(fl03) == 1
        assert fl03[0].severity.value == "high"

    def test_internal_path_not_flagged(self, scanner, tmp_path):
        subdir = tmp_path / "packages" / "local_pkg"
        subdir.mkdir(parents=True)
        (subdir / "pubspec.yaml").write_text("name: local_pkg\nversion: 1.0.0")
        pubspec = """\
name: my_app
dependencies:
  local_pkg:
    path: packages/local_pkg
"""
        (tmp_path / "pubspec.yaml").write_text(pubspec)
        findings = run(scanner.scan_project(tmp_path))
        fl03 = [f for f in findings if "FL-03" in f.title]
        assert fl03 == []


class TestCustomHosted:
    def test_non_pubdev_hosted_flagged(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_WITH_CUSTOM_HOSTED)
        findings = run(scanner.scan_project(tmp_path))
        fl04 = [f for f in findings if "FL-04" in f.title]
        assert len(fl04) == 1
        assert fl04[0].severity.value == "medium"


class TestEmpty:
    def test_no_pubspec_no_findings(self, scanner, tmp_path):
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []

    def test_clean_pubspec(self, scanner, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(PUBSPEC_CLEAN)
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []
