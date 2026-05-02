"""Tests for phantom dependency scanner."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.scanners.phantom_deps import PhantomDepsScanner


@pytest.fixture
def scanner():
    return PhantomDepsScanner()


@pytest.mark.asyncio
async def test_detects_unused_pypi_dep(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "requirements.txt").write_text("requests==2.31.0\nunused-pkg==1.0.0\n")
        (project / "app.py").write_text("import requests\nresponse = requests.get('http://example.com')\n")
        findings = await scanner.scan_project(project)
        assert any("unused-pkg" in f.detail for f in findings)
        assert not any("requests" in f.detail for f in findings)


@pytest.mark.asyncio
async def test_detects_unused_npm_dep(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/unused-lib": {"version": "1.0.0"},
            },
        }))
        (project / "index.js").write_text("const lodash = require('lodash');\n")
        findings = await scanner.scan_project(project)
        assert any("unused-lib" in f.detail for f in findings)
        assert not any("lodash" in f.detail for f in findings)


@pytest.mark.asyncio
async def test_no_findings_when_all_used(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\n")
        (project / "app.py").write_text("import requests\nimport flask\n")
        findings = await scanner.scan_project(project)
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_skips_dev_tools(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "requirements.txt").write_text("pytest==8.0.0\nruff==0.4.0\nflask>=2.0\n")
        (project / "app.py").write_text("import flask\n")
        findings = await scanner.scan_project(project)
        assert not any("pytest" in f.detail for f in findings)
        assert not any("ruff" in f.detail for f in findings)


@pytest.mark.asyncio
async def test_handles_scoped_npm_packages(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/@babel/core": {"version": "7.24.0"},
            },
        }))
        (project / "build.js").write_text("const babel = require('@babel/core');\n")
        findings = await scanner.scan_project(project)
        assert not any("@babel/core" in f.detail for f in findings)


@pytest.mark.asyncio
async def test_no_lockfiles(scanner):
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_python_from_import(scanner):
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / "requirements.txt").write_text("flask>=2.0\n")
        (project / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
        findings = await scanner.scan_project(project)
        assert not any("flask" in f.detail for f in findings)
