"""Tests for lockfile parsing."""

import json
import tempfile
from pathlib import Path

from depfence.core.lockfile import detect_ecosystem, parse_lockfile


def test_detect_npm_lockfile():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text("{}")
        result = detect_ecosystem(Path(d))
        assert len(result) == 1
        assert result[0][0] == "npm"


def test_detect_pypi_requirements():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "requirements.txt").write_text("requests==2.31.0")
        result = detect_ecosystem(Path(d))
        assert len(result) == 1
        assert result[0][0] == "pypi"


def test_detect_multiple():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text("{}")
        (Path(d) / "requirements.txt").write_text("")
        result = detect_ecosystem(Path(d))
        assert len(result) == 2


def test_parse_package_lock_v3():
    lock_data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "myapp", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/express": {"version": "4.18.2"},
        },
    }
    with tempfile.TemporaryDirectory() as d:
        lock_path = Path(d) / "package-lock.json"
        lock_path.write_text(json.dumps(lock_data))
        packages = parse_lockfile("npm", lock_path)
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert "lodash" in names
        assert "express" in names


def test_parse_requirements_txt():
    content = "requests==2.31.0\nflask>=2.0\n# comment\nnumpy~=1.26.0"
    with tempfile.TemporaryDirectory() as d:
        req_path = Path(d) / "requirements.txt"
        req_path.write_text(content)
        packages = parse_lockfile("pypi", req_path)
        assert len(packages) == 3
        names = {p.name for p in packages}
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names


def test_parse_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        result = detect_ecosystem(Path(d))
        assert result == []
