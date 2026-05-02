"""Tests for NuGet lockfile parsers."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.parsers.nuget_lockfiles import (
    detect_nuget_lockfiles,
    parse_packages_config,
    parse_packages_lock_json,
)


class TestPackagesLockJson:
    def test_basic_parsing(self):
        data = {
            "version": 2,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "requested": "[13.0.3, )",
                        "resolved": "13.0.3",
                    },
                    "System.Text.Json": {
                        "type": "Transitive",
                        "resolved": "8.0.0",
                    },
                }
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        assert len(packages) == 2
        assert packages[0].ecosystem == "nuget"
        names = {p.name for p in packages}
        assert "Newtonsoft.Json" in names
        assert "System.Text.Json" in names

    def test_multiple_frameworks(self):
        data = {
            "version": 2,
            "dependencies": {
                "net8.0": {
                    "Pkg.A": {"type": "Direct", "resolved": "1.0.0"},
                },
                "net6.0": {
                    "Pkg.A": {"type": "Direct", "resolved": "1.0.0"},
                    "Pkg.B": {"type": "Transitive", "resolved": "2.0.0"},
                },
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            packages = parse_packages_lock_json(Path(f.name))
        names = {p.name for p in packages}
        assert "Pkg.A" in names
        assert "Pkg.B" in names


class TestPackagesConfig:
    def test_basic_parsing(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="NUnit" version="3.14.0" targetFramework="net48" />
</packages>"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".config", delete=False) as f:
            f.write(xml)
            f.flush()
            packages = parse_packages_config(Path(f.name))
        assert len(packages) == 2
        assert packages[0].ecosystem == "nuget"
        names = {p.name for p in packages}
        assert "Newtonsoft.Json" in names
        assert "NUnit" in names


class TestDetection:
    def test_detects_packages_lock_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "packages.lock.json").write_text("{}")
            results = detect_nuget_lockfiles(p)
            assert any("packages.lock.json" in str(path) for _, path in results)

    def test_detects_packages_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "packages.config").write_text("<packages></packages>")
            results = detect_nuget_lockfiles(p)
            assert any("packages.config" in str(path) for _, path in results)
