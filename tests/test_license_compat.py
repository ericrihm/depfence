"""Tests for license compatibility checker."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.license_compat import (
    check_license_compatibility,
    detect_project_license,
    generate_license_findings,
)


class TestLicenseCompatibility:
    def test_gpl_in_mit_project(self):
        deps = [{"name": "gpl-pkg", "license": "GPL-3.0", "ecosystem": "npm"}]
        conflicts = check_license_compatibility("MIT", deps)
        assert len(conflicts) >= 1
        assert conflicts[0].severity == "error"

    def test_agpl_in_proprietary(self):
        deps = [{"name": "agpl-pkg", "license": "AGPL-3.0", "ecosystem": "pypi"}]
        conflicts = check_license_compatibility("proprietary", deps)
        assert len(conflicts) >= 1

    def test_permissive_in_mit_ok(self):
        deps = [
            {"name": "apache-pkg", "license": "Apache-2.0", "ecosystem": "npm"},
            {"name": "bsd-pkg", "license": "BSD-3-Clause", "ecosystem": "npm"},
            {"name": "isc-pkg", "license": "ISC", "ecosystem": "npm"},
        ]
        conflicts = check_license_compatibility("MIT", deps)
        assert len(conflicts) == 0

    def test_lgpl_warning(self):
        deps = [{"name": "lgpl-pkg", "license": "LGPL-3.0", "ecosystem": "pypi"}]
        conflicts = check_license_compatibility("MIT", deps)
        assert len(conflicts) >= 1
        assert any(c.severity == "warning" for c in conflicts)

    def test_unknown_license_warning(self):
        deps = [{"name": "mystery-pkg", "license": "NOASSERTION", "ecosystem": "npm"}]
        conflicts = check_license_compatibility("MIT", deps)
        assert len(conflicts) >= 1

    def test_gpl_in_gpl_ok(self):
        deps = [{"name": "gpl-pkg", "license": "GPL-3.0", "ecosystem": "npm"}]
        conflicts = check_license_compatibility("GPL-3.0", deps)
        assert len(conflicts) == 0

    def test_empty_deps(self):
        conflicts = check_license_compatibility("MIT", [])
        assert conflicts == []


class TestDetectProjectLicense:
    def test_detects_from_license_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "LICENSE").write_text("MIT License\n\nCopyright (c) 2024 ...\n")
            result = detect_project_license(p)
            assert result is not None
            assert "MIT" in result.upper()

    def test_detects_from_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            import json
            (p / "package.json").write_text(json.dumps({"license": "Apache-2.0"}))
            result = detect_project_license(p)
            assert result == "Apache-2.0"

    def test_returns_none_if_not_found(self):
        with tempfile.TemporaryDirectory() as d:
            result = detect_project_license(Path(d))
            assert result is None


class TestGenerateFindings:
    def test_generates_findings_for_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "LICENSE").write_text("MIT License\n\nCopyright ...\n")
            deps = [{"name": "gpl-thing", "license": "GPL-3.0", "ecosystem": "npm"}]
            findings = generate_license_findings(p, deps)
            assert len(findings) >= 1
            assert findings[0].severity.name in ("HIGH", "MEDIUM")
