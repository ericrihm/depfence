"""Tests for auto-fix engine."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.fixer import (
    apply_fixes_package_json,
    apply_fixes_requirements,
    generate_diff,
    generate_fixes,
)
from depfence.core.models import Finding, FindingType, Severity


def _make_finding(pkg: str, fix_version: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=pkg,
        title="Test vuln",
        detail="Test detail",
        fix_version=fix_version,
    )


def test_generate_fixes_basic():
    findings = [
        _make_finding("npm:lodash@4.17.20", "4.17.21"),
        _make_finding("pypi:requests@2.28.0", "2.31.0"),
    ]
    fixes = generate_fixes(findings, Path("/tmp"))
    assert len(fixes) == 2
    assert fixes[0]["package"] == "lodash"
    assert fixes[0]["fix_version"] == "4.17.21"
    assert fixes[1]["package"] == "requests"


def test_generate_fixes_no_fix_version():
    findings = [
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package="npm:express@4.0.0",
            title="No fix",
            detail="No fix available",
        )
    ]
    fixes = generate_fixes(findings, Path("/tmp"))
    assert len(fixes) == 0


def test_apply_fixes_requirements():
    with tempfile.TemporaryDirectory() as d:
        req = Path(d) / "requirements.txt"
        req.write_text("requests==2.28.0\nflask>=2.0\nnumpy\n")
        fixes = [{"package": "requests", "ecosystem": "pypi", "current_version": "2.28.0", "fix_version": "2.31.0", "severity": "HIGH", "title": ""}]
        changes = apply_fixes_requirements(req, fixes)
        assert len(changes) == 1
        content = req.read_text()
        assert "requests>=2.31.0" in content
        assert "flask>=2.0" in content


def test_apply_fixes_package_json():
    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d) / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"},
        }))
        fixes = [{"package": "lodash", "ecosystem": "npm", "current_version": "4.17.20", "fix_version": "4.17.21", "severity": "HIGH", "title": ""}]
        changes = apply_fixes_package_json(pkg, fixes)
        assert len(changes) == 1
        data = json.loads(pkg.read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"
        assert data["dependencies"]["express"] == "^4.18.0"


def test_generate_diff():
    findings = [
        _make_finding("npm:lodash@4.17.20", "4.17.21", Severity.CRITICAL),
        _make_finding("pypi:requests@2.28.0", "2.31.0"),
    ]
    diff = generate_diff(findings, Path("/tmp"))
    assert "lodash" in diff
    assert "4.17.21" in diff
    assert "requests" in diff


def test_deduplication():
    findings = [
        _make_finding("npm:lodash@4.17.20", "4.17.21", Severity.HIGH),
        _make_finding("npm:lodash@4.17.20", "4.17.21", Severity.CRITICAL),
    ]
    fixes = generate_fixes(findings, Path("/tmp"))
    assert len(fixes) == 1
    assert fixes[0]["severity"] == "CRITICAL"
