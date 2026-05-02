"""Tests for freshness scanner."""

import pytest

from depfence.core.models import PackageId
from depfence.scanners.freshness_scanner import FreshnessScanner


@pytest.fixture
def scanner():
    return FreshnessScanner()


@pytest.mark.asyncio
async def test_known_deprecated_npm(scanner):
    packages = [PackageId("npm", "request", "2.88.2")]
    findings = await scanner.scan(packages)
    assert len(findings) >= 1
    assert any("Deprecated" in f.title for f in findings)


@pytest.mark.asyncio
async def test_known_deprecated_pypi(scanner):
    packages = [PackageId("pypi", "pycrypto", "2.6.1")]
    findings = await scanner.scan(packages)
    assert len(findings) >= 1
    assert any("pycryptodome" in f.detail for f in findings)


@pytest.mark.asyncio
async def test_not_deprecated(scanner):
    packages = [PackageId("npm", "express", "4.18.2")]
    findings = await scanner.scan(packages)
    assert not any("Deprecated" in f.title for f in findings)


@pytest.mark.asyncio
async def test_pre_release_flagged(scanner):
    packages = [PackageId("npm", "some-pkg", "0.3.1")]
    findings = await scanner.scan(packages)
    assert any("Pre-1.0" in f.title for f in findings)


@pytest.mark.asyncio
async def test_stable_version_not_flagged(scanner):
    packages = [PackageId("npm", "express", "4.18.2")]
    findings = await scanner.scan(packages)
    assert not any("Pre-1.0" in f.title for f in findings)


@pytest.mark.asyncio
async def test_scan_project_returns_empty(scanner):
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_no_crash_on_empty_packages(scanner):
    findings = await scanner.scan([])
    assert findings == []
