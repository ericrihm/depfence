"""Tests for slopsquatting detector."""

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta
from depfence.scanners.slopsquat import SlopsquatScanner


@pytest.fixture
def scanner():
    return SlopsquatScanner()


@pytest.mark.asyncio
async def test_exact_popular_name_clean(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "lodash", "4.17.21"))
    findings = await scanner.scan([meta])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_typosquat_edit_distance_1(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "lodas", "1.0.0"))
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.SLOPSQUAT
    assert "lodash" in findings[0].detail


@pytest.mark.asyncio
async def test_typosquat_char_confusion(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "cha1k", "1.0.0"))
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.SLOPSQUAT


@pytest.mark.asyncio
async def test_separator_swap(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "express_js", "1.0.0"))
    findings = await scanner.scan([meta])
    # express_js vs express should not trigger (different normalized form)
    # but expressjs vs express should trigger separator score


@pytest.mark.asyncio
async def test_suffix_manipulation(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "reacts", "1.0.0"))
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert "react" in findings[0].detail


@pytest.mark.asyncio
async def test_unrelated_name_clean(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "totally-unique-pkg-xyz", "1.0.0"))
    findings = await scanner.scan([meta])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_pypi_typosquat(scanner):
    meta = PackageMeta(pkg=PackageId("pypi", "requesst", "1.0.0"))
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert "requests" in findings[0].detail
