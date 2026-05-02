"""Tests for SLSA provenance verification scanner."""

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.provenance import ProvenanceScanner


@pytest.fixture
def scanner():
    return ProvenanceScanner()


@pytest.mark.asyncio
async def test_high_value_without_provenance_flagged(scanner):
    meta = PackageMeta(pkg=PackageId("pypi", "langchain", "0.2.0"))
    meta.has_provenance = False
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].finding_type == FindingType.PROVENANCE


@pytest.mark.asyncio
async def test_high_value_with_provenance_clean(scanner):
    meta = PackageMeta(pkg=PackageId("pypi", "langchain", "0.2.0"))
    meta.has_provenance = True
    findings = await scanner.scan([meta])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_non_high_value_without_provenance_clean(scanner):
    meta = PackageMeta(pkg=PackageId("pypi", "my-random-pkg", "1.0.0"))
    meta.has_provenance = False
    findings = await scanner.scan([meta])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_npm_high_value_flagged(scanner):
    meta = PackageMeta(pkg=PackageId("npm", "express", "4.18.0"))
    meta.has_provenance = False
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert "provenance" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_multiple_packages_mixed(scanner):
    packages = [
        PackageMeta(pkg=PackageId("pypi", "transformers", "4.40.0")),
        PackageMeta(pkg=PackageId("pypi", "openai", "1.30.0")),
        PackageMeta(pkg=PackageId("pypi", "my-util", "0.1.0")),
    ]
    for p in packages:
        p.has_provenance = False
    findings = await scanner.scan(packages)
    assert len(findings) == 2  # transformers and openai are high-value
