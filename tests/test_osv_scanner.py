"""Tests for OSV scanner (uses mocked OSV client)."""

from unittest.mock import AsyncMock, patch

import pytest

from depfence.core.models import PackageId
from depfence.core.osv_client import OsvVulnerability
from depfence.scanners.osv_scanner import OsvScanner


@pytest.fixture
def scanner():
    # Disable cache so unit tests are fully isolated from on-disk state
    return OsvScanner(use_cache=False)


@pytest.mark.asyncio
async def test_scan_converts_vulns_to_findings(scanner):
    mock_vulns = {
        "npm:lodash@4.17.20": [
            OsvVulnerability(
                id="GHSA-test-1234",
                summary="Prototype pollution",
                severity="HIGH",
                affected_versions=["4.17.20"],
                fixed_version="4.17.21",
                references=["https://example.com"],
                published="2024-01-01",
            )
        ]
    }

    mock_client = AsyncMock()
    mock_client.query_batch = AsyncMock(return_value=mock_vulns)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("depfence.scanners.osv_scanner.OsvClient", return_value=mock_client):
        packages = [PackageId("npm", "lodash", "4.17.20")]
        findings = await scanner.scan(packages)
        assert len(findings) == 1
        assert findings[0].title == "Prototype pollution"
        assert findings[0].fix_version == "4.17.21"
        assert findings[0].cve == "GHSA-test-1234"


@pytest.mark.asyncio
async def test_scan_empty_packages(scanner):
    findings = await scanner.scan([])
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_returns_empty(scanner):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_scan_handles_network_error(scanner):
    mock_client = AsyncMock()
    mock_client.query_batch = AsyncMock(return_value={})
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("depfence.scanners.osv_scanner.OsvClient", return_value=mock_client):
        packages = [PackageId("npm", "lodash", "4.17.20")]
        findings = await scanner.scan(packages)
        assert findings == []


@pytest.mark.asyncio
async def test_partial_batch_result_is_not_cached(tmp_path):
    from depfence.cache.advisory_cache import AdvisoryCache

    scanner = OsvScanner(use_cache=True)
    scanner._cache = AdvisoryCache(cache_dir=tmp_path / "cache")
    vuln = OsvVulnerability(
        id="OSV-PARTIAL",
        summary="Hydrated before another advisory failed",
        severity="HIGH",
        affected_versions=["1.0.0"],
        fixed_version="1.0.1",
        references=[],
        published="2026-01-01T00:00:00Z",
    )
    mock_client = AsyncMock()
    mock_client.query_batch.return_value = {"npm:demo@1.0.0": [vuln]}
    mock_client.last_error = "hydration failed for OSV-OTHER: HTTP 503"
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("depfence.scanners.osv_scanner.OsvClient", return_value=mock_client):
        findings = await scanner.scan([PackageId("npm", "demo", "1.0.0")])

    assert [finding.metadata["osv_id"] for finding in findings] == ["OSV-PARTIAL"]
    assert scanner._cache.get("npm", "demo", "1.0.0") is None


@pytest.mark.asyncio
async def test_withdrawn_advisory_is_not_an_active_finding(scanner):
    vuln = OsvVulnerability(
        id="OSV-WITHDRAWN",
        summary="Withdrawn advisory",
        severity="HIGH",
        affected_versions=["1.0.0"],
        fixed_version=None,
        references=[],
        published="2026-01-01T00:00:00Z",
        withdrawn="2026-01-02T00:00:00Z",
    )
    mock_client = AsyncMock()
    mock_client.query_batch.return_value = {"npm:demo@1.0.0": [vuln]}
    mock_client.last_error = None
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("depfence.scanners.osv_scanner.OsvClient", return_value=mock_client):
        findings = await scanner.scan([PackageId("npm", "demo", "1.0.0")])

    assert findings == []
