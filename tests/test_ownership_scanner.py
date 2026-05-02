"""Tests for ownership change and version anomaly scanner."""

from datetime import datetime, timezone

import pytest

from depfence.core.models import (
    Finding,
    MaintainerInfo,
    PackageId,
    PackageMeta,
    Severity,
)
from depfence.scanners.ownership_scanner import (
    OwnershipScanner,
    check_version_anomaly,
)


def _make_meta(
    name="lodash",
    ecosystem="npm",
    downloads=100000,
    maintainers=None,
) -> PackageMeta:
    if maintainers is None:
        maintainers = [MaintainerInfo(username="original-author")]
    return PackageMeta(
        pkg=PackageId(ecosystem, name, "4.17.21"),
        download_count=downloads,
        first_published=datetime(2015, 1, 1, tzinfo=timezone.utc),
        latest_publish=datetime(2024, 6, 1, tzinfo=timezone.utc),
        maintainers=maintainers,
    )


@pytest.mark.asyncio
async def test_ownership_change_popular_package():
    scanner = OwnershipScanner()
    meta = _make_meta(
        downloads=500000,
        maintainers=[
            MaintainerInfo(username="new-guy", recent_ownership_change=True, account_age_days=15),
        ],
    )
    findings = await scanner.scan([meta])
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("ownership change" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_no_findings_stable_package():
    scanner = OwnershipScanner()
    meta = _make_meta(
        downloads=1000000,
        maintainers=[MaintainerInfo(username="stable-author", account_age_days=2000)],
    )
    findings = await scanner.scan([meta])
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_young_account_flagged():
    scanner = OwnershipScanner()
    meta = _make_meta(
        downloads=50000,
        maintainers=[
            MaintainerInfo(username="baby-account", account_age_days=5, recent_ownership_change=True),
        ],
    )
    findings = await scanner.scan([meta])
    assert any("young account" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_single_maintainer_no_2fa():
    scanner = OwnershipScanner()
    meta = _make_meta(
        downloads=200000,
        maintainers=[MaintainerInfo(username="solo-dev", has_2fa=False)],
    )
    findings = await scanner.scan([meta])
    assert any("2FA" in f.title or "2fa" in f.detail.lower() for f in findings)


@pytest.mark.asyncio
async def test_moderate_downloads_ownership_change():
    scanner = OwnershipScanner()
    meta = _make_meta(
        downloads=5000,
        maintainers=[
            MaintainerInfo(username="new-person", recent_ownership_change=True),
        ],
    )
    findings = await scanner.scan([meta])
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_version_anomaly_backfill():
    versions = [
        {"version": "1.0.0", "published_at": "2020-01-01T00:00:00Z"},
        {"version": "2.0.0", "published_at": "2021-01-01T00:00:00Z"},
        {"version": "3.0.0", "published_at": "2022-01-01T00:00:00Z"},
        {"version": "1.0.1", "published_at": "2023-06-01T00:00:00Z"},  # suspicious backfill
    ]
    findings = check_version_anomaly("target-pkg", "npm", versions)
    assert len(findings) >= 1
    assert any("out of chronological order" in f.title for f in findings)


def test_version_anomaly_normal():
    versions = [
        {"version": "1.0.0", "published_at": "2020-01-01T00:00:00Z"},
        {"version": "1.1.0", "published_at": "2020-06-01T00:00:00Z"},
        {"version": "2.0.0", "published_at": "2021-01-01T00:00:00Z"},
    ]
    findings = check_version_anomaly("normal-pkg", "npm", versions)
    assert len(findings) == 0


def test_version_burst_detection():
    versions = [
        {"version": f"1.0.{i}", "published_at": f"2024-03-15T{i:02d}:00:00Z"}
        for i in range(10)
    ]
    findings = check_version_anomaly("burst-pkg", "npm", versions)
    assert any("burst" in f.title.lower() for f in findings)


def test_too_few_versions_skipped():
    versions = [
        {"version": "1.0.0", "published_at": "2020-01-01T00:00:00Z"},
        {"version": "2.0.0", "published_at": "2021-01-01T00:00:00Z"},
    ]
    findings = check_version_anomaly("small-pkg", "npm", versions)
    assert findings == []
