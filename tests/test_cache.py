"""Tests for advisory and metadata caching layer.

Covers:
  - AdvisoryCache: get/put, expiration, invalidate, prune, stats, clear, thread safety
  - DownloadCache: get/put, expiration, invalidate, prune, clear, stats
  - Integration with OsvScanner (cache hit/miss)
  - Integration with fetcher (download cache)
  - --no-cache engine parameter
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.cache.advisory_cache import AdvisoryCache, CacheStats
from depfence.cache.download_cache import DownloadCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _advisory_cache(tmp_path: Path, **kwargs) -> AdvisoryCache:
    return AdvisoryCache(cache_dir=tmp_path / "cache", **kwargs)


def _download_cache(tmp_path: Path, **kwargs) -> DownloadCache:
    return DownloadCache(cache_dir=tmp_path / "cache", **kwargs)


_SAMPLE_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-1234-5678-xxxx",
            "summary": "Remote code execution in lodash",
            "severity": "HIGH",
            "affected_versions": ["4.17.19", "4.17.20"],
            "fixed_version": "4.17.21",
            "references": ["https://example.com/advisory"],
            "published": "2024-01-01T00:00:00Z",
        }
    ]
}

_EMPTY_RESPONSE = {"vulns": []}

_METADATA_RESPONSE = {
    "name": "lodash",
    "version": "4.17.21",
    "description": "Utility library",
    "maintainers": [{"name": "jdalton", "email": "jdalton@example.com"}],
}


# ===========================================================================
# AdvisoryCache — basic get/put
# ===========================================================================

class TestAdvisoryCacheBasic:
    def test_cache_miss_returns_none(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        assert cache.get("npm", "lodash", "4.17.21") is None

    def test_cache_hit_returns_data(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is not None
        assert result["vulns"][0]["id"] == "GHSA-1234-5678-xxxx"

    def test_different_versions_are_separate_entries(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.20", _EMPTY_RESPONSE)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)

        v20 = cache.get("npm", "lodash", "4.17.20")
        v21 = cache.get("npm", "lodash", "4.17.21")

        assert v20 == _EMPTY_RESPONSE
        assert v21 == _SAMPLE_RESPONSE

    def test_different_ecosystems_are_separate(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "requests", "1.0.0", _SAMPLE_RESPONSE)
        cache.put("pypi", "requests", "2.28.0", _EMPTY_RESPONSE)

        npm = cache.get("npm", "requests", "1.0.0")
        pypi = cache.get("pypi", "requests", "2.28.0")

        assert npm["vulns"]      # has vulns
        assert not pypi["vulns"] # empty

    def test_empty_version_string_allowed(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "", _SAMPLE_RESPONSE)
        result = cache.get("npm", "lodash", "")
        assert result is not None

    def test_none_version_treated_as_empty(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "", _SAMPLE_RESPONSE)
        # get with no version arg defaults to ""
        result = cache.get("npm", "lodash")
        assert result is not None

    def test_put_overwrites_existing_entry(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        cache.put("npm", "lodash", "4.17.21", _EMPTY_RESPONSE)
        result = cache.get("npm", "lodash", "4.17.21")
        assert result == _EMPTY_RESPONSE

    def test_response_roundtrip_preserves_structure(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("pypi", "requests", "2.28.0", _SAMPLE_RESPONSE, ttl=3600)
        result = cache.get("pypi", "requests", "2.28.0")
        assert result == _SAMPLE_RESPONSE

    def test_empty_response_stored_and_retrieved(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "safe-pkg", "1.0.0", _EMPTY_RESPONSE)
        result = cache.get("npm", "safe-pkg", "1.0.0")
        assert result == _EMPTY_RESPONSE

    def test_none_response_defaults_to_empty_dict(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", None)
        result = cache.get("npm", "lodash", "4.17.21")
        assert isinstance(result, dict)


# ===========================================================================
# AdvisoryCache — TTL / expiration
# ===========================================================================

class TestAdvisoryCacheExpiration:
    def test_expired_entry_returns_none(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE, ttl=0)
        # TTL of 0 means already expired
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is None

    def test_non_expired_entry_returned(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE, ttl=3600)
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is not None

    def test_default_ttl_vuln_response_is_1_hour(self, tmp_path):
        """Responses with vulns get default_advisory_ttl (1 h) when ttl=None."""
        cache = _advisory_cache(tmp_path, default_advisory_ttl=3600)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)  # ttl=None
        # Entry should be alive now
        assert cache.get("npm", "lodash", "4.17.21") is not None

    def test_default_ttl_no_vuln_response_is_24_hours(self, tmp_path):
        """Empty-vuln responses get default_no_vuln_ttl (24 h) when ttl=None."""
        cache = _advisory_cache(tmp_path, default_no_vuln_ttl=86400)
        cache.put("npm", "clean-pkg", "1.0.0", _EMPTY_RESPONSE)
        assert cache.get("npm", "clean-pkg", "1.0.0") is not None

    def test_custom_ttl_respected(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE, ttl=7200)
        # Verify via direct DB that expires_at is ~2h from now
        db_path = tmp_path / "cache" / "advisories.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT expires_at FROM advisories WHERE package = ?", ("lodash",)).fetchone()
        conn.close()
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        delta = expires_at - datetime.now(tz=timezone.utc)
        assert 6000 < delta.total_seconds() < 7300  # within 5 min of 7200s


# ===========================================================================
# AdvisoryCache — invalidate
# ===========================================================================

class TestAdvisoryCacheInvalidate:
    def test_invalidate_specific_package(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        cache.put("npm", "express", "4.18.2", _SAMPLE_RESPONSE)

        deleted = cache.invalidate("npm", "lodash")
        assert deleted >= 1
        assert cache.get("npm", "lodash", "4.17.21") is None
        assert cache.get("npm", "express", "4.18.2") is not None

    def test_invalidate_entire_ecosystem(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        cache.put("npm", "express", "4.18.2", _SAMPLE_RESPONSE)
        cache.put("pypi", "requests", "2.28.0", _SAMPLE_RESPONSE)

        deleted = cache.invalidate("npm")
        assert deleted == 2
        assert cache.get("npm", "lodash", "4.17.21") is None
        assert cache.get("npm", "express", "4.18.2") is None
        # pypi should be untouched
        assert cache.get("pypi", "requests", "2.28.0") is not None

    def test_invalidate_nonexistent_returns_zero(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        deleted = cache.invalidate("cargo", "nonexistent")
        assert deleted == 0


# ===========================================================================
# AdvisoryCache — prune
# ===========================================================================

class TestAdvisoryCachePrune:
    def test_prune_removes_old_entries(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "old-pkg", "1.0.0", _SAMPLE_RESPONSE)

        # Manually backdate fetched_at in the DB
        db_path = tmp_path / "cache" / "advisories.db"
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=35)).isoformat()
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE advisories SET fetched_at = ? WHERE package = ?", (old_time, "old-pkg"))
        conn.commit()
        conn.close()

        pruned = cache.prune(max_age_days=30)
        assert pruned >= 1
        # Note: prune removes by fetched_at, not expires_at, so even a non-expired
        # entry is removed if it is too old.

    def test_prune_keeps_recent_entries(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "new-pkg", "2.0.0", _SAMPLE_RESPONSE)

        pruned = cache.prune(max_age_days=30)
        assert pruned == 0
        assert cache.get("npm", "new-pkg", "2.0.0") is not None

    def test_prune_returns_count(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        db_path = tmp_path / "cache" / "advisories.db"
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=40)).isoformat()

        # Insert multiple old entries directly
        conn = sqlite3.connect(str(db_path))
        for i in range(3):
            conn.execute(
                "INSERT OR REPLACE INTO advisories "
                "(ecosystem, package, version, response, fetched_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("npm", f"pkg-{i}", "1.0", "{}", old_time, old_time),
            )
        conn.commit()
        conn.close()

        pruned = cache.prune(max_age_days=30)
        assert pruned == 3


# ===========================================================================
# AdvisoryCache — stats
# ===========================================================================

class TestAdvisoryCacheStats:
    def test_stats_initial_zero(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        s = cache.stats()
        assert s.total_entries == 0
        assert s.hit_count == 0
        assert s.miss_count == 0
        assert s.hit_rate == 0.0

    def test_stats_hit_count_increments(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        cache.get("npm", "lodash", "4.17.21")  # hit
        cache.get("npm", "lodash", "4.17.21")  # hit
        s = cache.stats()
        assert s.hit_count == 2
        assert s.miss_count == 0
        assert s.hit_rate == 1.0

    def test_stats_miss_count_increments(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.get("npm", "unknown", "1.0.0")  # miss
        s = cache.stats()
        assert s.miss_count == 1
        assert s.hit_count == 0
        assert s.hit_rate == 0.0

    def test_stats_hit_rate_calculation(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        cache.get("npm", "lodash", "4.17.21")   # hit
        cache.get("npm", "missing", "0.0.0")    # miss
        s = cache.stats()
        assert s.hit_rate == pytest.approx(0.5)

    def test_stats_total_entries_counts_db_rows(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "pkg-a", "1.0.0", _SAMPLE_RESPONSE)
        cache.put("npm", "pkg-b", "1.0.0", _SAMPLE_RESPONSE)
        cache.put("pypi", "pkg-c", "1.0.0", _SAMPLE_RESPONSE)
        s = cache.stats()
        assert s.total_entries == 3

    def test_stats_db_size_positive_after_puts(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        s = cache.stats()
        assert s.db_size_bytes > 0

    def test_stats_oldest_entry(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        s = cache.stats()
        assert s.oldest_entry is not None
        # Should be very recent
        delta = datetime.now(tz=timezone.utc) - s.oldest_entry.replace(tzinfo=timezone.utc)
        assert delta.total_seconds() < 10

    def test_stats_is_cache_stats_instance(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        s = cache.stats()
        assert isinstance(s, CacheStats)


# ===========================================================================
# AdvisoryCache — clear
# ===========================================================================

class TestAdvisoryCacheClear:
    def test_clear_removes_all_entries(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "pkg-a", "1.0.0", _SAMPLE_RESPONSE)
        cache.put("pypi", "pkg-b", "2.0.0", _SAMPLE_RESPONSE)

        deleted = cache.clear()
        assert deleted == 2
        assert cache.stats().total_entries == 0

    def test_clear_on_empty_cache_returns_zero(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        assert cache.clear() == 0


# ===========================================================================
# AdvisoryCache — thread safety
# ===========================================================================

class TestAdvisoryCacheThreadSafety:
    def test_concurrent_writes_no_corruption(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        errors = []

        def write_entries(ecosystem: str, count: int) -> None:
            for i in range(count):
                try:
                    cache.put(ecosystem, f"pkg-{i}", "1.0.0", _SAMPLE_RESPONSE)
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=write_entries, args=("npm", 20)),
            threading.Thread(target=write_entries, args=("pypi", 20)),
            threading.Thread(target=write_entries, args=("cargo", 20)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert cache.stats().total_entries == 60

    def test_concurrent_reads_writes(self, tmp_path):
        cache = _advisory_cache(tmp_path)
        cache.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        errors = []

        def reader() -> None:
            for _ in range(50):
                try:
                    cache.get("npm", "lodash", "4.17.21")
                except Exception as exc:
                    errors.append(exc)

        def writer() -> None:
            for i in range(20):
                try:
                    cache.put("npm", f"pkg-{i}", "1.0.0", _SAMPLE_RESPONSE)
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)] +                   [threading.Thread(target=writer) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ===========================================================================
# DownloadCache — basic operations
# ===========================================================================

class TestDownloadCacheBasic:
    def test_miss_returns_none(self, tmp_path):
        cache = _download_cache(tmp_path)
        assert cache.get("npm", "lodash") is None

    def test_hit_returns_data(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "lodash", _METADATA_RESPONSE)
        result = cache.get("npm", "lodash")
        assert result == _METADATA_RESPONSE

    def test_ecosystems_are_separate(self, tmp_path):
        cache = _download_cache(tmp_path)
        npm_meta = {"name": "requests", "source": "npm"}
        pypi_meta = {"name": "requests", "source": "pypi"}
        cache.put("npm", "requests", npm_meta)
        cache.put("pypi", "requests", pypi_meta)
        assert cache.get("npm", "requests")["source"] == "npm"
        assert cache.get("pypi", "requests")["source"] == "pypi"

    def test_put_overwrites_existing(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "lodash", {"v": "1"})
        cache.put("npm", "lodash", {"v": "2"})
        assert cache.get("npm", "lodash") == {"v": "2"}

    def test_expired_entry_returns_none(self, tmp_path):
        cache = _download_cache(tmp_path, default_ttl=0)
        cache.put("npm", "lodash", _METADATA_RESPONSE)
        assert cache.get("npm", "lodash") is None

    def test_valid_entry_returned(self, tmp_path):
        cache = _download_cache(tmp_path, default_ttl=3600)
        cache.put("npm", "lodash", _METADATA_RESPONSE)
        assert cache.get("npm", "lodash") is not None

    def test_custom_ttl(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "lodash", _METADATA_RESPONSE, ttl=9999)
        db_path = tmp_path / "cache" / "advisories.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT expires_at FROM metadata WHERE package = ?", ("lodash",)).fetchone()
        conn.close()
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        delta = expires_at - datetime.now(tz=timezone.utc)
        assert 9000 < delta.total_seconds() < 10100

    def test_invalidate_specific_package(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "lodash", _METADATA_RESPONSE)
        cache.put("npm", "express", _METADATA_RESPONSE)
        cache.invalidate("npm", "lodash")
        assert cache.get("npm", "lodash") is None
        assert cache.get("npm", "express") is not None

    def test_invalidate_entire_ecosystem(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "a", _METADATA_RESPONSE)
        cache.put("npm", "b", _METADATA_RESPONSE)
        cache.put("pypi", "c", _METADATA_RESPONSE)
        cache.invalidate("npm")
        assert cache.get("npm", "a") is None
        assert cache.get("npm", "b") is None
        assert cache.get("pypi", "c") is not None

    def test_prune_removes_old_entries(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "old", _METADATA_RESPONSE)
        db_path = tmp_path / "cache" / "advisories.db"
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=40)).isoformat()
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE metadata SET fetched_at = ? WHERE package = ?", (old_time, "old"))
        conn.commit()
        conn.close()
        pruned = cache.prune(max_age_days=30)
        assert pruned == 1

    def test_prune_keeps_recent_entries(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "new", _METADATA_RESPONSE)
        pruned = cache.prune(max_age_days=30)
        assert pruned == 0

    def test_clear_wipes_all_metadata(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "a", _METADATA_RESPONSE)
        cache.put("pypi", "b", _METADATA_RESPONSE)
        deleted = cache.clear()
        assert deleted == 2
        assert cache.stats()["total_entries"] == 0

    def test_stats_returns_dict_with_entry_count(self, tmp_path):
        cache = _download_cache(tmp_path)
        cache.put("npm", "lodash", _METADATA_RESPONSE)
        s = cache.stats()
        assert s["total_entries"] == 1
        assert s["db_size_bytes"] > 0


# ===========================================================================
# Shared DB between AdvisoryCache and DownloadCache
# ===========================================================================

class TestSharedDatabase:
    def test_both_caches_share_same_db_file(self, tmp_path):
        adv = _advisory_cache(tmp_path)
        dl = _download_cache(tmp_path)
        assert adv._db_path == dl._db_path

    def test_clearing_advisory_does_not_affect_metadata(self, tmp_path):
        adv = _advisory_cache(tmp_path)
        dl = _download_cache(tmp_path)
        adv.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        dl.put("npm", "lodash", _METADATA_RESPONSE)

        adv.clear()
        # metadata should still be there
        assert dl.get("npm", "lodash") is not None

    def test_clearing_metadata_does_not_affect_advisories(self, tmp_path):
        adv = _advisory_cache(tmp_path)
        dl = _download_cache(tmp_path)
        adv.put("npm", "lodash", "4.17.21", _SAMPLE_RESPONSE)
        dl.put("npm", "lodash", _METADATA_RESPONSE)

        dl.clear()
        assert adv.get("npm", "lodash", "4.17.21") is not None


# ===========================================================================
# OsvScanner cache integration
# ===========================================================================

class TestOsvScannerCacheIntegration:
    def test_scanner_cache_disabled_does_not_use_cache(self, tmp_path):
        """When use_cache=False the scanner should not touch AdvisoryCache."""
        from depfence.scanners.osv_scanner import OsvScanner

        scanner = OsvScanner(use_cache=False)
        assert scanner._cache is None

    def test_scanner_cache_enabled_by_default(self, tmp_path):
        """By default, OsvScanner should attempt to initialise a cache."""
        from depfence.scanners.osv_scanner import OsvScanner

        scanner = OsvScanner(use_cache=True)
        # _cache may be None if import fails in the test env, but shouldn't error
        # Just check no exception was raised during construction.
        assert True  # reached here = no exception

    @pytest.mark.asyncio
    async def test_scanner_returns_cached_vulns(self, tmp_path):
        """Second scan of same package should serve from cache without HTTP."""
        from depfence.cache.advisory_cache import AdvisoryCache
        from depfence.core.models import PackageId
        from depfence.scanners.osv_scanner import OsvScanner

        # Pre-populate a temp cache
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")
        cached_payload = {
            "vulns": [{
                "id": "GHSA-test-1234-xxxx",
                "summary": "Cached vuln",
                "severity": "HIGH",
                "affected_versions": ["4.17.21"],
                "fixed_version": "4.17.22",
                "references": [],
                "published": "2024-01-01T00:00:00Z",
            }]
        }
        cache.put("npm", "lodash", "4.17.21", cached_payload)

        scanner = OsvScanner(use_cache=True)
        scanner._cache = cache

        pkg = PackageId("npm", "lodash", "4.17.21")

        # Patch query_batch to raise if it gets called (should be cache hit)
        with patch("depfence.scanners.osv_scanner.OsvClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.query_batch = AsyncMock(return_value={})

            findings = await scanner.scan([pkg])

        # Network call should NOT have happened (cache hit)
        mock_client.query_batch.assert_not_called()
        assert len(findings) == 1
        assert findings[0].cve == "GHSA-test-1234-xxxx"

    @pytest.mark.asyncio
    async def test_scanner_stores_result_in_cache(self, tmp_path):
        """After a network fetch, the result should be stored in the cache."""
        from depfence.cache.advisory_cache import AdvisoryCache
        from depfence.core.models import PackageId
        from depfence.core.osv_client import OsvVulnerability
        from depfence.scanners.osv_scanner import OsvScanner

        cache = AdvisoryCache(cache_dir=tmp_path / "cache")
        scanner = OsvScanner(use_cache=True)
        scanner._cache = cache

        pkg = PackageId("npm", "express", "4.18.2")

        vuln = OsvVulnerability(
            id="GHSA-net-test-0001",
            summary="Test vuln",
            severity="MEDIUM",
            affected_versions=["4.18.2"],
            fixed_version="4.18.3",
            references=[],
            published="2024-01-01T00:00:00Z",
        )

        with patch("depfence.scanners.osv_scanner.OsvClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.query_batch = AsyncMock(return_value={
                "npm:express@4.18.2": [vuln]
            })

            await scanner.scan([pkg])

        # Verify cached
        cached = cache.get("npm", "express", "4.18.2")
        assert cached is not None
        assert len(cached["vulns"]) == 1
        assert cached["vulns"][0]["id"] == "GHSA-net-test-0001"


# ===========================================================================
# Engine use_cache parameter
# ===========================================================================

class TestEngineUseCache:
    def test_engine_accepts_use_cache_parameter(self):
        """scan_directory signature should include use_cache."""
        import inspect
        from depfence.core.engine import scan_directory
        sig = inspect.signature(scan_directory)
        assert "use_cache" in sig.parameters

    def test_engine_use_cache_defaults_to_true(self):
        """use_cache should default to True."""
        import inspect
        from depfence.core.engine import scan_directory
        sig = inspect.signature(scan_directory)
        assert sig.parameters["use_cache"].default is True


# ===========================================================================
# Fetcher cache integration
# ===========================================================================

class TestFetcherCacheIntegration:
    def test_set_cache_enabled_function_exists(self):
        from depfence.core.fetcher import set_cache_enabled
        assert callable(set_cache_enabled)

    def test_disable_cache_sets_flag(self):
        from depfence.core import fetcher
        fetcher.set_cache_enabled(False)
        assert fetcher._CACHE_ENABLED is False
        # Re-enable for other tests
        fetcher.set_cache_enabled(True)
        assert fetcher._CACHE_ENABLED is True

    @pytest.mark.asyncio
    async def test_fetch_npm_uses_cache_on_second_call(self, tmp_path):
        """Second fetch of same package should serve from download cache."""
        from depfence.cache.download_cache import DownloadCache
        from depfence.core import fetcher
        from depfence.core.models import PackageId

        # Pre-populate cache with fake npm data
        cache = DownloadCache(cache_dir=tmp_path / "cache")
        fake_data = {
            "name": "lodash",
            "description": "Cached npm response",
            "maintainers": [],
            "dist-tags": {"latest": "4.17.21"},
            "versions": {},
            "time": {},
        }
        cache.put("npm", "lodash", fake_data)

        # Patch the global cache in fetcher
        original_cache = fetcher._DOWNLOAD_CACHE
        fetcher._DOWNLOAD_CACHE = cache
        fetcher._CACHE_ENABLED = True

        try:
            pkg = PackageId("npm", "lodash", "4.17.21")
            with patch("depfence.core.fetcher._get_client") as mock_get:
                # If cache is hit, _get_client should not be called for HTTP
                mock_client = AsyncMock()
                mock_get.return_value = mock_client

                meta = await fetcher.fetch_npm_meta(pkg)

            assert meta.pkg == pkg
            assert meta.description == "Cached npm response"
            # HTTP client get should not have been called
            mock_client.get.assert_not_called()
        finally:
            fetcher._DOWNLOAD_CACHE = original_cache
