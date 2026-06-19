"""Tests for depfence/cache/advisory_cache.py."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depfence.cache.advisory_cache import AdvisoryCache, CacheStats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cache(tmp_path: Path, **kwargs) -> AdvisoryCache:
    return AdvisoryCache(cache_dir=tmp_path / "adv_cache", **kwargs)


_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-test-0001",
            "summary": "Remote code execution",
            "severity": "CRITICAL",
            "affected_versions": ["1.0.0"],
            "fixed_version": "1.0.1",
            "references": ["https://example.com/cve"],
            "published": "2024-01-01T00:00:00Z",
        }
    ]
}

_CLEAN_RESPONSE: dict = {"vulns": []}

_RICH_RESPONSE = {
    "vulns": [
        {"id": "CVE-2024-1234", "severity": "HIGH"},
        {"id": "CVE-2024-5678", "severity": "MEDIUM"},
    ],
    "metadata": {"checked_at": "2024-06-01T00:00:00Z"},
}


# ---------------------------------------------------------------------------
# Basic get/put
# ---------------------------------------------------------------------------

class TestAdvisoryCacheGetPut:
    def test_miss_on_empty_cache(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.get("npm", "lodash", "4.17.21") is None

    def test_hit_after_put(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", "4.17.21", _VULN_RESPONSE)
        result = c.get("npm", "lodash", "4.17.21")
        assert result is not None
        assert result["vulns"][0]["id"] == "GHSA-test-0001"

    def test_roundtrip_preserves_structure(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("pypi", "requests", "2.28.0", _RICH_RESPONSE, ttl=3600)
        assert c.get("pypi", "requests", "2.28.0") == _RICH_RESPONSE

    def test_different_versions_independent(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _CLEAN_RESPONSE)
        c.put("npm", "pkg", "2.0.0", _VULN_RESPONSE)
        assert c.get("npm", "pkg", "1.0.0") == _CLEAN_RESPONSE
        assert c.get("npm", "pkg", "2.0.0") == _VULN_RESPONSE

    def test_different_ecosystems_independent(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "requests", "1.0.0", _VULN_RESPONSE)
        c.put("pypi", "requests", "1.0.0", _CLEAN_RESPONSE)
        assert c.get("npm", "requests", "1.0.0")["vulns"]
        assert not c.get("pypi", "requests", "1.0.0")["vulns"]

    def test_put_overwrites_existing_entry(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        c.put("npm", "pkg", "1.0.0", _CLEAN_RESPONSE)
        assert c.get("npm", "pkg", "1.0.0") == _CLEAN_RESPONSE

    def test_empty_version_string_accepted(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "", _VULN_RESPONSE)
        assert c.get("npm", "pkg", "") is not None

    def test_default_version_arg_is_empty_string(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "", _VULN_RESPONSE)
        # get() with no version arg should default to ""
        assert c.get("npm", "pkg") is not None

    def test_none_response_stored_as_empty_dict(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", None)
        result = c.get("npm", "pkg", "1.0.0")
        assert isinstance(result, dict)
        assert result == {}


# ---------------------------------------------------------------------------
# TTL / expiration
# ---------------------------------------------------------------------------

class TestAdvisoryCacheExpiration:
    def test_expired_entry_returns_none(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE, ttl=0)
        assert c.get("npm", "pkg", "1.0.0") is None

    def test_fresh_entry_returned(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE, ttl=3600)
        assert c.get("npm", "pkg", "1.0.0") is not None

    def test_auto_ttl_vuln_response_uses_advisory_ttl(self, tmp_path: Path):
        c = _cache(tmp_path, default_advisory_ttl=3600)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        assert c.get("npm", "pkg", "1.0.0") is not None

    def test_auto_ttl_clean_response_uses_no_vuln_ttl(self, tmp_path: Path):
        c = _cache(tmp_path, default_no_vuln_ttl=86400)
        c.put("npm", "clean", "1.0.0", _CLEAN_RESPONSE)
        assert c.get("npm", "clean", "1.0.0") is not None

    def test_custom_ttl_stored_correctly(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE, ttl=7200)
        db = tmp_path / "adv_cache" / "advisories.db"
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT expires_at FROM advisories WHERE package = ?", ("pkg",)
        ).fetchone()
        conn.close()
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        delta = expires_at - datetime.now(tz=timezone.utc)
        # Should be within ±5 minutes of 7200s
        assert 6900 < delta.total_seconds() < 7500


# ---------------------------------------------------------------------------
# Invalidate
# ---------------------------------------------------------------------------

class TestAdvisoryCacheInvalidate:
    def test_invalidate_specific_package(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", "4.17.21", _VULN_RESPONSE)
        c.put("npm", "express", "4.18.2", _VULN_RESPONSE)
        deleted = c.invalidate("npm", "lodash")
        assert deleted >= 1
        assert c.get("npm", "lodash", "4.17.21") is None
        assert c.get("npm", "express", "4.18.2") is not None

    def test_invalidate_entire_ecosystem(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", "1.0.0", _VULN_RESPONSE)
        c.put("npm", "b", "2.0.0", _VULN_RESPONSE)
        c.put("pypi", "c", "3.0.0", _VULN_RESPONSE)
        deleted = c.invalidate("npm")
        assert deleted == 2
        assert c.get("npm", "a", "1.0.0") is None
        assert c.get("npm", "b", "2.0.0") is None
        assert c.get("pypi", "c", "3.0.0") is not None

    def test_invalidate_nonexistent_returns_zero(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.invalidate("cargo", "phantom") == 0

    def test_invalidate_ecosystem_with_none_package(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("cargo", "serde", "1.0.0", _VULN_RESPONSE)
        deleted = c.invalidate("cargo", None)
        assert deleted >= 1
        assert c.get("cargo", "serde", "1.0.0") is None


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------

class TestAdvisoryCachePrune:
    def _backdate(self, db_path: Path, package: str, days: int) -> None:
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE advisories SET fetched_at = ? WHERE package = ?",
            (old_time, package),
        )
        conn.commit()
        conn.close()

    def test_prune_removes_old_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "old", "1.0.0", _VULN_RESPONSE)
        self._backdate(tmp_path / "adv_cache" / "advisories.db", "old", 35)
        assert c.prune(max_age_days=30) >= 1

    def test_prune_keeps_recent_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "fresh", "1.0.0", _VULN_RESPONSE)
        assert c.prune(max_age_days=30) == 0
        assert c.get("npm", "fresh", "1.0.0") is not None

    def test_prune_returns_correct_count(self, tmp_path: Path):
        c = _cache(tmp_path)
        db_path = tmp_path / "adv_cache" / "advisories.db"
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=40)).isoformat()
        conn = sqlite3.connect(str(db_path))
        for i in range(4):
            conn.execute(
                "INSERT OR REPLACE INTO advisories "
                "(ecosystem, package, version, response, fetched_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("npm", f"stale-{i}", "1.0", "{}", old_time, old_time),
            )
        conn.commit()
        conn.close()
        assert c.prune(max_age_days=30) == 4

    def test_prune_mixed_ages(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "old", "1.0.0", _VULN_RESPONSE)
        c.put("npm", "new", "2.0.0", _VULN_RESPONSE)
        self._backdate(tmp_path / "adv_cache" / "advisories.db", "old", 40)
        pruned = c.prune(max_age_days=30)
        assert pruned == 1
        assert c.get("npm", "new", "2.0.0") is not None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestAdvisoryCacheStats:
    def test_initial_stats_all_zeros(self, tmp_path: Path):
        c = _cache(tmp_path)
        s = c.stats()
        assert s.total_entries == 0
        assert s.hit_count == 0
        assert s.miss_count == 0
        assert s.hit_rate == 0.0
        assert s.oldest_entry is None

    def test_hit_rate_after_hits(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        c.get("npm", "pkg", "1.0.0")
        c.get("npm", "pkg", "1.0.0")
        s = c.stats()
        assert s.hit_count == 2
        assert s.miss_count == 0
        assert s.hit_rate == 1.0

    def test_miss_count_increments(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.get("npm", "ghost", "0.0.0")
        s = c.stats()
        assert s.miss_count == 1
        assert s.hit_rate == 0.0

    def test_mixed_hit_rate(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        c.get("npm", "pkg", "1.0.0")    # hit
        c.get("npm", "ghost", "0.0.0")  # miss
        assert c.stats().hit_rate == pytest.approx(0.5)

    def test_total_entries_counts_db_rows(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", "1.0.0", _VULN_RESPONSE)
        c.put("npm", "b", "2.0.0", _VULN_RESPONSE)
        c.put("pypi", "c", "3.0.0", _VULN_RESPONSE)
        assert c.stats().total_entries == 3

    def test_db_size_positive_after_writes(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        assert c.stats().db_size_bytes > 0

    def test_oldest_entry_set_after_put(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        s = c.stats()
        assert s.oldest_entry is not None

    def test_is_cache_stats_instance(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert isinstance(c.stats(), CacheStats)

    def test_stats_str_representation(self, tmp_path: Path):
        c = _cache(tmp_path)
        s = c.stats()
        text = str(s)
        assert "AdvisoryCache stats" in text
        assert "hit rate" in text


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

class TestAdvisoryCacheClear:
    def test_clear_removes_all_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", "1.0.0", _VULN_RESPONSE)
        c.put("pypi", "b", "2.0.0", _CLEAN_RESPONSE)
        deleted = c.clear()
        assert deleted == 2
        assert c.stats().total_entries == 0

    def test_clear_on_empty_cache_returns_zero(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.clear() == 0

    def test_clear_makes_subsequent_gets_miss(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)
        c.clear()
        assert c.get("npm", "pkg", "1.0.0") is None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestAdvisoryCacheThreadSafety:
    def test_concurrent_puts_no_corruption(self, tmp_path: Path):
        c = _cache(tmp_path)
        errors: list[Exception] = []

        def write(ecosystem: str, count: int) -> None:
            for i in range(count):
                try:
                    c.put(ecosystem, f"pkg-{i}", "1.0.0", _VULN_RESPONSE)
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=write, args=("npm", 15)),
            threading.Thread(target=write, args=("pypi", 15)),
            threading.Thread(target=write, args=("cargo", 15)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert c.stats().total_entries == 45

    def test_concurrent_reads_writes_no_error(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", "4.17.21", _VULN_RESPONSE)
        errors: list[Exception] = []

        def reader() -> None:
            for _ in range(30):
                try:
                    c.get("npm", "lodash", "4.17.21")
                except Exception as exc:
                    errors.append(exc)

        def writer() -> None:
            for i in range(10):
                try:
                    c.put("npm", f"pkg-{i}", "1.0.0", _CLEAN_RESPONSE)
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(3)] + \
                  [threading.Thread(target=writer) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# DB initialisation / persistence
# ---------------------------------------------------------------------------

class TestAdvisoryCachePersistence:
    def test_data_persists_across_instances(self, tmp_path: Path):
        cache_dir = tmp_path / "shared_cache"
        c1 = AdvisoryCache(cache_dir=cache_dir)
        c1.put("npm", "pkg", "1.0.0", _VULN_RESPONSE)

        c2 = AdvisoryCache(cache_dir=cache_dir)
        assert c2.get("npm", "pkg", "1.0.0") is not None

    def test_cache_dir_created_if_missing(self, tmp_path: Path):
        cache_dir = tmp_path / "new" / "nested" / "dir"
        AdvisoryCache(cache_dir=cache_dir)
        assert cache_dir.exists()

    def test_db_file_created(self, tmp_path: Path):
        c = _cache(tmp_path)
        db = tmp_path / "adv_cache" / "advisories.db"
        assert db.exists()
