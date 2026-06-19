"""Tests for depfence/cache/download_cache.py."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depfence.cache.advisory_cache import AdvisoryCache
from depfence.cache.download_cache import DownloadCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cache(tmp_path: Path, **kwargs) -> DownloadCache:
    return DownloadCache(cache_dir=tmp_path / "dl_cache", **kwargs)


_NPM_RESPONSE = {
    "name": "lodash",
    "version": "4.17.21",
    "description": "Lodash modular utilities.",
    "maintainers": [{"name": "jdalton", "email": "jdalton@example.com"}],
    "dist-tags": {"latest": "4.17.21"},
    "versions": {"4.17.21": {}},
    "time": {"4.17.21": "2021-02-20T15:42:16.891Z"},
}

_PYPI_RESPONSE = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
        "author": "Kenneth Reitz",
        "license": "Apache 2.0",
    },
    "releases": {"2.31.0": []},
}

_MINIMAL_RESPONSE = {"name": "minimal"}


# ---------------------------------------------------------------------------
# Basic get/put
# ---------------------------------------------------------------------------

class TestDownloadCacheGetPut:
    def test_miss_on_empty_cache(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.get("npm", "lodash") is None

    def test_hit_after_put(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE)
        result = c.get("npm", "lodash")
        assert result is not None
        assert result["name"] == "lodash"

    def test_roundtrip_preserves_structure(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("pypi", "requests", _PYPI_RESPONSE)
        assert c.get("pypi", "requests") == _PYPI_RESPONSE

    def test_different_ecosystems_independent(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "requests", {"source": "npm"})
        c.put("pypi", "requests", {"source": "pypi"})
        assert c.get("npm", "requests")["source"] == "npm"
        assert c.get("pypi", "requests")["source"] == "pypi"

    def test_put_overwrites_existing_entry(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", {"v": "old"})
        c.put("npm", "lodash", {"v": "new"})
        assert c.get("npm", "lodash") == {"v": "new"}

    def test_miss_for_different_package(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE)
        assert c.get("npm", "express") is None

    def test_empty_dict_storable(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "empty-pkg", {})
        assert c.get("npm", "empty-pkg") == {}


# ---------------------------------------------------------------------------
# TTL / expiration
# ---------------------------------------------------------------------------

class TestDownloadCacheExpiration:
    def test_expired_entry_returns_none(self, tmp_path: Path):
        c = _cache(tmp_path, default_ttl=0)
        c.put("npm", "lodash", _NPM_RESPONSE)
        assert c.get("npm", "lodash") is None

    def test_fresh_entry_returned(self, tmp_path: Path):
        c = _cache(tmp_path, default_ttl=3600)
        c.put("npm", "lodash", _NPM_RESPONSE)
        assert c.get("npm", "lodash") is not None

    def test_custom_ttl_applied(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE, ttl=9999)
        db = tmp_path / "dl_cache" / "advisories.db"
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT expires_at FROM metadata WHERE package = ?", ("lodash",)
        ).fetchone()
        conn.close()
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        delta = expires_at - datetime.now(tz=timezone.utc)
        # Within ±5 min of 9999s
        assert 9500 < delta.total_seconds() < 10500

    def test_default_ttl_is_six_hours(self, tmp_path: Path):
        """Default TTL = 6h; entry should be alive immediately after insertion."""
        c = _cache(tmp_path)
        c.put("npm", "pkg", _MINIMAL_RESPONSE)
        assert c.get("npm", "pkg") is not None


# ---------------------------------------------------------------------------
# Invalidate
# ---------------------------------------------------------------------------

class TestDownloadCacheInvalidate:
    def test_invalidate_specific_package(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", _NPM_RESPONSE)
        c.put("npm", "b", _NPM_RESPONSE)
        deleted = c.invalidate("npm", "a")
        assert deleted >= 1
        assert c.get("npm", "a") is None
        assert c.get("npm", "b") is not None

    def test_invalidate_entire_ecosystem(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", _NPM_RESPONSE)
        c.put("npm", "b", _NPM_RESPONSE)
        c.put("pypi", "c", _PYPI_RESPONSE)
        deleted = c.invalidate("npm")
        assert deleted == 2
        assert c.get("npm", "a") is None
        assert c.get("npm", "b") is None
        assert c.get("pypi", "c") is not None

    def test_invalidate_nonexistent_returns_zero(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.invalidate("cargo", "phantom") == 0

    def test_invalidate_ecosystem_no_package_arg(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("cargo", "serde", _MINIMAL_RESPONSE)
        deleted = c.invalidate("cargo")
        assert deleted >= 1
        assert c.get("cargo", "serde") is None


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------

class TestDownloadCachePrune:
    def _backdate(self, db_path: Path, package: str, days: int) -> None:
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE metadata SET fetched_at = ? WHERE package = ?",
            (old_time, package),
        )
        conn.commit()
        conn.close()

    def test_prune_removes_old_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "old", _NPM_RESPONSE)
        self._backdate(tmp_path / "dl_cache" / "advisories.db", "old", 40)
        assert c.prune(max_age_days=30) >= 1

    def test_prune_keeps_recent_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "fresh", _NPM_RESPONSE)
        assert c.prune(max_age_days=30) == 0
        assert c.get("npm", "fresh") is not None

    def test_prune_returns_correct_count(self, tmp_path: Path):
        c = _cache(tmp_path)
        db_path = tmp_path / "dl_cache" / "advisories.db"
        old_time = (datetime.now(tz=timezone.utc) - timedelta(days=40)).isoformat()
        conn = sqlite3.connect(str(db_path))
        for i in range(3):
            conn.execute(
                "INSERT OR REPLACE INTO metadata "
                "(ecosystem, package, response, fetched_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("npm", f"stale-{i}", "{}", old_time, old_time),
            )
        conn.commit()
        conn.close()
        assert c.prune(max_age_days=30) == 3

    def test_prune_mixed_ages_selective(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "old", _NPM_RESPONSE)
        c.put("npm", "new", _MINIMAL_RESPONSE)
        self._backdate(tmp_path / "dl_cache" / "advisories.db", "old", 40)
        assert c.prune(max_age_days=30) == 1
        assert c.get("npm", "new") is not None


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

class TestDownloadCacheClear:
    def test_clear_removes_all_entries(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "a", _NPM_RESPONSE)
        c.put("pypi", "b", _PYPI_RESPONSE)
        deleted = c.clear()
        assert deleted == 2
        assert c.stats()["total_entries"] == 0

    def test_clear_on_empty_cache_returns_zero(self, tmp_path: Path):
        c = _cache(tmp_path)
        assert c.clear() == 0

    def test_clear_makes_subsequent_gets_miss(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "pkg", _NPM_RESPONSE)
        c.clear()
        assert c.get("npm", "pkg") is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestDownloadCacheStats:
    def test_stats_empty_cache(self, tmp_path: Path):
        c = _cache(tmp_path)
        s = c.stats()
        assert s["total_entries"] == 0

    def test_stats_after_puts(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE)
        c.put("pypi", "requests", _PYPI_RESPONSE)
        s = c.stats()
        assert s["total_entries"] == 2

    def test_stats_db_size_positive(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE)
        assert c.stats()["db_size_bytes"] > 0

    def test_stats_returns_dict(self, tmp_path: Path):
        c = _cache(tmp_path)
        s = c.stats()
        assert isinstance(s, dict)
        assert "total_entries" in s
        assert "db_size_bytes" in s


# ---------------------------------------------------------------------------
# Shared DB with AdvisoryCache
# ---------------------------------------------------------------------------

class TestSharedDatabase:
    def test_both_caches_use_same_db_file(self, tmp_path: Path):
        shared = tmp_path / "shared"
        adv = AdvisoryCache(cache_dir=shared)
        dl = DownloadCache(cache_dir=shared)
        assert adv._db_path == dl._db_path

    def test_clear_metadata_does_not_remove_advisories(self, tmp_path: Path):
        shared = tmp_path / "shared"
        adv = AdvisoryCache(cache_dir=shared)
        dl = DownloadCache(cache_dir=shared)

        adv.put("npm", "lodash", "4.17.21", {"vulns": []})
        dl.put("npm", "lodash", _NPM_RESPONSE)

        dl.clear()
        assert adv.get("npm", "lodash", "4.17.21") is not None

    def test_clear_advisories_does_not_remove_metadata(self, tmp_path: Path):
        shared = tmp_path / "shared"
        adv = AdvisoryCache(cache_dir=shared)
        dl = DownloadCache(cache_dir=shared)

        adv.put("npm", "lodash", "4.17.21", {"vulns": []})
        dl.put("npm", "lodash", _NPM_RESPONSE)

        adv.clear()
        assert dl.get("npm", "lodash") is not None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestDownloadCacheThreadSafety:
    def test_concurrent_puts_no_corruption(self, tmp_path: Path):
        c = _cache(tmp_path)
        errors: list[Exception] = []

        def write(eco: str, count: int) -> None:
            for i in range(count):
                try:
                    c.put(eco, f"pkg-{i}", {"i": i})
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=write, args=("npm", 10)),
            threading.Thread(target=write, args=("pypi", 10)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert c.stats()["total_entries"] == 20

    def test_concurrent_reads_no_error(self, tmp_path: Path):
        c = _cache(tmp_path)
        c.put("npm", "lodash", _NPM_RESPONSE)
        errors: list[Exception] = []

        def reader() -> None:
            for _ in range(40):
                try:
                    c.get("npm", "lodash")
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestDownloadCachePersistence:
    def test_data_persists_across_instances(self, tmp_path: Path):
        cache_dir = tmp_path / "persistent"
        c1 = DownloadCache(cache_dir=cache_dir)
        c1.put("npm", "lodash", _NPM_RESPONSE)

        c2 = DownloadCache(cache_dir=cache_dir)
        assert c2.get("npm", "lodash") is not None

    def test_cache_dir_created_if_missing(self, tmp_path: Path):
        cache_dir = tmp_path / "new" / "deep" / "dir"
        DownloadCache(cache_dir=cache_dir)
        assert cache_dir.exists()

    def test_db_file_created_on_init(self, tmp_path: Path):
        c = _cache(tmp_path)
        db = tmp_path / "dl_cache" / "advisories.db"
        assert db.exists()
