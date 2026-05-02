"""SQLite-backed advisory response cache for OSV/NVD/GitHub advisory lookups.

Stores serialised advisory API responses keyed on (ecosystem, package, version)
with configurable TTLs.  Uses WAL mode for concurrent access safety.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path.home() / ".depfence" / "cache"
_DB_NAME = "advisories.db"

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS advisories (
    ecosystem   TEXT      NOT NULL,
    package     TEXT      NOT NULL,
    version     TEXT      NOT NULL DEFAULT \'\',
    response    BLOB      NOT NULL,
    fetched_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (ecosystem, package, version)
);

CREATE INDEX IF NOT EXISTS idx_advisories_expires ON advisories (expires_at);
CREATE INDEX IF NOT EXISTS idx_advisories_ecosystem ON advisories (ecosystem, package);
"""

# Default TTLs (seconds)
_TTL_ADVISORY = 3600        # 1 hour for packages with vulnerabilities
_TTL_NO_VULN   = 86400      # 24 hours for "no vulnerabilities found"


@dataclass(frozen=True)
class CacheStats:
    """Statistics returned by AdvisoryCache.stats()."""
    total_entries: int
    hit_count: int
    miss_count: int
    hit_rate: float
    db_size_bytes: int
    oldest_entry: datetime | None

    def __str__(self) -> str:
        oldest = self.oldest_entry.isoformat() if self.oldest_entry else "N/A"
        return (
            f"AdvisoryCache stats: {self.total_entries} entries, "
            f"hit rate {self.hit_rate:.1%} ({self.hit_count} hits / "
            f"{self.miss_count} misses), "
            f"db size {self.db_size_bytes:,} bytes, oldest {oldest}"
        )


class AdvisoryCache:
    """SQLite-backed cache for advisory API responses.

    Thread-safe via a per-instance lock; WAL mode is enabled so multiple
    readers can coexist with a single writer.

    Typical usage::

        cache = AdvisoryCache()

        # Check cache before network call
        data = cache.get("npm", "lodash", "4.17.21")
        if data is None:
            data = await fetch_from_osv(...)
            ttl = _TTL_NO_VULN if not data.get("vulns") else _TTL_ADVISORY
            cache.put("npm", "lodash", "4.17.21", data, ttl=ttl)
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        default_advisory_ttl: int = _TTL_ADVISORY,
        default_no_vuln_ttl: int = _TTL_NO_VULN,
    ) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._cache_dir / _DB_NAME
        self._default_advisory_ttl = default_advisory_ttl
        self._default_no_vuln_ttl = default_no_vuln_ttl
        self._lock = threading.Lock()
        # Simple in-process hit/miss counters (reset on each instantiation)
        self._hits = 0
        self._misses = 0
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            for stmt in _SCHEMA.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(tz=timezone.utc).isoformat()

    @staticmethod
    def _expires_iso(ttl: int) -> str:
        from datetime import timedelta
        return (datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)).isoformat()

    @staticmethod
    def _parse_dt(iso: str) -> datetime:
        # Python 3.10 fromisoformat does not handle the trailing Z
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, ecosystem: str, package: str, version: str = "") -> dict[str, Any] | None:
        """Return a cached advisory response if it exists and has not expired.

        Parameters
        ----------
        ecosystem:  e.g. ``"npm"``, ``"pypi"``
        package:    Package name
        version:    Package version (empty string means "any/unversioned")

        Returns
        -------
        dict | None
            The cached response dict, or ``None`` on a cache miss / expiry.
        """
        now = self._now_iso()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT response FROM advisories
                WHERE ecosystem = ? AND package = ? AND version = ?
                  AND expires_at > ?
                """,
                (ecosystem, package, version or "", now),
            ).fetchone()

        if row is None:
            self._misses += 1
            return None

        self._hits += 1
        try:
            return json.loads(row["response"])
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("AdvisoryCache: corrupt entry for %s/%s@%s — %s", ecosystem, package, version, exc)
            return None

    def put(
        self,
        ecosystem: str,
        package: str,
        version: str = "",
        response: dict[str, Any] | None = None,
        *,
        ttl: int | None = None,
    ) -> None:
        """Store an advisory response in the cache.

        Parameters
        ----------
        ecosystem:  e.g. ``"npm"``, ``"pypi"``
        package:    Package name
        version:    Package version (empty string for unversioned queries)
        response:   The API response dict to serialise and store
        ttl:        Time-to-live in seconds.  If omitted the default TTL is
                    chosen based on whether the response contains any vulns
                    (``"vulns"`` key).
        """
        if response is None:
            response = {}

        if ttl is None:
            has_vulns = bool(response.get("vulns"))
            ttl = self._default_advisory_ttl if has_vulns else self._default_no_vuln_ttl

        now = self._now_iso()
        expires = self._expires_iso(ttl)
        blob = json.dumps(response, separators=(",", ":"))

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO advisories (ecosystem, package, version, response, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, package, version) DO UPDATE SET
                    response   = excluded.response,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (ecosystem, package, version or "", blob, now, expires),
            )

    def invalidate(self, ecosystem: str, package: str | None = None) -> int:
        """Remove cached entries for an ecosystem or a specific package.

        Parameters
        ----------
        ecosystem:  The ecosystem to invalidate (e.g. ``"npm"``).
        package:    If given, only this package\'s entries are removed;
                    otherwise all entries for the ecosystem are removed.

        Returns
        -------
        int
            Number of rows deleted.
        """
        with self._lock, self._connect() as conn:
            if package is None:
                cur = conn.execute(
                    "DELETE FROM advisories WHERE ecosystem = ?", (ecosystem,)
                )
            else:
                cur = conn.execute(
                    "DELETE FROM advisories WHERE ecosystem = ? AND package = ?",
                    (ecosystem, package),
                )
            return cur.rowcount

    def prune(self, max_age_days: int = 30) -> int:
        """Delete entries older than *max_age_days* days (by fetched_at).

        This goes beyond TTL-based expiry — it ensures the DB does not grow
        unboundedly even if TTLs are very long.

        Returns
        -------
        int
            Number of rows pruned.
        """
        from datetime import timedelta
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM advisories WHERE fetched_at < ?", (cutoff,)
            )
            return cur.rowcount

    def stats(self) -> CacheStats:
        """Return hit-rate, size, and age statistics for this cache."""
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0.0

        with self._lock, self._connect() as conn:
            count_row = conn.execute("SELECT COUNT(*) AS cnt FROM advisories").fetchone()
            oldest_row = conn.execute(
                "SELECT MIN(fetched_at) AS oldest FROM advisories"
            ).fetchone()

        total_entries = count_row["cnt"] if count_row else 0
        oldest_iso = oldest_row["oldest"] if oldest_row else None
        oldest_dt: datetime | None = None
        if oldest_iso:
            try:
                oldest_dt = self._parse_dt(oldest_iso)
            except (ValueError, TypeError):
                pass

        db_size = 0
        if self._db_path.exists():
            db_size = self._db_path.stat().st_size

        return CacheStats(
            total_entries=total_entries,
            hit_count=self._hits,
            miss_count=self._misses,
            hit_rate=hit_rate,
            db_size_bytes=db_size,
            oldest_entry=oldest_dt,
        )

    def clear(self) -> int:
        """Wipe all cached advisory data.

        Returns
        -------
        int
            Number of rows deleted.
        """
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM advisories")
            return cur.rowcount
