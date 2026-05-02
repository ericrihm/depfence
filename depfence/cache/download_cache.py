"""SQLite-backed package metadata cache for npm/PyPI registry responses.

Shares the same database file as AdvisoryCache (different table) to keep
everything in one place.  TTL defaults to 6 hours.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path.home() / ".depfence" / "cache"
_DB_NAME = "advisories.db"   # shared DB with AdvisoryCache

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS metadata (
    ecosystem  TEXT      NOT NULL,
    package    TEXT      NOT NULL,
    response   BLOB      NOT NULL,
    fetched_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (ecosystem, package)
);

CREATE INDEX IF NOT EXISTS idx_metadata_expires ON metadata (expires_at);
"""

_TTL_METADATA = 6 * 3600   # 6 hours


class DownloadCache:
    """Cache for npm and PyPI registry metadata responses.

    Uses the same ``advisories.db`` SQLite file as :class:`AdvisoryCache`
    but a separate ``metadata`` table, so the two caches can be cleared
    independently.

    Example::

        cache = DownloadCache()
        data = cache.get("npm", "lodash")
        if data is None:
            data = await fetch_npm_registry("lodash")
            cache.put("npm", "lodash", data)
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        default_ttl: int = _TTL_METADATA,
    ) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._cache_dir / _DB_NAME
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
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
        return (datetime.now(tz=timezone.utc) + timedelta(seconds=ttl)).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, ecosystem: str, package: str) -> dict[str, Any] | None:
        """Return cached metadata if not expired, else ``None``."""
        now = self._now_iso()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT response FROM metadata
                WHERE ecosystem = ? AND package = ?
                  AND expires_at > ?
                """,
                (ecosystem, package, now),
            ).fetchone()

        if row is None:
            return None

        try:
            return json.loads(row["response"])
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("DownloadCache: corrupt entry for %s/%s — %s", ecosystem, package, exc)
            return None

    def put(
        self,
        ecosystem: str,
        package: str,
        response: dict[str, Any],
        *,
        ttl: int | None = None,
    ) -> None:
        """Store registry metadata in the cache."""
        if ttl is None:
            ttl = self._default_ttl

        now = self._now_iso()
        expires = self._expires_iso(ttl)
        blob = json.dumps(response, separators=(",", ":"))

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metadata (ecosystem, package, response, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, package) DO UPDATE SET
                    response   = excluded.response,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (ecosystem, package, blob, now, expires),
            )

    def invalidate(self, ecosystem: str, package: str | None = None) -> int:
        """Remove metadata cache entries.

        Parameters
        ----------
        ecosystem:  The ecosystem to clear.
        package:    If given, only this package is cleared; otherwise all
                    entries for the ecosystem are removed.

        Returns
        -------
        int
            Number of rows deleted.
        """
        with self._lock, self._connect() as conn:
            if package is None:
                cur = conn.execute(
                    "DELETE FROM metadata WHERE ecosystem = ?", (ecosystem,)
                )
            else:
                cur = conn.execute(
                    "DELETE FROM metadata WHERE ecosystem = ? AND package = ?",
                    (ecosystem, package),
                )
            return cur.rowcount

    def prune(self, max_age_days: int = 30) -> int:
        """Delete metadata entries older than *max_age_days* days.

        Returns
        -------
        int
            Number of rows pruned.
        """
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM metadata WHERE fetched_at < ?", (cutoff,)
            )
            return cur.rowcount

    def clear(self) -> int:
        """Wipe all cached metadata.

        Returns
        -------
        int
            Number of rows deleted.
        """
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM metadata")
            return cur.rowcount

    def stats(self) -> dict[str, Any]:
        """Return basic stats for the metadata cache."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM metadata").fetchone()
        db_size = self._db_path.stat().st_size if self._db_path.exists() else 0
        return {
            "total_entries": row["cnt"] if row else 0,
            "db_size_bytes": db_size,
        }
