"""EPSS trend tracker — stores historical EPSS scores and surfaces rising CVEs.

Maintains a SQLite database at ``~/.depfence/cache/epss_history.db`` with one
row per (CVE, timestamp) data point.  Callers record a score whenever they
fetch fresh EPSS data; the tracker then exposes trend analysis helpers:

* ``get_trend(cve)``            — structured trend for a single CVE
* ``get_rising(threshold, days)`` — CVEs whose score jumped significantly
* ``get_critical_trajectory(days)`` — CVEs likely heading toward exploitation

All read methods gracefully handle an empty or missing database.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

_DEFAULT_DB_PATH = Path.home() / ".depfence" / "cache" / "epss_history.db"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class EPSSTrend:
    """Trend summary for a single CVE over time."""

    cve: str
    current_score: float
    score_7d_ago: float | None
    score_30d_ago: float | None
    direction: str  # "rising", "falling", or "stable"
    velocity: float  # score change per day (positive = rising, negative = falling)


@dataclass
class RisingCVE:
    """A CVE whose EPSS score has increased notably over the observation window."""

    cve: str
    current_score: float
    delta_7d: float
    affected_packages: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------


class EPSSTracker:
    """Persistent EPSS history tracker backed by SQLite.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Defaults to
        ``~/.depfence/cache/epss_history.db``.

    Example::

        tracker = EPSSTracker()
        tracker.record("CVE-2024-1234", score=0.42, percentile=0.81)
        trend = tracker.get_trend("CVE-2024-1234")
        rising = tracker.get_rising(threshold=0.1, days=7)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return (lazily-created) database connection."""
        if self._conn is not None:
            return self._conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        self._ensure_schema(conn)
        self._conn = conn
        return conn

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS epss_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                cve         TEXT        NOT NULL,
                score       REAL        NOT NULL,
                percentile  REAL        NOT NULL,
                recorded_at TIMESTAMP   NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_epss_cve_ts ON epss_history(cve, recorded_at)"
        )
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _score_at(self, conn: sqlite3.Connection, cve: str, cutoff: datetime) -> float | None:
        """Return the EPSS score closest to (but not after) *cutoff*, or None."""
        row = conn.execute(
            """
            SELECT score FROM epss_history
            WHERE cve = ? AND recorded_at <= ?
            ORDER BY recorded_at DESC
            LIMIT 1
            """,
            (cve, cutoff.isoformat()),
        ).fetchone()
        return float(row["score"]) if row else None

    def _latest_score(self, conn: sqlite3.Connection, cve: str) -> float | None:
        row = conn.execute(
            "SELECT score FROM epss_history WHERE cve = ? ORDER BY recorded_at DESC LIMIT 1",
            (cve,),
        ).fetchone()
        return float(row["score"]) if row else None

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def record(self, cve: str, score: float, percentile: float) -> None:
        """Store an EPSS data point for *cve*.

        Parameters
        ----------
        cve:
            CVE identifier, e.g. ``"CVE-2024-1234"``.
        score:
            Raw EPSS probability (0.0–1.0).
        percentile:
            Relative percentile (0.0–1.0).
        """
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO epss_history (cve, score, percentile, recorded_at) VALUES (?, ?, ?, ?)",
            (cve, float(score), float(percentile), self._now()),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_trend(self, cve: str, days: int = 30) -> EPSSTrend:
        """Return an :class:`EPSSTrend` for *cve*.

        Parameters
        ----------
        cve:
            CVE identifier.
        days:
            How far back to look when calculating ``score_30d_ago``.

        Returns
        -------
        EPSSTrend
            Trend object.  ``score_7d_ago`` / ``score_30d_ago`` are ``None``
            when insufficient history is available.  ``direction`` is
            ``"stable"`` when velocity magnitude is below 0.005/day.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc)

        current_score = self._latest_score(conn, cve) or 0.0
        score_7d_ago = self._score_at(conn, cve, now - timedelta(days=7))
        score_30d_ago = self._score_at(conn, cve, now - timedelta(days=days))

        # Velocity: use 7-day window when available, else 30-day
        if score_7d_ago is not None:
            velocity = (current_score - score_7d_ago) / 7.0
        elif score_30d_ago is not None:
            velocity = (current_score - score_30d_ago) / float(days)
        else:
            velocity = 0.0

        if velocity > 0.005:
            direction = "rising"
        elif velocity < -0.005:
            direction = "falling"
        else:
            direction = "stable"

        return EPSSTrend(
            cve=cve,
            current_score=current_score,
            score_7d_ago=score_7d_ago,
            score_30d_ago=score_30d_ago,
            direction=direction,
            velocity=velocity,
        )

    def get_rising(
        self,
        threshold: float = 0.1,
        days: int = 7,
        affected_packages: dict[str, list[str]] | None = None,
    ) -> list[RisingCVE]:
        """Return CVEs whose score has risen by at least *threshold* in *days* days.

        Parameters
        ----------
        threshold:
            Minimum absolute score increase to include a CVE.
        days:
            Look-back window in days.
        affected_packages:
            Optional mapping of CVE -> list[package_name] to populate
            :attr:`RisingCVE.affected_packages`.

        Returns
        -------
        list[RisingCVE]
            Sorted descending by ``delta_7d``.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=days)

        # Get all CVEs that have data in both windows
        rows = conn.execute(
            """
            SELECT DISTINCT cve FROM epss_history
            WHERE recorded_at >= ?
            """,
            (cutoff.isoformat(),),
        ).fetchall()

        results: list[RisingCVE] = []
        for row in rows:
            cve = row["cve"]
            current = self._latest_score(conn, cve)
            past = self._score_at(conn, cve, cutoff)
            if current is None or past is None:
                continue
            delta = current - past
            if delta >= threshold:
                pkgs = (affected_packages or {}).get(cve, [])
                results.append(RisingCVE(
                    cve=cve,
                    current_score=current,
                    delta_7d=delta,
                    affected_packages=pkgs,
                ))

        results.sort(key=lambda r: r.delta_7d, reverse=True)
        return results

    def get_critical_trajectory(self, days: int = 14) -> list[EPSSTrend]:
        """Return CVEs that are rising fast and may reach exploitation threshold.

        "Critical trajectory" means:
        * Direction is ``"rising"``
        * Projected score in *days* days (extrapolated linearly) would exceed 0.5

        Parameters
        ----------
        days:
            Forward-projection window in days.

        Returns
        -------
        list[EPSSTrend]
            Sorted descending by projected score.
        """
        conn = self._get_conn()
        rows = conn.execute("SELECT DISTINCT cve FROM epss_history").fetchall()

        results: list[EPSSTrend] = []
        for row in rows:
            cve = row["cve"]
            trend = self.get_trend(cve)
            if trend.direction != "rising":
                continue
            projected = trend.current_score + trend.velocity * days
            if projected > 0.5:
                results.append(trend)

        results.sort(key=lambda t: t.current_score + t.velocity * days, reverse=True)
        return results

    def all_cves(self) -> list[str]:
        """Return all CVEs with stored history."""
        conn = self._get_conn()
        rows = conn.execute("SELECT DISTINCT cve FROM epss_history ORDER BY cve").fetchall()
        return [row["cve"] for row in rows]

    def history(self, cve: str) -> list[dict]:
        """Return all recorded data points for *cve*, oldest first.

        Each dict has keys: ``cve``, ``score``, ``percentile``, ``recorded_at``.
        """
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT cve, score, percentile, recorded_at FROM epss_history "
            "WHERE cve = ? ORDER BY recorded_at ASC",
            (cve,),
        ).fetchall()
        return [dict(row) for row in rows]
