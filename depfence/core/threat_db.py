"""Local threat intelligence database client.

Reads from the SQLite DB populated by the autonomous crawler at
~/.depfence/threat_intel.db. All methods degrade gracefully when the
DB does not exist (first run, CI).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_DEFAULT_DB_PATH = Path.home() / ".depfence" / "threat_intel.db"

_MALICIOUS_SEVERITIES = {"critical"}
_MALICIOUS_THREAT_TYPES = {"malware", "malicious", "backdoor", "credential_theft", "exfiltration"}


class ThreatDB:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else _DEFAULT_DB_PATH

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        """Return a read-only connection, or None if DB does not exist."""
        if not self._db_path.exists():
            return None
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, ecosystem: str, package_name: str) -> list[dict]:
        """Return all threat_entries rows for the given package.

        Parameters
        ----------
        ecosystem:
            Ecosystem identifier (e.g. ``"npm"``, ``"pypi"``).  The comparison
            is case-insensitive so callers need not normalise the value.
        package_name:
            Package name.  Also compared case-insensitively.

        Returns
        -------
        list[dict]
            One dict per matching row, with the same keys as the
            ``threat_entries`` table columns.  Returns an empty list if the DB
            is absent or no entries are found.
        """
        conn = self._connect()
        if conn is None:
            return []

        try:
            cur = conn.execute(
                """
                SELECT source, ecosystem, package_name, version_range,
                       threat_type, severity, title, detail, cve,
                       first_seen, last_updated
                FROM threat_entries
                WHERE LOWER(ecosystem) = LOWER(?)
                  AND LOWER(package_name) = LOWER(?)
                ORDER BY last_updated DESC
                """,
                (ecosystem, package_name),
            )
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.OperationalError:
            # Table might not exist yet on older DB versions.
            return []
        finally:
            conn.close()

    def is_known_malicious(self, ecosystem: str, package_name: str) -> bool:
        """Return True if the package has any critical or explicitly malicious entries.

        A package is considered malicious when at least one threat entry either:

        * has ``severity`` == ``"critical"``, or
        * has a ``threat_type`` that indicates active malice (e.g. ``"malware"``,
          ``"backdoor"``, ``"credential_theft"``).
        """
        threats = self.lookup(ecosystem, package_name)
        for threat in threats:
            severity = (threat.get("severity") or "").lower()
            threat_type = (threat.get("threat_type") or "").lower()
            if severity in _MALICIOUS_SEVERITIES:
                return True
            if threat_type in _MALICIOUS_THREAT_TYPES:
                return True
        return False

    def get_crawler_verdict(self, ecosystem: str, package_name: str) -> dict | None:
        """Return the most-recent crawler verdict for the package, or None.

        Queries the ``crawl_results`` table.  The returned dict contains the
        ``ecosystem``, ``package_name``, ``version``, ``score``, ``signals``,
        and ``verdict`` columns (matching the crawler schema).
        """
        conn = self._connect()
        if conn is None:
            return None

        try:
            cur = conn.execute(
                """
                SELECT ecosystem, package_name, version, score, signals, verdict
                FROM crawl_results
                WHERE LOWER(ecosystem) = LOWER(?)
                  AND LOWER(package_name) = LOWER(?)
                ORDER BY crawled_at DESC
                LIMIT 1
                """,
                (ecosystem, package_name),
            )
            row = cur.fetchone()
            return dict(row) if row else None
        except sqlite3.OperationalError:
            return None
        finally:
            conn.close()
