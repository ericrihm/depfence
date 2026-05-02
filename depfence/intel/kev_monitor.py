"""CISA Known Exploited Vulnerabilities (KEV) monitor.

Maintains a local SQLite cache of KEV catalog entries alongside the EPSS data.
Provides synchronous helpers for cross-referencing scan findings against the
local KEV cache and for escalating severity.

HTTP is intentionally mocked-out in this module; actual network fetches are
delegated to :mod:`depfence.core.kev_client`.  This module focuses on
*persistence* (SQLite) and *policy* (severity escalation).
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depfence.core.models import Finding

log = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".depfence" / "cache" / "epss_history.db"

# CISA KEV JSON feed URL
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class KEVEntry:
    """A single entry from the CISA Known Exploited Vulnerabilities catalog."""

    cve: str
    vendor: str
    product: str
    date_added: str          # ISO 8601 date string, e.g. "2021-12-10"
    due_date: str            # ISO 8601 date string, e.g. "2021-12-24"
    known_ransomware: bool = False
    description: str = ""
    required_action: str = ""


# ---------------------------------------------------------------------------
# KEVMonitor
# ---------------------------------------------------------------------------


class KEVMonitor:
    """Monitor for CISA Known Exploited Vulnerabilities.

    Maintains a local SQLite cache table (``kev_catalog``) in the same database
    file used by :class:`~depfence.intel.epss_tracker.EPSSTracker` so that all
    intel data lives in one place.

    Usage::

        monitor = KEVMonitor()
        monitor.store_kev_entries(monitor.fetch_kev_catalog())
        kev_hits = monitor.check_local_kev(findings)
        escalated = monitor.escalate_severity(findings)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
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
            CREATE TABLE IF NOT EXISTS kev_catalog (
                cve              TEXT PRIMARY KEY,
                vendor           TEXT NOT NULL DEFAULT '',
                product          TEXT NOT NULL DEFAULT '',
                date_added       TEXT NOT NULL DEFAULT '',
                due_date         TEXT NOT NULL DEFAULT '',
                known_ransomware INTEGER NOT NULL DEFAULT 0,
                description      TEXT NOT NULL DEFAULT '',
                required_action  TEXT NOT NULL DEFAULT '',
                cached_at        TIMESTAMP NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kev_cve ON kev_catalog(cve)"
        )
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def store_kev_entries(self, entries: list[KEVEntry]) -> int:
        """Persist *entries* into the local SQLite cache.

        Uses ``INSERT OR REPLACE`` so existing rows are updated on conflict.

        Parameters
        ----------
        entries:
            List of :class:`KEVEntry` objects to store.

        Returns
        -------
        int
            Number of entries stored.
        """
        if not entries:
            return 0
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                e.cve,
                e.vendor,
                e.product,
                e.date_added,
                e.due_date,
                1 if e.known_ransomware else 0,
                e.description,
                e.required_action,
                now,
            )
            for e in entries
        ]
        conn.executemany(
            """
            INSERT OR REPLACE INTO kev_catalog
                (cve, vendor, product, date_added, due_date,
                 known_ransomware, description, required_action, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        return len(rows)

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def check_local_kev(self, findings: list) -> list[KEVEntry]:
        """Cross-reference *findings* against the local KEV cache.

        Parameters
        ----------
        findings:
            Scan findings to check.  Only findings with a non-None ``cve``
            attribute are considered.

        Returns
        -------
        list[KEVEntry]
            KEV entries matching CVEs present in *findings*.
        """
        cves = {f.cve for f in findings if getattr(f, "cve", None)}
        if not cves:
            return []
        conn = self._get_conn()
        placeholders = ",".join("?" * len(cves))
        rows = conn.execute(
            f"SELECT * FROM kev_catalog WHERE cve IN ({placeholders})",
            list(cves),
        ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def get_entry(self, cve: str) -> KEVEntry | None:
        """Return the local KEV entry for *cve*, or ``None`` if not cached."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM kev_catalog WHERE cve = ?", (cve,)
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def all_cves(self) -> list[str]:
        """Return all CVEs stored in the local KEV cache."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT cve FROM kev_catalog ORDER BY cve"
        ).fetchall()
        return [r["cve"] for r in rows]

    def ransomware_cves(self) -> list[str]:
        """Return CVEs flagged as associated with ransomware campaigns."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT cve FROM kev_catalog WHERE known_ransomware = 1 ORDER BY cve"
        ).fetchall()
        return [r["cve"] for r in rows]

    def count(self) -> int:
        """Return the number of CVEs in the local cache."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) AS n FROM kev_catalog").fetchone()
        return row["n"] if row else 0

    # ------------------------------------------------------------------
    # KEV catalog fetch (HTTP mocked — structure only)
    # ------------------------------------------------------------------

    def fetch_kev_catalog(self) -> list[KEVEntry]:
        """Fetch the CISA KEV catalog and return parsed entries.

        In production this would issue an HTTP GET to :data:`CISA_KEV_URL`.
        This implementation returns a representative minimal set so that the
        module works without network access; callers that need a live feed
        should use :class:`~depfence.core.kev_client.KevClient` directly.

        Returns
        -------
        list[KEVEntry]
            Parsed KEV entries.  Pass these to :meth:`store_kev_entries` to
            persist them locally.
        """
        # Mock CISA JSON structure — mirrors the real feed shape exactly
        mock_payload: dict = {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "mock",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Apache Log4j2 contains an RCE vulnerability.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2022-30190",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Microsoft MSDT RCE Vulnerability",
                    "dateAdded": "2022-05-31",
                    "shortDescription": "Microsoft MSDT remote code execution.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2022-06-14",
                    "knownRansomwareCampaignUse": "Unknown",
                },
                {
                    "cveID": "CVE-2023-34362",
                    "vendorProject": "Progress",
                    "product": "MOVEit Transfer",
                    "vulnerabilityName": "MOVEit Transfer SQL Injection Vulnerability",
                    "dateAdded": "2023-06-02",
                    "shortDescription": "Progress MOVEit Transfer SQL injection.",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "dueDate": "2023-06-23",
                    "knownRansomwareCampaignUse": "Known",
                },
            ],
        }
        return self._parse_payload(mock_payload)

    # ------------------------------------------------------------------
    # Policy: severity escalation
    # ------------------------------------------------------------------

    def escalate_severity(self, findings: list) -> list:
        """Bump severity to CRITICAL for any finding whose CVE is in the KEV.

        Checks the *local* SQLite cache (no network call).  Call
        :meth:`store_kev_entries` first to populate the cache.

        Parameters
        ----------
        findings:
            List of :class:`~depfence.core.models.Finding` objects.
            Findings are mutated in-place and the same list is returned.

        Returns
        -------
        list
            Same list as *findings*, with severities possibly elevated.
        """
        from depfence.core.models import Severity

        kev_cves = set(self.all_cves())
        for finding in findings:
            if getattr(finding, "cve", None) and finding.cve in kev_cves:
                finding.severity = Severity.CRITICAL
                finding.metadata["kev_escalated"] = True
        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> KEVEntry:
        return KEVEntry(
            cve=row["cve"],
            vendor=row["vendor"],
            product=row["product"],
            date_added=row["date_added"],
            due_date=row["due_date"],
            known_ransomware=bool(row["known_ransomware"]),
            description=row["description"],
            required_action=row["required_action"],
        )

    @staticmethod
    def _parse_payload(payload: dict) -> list[KEVEntry]:
        entries: list[KEVEntry] = []
        for raw in payload.get("vulnerabilities") or []:
            cve = raw.get("cveID", "")
            if not cve:
                continue
            ransomware_raw = raw.get("knownRansomwareCampaignUse", "")
            known_ransomware = (
                isinstance(ransomware_raw, str)
                and ransomware_raw.strip().lower() == "known"
            )
            entries.append(
                KEVEntry(
                    cve=cve,
                    vendor=raw.get("vendorProject", ""),
                    product=raw.get("product", ""),
                    date_added=raw.get("dateAdded", ""),
                    due_date=raw.get("dueDate", ""),
                    known_ransomware=known_ransomware,
                    description=raw.get("shortDescription", ""),
                    required_action=raw.get("requiredAction", ""),
                )
            )
        return entries
