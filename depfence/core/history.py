"""Scan history — persist and compare scan states over time using SQLite."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import PackageId, ScanResult

_DEFAULT_DB_DIR = Path.home() / ".depfence" / "cache"
_DB_NAME = "scan_history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_hash TEXT NOT NULL,
    project_path TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    ecosystem TEXT,
    packages_json TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    packages_scanned INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snapshots_project ON scan_snapshots (project_hash, scanned_at);
"""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ScanSnapshot:
    """A point-in-time record of a scan."""
    id: int
    project_hash: str
    project_path: str
    scanned_at: datetime
    ecosystem: str
    packages: list[PackageId]
    findings_summary: list[dict]  # lightweight: {type, severity, package}
    finding_count: int
    critical_count: int
    high_count: int
    packages_scanned: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_path": self.project_path,
            "scanned_at": self.scanned_at.isoformat(),
            "ecosystem": self.ecosystem,
            "finding_count": self.finding_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "packages_scanned": self.packages_scanned,
        }


@dataclass
class ScanDelta:
    """Changes between two scan snapshots."""
    old_snapshot_id: int
    new_snapshot_id: int
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    new_packages: list[PackageId] = field(default_factory=list)
    removed_packages: list[PackageId] = field(default_factory=list)
    version_changes: list[dict] = field(default_factory=list)  # {name, old, new}

    @property
    def is_clean(self) -> bool:
        return (
            not self.new_findings
            and not self.new_packages
            and not self.removed_packages
            and not self.version_changes
        )

    @property
    def regression(self) -> bool:
        """True if new critical/high findings appeared."""
        return any(
            f.get("severity") in ("critical", "high") for f in self.new_findings
        )

    def to_dict(self) -> dict:
        return {
            "old_snapshot_id": self.old_snapshot_id,
            "new_snapshot_id": self.new_snapshot_id,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "new_packages": [str(p) for p in self.new_packages],
            "removed_packages": [str(p) for p in self.removed_packages],
            "version_changes": self.version_changes,
            "is_clean": self.is_clean,
            "regression": self.regression,
        }

    def render_table(self) -> str:
        lines: list[str] = []
        if self.is_clean:
            return "  No changes since last scan."

        if self.new_packages:
            lines.append(f"  + {len(self.new_packages)} new package(s):")
            for p in self.new_packages:
                lines.append(f"    \033[32m+ {p}\033[0m")

        if self.removed_packages:
            lines.append(f"  - {len(self.removed_packages)} removed package(s):")
            for p in self.removed_packages:
                lines.append(f"    \033[31m- {p}\033[0m")

        if self.version_changes:
            lines.append(f"  ~ {len(self.version_changes)} version change(s):")
            for vc in self.version_changes:
                lines.append(f"    \033[33m~ {vc['ecosystem']}:{vc['name']} {vc['old']} -> {vc['new']}\033[0m")

        if self.new_findings:
            lines.append(f"  ! {len(self.new_findings)} new finding(s):")
            for f in self.new_findings:
                sev = f.get("severity", "?").upper()
                pkg = f.get("package", "?")
                ftype = f.get("finding_type", "?")
                lines.append(f"    \033[31m! [{sev}] {pkg} — {ftype}\033[0m")

        if self.resolved_findings:
            lines.append(f"  v {len(self.resolved_findings)} resolved finding(s):")
            for f in self.resolved_findings:
                sev = f.get("severity", "?").upper()
                pkg = f.get("package", "?")
                ftype = f.get("finding_type", "?")
                lines.append(f"    \033[32mv [{sev}] {pkg} — {ftype}\033[0m")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _project_hash(project_path: str) -> str:
    return hashlib.sha256(str(Path(project_path).resolve()).encode()).hexdigest()[:16]


def _pkg_to_dict(pkg: PackageId) -> dict:
    return {"ecosystem": pkg.ecosystem, "name": pkg.name, "version": pkg.version}


def _dict_to_pkg(d: dict) -> PackageId:
    return PackageId(d["ecosystem"], d["name"], d.get("version"))


def _finding_key(f: dict) -> str:
    return f"{f.get('finding_type','?')}:{f.get('package','?')}"


# ---------------------------------------------------------------------------
# ScanHistory
# ---------------------------------------------------------------------------

class ScanHistory:
    """Persists scan state to SQLite and enables time-series diffing."""

    def __init__(self, db_dir: Path | None = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._db_dir / _DB_NAME
        self._init_db()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record_scan(
        self,
        result: ScanResult,
        packages: list[PackageId] | None = None,
        project_path: str | None = None,
    ) -> int:
        """Save a scan result and return the new snapshot id."""
        path = project_path or result.target or "."
        proj_hash = _project_hash(path)
        scanned_at = (result.completed_at or datetime.now(timezone.utc)).isoformat()

        pkgs = packages or []
        packages_json = json.dumps([_pkg_to_dict(p) for p in pkgs])

        findings_summary = [
            {
                "finding_type": f.finding_type.value,
                "severity": f.severity.value,
                "package": str(f.package),
            }
            for f in result.findings
        ]
        findings_json = json.dumps(findings_summary)

        critical = sum(1 for f in result.findings if f.severity.value == "critical")
        high = sum(1 for f in result.findings if f.severity.value == "high")

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_snapshots
                    (project_hash, project_path, scanned_at, ecosystem,
                     packages_json, findings_json, finding_count,
                     critical_count, high_count, packages_scanned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proj_hash,
                    str(Path(path).resolve()),
                    scanned_at,
                    result.ecosystem,
                    packages_json,
                    findings_json,
                    len(result.findings),
                    critical,
                    high,
                    result.packages_scanned or len(pkgs),
                ),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_last(self, project_path: str = ".", n: int = 5) -> list[ScanSnapshot]:
        """Return the n most recent scan snapshots for this project."""
        proj_hash = _project_hash(project_path)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM scan_snapshots
                WHERE project_hash = ?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (proj_hash, n),
            ).fetchall()

        snapshots = []
        for row in rows:
            pkgs = [_dict_to_pkg(d) for d in json.loads(row["packages_json"])]
            findings = json.loads(row["findings_json"])
            ts = datetime.fromisoformat(row["scanned_at"])
            snapshots.append(
                ScanSnapshot(
                    id=row["id"],
                    project_hash=row["project_hash"],
                    project_path=row["project_path"],
                    scanned_at=ts,
                    ecosystem=row["ecosystem"] or "",
                    packages=pkgs,
                    findings_summary=findings,
                    finding_count=row["finding_count"],
                    critical_count=row["critical_count"],
                    high_count=row["high_count"],
                    packages_scanned=row["packages_scanned"],
                )
            )
        return snapshots

    def get_snapshot_by_id(self, snapshot_id: int) -> ScanSnapshot | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        if row is None:
            return None
        pkgs = [_dict_to_pkg(d) for d in json.loads(row["packages_json"])]
        findings = json.loads(row["findings_json"])
        ts = datetime.fromisoformat(row["scanned_at"])
        return ScanSnapshot(
            id=row["id"],
            project_hash=row["project_hash"],
            project_path=row["project_path"],
            scanned_at=ts,
            ecosystem=row["ecosystem"] or "",
            packages=pkgs,
            findings_summary=findings,
            finding_count=row["finding_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            packages_scanned=row["packages_scanned"],
        )

    def get_all(self, project_path: str = ".") -> list[ScanSnapshot]:
        """Return all snapshots for a project, newest first."""
        proj_hash = _project_hash(project_path)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM scan_snapshots
                WHERE project_hash = ?
                ORDER BY scanned_at DESC
                """,
                (proj_hash,),
            ).fetchall()
        snapshots = []
        for row in rows:
            pkgs = [_dict_to_pkg(d) for d in json.loads(row["packages_json"])]
            findings = json.loads(row["findings_json"])
            ts = datetime.fromisoformat(row["scanned_at"])
            snapshots.append(
                ScanSnapshot(
                    id=row["id"],
                    project_hash=row["project_hash"],
                    project_path=row["project_path"],
                    scanned_at=ts,
                    ecosystem=row["ecosystem"] or "",
                    packages=pkgs,
                    findings_summary=findings,
                    finding_count=row["finding_count"],
                    critical_count=row["critical_count"],
                    high_count=row["high_count"],
                    packages_scanned=row["packages_scanned"],
                )
            )
        return snapshots

    def delete_project_history(self, project_path: str = ".") -> int:
        """Delete all snapshots for a project. Returns rows deleted."""
        proj_hash = _project_hash(project_path)
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM scan_snapshots WHERE project_hash = ?", (proj_hash,)
            )
            return cursor.rowcount

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------

    def compare(self, old: ScanSnapshot, new: ScanSnapshot) -> ScanDelta:
        """Compute what changed between two scan snapshots."""
        old_pkgs = {(p.ecosystem, p.name): p for p in old.packages}
        new_pkgs = {(p.ecosystem, p.name): p for p in new.packages}

        new_packages: list[PackageId] = []
        removed_packages: list[PackageId] = []
        version_changes: list[dict] = []

        for key, pkg in new_pkgs.items():
            if key not in old_pkgs:
                new_packages.append(pkg)
            elif old_pkgs[key].version != pkg.version:
                version_changes.append(
                    {
                        "ecosystem": pkg.ecosystem,
                        "name": pkg.name,
                        "old": old_pkgs[key].version,
                        "new": pkg.version,
                    }
                )

        for key, pkg in old_pkgs.items():
            if key not in new_pkgs:
                removed_packages.append(pkg)

        old_finding_keys = {_finding_key(f) for f in old.findings_summary}
        new_finding_keys = {_finding_key(f) for f in new.findings_summary}

        new_findings = [
            f for f in new.findings_summary if _finding_key(f) not in old_finding_keys
        ]
        resolved_findings = [
            f for f in old.findings_summary if _finding_key(f) not in new_finding_keys
        ]

        return ScanDelta(
            old_snapshot_id=old.id,
            new_snapshot_id=new.id,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            new_packages=new_packages,
            removed_packages=removed_packages,
            version_changes=version_changes,
        )

    def compare_last_two(self, project_path: str = ".") -> ScanDelta | None:
        """Compare the two most recent scans. Returns None if fewer than 2 scans."""
        snapshots = self.get_last(project_path, n=2)
        if len(snapshots) < 2:
            return None
        # snapshots[0] is newest, snapshots[1] is older
        return self.compare(old=snapshots[1], new=snapshots[0])
