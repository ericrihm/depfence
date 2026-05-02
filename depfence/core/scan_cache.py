"""Scan cache — persists lockfile state to enable diff scanning."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import PackageId

_DEFAULT_CACHE_DIR = Path.home() / ".depfence" / "cache"
_DB_NAME = "scan_cache.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
    project_hash TEXT PRIMARY KEY,
    project_path TEXT,
    lockfile_hash TEXT,
    packages_json TEXT,
    scanned_at TEXT
)
"""


def _pkg_to_dict(pkg: PackageId) -> dict:
    return {"ecosystem": pkg.ecosystem, "name": pkg.name, "version": pkg.version}


def _dict_to_pkg(d: dict) -> PackageId:
    return PackageId(d["ecosystem"], d["name"], d.get("version"))


class ScanCache:
    """Caches lockfile state to enable diff scanning."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._cache_dir / _DB_NAME
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    @staticmethod
    def _project_hash(project_dir: Path) -> str:
        return hashlib.sha256(str(project_dir.resolve()).encode()).hexdigest()[:16]

    @staticmethod
    def _lockfile_hash(project_dir: Path) -> str:
        from depfence.core.lockfile import detect_ecosystem

        lockfiles = detect_ecosystem(project_dir)
        h = hashlib.sha256()
        for _, lf in sorted(lockfiles, key=lambda x: str(x[1])):
            try:
                h.update(lf.read_bytes())
            except OSError:
                pass
        return h.hexdigest()

    def get_cached_packages(self, project_dir: Path) -> set[str] | None:
        """Return the previously cached package key set, or None if no cache exists."""
        project_hash = self._project_hash(project_dir)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT packages_json FROM scan_cache WHERE project_hash = ?",
                (project_hash,),
            ).fetchone()
        if row is None:
            return None
        packages = json.loads(row["packages_json"])
        return {f"{p['ecosystem']}:{p['name']}@{p['version']}" for p in packages}

    def save_scan(self, project_dir: Path, packages: list[PackageId]) -> None:
        """Persist the current package list after a successful scan."""
        project_hash = self._project_hash(project_dir)
        lockfile_hash = self._lockfile_hash(project_dir)
        packages_json = json.dumps([_pkg_to_dict(p) for p in packages])
        scanned_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_cache (project_hash, project_path, lockfile_hash, packages_json, scanned_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project_hash) DO UPDATE SET
                    lockfile_hash = excluded.lockfile_hash,
                    packages_json = excluded.packages_json,
                    scanned_at = excluded.scanned_at
                """,
                (project_hash, str(project_dir.resolve()), lockfile_hash, packages_json, scanned_at),
            )

    def get_diff(self, project_dir: Path, current_packages: list[PackageId]) -> dict:
        """Return {added: [...], removed: [...], updated: [...]} against cached state."""
        project_hash = self._project_hash(project_dir)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT packages_json FROM scan_cache WHERE project_hash = ?",
                (project_hash,),
            ).fetchone()

        if row is None:
            return {"added": list(current_packages), "removed": [], "updated": []}

        cached = [_dict_to_pkg(d) for d in json.loads(row["packages_json"])]

        cached_by_key = {(p.ecosystem, p.name): p for p in cached}
        current_by_key = {(p.ecosystem, p.name): p for p in current_packages}

        added = []
        updated = []
        for key, pkg in current_by_key.items():
            if key not in cached_by_key:
                added.append(pkg)
            elif cached_by_key[key].version != pkg.version:
                updated.append(pkg)

        removed = [p for key, p in cached_by_key.items() if key not in current_by_key]

        return {"added": added, "removed": removed, "updated": updated}
