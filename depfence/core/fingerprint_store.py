"""Private observed-versus-approved fingerprints for local trust decisions."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from depfence.core.local_state import PrivateState, PrivateStateError

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_SNAPSHOT_BYTES = 256 * 1024


class FingerprintStoreError(RuntimeError):
    """Fingerprint state could not be used without weakening its trust boundary."""


@dataclass(frozen=True)
class FingerprintStatus:
    kind: str
    project_id: str
    subject_id: str
    observed_digest: str
    approved_digest: str | None
    previous_observed_digest: str | None

    @property
    def state(self) -> str:
        if self.approved_digest is None:
            return "UNAPPROVED"
        if self.approved_digest == self.observed_digest:
            return "APPROVED"
        return "DRIFT"


class FingerprintStore:
    """Persist observations without ever turning them into implicit approval."""

    def __init__(self, state: PrivateState, database: Path) -> None:
        self._state = state
        self._database = database
        try:
            self._prepare_database()
        except FingerprintStoreError:
            raise
        except (OSError, sqlite3.Error, PrivateStateError) as exc:
            raise FingerprintStoreError(
                f"cannot initialize fingerprint state: {exc}"
            ) from exc

    @classmethod
    def open(
        cls,
        *,
        project_root: Path | str,
        private_root: Path | str | None = None,
        database_path: Path | str | None = None,
    ) -> FingerprintStore:
        try:
            state = PrivateState.open(project_root=project_root, root=private_root)
        except PrivateStateError as exc:
            raise FingerprintStoreError(
                f"cannot open private fingerprint state: {exc}"
            ) from exc
        if database_path is None:
            database = state.path("fingerprints/fingerprints.sqlite3")
        else:
            requested = Path(database_path).expanduser()
            if not requested.is_absolute():
                requested = Path.cwd() / requested
            if requested.is_symlink():
                raise FingerprintStoreError(f"fingerprint database is a symlink: {requested}")
            database = requested.resolve(strict=False)
            try:
                relative = database.relative_to(state.root)
            except ValueError as exc:
                raise FingerprintStoreError(
                    "explicit fingerprint database must remain inside PrivateState"
                ) from exc
            try:
                database = state.path(relative)
            except PrivateStateError as exc:
                raise FingerprintStoreError(
                    f"explicit fingerprint database is unsafe: {exc}"
                ) from exc
        return cls(state, database)

    def project_id(self, project_root: Path | str) -> str:
        return cast(str, self._state.project_id(project_root))

    def subject_id(self, *, kind: str, source: str, name: str) -> str:
        return cast(
            str, self._state.opaque_id("fingerprint", f"{kind}\0{source}\0{name}")
        )

    def _prepare_database(self) -> None:
        if self._database.is_symlink():
            raise FingerprintStoreError(f"fingerprint database is a symlink: {self._database}")
        self._database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._database.parent, 0o700)
        if not self._database.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self._database, flags, 0o600)
            except FileExistsError:
                if self._database.is_symlink():
                    raise FingerprintStoreError(
                        f"fingerprint database is a symlink: {self._database}"
                    ) from None
            else:
                os.close(descriptor)
        os.chmod(self._database, 0o600)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fingerprint_state (
                    kind TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    observed_digest TEXT NOT NULL,
                    approved_digest TEXT,
                    schema_snapshot TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    approved_at TEXT,
                    PRIMARY KEY (kind, project_id, subject_id)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        if self._database.is_symlink():
            raise FingerprintStoreError(f"fingerprint database is a symlink: {self._database}")
        connection = sqlite3.connect(str(self._database), timeout=5)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA secure_delete=ON")
        except BaseException:
            connection.close()
            raise
        return connection

    def observe(
        self,
        *,
        kind: str,
        project_id: str,
        subject_id: str,
        digest: str,
        snapshot: dict[str, Any],
    ) -> FingerprintStatus:
        normalized = digest.lower()
        if not _DIGEST_RE.fullmatch(normalized):
            raise FingerprintStoreError("fingerprint digest must be a SHA-256 hex value")
        try:
            snapshot_json = json.dumps(
                snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise FingerprintStoreError(
                f"cannot record fingerprint snapshot: {exc}"
            ) from exc
        if len(snapshot_json.encode()) > _MAX_SNAPSHOT_BYTES:
            raise FingerprintStoreError("fingerprint schema snapshot exceeds the size limit")
        now = datetime.now(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    """
                    SELECT observed_digest, approved_digest
                    FROM fingerprint_state
                    WHERE kind = ? AND project_id = ? AND subject_id = ?
                    """,
                    (kind, project_id, subject_id),
                ).fetchone()
                previous = str(row[0]) if row else None
                approved = str(row[1]) if row and row[1] is not None else None
                connection.execute(
                    """
                    INSERT INTO fingerprint_state (
                        kind, project_id, subject_id, observed_digest, approved_digest,
                        schema_snapshot, first_seen, last_seen, approved_at
                    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, NULL)
                    ON CONFLICT(kind, project_id, subject_id) DO UPDATE SET
                        observed_digest = excluded.observed_digest,
                        schema_snapshot = excluded.schema_snapshot,
                        last_seen = excluded.last_seen
                    """,
                    (kind, project_id, subject_id, normalized, snapshot_json, now, now),
                )
        except (OSError, sqlite3.Error, TypeError, ValueError, PrivateStateError) as exc:
            raise FingerprintStoreError(f"cannot record fingerprint observation: {exc}") from exc
        return FingerprintStatus(
            kind, project_id, subject_id, normalized, approved, previous
        )

    def approve(
        self,
        *,
        kind: str,
        project_id: str,
        subject_id: str,
        digest: str,
    ) -> FingerprintStatus:
        normalized = digest.lower()
        if not _DIGEST_RE.fullmatch(normalized):
            raise FingerprintStoreError("approval digest must be a SHA-256 hex value")
        now = datetime.now(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    """
                    SELECT observed_digest, approved_digest
                    FROM fingerprint_state
                    WHERE kind = ? AND project_id = ? AND subject_id = ?
                    """,
                    (kind, project_id, subject_id),
                ).fetchone()
                if row is None:
                    raise FingerprintStoreError(
                        "cannot approve an identity with no observation"
                    )
                observed = str(row[0])
                previous_approved = str(row[1]) if row[1] is not None else None
                if observed != normalized:
                    raise FingerprintStoreError(
                        "approval digest does not match the latest observed fingerprint"
                    )
                connection.execute(
                    """
                    UPDATE fingerprint_state
                    SET approved_digest = ?, approved_at = ?
                    WHERE kind = ? AND project_id = ? AND subject_id = ?
                    """,
                    (normalized, now, kind, project_id, subject_id),
                )
        except FingerprintStoreError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError, PrivateStateError) as exc:
            raise FingerprintStoreError(f"cannot approve fingerprint: {exc}") from exc
        return FingerprintStatus(
            kind, project_id, subject_id, observed, normalized, previous_approved
        )

    def statuses(self, *, kind: str, project_id: str) -> list[FingerprintStatus]:
        try:
            with closing(self._connect()) as connection, connection:
                rows = connection.execute(
                    """
                    SELECT subject_id, observed_digest, approved_digest
                    FROM fingerprint_state
                    WHERE kind = ? AND project_id = ?
                    ORDER BY subject_id
                    """,
                    (kind, project_id),
                ).fetchall()
        except (OSError, sqlite3.Error, TypeError, ValueError, PrivateStateError) as exc:
            raise FingerprintStoreError(f"cannot read fingerprints: {exc}") from exc
        return [
            FingerprintStatus(
                kind,
                project_id,
                str(subject),
                str(observed),
                str(approved) if approved is not None else None,
                None,
            )
            for subject, observed, approved in rows
        ]
