"""Private-state inspection, migration, and bounded retention.

This module deliberately separates planning from mutation.  Callers must pass
``apply=True`` before any directory, key, database, or quarantine file is
created.  Deletion is logical filesystem removal; it is never described as
secure erasure.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

from depfence.core.local_state import PrivateState, PrivateStateError

SCHEMA_VERSION = "depfence.privacy/v1"
DETAIL_DAYS = 30
SUMMARY_DAYS = 365
_MAX_SIGNAL_BYTES = 16 * 1024
_PATH_KEYS = {"file", "filename", "path", "project", "project_path", "repository", "root"}
_SECRET_FRAGMENTS = ("secret", "token", "password", "credential", "api_key", "private_key")


def state_project_boundary(start: Path | None = None) -> Path:
    """Return the enclosing Git worktree, or a non-enclosing sentinel."""
    current = (start or Path.cwd()).expanduser().resolve(strict=False)
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current / ".depfence-no-worktree"


@dataclass(frozen=True)
class PrivacyLayout:
    """Locations participating in the legacy-to-private-state boundary."""

    legacy_root: Path
    private_root: Path
    project_root: Path

    @classmethod
    def default(cls, *, state_root: Path | None = None) -> PrivacyLayout:
        root = (state_root or (Path.home() / ".depfence")).expanduser()
        return cls(root, root / "private" / "v1", state_project_boundary())

    @property
    def artifacts(self) -> tuple[tuple[str, Path, str], ...]:
        return (
            ("legacy_signals", self.legacy_root / "signals" / "pending.jsonl", "signals/pending.jsonl"),
            ("scan_cache", self.legacy_root / "cache" / "scan_cache.db", "cache/scan_cache.db"),
            ("scan_history", self.legacy_root / "cache" / "scan_history.db", "cache/scan_history.db"),
        )


@dataclass(frozen=True)
class PrivacyError:
    code: str
    artifact: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "artifact": self.artifact, "detail": self.detail}


@dataclass(frozen=True)
class PrivacyAction:
    artifact: str
    action: str
    records: int = 0

    def to_dict(self) -> dict[str, str | int]:
        return {"artifact": self.artifact, "action": self.action, "records": self.records}


@dataclass
class PrivacyReport:
    operation: str
    apply: bool
    status: str = "PASS"
    actions: list[PrivacyAction] = field(default_factory=list)
    errors: list[PrivacyError] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 2 if self.status == "INDETERMINATE" else 0

    def add_error(self, code: str, artifact: str, detail: str) -> None:
        self.errors.append(PrivacyError(code, artifact, detail))
        self.status = "INDETERMINATE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": self.operation,
            "mode": "apply" if self.apply else "dry-run",
            "status": self.status,
            "secure_erasure": False,
            "retention": {"detailed_days": DETAIL_DAYS, "summary_days": SUMMARY_DAYS},
            "actions": [action.to_dict() for action in self.actions],
            "errors": [error.to_dict() for error in self.errors],
        }

    def render(self, output_format: str) -> str:
        if output_format == "json":
            return json.dumps(self.to_dict(), sort_keys=True)
        mode = "APPLY" if self.apply else "DRY RUN"
        lines = [f"Privacy {self.operation}: {self.status} ({mode})"]
        lines.extend(
            f"  {action.artifact}: {action.action} ({action.records} record(s))"
            for action in self.actions
        )
        lines.extend(
            f"  {error.artifact}: {error.code} — {error.detail}"
            for error in self.errors
        )
        lines.append("Retention: 30 days detailed; 365 days summary.")
        lines.append("Removal is logical only; secure erasure is not claimed.")
        return "\n".join(lines)


def _has_symlink_component(path: Path) -> bool:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
    return False


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _is_opaque_project_id(value: object) -> bool:
    text = str(value)
    for prefix in ("project-hmac-sha256:", "project-sha256:"):
        if text.startswith(prefix):
            digest = text.removeprefix(prefix)
            return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)
    return False


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ValueError("timestamp is not finite")
        return datetime.fromtimestamp(float(value), timezone.utc)
    if not isinstance(value, str):
        raise ValueError("timestamp is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for line_number, raw in enumerate(handle, 1):
            if len(raw) > _MAX_SIGNAL_BYTES:
                raise ValueError(f"record {line_number} exceeds the size limit")
            if not raw.strip():
                continue
            record = json.loads(raw)
            if not isinstance(record, dict):
                raise ValueError(f"record {line_number} is not an object")
            records.append(record)
    return records


def _safe_text(value: object, *, maximum: int = 256) -> str:
    text = str(value)
    return "".join(character for character in text if character.isprintable())[:maximum]


def _redact_value(value: object, state: PrivateState, *, key: str = "", depth: int = 0) -> Any:
    if depth > 5:
        return "[TRUNCATED]"
    lower = key.lower()
    if any(fragment in lower for fragment in _SECRET_FRAGMENTS):
        return "[REDACTED]"
    if (lower in _PATH_KEYS or lower.endswith(("_path", "_file", "_root"))) and isinstance(value, (str, Path)):
        return state.opaque_id("path", str(value))
    if isinstance(value, dict):
        return {
            _safe_text(child_key, maximum=64): _redact_value(child, state, key=str(child_key), depth=depth + 1)
            for child_key, child in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_redact_value(child, state, key=key, depth=depth + 1) for child in value[:100]]
    if isinstance(value, str):
        # Historical secrets-leak signals embedded a detector label followed by
        # a masked or partial token hint.  The label is useful; the hint is not.
        if key == "finding" and ":" in value:
            return _safe_text(value.split(":", 1)[0], maximum=128)
        return _safe_text(value, maximum=1024)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[INVALID_NUMBER]"
    return _safe_text(value)


def _normalise_signal(record: dict[str, Any], state: PrivateState) -> dict[str, Any]:
    timestamp = _parse_timestamp(record.get("timestamp"))
    name = _safe_text(record.get("name", "unknown"), maximum=128) or "unknown"
    source = _safe_text(record.get("source", "unknown"), maximum=128) or "unknown"
    value = record.get("value", {})
    if not isinstance(value, dict):
        value = {"value": value}
    return {
        "schema": "depfence.signal/v1",
        "name": name,
        "source": source,
        "timestamp": timestamp.timestamp(),
        "value": _redact_value(value, state),
    }


def _validate_sqlite(path: Path, table: str) -> int:
    uri = f"file:{path}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise ValueError("database integrity check failed")
        found = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if found is None:
            raise ValueError("expected database table is missing")
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _state(layout: PrivacyLayout) -> PrivateState:
    return PrivateState.open(project_root=layout.project_root, root=layout.private_root)


class PrivacyManager:
    """Plan and apply private-state lifecycle operations."""

    def __init__(self, layout: PrivacyLayout, *, now: datetime | None = None) -> None:
        self.layout = layout
        current = now or datetime.now(timezone.utc)
        self.now = current if current.tzinfo else current.replace(tzinfo=timezone.utc)

    def _validate_boundary(self, report: PrivacyReport) -> bool:
        paths = [
            ("legacy_state", self.layout.legacy_root),
            ("private_state", self.layout.private_root),
            *((label, source) for label, source, _ in self.layout.artifacts),
        ]
        for label, path in paths:
            if _has_symlink_component(path):
                report.add_error("SYMLINK_REFUSED", label, "a state path contains a symbolic link")
        if self.layout.private_root.exists():
            try:
                for path in self.layout.private_root.rglob("*"):
                    if path.is_symlink():
                        report.add_error(
                            "SYMLINK_REFUSED",
                            "private_state",
                            "private state contains a symbolic link",
                        )
                        break
            except OSError:
                report.add_error(
                    "PRIVATE_STATE_UNREADABLE",
                    "private_state",
                    "private state could not be inspected",
                )
        try:
            private = self.layout.private_root.expanduser().resolve(strict=False)
            project = self.layout.project_root.expanduser().resolve(strict=False)
            private.relative_to(project)
        except ValueError:
            pass
        else:
            report.add_error("WORKTREE_STATE_REFUSED", "private_state", "private state must be outside the project worktree")
        return not report.errors

    def status(self) -> PrivacyReport:
        report = PrivacyReport("status", apply=False)
        if not self._validate_boundary(report):
            return report
        changes = False
        for label, source, destination_relative in self.layout.artifacts:
            destination = self.layout.private_root / destination_relative
            if source.exists():
                try:
                    if label == "legacy_signals":
                        count = len(_read_jsonl(source))
                    else:
                        table = "scan_cache" if label == "scan_cache" else "scan_snapshots"
                        count = _validate_sqlite(source, table)
                except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error):
                    report.add_error(
                        "LEGACY_DATA_INVALID",
                        label,
                        "legacy data could not be validated",
                    )
                    continue
                report.actions.append(PrivacyAction(label, "legacy_data_present", count))
                changes = True
            if destination.exists() and _mode(destination) != 0o600:
                report.actions.append(PrivacyAction(label, "private_file_mode_requires_0600"))
                changes = True
        if self.layout.private_root.exists() and _mode(self.layout.private_root) != 0o700:
            report.actions.append(PrivacyAction("private_state", "directory_mode_requires_0700"))
            changes = True
        if self.layout.private_root.exists():
            private_mode_issue = any(
                (_mode(path) != (0o700 if path.is_dir() else 0o600))
                for path in self.layout.private_root.rglob("*")
                if not path.is_symlink()
            )
            if private_mode_issue:
                report.actions.append(PrivacyAction("private_state", "nested_modes_require_repair"))
                changes = True
        if not report.errors:
            report.status = "CHANGES_REQUIRED" if changes else "PASS"
        return report

    def migrate(self, *, apply: bool = False) -> PrivacyReport:
        report = PrivacyReport("migrate", apply=apply)
        if not self._validate_boundary(report):
            return report

        prepared: list[tuple[str, Path, str, int, str]] = []
        for label, source, destination in self.layout.artifacts:
            if not source.exists():
                continue
            if not source.is_file():
                report.add_error("LEGACY_TYPE_UNSUPPORTED", label, "legacy state is not a regular file")
                continue
            if label != "legacy_signals" and any(
                Path(f"{source}{suffix}").exists() for suffix in ("-wal", "-shm")
            ):
                report.add_error(
                    "SQLITE_SIDECAR_PRESENT",
                    label,
                    "database has live sidecars; close writers before migration",
                )
                continue
            try:
                if label == "legacy_signals":
                    records = _read_jsonl(source)
                    for record in records:
                        _parse_timestamp(record.get("timestamp"))
                    count = len(records)
                else:
                    table = "scan_cache" if label == "scan_cache" else "scan_snapshots"
                    count = _validate_sqlite(source, table)
            except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error):
                report.add_error("LEGACY_DATA_INVALID", label, "legacy data could not be validated")
                continue
            destination_path = self.layout.private_root / destination
            action = "migrate"
            if destination_path.exists():
                try:
                    added = self._validate_merge(label, source, destination_path)
                except PrivateStateError:
                    report.add_error(
                        "PRIVATE_KEY_UNAVAILABLE",
                        label,
                        "existing private data cannot be matched without its valid install key",
                    )
                    continue
                except FileExistsError:
                    report.add_error(
                        "MERGE_CONFLICT",
                        label,
                        "legacy and private records share an identity but differ",
                    )
                    continue
                except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error):
                    report.add_error(
                        "PRIVATE_DATA_INVALID",
                        label,
                        "existing private data could not be validated for a lossless merge",
                    )
                    continue
                count = added
                action = "merge"
            prepared.append((label, source, destination, count, action))

        if report.errors:
            return report
        if not prepared:
            report.actions.append(PrivacyAction("private_state", "no_legacy_data"))
            return report
        if not apply:
            report.status = "CHANGES_REQUIRED"
            report.actions.extend(
                PrivacyAction(label, "would_migrate_and_quarantine", count)
                if action == "migrate"
                else PrivacyAction(label, "would_merge_and_quarantine", count)
                for label, _, _, count, action in prepared
            )
            return report

        try:
            state = _state(self.layout)
        except (OSError, PrivateStateError):
            report.add_error("PRIVATE_STATE_UNAVAILABLE", "private_state", "private state could not be opened safely")
            return report

        for label, source, destination, count, action in prepared:
            try:
                quarantined = self._quarantine(state, source, label)
                if label == "legacy_signals":
                    records = [_normalise_signal(record, state) for record in _read_jsonl(quarantined)]
                    target = state.path(destination)
                    existing = _read_jsonl(target) if target.exists() else []
                    combined = {
                        json.dumps(record, sort_keys=True): record
                        for record in [*existing, *records]
                    }
                    payload = "".join(key + "\n" for key in sorted(combined))
                    state.write_text(destination, payload)
                else:
                    self._migrate_database(
                        state,
                        quarantined,
                        destination,
                        merge=action == "merge",
                    )
                completed = "merged_and_quarantined" if action == "merge" else "migrated_and_quarantined"
                report.actions.append(PrivacyAction(label, completed, count))
            except (OSError, ValueError, PrivateStateError, sqlite3.Error):
                report.add_error("MIGRATION_INCOMPLETE", label, "migration could not be completed atomically")
        if not report.errors:
            self._enforce_modes(state)
            report.status = "UPDATED"
        return report

    def _existing_state(self) -> PrivateState:
        root = self.layout.private_root
        key = root / "install.key"
        if (
            not root.is_dir()
            or key.is_symlink()
            or not key.is_file()
            or _mode(key) != 0o600
            or len(key.read_bytes()) != 32
        ):
            raise PrivateStateError("existing private state has no valid install key")
        return PrivateState(root.resolve())

    def _validate_merge(self, label: str, source: Path, destination: Path) -> int:
        if not destination.is_file() or destination.is_symlink():
            raise ValueError("private destination is not a regular file")
        if label != "legacy_signals" and any(
            Path(f"{destination}{suffix}").exists() for suffix in ("-wal", "-shm")
        ):
            raise ValueError("private database has live sidecars")
        state = self._existing_state()
        if label == "legacy_signals":
            existing = _read_jsonl(destination)
            for record in existing:
                timestamp = record.get("timestamp")
                if (
                    not isinstance(timestamp, (int, float))
                    or isinstance(timestamp, bool)
                    or not math.isfinite(float(timestamp))
                ):
                    raise ValueError("private signal timestamp is not a finite epoch number")
                _parse_timestamp(timestamp)
                normalized = _normalise_signal(record, state)
                # SignalBus uses time.time(), whose fractional precision can
                # exceed datetime's microsecond resolution.  Compare the
                # redaction-bearing fields exactly while preserving a valid
                # numeric v1 timestamp without a lossy round trip.
                comparable = {key: value for key, value in record.items() if key != "timestamp"}
                normalized_comparable = {
                    key: value for key, value in normalized.items() if key != "timestamp"
                }
                if comparable != normalized_comparable:
                    raise ValueError("private signal is not normalized and redacted")
            existing_keys = {json.dumps(record, sort_keys=True) for record in existing}
            incoming_keys = {
                json.dumps(_normalise_signal(record, state), sort_keys=True)
                for record in _read_jsonl(source)
            }
            return len(incoming_keys - existing_keys)

        table = "scan_cache" if label == "scan_cache" else "scan_snapshots"
        _validate_sqlite(destination, table)
        incoming = self._database_rows(source, table, state)
        with closing(
            sqlite3.connect(f"file:{destination}?mode=ro&immutable=1", uri=True)
        ) as connection:
            if table == "scan_cache":
                existing_cache = {
                    str(row[0]): tuple(row)
                    for row in connection.execute(
                        "SELECT project_hash, project_path, lockfile_hash, packages_json, scanned_at FROM scan_cache"
                    )
                }
                if any(not _is_opaque_project_id(row[1]) for row in existing_cache.values()):
                    raise ValueError("private cache contains a cleartext project identity")
                added = 0
                for row in incoming:
                    prior = existing_cache.get(str(row[0]))
                    if prior is None:
                        added += 1
                    elif prior != row:
                        raise FileExistsError("scan-cache identity collision")
                return added
            existing_history = {
                tuple(row)
                for row in connection.execute(
                    "SELECT project_hash, project_path, scanned_at, ecosystem, packages_json, "
                    "findings_json, finding_count, critical_count, high_count, packages_scanned "
                    "FROM scan_snapshots"
                )
            }
            if any(not _is_opaque_project_id(row[1]) for row in existing_history):
                raise ValueError("private history contains a cleartext project identity")
            return sum(row not in existing_history for row in incoming)

    def _database_rows(
        self,
        source: Path,
        table: str,
        state: PrivateState,
    ) -> list[tuple[Any, ...]]:
        with closing(
            sqlite3.connect(f"file:{source}?mode=ro&immutable=1", uri=True)
        ) as connection:
            if table == "scan_cache":
                raw = connection.execute(
                    "SELECT project_hash, project_path, lockfile_hash, packages_json, scanned_at FROM scan_cache"
                ).fetchall()
            else:
                raw = connection.execute(
                    "SELECT project_hash, project_path, scanned_at, ecosystem, packages_json, "
                    "findings_json, finding_count, critical_count, high_count, packages_scanned "
                    "FROM scan_snapshots"
                ).fetchall()
        return [
            (row[0], state.opaque_id("project", str(row[1])), *row[2:])
            for row in raw
        ]

    def _migrate_database(
        self,
        state: PrivateState,
        source: Path,
        destination: str,
        *,
        merge: bool = False,
    ) -> None:
        target = state.path(destination)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        os.close(descriptor)
        temp_path = Path(temporary)
        try:
            shutil.copyfile(target if merge else source, temp_path)
            os.chmod(temp_path, 0o600)
            with closing(sqlite3.connect(temp_path)) as connection, connection:
                tables = {
                    row[0]
                    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                table = "scan_cache" if "scan_cache" in tables else "scan_snapshots"
                if merge:
                    incoming = self._database_rows(source, table, state)
                    if table == "scan_cache":
                        existing_cache = {
                            str(row[0]): tuple(row)
                            for row in connection.execute(
                                "SELECT project_hash, project_path, lockfile_hash, packages_json, scanned_at FROM scan_cache"
                            )
                        }
                        additions: list[tuple[Any, ...]] = []
                        for row in incoming:
                            prior = existing_cache.get(str(row[0]))
                            if prior is None:
                                additions.append(row)
                            elif prior != row:
                                raise FileExistsError("scan-cache identity collision")
                        connection.executemany(
                            "INSERT INTO scan_cache "
                            "(project_hash, project_path, lockfile_hash, packages_json, scanned_at) "
                            "VALUES (?, ?, ?, ?, ?)",
                            additions,
                        )
                    else:
                        existing_history = {
                            tuple(row)
                            for row in connection.execute(
                                "SELECT project_hash, project_path, scanned_at, ecosystem, packages_json, "
                                "findings_json, finding_count, critical_count, high_count, packages_scanned "
                                "FROM scan_snapshots"
                            )
                        }
                        connection.executemany(
                            "INSERT INTO scan_snapshots "
                            "(project_hash, project_path, scanned_at, ecosystem, packages_json, "
                            "findings_json, finding_count, critical_count, high_count, packages_scanned) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            [row for row in incoming if row not in existing_history],
                        )
                else:
                    rows = connection.execute(f"SELECT rowid, project_path FROM {table}").fetchall()
                    for rowid, cleartext_path in rows:
                        opaque = state.opaque_id("project", str(cleartext_path))
                        connection.execute(
                            f"UPDATE {table} SET project_path=? WHERE rowid=?", (opaque, rowid)
                        )
                connection.commit()
                check = connection.execute("PRAGMA quick_check").fetchone()
                if check is None or check[0] != "ok":
                    raise ValueError("database integrity check failed")
            os.replace(temp_path, target)
            os.chmod(target, 0o600)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _quarantine(self, state: PrivateState, source: Path, label: str) -> Path:
        suffix = f"{int(self.now.timestamp())}-{source.name}"
        target = cast(Path, state.path(Path("quarantine") / label / suffix))
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(target.parent, 0o700)
        if target.exists() or target.is_symlink():
            raise PrivateStateError("quarantine collision")
        os.replace(source, target)
        os.chmod(target, 0o600)
        return target

    def _enforce_modes(self, state: PrivateState) -> None:
        for root, directories, files in os.walk(state.root, followlinks=False):
            root_path = Path(root)
            if root_path.is_symlink():
                raise PrivateStateError("symlink in private state")
            os.chmod(root_path, 0o700)
            for directory in directories:
                path = root_path / directory
                if path.is_symlink():
                    raise PrivateStateError("symlink in private state")
                os.chmod(path, 0o700)
            for filename in files:
                path = root_path / filename
                if path.is_symlink():
                    raise PrivateStateError("symlink in private state")
                os.chmod(path, 0o600)

    def prune(self, *, apply: bool = False) -> PrivacyReport:
        report = PrivacyReport("prune", apply=apply)
        if not self._validate_boundary(report):
            return report
        if not self.layout.private_root.exists():
            report.actions.append(PrivacyAction("private_state", "no_private_data"))
            return report

        try:
            signal_plan = self._plan_signal_retention()
            database_plans = self._plan_database_retention()
            quarantine = self._plan_quarantine_retention()
            artifact_payloads = self._plan_artifact_retention()
        except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error):
            report.add_error("RETENTION_DATA_INVALID", "private_state", "retention data could not be validated")
            return report

        detailed_count, summary_count, expired_count, _, _ = signal_plan
        report.actions.append(
            PrivacyAction("private_signals", "would_retain_detail_and_summary" if not apply else "retained_detail_and_summary", detailed_count + summary_count)
        )
        affected = (
            expired_count
            + quarantine
            + len(artifact_payloads)
            + sum(plan[1] for plan in database_plans)
        )
        if not apply:
            if affected or summary_count:
                report.status = "CHANGES_REQUIRED"
            report.actions.append(PrivacyAction("private_state", "would_logically_remove", affected))
            return report

        try:
            state = _state(self.layout)
            self._apply_signal_retention(state, signal_plan)
            for path, _, rows_to_keep, summaries in database_plans:
                self._apply_database_retention(path, rows_to_keep)
                if summaries:
                    self._append_summaries(state, summaries)
            removed_quarantine = self._apply_quarantine_retention()
            removed_artifacts = self._apply_artifact_retention(state, artifact_payloads)
            self._enforce_modes(state)
            report.actions.append(PrivacyAction("private_state", "logically_removed", expired_count + removed_quarantine + removed_artifacts + sum(plan[1] for plan in database_plans)))
            report.status = "UPDATED"
        except (OSError, ValueError, PrivateStateError, sqlite3.Error):
            report.add_error("RETENTION_INCOMPLETE", "private_state", "retention could not be applied completely")
        return report

    def _plan_signal_retention(self) -> tuple[int, int, int, list[dict[str, Any]], list[dict[str, Any]]]:
        path = self.layout.private_root / "signals" / "pending.jsonl"
        if not path.exists():
            return 0, 0, 0, [], []
        detailed: list[dict[str, Any]] = []
        grouped: dict[tuple[str, str, str], int] = {}
        expired = 0
        for record in _read_jsonl(path):
            timestamp = _parse_timestamp(record.get("timestamp"))
            age = self.now - timestamp
            if age <= timedelta(days=DETAIL_DAYS):
                detailed.append(record)
            elif age <= timedelta(days=SUMMARY_DAYS):
                key = (
                    timestamp.date().isoformat(),
                    _safe_text(record.get("name", "unknown"), maximum=128),
                    _safe_text(record.get("source", "unknown"), maximum=128),
                )
                grouped[key] = grouped.get(key, 0) + 1
            else:
                expired += 1
        summaries = [
            {
                "schema_version": "depfence.privacy-summary/v1",
                "kind": "signal",
                "day": day,
                "name": name,
                "source": source,
                "count": count,
            }
            for (day, name, source), count in sorted(grouped.items())
        ]
        return len(detailed), len(summaries), expired, detailed, summaries

    def _apply_signal_retention(
        self,
        state: PrivateState,
        plan: tuple[int, int, int, list[dict[str, Any]], list[dict[str, Any]]],
    ) -> None:
        _, _, _, detailed, summaries = plan
        if (self.layout.private_root / "signals" / "pending.jsonl").exists():
            state.write_text(
                "signals/pending.jsonl",
                "".join(json.dumps(record, sort_keys=True) + "\n" for record in detailed),
            )
        if summaries:
            self._append_summaries(state, summaries)

    def _plan_database_retention(self) -> list[tuple[Path, int, set[int], list[dict[str, Any]]]]:
        plans: list[tuple[Path, int, set[int], list[dict[str, Any]]]] = []
        definitions = (
            (self.layout.private_root / "cache" / "scan_cache.db", "scan_cache"),
            (self.layout.private_root / "cache" / "scan_history.db", "scan_snapshots"),
        )
        for path, table in definitions:
            if not path.exists():
                continue
            _validate_sqlite(path, table)
            with closing(
                sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            ) as connection:
                rows = connection.execute(
                    f"SELECT rowid, project_path, scanned_at FROM {table}"
                ).fetchall()
            keep: set[int] = set()
            summaries: list[dict[str, Any]] = []
            removed = 0
            for rowid, project_id, raw_timestamp in rows:
                timestamp = _parse_timestamp(raw_timestamp)
                age = self.now - timestamp
                project_text = _safe_text(project_id, maximum=96)
                if not project_text.startswith(("project-hmac-sha256:", "project-sha256:")):
                    raise ValueError("private database contains a cleartext project identity")
                if age <= timedelta(days=DETAIL_DAYS):
                    keep.add(int(rowid))
                    continue
                removed += 1
                if age <= timedelta(days=SUMMARY_DAYS):
                    summaries.append(
                        {
                            "schema_version": "depfence.privacy-summary/v1",
                            "kind": table,
                            "day": timestamp.date().isoformat(),
                            "project_id": project_text,
                            "count": 1,
                        }
                    )
            plans.append((path, removed, keep, summaries))
        return plans

    def _apply_database_retention(self, path: Path, keep: set[int]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.close(descriptor)
        temp_path = Path(temporary)
        try:
            shutil.copyfile(path, temp_path)
            os.chmod(temp_path, 0o600)
            with closing(sqlite3.connect(temp_path)) as connection, connection:
                tables = {
                    row[0]
                    for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                table = "scan_cache" if "scan_cache" in tables else "scan_snapshots"
                if keep:
                    placeholders = ",".join("?" for _ in keep)
                    connection.execute(
                        f"DELETE FROM {table} WHERE rowid NOT IN ({placeholders})", tuple(keep)
                    )
                else:
                    connection.execute(f"DELETE FROM {table}")
                connection.commit()
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def _append_summaries(self, state: PrivateState, summaries: list[dict[str, Any]]) -> None:
        path = state.path("history/summary.jsonl")
        existing: list[dict[str, Any]] = []
        if path.exists():
            existing = _read_jsonl(path)
        combined = existing + summaries
        retained = [
            record
            for record in combined
            if self.now - _parse_timestamp(f"{record['day']}T00:00:00+00:00") <= timedelta(days=SUMMARY_DAYS)
        ]
        # Stable de-duplication makes repeated prune operations idempotent.
        unique = {json.dumps(record, sort_keys=True): record for record in retained}
        state.write_text(
            "history/summary.jsonl",
            "".join(key + "\n" for key in sorted(unique)),
        )

    def _plan_quarantine_retention(self) -> int:
        root = self.layout.private_root / "quarantine"
        if not root.exists():
            return 0
        cutoff = self.now.timestamp() - timedelta(days=DETAIL_DAYS).total_seconds()
        return sum(1 for path in root.rglob("*") if path.is_file() and path.stat().st_mtime < cutoff)

    def _plan_artifact_retention(self) -> list[tuple[Path, Path, dict[str, Any]]]:
        """Return expired retained payloads after validating their redacted records."""
        root = self.layout.private_root / "artifacts"
        if not root.exists():
            return []
        planned: list[tuple[Path, Path, dict[str, Any]]] = []
        for payload in root.glob("*/payload"):
            record_path = payload.with_name("record.json")
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record.get("payload_retained") is not True:
                raise ValueError("retained artifact is missing its lifecycle record")
            expires_at = record.get("expires_at")
            if expires_at is None:
                created = _parse_timestamp(record.get("created_at"))
                expiry = created + timedelta(days=DETAIL_DAYS)
            else:
                expiry = _parse_timestamp(expires_at)
            if expiry <= self.now:
                planned.append((payload, record_path, record))
        return planned

    def _apply_artifact_retention(
        self,
        state: PrivateState,
        planned: list[tuple[Path, Path, dict[str, Any]]],
    ) -> int:
        for payload, record_path, record in planned:
            payload.unlink()
            record["payload_retained"] = False
            record["secure_erasure"] = False
            record.pop("retention_days", None)
            record.pop("expires_at", None)
            relative_record = record_path.relative_to(self.layout.private_root)
            state.write_text(
                relative_record,
                json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
            )
        return len(planned)

    def _apply_quarantine_retention(self) -> int:
        root = self.layout.private_root / "quarantine"
        if not root.exists():
            return 0
        cutoff = self.now.timestamp() - timedelta(days=DETAIL_DAYS).total_seconds()
        removed = 0
        for path in root.rglob("*"):
            if path.is_symlink():
                raise PrivateStateError("symlink in quarantine")
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        return removed
