from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner
from jsonschema import Draft202012Validator

from depfence.cli.main import cli
from depfence.core.history import ScanHistory
from depfence.core.local_state import PrivateState
from depfence.core.models import ScanResult
from depfence.core.privacy import PrivacyLayout, PrivacyManager
from depfence.core.scan_cache import ScanCache
from depfence.schemas import validate_document

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def _layout(tmp_path: Path) -> PrivacyLayout:
    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir()
    return PrivacyLayout(state, state / "private" / "v1", project)


def _write_signal(path: Path, *, age_days: int = 1, value: dict[str, object] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "name": "depfence_secrets_leak",
        "source": "test",
        "timestamp": (NOW - timedelta(days=age_days)).isoformat(),
        "value": value or {"file": "/sensitive/project/.env", "finding": "api_token:ghp_partial"},
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def _write_scan_cache(path: Path, project_path: str = "/sensitive/project") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE scan_cache (
                project_hash TEXT PRIMARY KEY,
                project_path TEXT,
                lockfile_hash TEXT,
                packages_json TEXT,
                scanned_at TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO scan_cache VALUES (?, ?, ?, ?, ?)",
            ("hash", project_path, "lock", "[]", NOW.isoformat()),
        )


def _write_scan_history(path: Path, project_path: str = "/sensitive/history-project") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE scan_snapshots (
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
            )
            """
        )
        connection.execute(
            "INSERT INTO scan_snapshots "
            "(project_hash, project_path, scanned_at, ecosystem, packages_json, findings_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("hash", project_path, NOW.isoformat(), "pypi", "[]", "[]"),
        )


def test_status_is_read_only_and_reports_legacy_data(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(signal)

    report = PrivacyManager(layout, now=NOW).status()

    assert report.status == "CHANGES_REQUIRED"
    assert report.to_dict()["secure_erasure"] is False
    assert not layout.private_root.exists()
    assert not (layout.private_root / "install.key").exists()
    assert str(tmp_path) not in report.render("json")
    assert report.actions[0].records == 1


def test_status_reports_actual_record_counts_without_creating_private_state(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(signal)
    _write_signal(signal, age_days=2)
    _write_scan_cache(layout.legacy_root / "cache" / "scan_cache.db")

    report = PrivacyManager(layout, now=NOW).status()

    assert [(action.artifact, action.records) for action in report.actions] == [
        ("legacy_signals", 2),
        ("scan_cache", 1),
    ]
    assert not layout.private_root.exists()


def test_migrate_defaults_to_non_mutating_dry_run(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(signal)
    before = signal.read_bytes()

    report = PrivacyManager(layout, now=NOW).migrate()

    assert report.status == "CHANGES_REQUIRED"
    assert report.to_dict()["mode"] == "dry-run"
    assert signal.read_bytes() == before
    assert not layout.private_root.exists()


def test_migrate_redacts_signal_and_quarantines_raw_source(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(signal)

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "UPDATED"
    assert not signal.exists()
    active = layout.private_root / "signals" / "pending.jsonl"
    payload = active.read_text()
    assert "/sensitive/project/.env" not in payload
    assert "ghp_partial" not in payload
    assert "path-hmac-sha256:" in payload
    assert stat.S_IMODE(active.stat().st_mode) == 0o600
    assert stat.S_IMODE(active.parent.stat().st_mode) == 0o700
    quarantined = list((layout.private_root / "quarantine" / "legacy_signals").iterdir())
    assert len(quarantined) == 1
    assert stat.S_IMODE(quarantined[0].stat().st_mode) == 0o600


def test_malformed_signal_is_named_incomplete_and_unchanged(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    signal.parent.mkdir(parents=True)
    signal.write_text("not json\n")

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "INDETERMINATE"
    assert report.exit_code == 2
    assert report.errors[0].code == "LEGACY_DATA_INVALID"
    assert signal.read_text() == "not json\n"
    assert not layout.private_root.exists()


def test_status_does_not_turn_invalid_legacy_data_into_pass(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    signal = layout.legacy_root / "signals" / "pending.jsonl"
    signal.parent.mkdir(parents=True)
    signal.write_text("not json\n")

    report = PrivacyManager(layout, now=NOW).status()

    assert report.status == "INDETERMINATE"
    assert report.exit_code == 2
    assert report.errors[0].code == "LEGACY_DATA_INVALID"


def test_symlinked_legacy_state_is_refused_without_mutation(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    actual = tmp_path / "actual"
    actual.mkdir()
    (layout.legacy_root).mkdir()
    os.symlink(actual, layout.legacy_root / "signals")
    signal = actual / "pending.jsonl"
    _write_signal(signal)

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "INDETERMINATE"
    assert any(error.code == "SYMLINK_REFUSED" for error in report.errors)
    assert signal.exists()
    assert not layout.private_root.exists()


def test_scan_cache_migration_replaces_cleartext_project_path(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    source = layout.legacy_root / "cache" / "scan_cache.db"
    _write_scan_cache(source)

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "UPDATED"
    assert not source.exists()
    destination = layout.private_root / "cache" / "scan_cache.db"
    with closing(sqlite3.connect(destination)) as connection:
        stored = connection.execute("SELECT project_path FROM scan_cache").fetchone()[0]
    assert stored.startswith("project-hmac-sha256:")
    assert "/sensitive/project" not in stored
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_scan_history_migration_replaces_cleartext_project_path(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    source = layout.legacy_root / "cache" / "scan_history.db"
    _write_scan_history(source)

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "UPDATED"
    assert not source.exists()
    destination = layout.private_root / "cache" / "scan_history.db"
    with closing(sqlite3.connect(destination)) as connection:
        stored = connection.execute("SELECT project_path FROM scan_snapshots").fetchone()[0]
    assert stored.startswith("project-hmac-sha256:")
    assert "/sensitive/history-project" not in stored


def test_signal_merge_is_dry_run_first_lossless_redacted_and_idempotent(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    state = PrivateState.open(project_root=layout.project_root, root=layout.private_root)
    state.opaque_id("project", "/key-initializer")
    legacy = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(legacy, value={"file": "/new/private/.env", "token": "secret"})
    existing = {
        "schema": "depfence.signal/v1",
        "name": "existing",
        "source": "test",
        "timestamp": (NOW - timedelta(days=2)).timestamp(),
        "value": {"finding": "safe"},
    }
    state.write_text("signals/pending.jsonl", json.dumps(existing, sort_keys=True) + "\n")
    before_legacy = legacy.read_bytes()
    before_private = state.path("signals/pending.jsonl").read_bytes()

    dry_run = PrivacyManager(layout, now=NOW).migrate()

    assert dry_run.status == "CHANGES_REQUIRED"
    assert dry_run.actions[0].action == "would_merge_and_quarantine"
    assert dry_run.actions[0].records == 1
    assert legacy.read_bytes() == before_legacy
    assert state.path("signals/pending.jsonl").read_bytes() == before_private

    applied = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert applied.status == "UPDATED"
    assert applied.actions[0].action == "merged_and_quarantined"
    payload = state.path("signals/pending.jsonl").read_text()
    assert len(payload.splitlines()) == 2
    assert "/new/private/.env" not in payload
    assert '"token": "secret"' not in payload
    assert "path-hmac-sha256:" in payload
    assert not legacy.exists()
    after = state.path("signals/pending.jsonl").read_bytes()

    repeated = PrivacyManager(layout, now=NOW).migrate(apply=True)
    assert repeated.status == "PASS"
    assert repeated.actions[0].action == "no_legacy_data"
    assert state.path("signals/pending.jsonl").read_bytes() == after


def test_signal_merge_accepts_v1_time_time_precision_without_rewriting_it(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    state = PrivateState.open(project_root=layout.project_root, root=layout.private_root)
    state.opaque_id("project", "/key-initializer")
    legacy = layout.legacy_root / "signals" / "pending.jsonl"
    _write_signal(legacy)
    high_precision_timestamp = 1_786_708_800.0000002
    existing = {
        "schema": "depfence.signal/v1",
        "name": "existing",
        "source": "test",
        "timestamp": high_precision_timestamp,
        "value": {"finding": "safe"},
    }
    state.write_text("signals/pending.jsonl", json.dumps(existing, sort_keys=True) + "\n")
    before = state.path("signals/pending.jsonl").read_bytes()

    report = PrivacyManager(layout, now=NOW).migrate()

    assert report.status == "CHANGES_REQUIRED"
    assert report.actions[0].action == "would_merge_and_quarantine"
    assert state.path("signals/pending.jsonl").read_bytes() == before


def test_scan_cache_merge_preserves_existing_and_adds_redacted_legacy_row(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    state = PrivateState.open(project_root=layout.project_root, root=layout.private_root)
    destination = state.path("cache/scan_cache.db")
    _write_scan_cache(destination, project_path=state.opaque_id("project", "/existing"))
    with closing(sqlite3.connect(destination)) as connection, connection:
        connection.execute("UPDATE scan_cache SET project_hash='existing-hash'")
    source = layout.legacy_root / "cache" / "scan_cache.db"
    _write_scan_cache(source, project_path="/sensitive/incoming")
    before_source = source.read_bytes()
    before_destination = destination.read_bytes()

    dry_run = PrivacyManager(layout, now=NOW).migrate()
    assert dry_run.status == "CHANGES_REQUIRED"
    assert dry_run.actions[0].action == "would_merge_and_quarantine"
    assert dry_run.actions[0].records == 1
    assert source.read_bytes() == before_source
    assert destination.read_bytes() == before_destination

    applied = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert applied.status == "UPDATED"
    with closing(sqlite3.connect(destination)) as connection:
        rows = connection.execute(
            "SELECT project_hash, project_path FROM scan_cache ORDER BY project_hash"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "existing-hash"
    assert all("/sensitive/incoming" not in row[1] for row in rows)
    assert rows[1][1].startswith("project-hmac-sha256:")


def test_scan_cache_merge_conflict_is_named_and_preserves_both_files(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    state = PrivateState.open(project_root=layout.project_root, root=layout.private_root)
    destination = state.path("cache/scan_cache.db")
    source = layout.legacy_root / "cache" / "scan_cache.db"
    _write_scan_cache(destination, project_path=state.opaque_id("project", "/private"))
    _write_scan_cache(source, project_path="/legacy")
    before_source = source.read_bytes()
    before_destination = destination.read_bytes()

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "INDETERMINATE"
    assert report.exit_code == 2
    assert report.errors[0].code == "MERGE_CONFLICT"
    assert source.read_bytes() == before_source
    assert destination.read_bytes() == before_destination
    assert not (layout.private_root / "quarantine" / "scan_cache").exists()


def test_scan_history_merge_preserves_existing_and_appends_unique_rows(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    state = PrivateState.open(project_root=layout.project_root, root=layout.private_root)
    destination = state.path("cache/scan_history.db")
    _write_scan_history(destination, project_path=state.opaque_id("project", "/existing"))
    source = layout.legacy_root / "cache" / "scan_history.db"
    _write_scan_history(source, project_path="/sensitive/incoming-history")
    with closing(sqlite3.connect(source)) as connection, connection:
        connection.execute("UPDATE scan_snapshots SET project_hash='incoming-hash'")

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "UPDATED"
    assert report.actions[0].action == "merged_and_quarantined"
    with closing(sqlite3.connect(destination)) as connection:
        rows = connection.execute(
            "SELECT project_hash, project_path FROM scan_snapshots ORDER BY project_hash"
        ).fetchall()
    assert len(rows) == 2
    assert all("/sensitive/incoming-history" not in row[1] for row in rows)
    assert all(_path.startswith("project-hmac-sha256:") for _, _path in rows)


def test_existing_destination_without_install_key_is_named_and_unchanged(
    tmp_path: Path,
) -> None:
    layout = _layout(tmp_path)
    source = layout.legacy_root / "signals" / "pending.jsonl"
    destination = layout.private_root / "signals" / "pending.jsonl"
    _write_signal(source)
    _write_signal(destination, value={"finding": "private"})
    before_source = source.read_bytes()
    before_destination = destination.read_bytes()

    report = PrivacyManager(layout, now=NOW).migrate(apply=True)

    assert report.status == "INDETERMINATE"
    assert report.errors[0].code == "PRIVATE_KEY_UNAVAILABLE"
    assert source.read_bytes() == before_source
    assert destination.read_bytes() == before_destination


def test_prune_dry_run_and_apply_enforce_retention(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    pending = layout.private_root / "signals" / "pending.jsonl"
    _write_signal(pending, age_days=10, value={"finding": "recent"})
    _write_signal(pending, age_days=60, value={"finding": "summary"})
    _write_signal(pending, age_days=400, value={"finding": "expired"})
    before = pending.read_bytes()

    dry_run = PrivacyManager(layout, now=NOW).prune()
    assert dry_run.status == "CHANGES_REQUIRED"
    assert pending.read_bytes() == before

    applied = PrivacyManager(layout, now=NOW).prune(apply=True)
    assert applied.status == "UPDATED"
    retained = [json.loads(line) for line in pending.read_text().splitlines()]
    assert len(retained) == 1
    assert retained[0]["value"]["finding"] == "recent"
    summary = (layout.private_root / "history" / "summary.jsonl").read_text()
    assert '"count": 1' in summary
    assert '"finding": "summary"' not in summary
    assert "expired" not in summary
    assert applied.to_dict()["secure_erasure"] is False


def test_prune_database_keeps_detail_summarises_middle_and_expires_old(tmp_path: Path) -> None:
    layout = _layout(tmp_path)
    database = layout.private_root / "cache" / "scan_history.db"
    _write_scan_history(database, project_path="project-sha256:" + "a" * 64)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "UPDATE scan_snapshots SET scanned_at=?",
            ((NOW - timedelta(days=10)).isoformat(),),
        )
        for age in (60, 400):
            connection.execute(
                "INSERT INTO scan_snapshots "
                "(project_hash, project_path, scanned_at, ecosystem, packages_json, findings_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    f"hash-{age}",
                    "project-sha256:" + "a" * 64,
                    (NOW - timedelta(days=age)).isoformat(),
                    "pypi",
                    "[]",
                    "[]",
                ),
            )

    report = PrivacyManager(layout, now=NOW).prune(apply=True)

    assert report.status == "UPDATED"
    with closing(sqlite3.connect(database)) as connection:
        timestamps = connection.execute("SELECT scanned_at FROM scan_snapshots").fetchall()
    assert len(timestamps) == 1
    assert timestamps[0][0] == (NOW - timedelta(days=10)).isoformat()
    summaries = [
        json.loads(line)
        for line in (layout.private_root / "history" / "summary.jsonl").read_text().splitlines()
    ]
    assert len(summaries) == 1
    assert summaries[0]["day"] == (NOW - timedelta(days=60)).date().isoformat()
    assert summaries[0]["project_id"].startswith("project-sha256:")


def test_cli_json_contract_uses_explicit_apply_and_redacts_paths(tmp_path: Path) -> None:
    state = tmp_path / "state"
    signal = state / "signals" / "pending.jsonl"
    _write_signal(signal)
    runner = CliRunner()

    dry_run = runner.invoke(
        cli,
        ["privacy", "--state-root", str(state), "migrate", "--format", "json"],
    )
    assert dry_run.exit_code == 0
    document = json.loads(dry_run.output)
    assert document["schema_version"] == "depfence.privacy/v1"
    assert document["mode"] == "dry-run"
    assert document["secure_erasure"] is False
    assert str(tmp_path) not in dry_run.output
    assert signal.exists()
    schema_path = Path("depfence/schemas/depfence.privacy.v1.schema.json")
    Draft202012Validator(json.loads(schema_path.read_text())).validate(document)
    validate_document(document)

    applied = runner.invoke(
        cli,
        ["privacy", "--state-root", str(state), "migrate", "--apply", "--format", "json"],
    )
    assert applied.exit_code == 0, applied.output
    assert json.loads(applied.output)["status"] == "UPDATED"
    assert not signal.exists()


def test_new_cache_and_history_state_never_store_cleartext_paths(tmp_path: Path) -> None:
    project = tmp_path / "sensitive-project"
    project.mkdir()
    cache_dir = tmp_path / "private-cache"

    ScanCache(cache_dir=cache_dir).save_scan(project, [])
    history = ScanHistory(db_dir=cache_dir)
    history.record_scan(ScanResult(target=str(project), ecosystem="pypi"), project_path=str(project))

    for database, table in (
        (cache_dir / "scan_cache.db", "scan_cache"),
        (cache_dir / "scan_history.db", "scan_snapshots"),
    ):
        with closing(sqlite3.connect(database)) as connection:
            stored = connection.execute(f"SELECT project_path FROM {table}").fetchone()[0]
        assert str(project) not in stored
        assert stored.startswith("project-sha256:")
        assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700


def test_default_cache_root_is_private_and_safe_outside_a_worktree(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.chdir(fake_home)

    ScanCache().save_scan(fake_home / "project", [])
    history = ScanHistory()
    history.record_scan(ScanResult(target="project", ecosystem="pypi"), project_path="project")

    private = fake_home / ".depfence" / "private" / "v1"
    assert (private / "cache" / "scan_cache.db").exists()
    assert (private / "cache" / "scan_history.db").exists()
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    assert stat.S_IMODE((private / "install.key").stat().st_mode) == 0o600
    assert not (fake_home / ".depfence" / "cache").exists()
