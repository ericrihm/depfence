"""Tests for ThreatIntelDB and KNOWN_MALICIOUS."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.core.threat_intel import KNOWN_MALICIOUS, ThreatEntry, ThreatIntelDB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path) -> ThreatIntelDB:
    """Return a fresh ThreatIntelDB backed by a temp file (does NOT call load)."""
    return ThreatIntelDB(db_path=tmp_path / "threat_intel.json")


def _sample_entry(**overrides) -> ThreatEntry:
    defaults = dict(
        package_name="evil-pkg",
        ecosystem="npm",
        threat_type="malware",
        source="community",
        reported_date="2024-01-01",
        description="Does bad things",
        indicators=["evil.example.com"],
        severity="critical",
    )
    defaults.update(overrides)
    return ThreatEntry(**defaults)


# ---------------------------------------------------------------------------
# KNOWN_MALICIOUS sanity checks
# ---------------------------------------------------------------------------


def test_known_malicious_has_at_least_60_entries():
    assert len(KNOWN_MALICIOUS) >= 60


def test_known_malicious_keys_are_tuples_of_two_strings():
    for key in KNOWN_MALICIOUS:
        assert isinstance(key, tuple) and len(key) == 2
        ecosystem, name = key
        assert isinstance(ecosystem, str) and isinstance(name, str)


def test_known_malicious_includes_npm_event_stream():
    assert ("npm", "event-stream") in KNOWN_MALICIOUS


def test_known_malicious_includes_pypi_colourama():
    assert ("pypi", "colourama") in KNOWN_MALICIOUS


def test_known_malicious_all_entries_have_required_fields():
    required = {"threat_type", "severity", "description", "reported_date", "source", "indicators"}
    for key, meta in KNOWN_MALICIOUS.items():
        missing = required - meta.keys()
        assert not missing, f"{key} is missing fields: {missing}"


# ---------------------------------------------------------------------------
# ThreatIntelDB.load / save round-trip
# ---------------------------------------------------------------------------


def test_load_save_roundtrip(tmp_path):
    db_path = tmp_path / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()

    initial_count = db.count()
    assert initial_count >= 60  # seeded from KNOWN_MALICIOUS

    db.save()
    assert db_path.exists()

    db2 = ThreatIntelDB(db_path=db_path)
    db2.load()
    assert db2.count() == initial_count


def test_save_creates_parent_directories(tmp_path):
    db_path = tmp_path / "nested" / "dir" / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()
    db.save()
    assert db_path.exists()


def test_save_produces_valid_json(tmp_path):
    db_path = tmp_path / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()
    db.save()

    data = json.loads(db_path.read_text())
    assert "entries" in data
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) >= 60


def test_load_persisted_entry_survives_roundtrip(tmp_path):
    db_path = tmp_path / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()
    entry = _sample_entry(package_name="roundtrip-pkg", ecosystem="pypi")
    db.add_entry(entry)
    db.save()

    db2 = ThreatIntelDB(db_path=db_path)
    db2.load()
    found = db2.lookup("roundtrip-pkg", "pypi")
    assert found is not None
    assert found.package_name == "roundtrip-pkg"
    assert found.threat_type == "malware"


def test_load_from_nonexistent_path_uses_seed(tmp_path):
    db = ThreatIntelDB(db_path=tmp_path / "nonexistent.json")
    db.load()
    assert db.count() >= 60


# ---------------------------------------------------------------------------
# ThreatIntelDB.lookup
# ---------------------------------------------------------------------------


def test_lookup_finds_known_malicious_package(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    # event-stream is in KNOWN_MALICIOUS
    entry = db.lookup("event-stream", "npm")
    assert entry is not None
    assert entry.package_name == "event-stream"
    assert entry.ecosystem == "npm"


def test_lookup_returns_none_for_clean_package(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    assert db.lookup("lodash", "npm") is None


def test_lookup_case_insensitive_name(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    # KNOWN_MALICIOUS has ("npm", "event-stream")
    assert db.lookup("EVENT-STREAM", "npm") is not None
    assert db.lookup("Event-Stream", "npm") is not None
    assert db.lookup("event-stream", "npm") is not None


def test_lookup_case_insensitive_ecosystem(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    assert db.lookup("event-stream", "NPM") is not None
    assert db.lookup("event-stream", "Npm") is not None


def test_lookup_wrong_ecosystem_returns_none(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    # event-stream is npm, not pypi
    assert db.lookup("event-stream", "pypi") is None


def test_lookup_added_entry(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    entry = _sample_entry(package_name="new-evil", ecosystem="pypi")
    db.add_entry(entry)
    found = db.lookup("new-evil", "pypi")
    assert found is not None
    assert found.severity == "critical"


def test_lookup_returns_threat_entry_type(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    entry = db.lookup("colourama", "pypi")
    assert isinstance(entry, ThreatEntry)


# ---------------------------------------------------------------------------
# ThreatIntelDB.add_entry
# ---------------------------------------------------------------------------


def test_add_entry_overwrites_existing(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    e1 = _sample_entry(package_name="mypkg", ecosystem="npm", severity="high")
    e2 = _sample_entry(package_name="mypkg", ecosystem="npm", severity="critical")
    db.add_entry(e1)
    db.add_entry(e2)
    assert db.lookup("mypkg", "npm").severity == "critical"


def test_add_entry_persists_after_save_reload(tmp_path):
    db_path = tmp_path / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()
    db.add_entry(_sample_entry(package_name="persist-me", ecosystem="cargo"))
    db.save()

    db2 = ThreatIntelDB(db_path=db_path)
    db2.load()
    assert db2.lookup("persist-me", "cargo") is not None


def test_add_entry_increments_count(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    before = db.count()
    db.add_entry(_sample_entry(package_name="brand-new-unique-12345", ecosystem="go"))
    assert db.count() == before + 1


# ---------------------------------------------------------------------------
# ThreatIntelDB.lookup_batch
# ---------------------------------------------------------------------------


def test_lookup_batch_returns_malicious_only(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    packages = [
        PackageId("npm", "event-stream", "3.3.6"),
        PackageId("npm", "lodash", "4.17.21"),
        PackageId("pypi", "requests", "2.31.0"),
    ]
    result = db.lookup_batch(packages)
    # Only event-stream is malicious
    assert len(result) == 1
    key = str(PackageId("npm", "event-stream", "3.3.6"))
    assert key in result
    assert isinstance(result[key], ThreatEntry)


def test_lookup_batch_with_all_clean_returns_empty(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    packages = [
        PackageId("npm", "lodash", "4.17.21"),
        PackageId("pypi", "requests", "2.31.0"),
    ]
    assert db.lookup_batch(packages) == {}


def test_lookup_batch_with_multiple_malicious(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    db.add_entry(_sample_entry(package_name="pkg-a", ecosystem="npm"))
    db.add_entry(_sample_entry(package_name="pkg-b", ecosystem="npm"))
    packages = [
        PackageId("npm", "pkg-a", "1.0.0"),
        PackageId("npm", "pkg-b", "1.0.0"),
        PackageId("npm", "lodash", "4.17.21"),
    ]
    result = db.lookup_batch(packages)
    assert len(result) == 2


def test_lookup_batch_empty_list(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    assert db.lookup_batch([]) == {}


# ---------------------------------------------------------------------------
# ThreatIntelDB.get_recent
# ---------------------------------------------------------------------------


def test_get_recent_filters_by_date(tmp_path):
    db = _make_db(tmp_path)
    # Do NOT load — start fresh with no seed
    db._entries = {}

    today = datetime.now(tz=timezone.utc).date()
    recent_date = (datetime.now(tz=timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    old_date = (datetime.now(tz=timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%d")

    db.add_entry(_sample_entry(package_name="recent-pkg", reported_date=recent_date))
    db.add_entry(_sample_entry(package_name="old-pkg", reported_date=old_date))

    recent = db.get_recent(days=30)
    names = [e.package_name for e in recent]
    assert "recent-pkg" in names
    assert "old-pkg" not in names


def test_get_recent_default_30_days(tmp_path):
    db = _make_db(tmp_path)
    db._entries = {}
    recent_date = (datetime.now(tz=timezone.utc) - timedelta(days=15)).strftime("%Y-%m-%d")
    db.add_entry(_sample_entry(package_name="within-30", reported_date=recent_date))
    result = db.get_recent()
    assert any(e.package_name == "within-30" for e in result)


def test_get_recent_zero_days_returns_only_today(tmp_path):
    db = _make_db(tmp_path)
    db._entries = {}
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    yesterday = (datetime.now(tz=timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    db.add_entry(_sample_entry(package_name="today-pkg", reported_date=today))
    db.add_entry(_sample_entry(package_name="yesterday-pkg", reported_date=yesterday))
    result = db.get_recent(days=0)
    names = [e.package_name for e in result]
    assert "today-pkg" in names
    assert "yesterday-pkg" not in names


def test_get_recent_skips_unparseable_dates(tmp_path):
    db = _make_db(tmp_path)
    db._entries = {}
    db.add_entry(_sample_entry(package_name="bad-date-pkg", reported_date="not-a-date"))
    # Should not raise
    result = db.get_recent(days=30)
    assert all(e.package_name != "bad-date-pkg" for e in result)


# ---------------------------------------------------------------------------
# ThreatIntelDB.count
# ---------------------------------------------------------------------------


def test_count_returns_zero_on_empty_db(tmp_path):
    db = _make_db(tmp_path)
    # No load — internal dict is empty
    assert db.count() == 0


def test_count_reflects_seed_after_load(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    assert db.count() >= 60


def test_count_increments_after_add(tmp_path):
    db = _make_db(tmp_path)
    assert db.count() == 0
    db.add_entry(_sample_entry(package_name="a"))
    assert db.count() == 1
    db.add_entry(_sample_entry(package_name="b"))
    assert db.count() == 2


def test_count_does_not_double_count_same_key(tmp_path):
    db = _make_db(tmp_path)
    db.add_entry(_sample_entry(package_name="dup", ecosystem="npm"))
    db.add_entry(_sample_entry(package_name="dup", ecosystem="npm", severity="high"))
    assert db.count() == 1


# ---------------------------------------------------------------------------
# ThreatIntelDB.last_synced
# ---------------------------------------------------------------------------


def test_last_synced_is_none_before_any_sync(tmp_path):
    db = _make_db(tmp_path)
    db.load()
    assert db.last_synced is None


def test_last_synced_persists_through_save_load(tmp_path):
    db_path = tmp_path / "threat_intel.json"
    db = ThreatIntelDB(db_path=db_path)
    db.load()
    db._last_synced = "2024-06-01T12:00:00+00:00"
    db.save()

    db2 = ThreatIntelDB(db_path=db_path)
    db2.load()
    assert db2.last_synced == "2024-06-01T12:00:00+00:00"


# ---------------------------------------------------------------------------
# sync_from_ossf — offline mock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sync_from_ossf_sets_last_synced(tmp_path, monkeypatch):
    """sync_from_ossf should set last_synced even if the network call fails."""
    import httpx

    async def _raise(*args, **kwargs):
        raise httpx.ConnectError("offline")

    db = _make_db(tmp_path)
    db.load()
    monkeypatch.setattr(httpx.AsyncClient, "get", _raise)
    added = await db.sync_from_ossf()
    assert db.last_synced is not None
    # Offline sync should not crash and returns 0
    assert added == 0


@pytest.mark.asyncio
async def test_sync_from_ossf_adds_new_entries(tmp_path, monkeypatch):
    """Simulate a successful OSSF API response with one entry."""
    import httpx

    dir_response = [
        {
            "type": "file",
            "name": "MAL-2024-0001.json",
            "download_url": "https://raw.example.com/MAL-2024-0001.json",
        }
    ]
    osv_entry = {
        "id": "MAL-2024-0001",
        "published": "2024-03-01T00:00:00Z",
        "summary": "Malicious package that exfiltrates credentials",
        "details": "Sends environment variables to remote server",
        "affected": [
            {
                "package": {
                    "name": "totally-new-ossf-pkg",
                    "ecosystem": "npm",
                }
            }
        ],
    }

    call_count = 0

    async def _mock_get(self, url, **kwargs):
        nonlocal call_count
        call_count += 1
        mock = type(
            "R",
            (),
            {
                "raise_for_status": lambda s: None,
                "json": lambda s: dir_response if call_count == 1 else osv_entry,
            },
        )()
        return mock

    db = _make_db(tmp_path)
    db.load()
    monkeypatch.setattr(httpx.AsyncClient, "get", _mock_get)
    added = await db.sync_from_ossf()
    assert added >= 1
    assert db.lookup("totally-new-ossf-pkg", "npm") is not None
