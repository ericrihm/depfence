"""Tests for ThreatDB and its integration into advisory scanners."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.core.threat_db import ThreatDB
from depfence.scanners.npm_advisory import NpmAdvisoryScanner
from depfence.scanners.pypi_advisory import PypiAdvisoryScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path) -> Path:
    """Create a minimal threat_intel.db with the canonical schema."""
    db_path = tmp_path / "threat_intel.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE threat_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            version_range TEXT,
            threat_type TEXT,
            severity TEXT,
            title TEXT,
            detail TEXT,
            cve TEXT,
            first_seen TEXT,
            last_updated TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE crawl_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            version TEXT,
            crawled_at TEXT,
            score REAL,
            signals TEXT,
            verdict TEXT,
            UNIQUE(ecosystem, package_name, version)
        )
    """)
    conn.commit()
    conn.close()
    return db_path


def _insert_threat(db_path: Path, **kwargs) -> None:
    defaults = {
        "source": "test",
        "ecosystem": "npm",
        "package_name": "evil-pkg",
        "version_range": "*",
        "threat_type": "malware",
        "severity": "critical",
        "title": "Evil package",
        "detail": "Does bad things",
        "cve": None,
        "first_seen": "2024-01-01T00:00:00Z",
        "last_updated": "2024-01-02T00:00:00Z",
    }
    defaults.update(kwargs)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        INSERT INTO threat_entries
            (source, ecosystem, package_name, version_range, threat_type,
             severity, title, detail, cve, first_seen, last_updated)
        VALUES
            (:source, :ecosystem, :package_name, :version_range, :threat_type,
             :severity, :title, :detail, :cve, :first_seen, :last_updated)
    """, defaults)
    conn.commit()
    conn.close()


def _insert_verdict(db_path: Path, **kwargs) -> None:
    defaults = {
        "ecosystem": "npm",
        "package_name": "some-pkg",
        "version": "1.0.0",
        "crawled_at": "2024-01-01T00:00:00Z",
        "score": 0.95,
        "signals": '["exfil"]',
        "verdict": "malicious",
    }
    defaults.update(kwargs)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        INSERT OR REPLACE INTO crawl_results
            (ecosystem, package_name, version, crawled_at, score, signals, verdict)
        VALUES
            (:ecosystem, :package_name, :version, :crawled_at, :score, :signals, :verdict)
    """, defaults)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# ThreatDB.lookup
# ---------------------------------------------------------------------------

def test_lookup_returns_matching_entry(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="evil-pkg")
    tdb = ThreatDB(db_path=db)
    results = tdb.lookup("npm", "evil-pkg")
    assert len(results) == 1
    assert results[0]["package_name"] == "evil-pkg"
    assert results[0]["severity"] == "critical"


def test_lookup_case_insensitive(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="Evil-Pkg")
    tdb = ThreatDB(db_path=db)
    assert tdb.lookup("NPM", "evil-pkg")
    assert tdb.lookup("npm", "EVIL-PKG")


def test_lookup_wrong_ecosystem_returns_empty(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="evil-pkg")
    tdb = ThreatDB(db_path=db)
    assert tdb.lookup("pypi", "evil-pkg") == []


def test_lookup_unknown_package_returns_empty(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="evil-pkg")
    tdb = ThreatDB(db_path=db)
    assert tdb.lookup("npm", "safe-pkg") == []


def test_lookup_multiple_entries_ordered_by_last_updated(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="pkg",
                   last_updated="2024-01-01T00:00:00Z", title="older")
    _insert_threat(db, ecosystem="npm", package_name="pkg",
                   last_updated="2024-06-01T00:00:00Z", title="newer")
    tdb = ThreatDB(db_path=db)
    results = tdb.lookup("npm", "pkg")
    assert len(results) == 2
    assert results[0]["title"] == "newer"


# ---------------------------------------------------------------------------
# ThreatDB.is_known_malicious
# ---------------------------------------------------------------------------

def test_is_known_malicious_critical_severity(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, severity="critical", threat_type="vuln")
    tdb = ThreatDB(db_path=db)
    assert tdb.is_known_malicious("npm", "evil-pkg") is True


def test_is_known_malicious_malware_threat_type(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, severity="high", threat_type="malware")
    tdb = ThreatDB(db_path=db)
    assert tdb.is_known_malicious("npm", "evil-pkg") is True


def test_is_known_malicious_low_severity_not_flagged(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, severity="low", threat_type="vuln")
    tdb = ThreatDB(db_path=db)
    assert tdb.is_known_malicious("npm", "evil-pkg") is False


def test_is_known_malicious_unknown_package(tmp_path):
    db = _make_db(tmp_path)
    tdb = ThreatDB(db_path=db)
    assert tdb.is_known_malicious("npm", "safe-pkg") is False


# ---------------------------------------------------------------------------
# ThreatDB — missing DB (CI / first run)
# ---------------------------------------------------------------------------

def test_lookup_missing_db_returns_empty(tmp_path):
    tdb = ThreatDB(db_path=tmp_path / "nonexistent.db")
    assert tdb.lookup("npm", "any-pkg") == []


def test_is_known_malicious_missing_db_returns_false(tmp_path):
    tdb = ThreatDB(db_path=tmp_path / "nonexistent.db")
    assert tdb.is_known_malicious("npm", "any-pkg") is False


def test_get_crawler_verdict_missing_db_returns_none(tmp_path):
    tdb = ThreatDB(db_path=tmp_path / "nonexistent.db")
    assert tdb.get_crawler_verdict("npm", "any-pkg") is None


# ---------------------------------------------------------------------------
# ThreatDB.get_crawler_verdict
# ---------------------------------------------------------------------------

def test_get_crawler_verdict_returns_latest(tmp_path):
    db = _make_db(tmp_path)
    _insert_verdict(db, ecosystem="npm", package_name="some-pkg",
                    version="1.0.0", crawled_at="2024-01-01T00:00:00Z",
                    score=0.5, signals="[]", verdict="clean")
    _insert_verdict(db, ecosystem="npm", package_name="some-pkg",
                    version="2.0.0", crawled_at="2024-06-01T00:00:00Z",
                    score=0.95, signals='["exfil"]', verdict="malicious")
    tdb = ThreatDB(db_path=db)
    verdict = tdb.get_crawler_verdict("npm", "some-pkg")
    assert verdict is not None
    assert verdict["verdict"] == "malicious"
    assert verdict["version"] == "2.0.0"


def test_get_crawler_verdict_unknown_package_returns_none(tmp_path):
    db = _make_db(tmp_path)
    tdb = ThreatDB(db_path=db)
    assert tdb.get_crawler_verdict("npm", "unknown-pkg") is None


# ---------------------------------------------------------------------------
# Scanner integration — NpmAdvisoryScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_npm_scanner_emits_threat_db_finding(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="evil-pkg",
                   severity="high", threat_type="vuln",
                   title="Dangerous behaviour", detail="It phones home")
    tdb = ThreatDB(db_path=db)
    scanner = NpmAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("npm", "evil-pkg", "1.0.0"))
    # Patch _query_osv to avoid network call
    async def _no_osv(packages):
        return []
    scanner._query_osv = _no_osv

    findings = await scanner.scan([pkg])
    threat_findings = [f for f in findings if f.metadata.get("source") == "local_threat_db"]
    assert len(threat_findings) >= 1
    assert threat_findings[0].title == "Dangerous behaviour"
    assert threat_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_npm_scanner_emits_malicious_finding_for_critical(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="npm", package_name="nasty-pkg",
                   severity="critical", threat_type="malware",
                   title="Known malware", detail="Exfiltrates tokens")
    tdb = ThreatDB(db_path=db)
    scanner = NpmAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("npm", "nasty-pkg", "0.1.0"))
    async def _no_osv(packages):
        return []
    scanner._query_osv = _no_osv

    findings = await scanner.scan([pkg])
    malicious = [f for f in findings if f.finding_type == FindingType.MALICIOUS]
    assert len(malicious) >= 1
    critical = [f for f in malicious if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


@pytest.mark.asyncio
async def test_npm_scanner_no_findings_when_db_missing(tmp_path):
    tdb = ThreatDB(db_path=tmp_path / "nonexistent.db")
    scanner = NpmAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("npm", "any-pkg", "1.0.0"))
    async def _no_osv(packages):
        return []
    scanner._query_osv = _no_osv

    findings = await scanner.scan([pkg])
    assert findings == []


# ---------------------------------------------------------------------------
# Scanner integration — PypiAdvisoryScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pypi_scanner_emits_threat_db_finding(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="pypi", package_name="shady-lib",
                   severity="high", threat_type="backdoor",
                   title="Backdoor detected", detail="Opens reverse shell")
    tdb = ThreatDB(db_path=db)
    scanner = PypiAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("pypi", "shady-lib", "2.0.0"))

    # Monkeypatch the OSV HTTP call so the test is offline
    import unittest.mock as mock
    import httpx

    mock_resp = mock.MagicMock()
    mock_resp.raise_for_status = mock.MagicMock()
    mock_resp.json.return_value = {"vulns": []}

    with mock.patch.object(httpx.AsyncClient, "post", return_value=mock_resp):
        findings = await scanner.scan([pkg])

    threat_findings = [f for f in findings if f.metadata.get("source") == "local_threat_db"]
    assert len(threat_findings) >= 1
    assert threat_findings[0].finding_type == FindingType.MALICIOUS


@pytest.mark.asyncio
async def test_pypi_scanner_emits_critical_malicious_for_known_malicious(tmp_path):
    db = _make_db(tmp_path)
    _insert_threat(db, ecosystem="pypi", package_name="evil-lib",
                   severity="critical", threat_type="malware")
    tdb = ThreatDB(db_path=db)
    scanner = PypiAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("pypi", "evil-lib", "1.0.0"))

    import unittest.mock as mock
    import httpx

    mock_resp = mock.MagicMock()
    mock_resp.raise_for_status = mock.MagicMock()
    mock_resp.json.return_value = {"vulns": []}

    with mock.patch.object(httpx.AsyncClient, "post", return_value=mock_resp):
        findings = await scanner.scan([pkg])

    critical_malicious = [
        f for f in findings
        if f.finding_type == FindingType.MALICIOUS and f.severity == Severity.CRITICAL
    ]
    assert len(critical_malicious) >= 1


@pytest.mark.asyncio
async def test_pypi_scanner_no_findings_when_db_missing(tmp_path):
    tdb = ThreatDB(db_path=tmp_path / "nonexistent.db")
    scanner = PypiAdvisoryScanner(threat_db=tdb)

    pkg = PackageMeta(pkg=PackageId("pypi", "any-lib", "1.0.0"))

    import unittest.mock as mock
    import httpx

    mock_resp = mock.MagicMock()
    mock_resp.raise_for_status = mock.MagicMock()
    mock_resp.json.return_value = {"vulns": []}

    with mock.patch.object(httpx.AsyncClient, "post", return_value=mock_resp):
        findings = await scanner.scan([pkg])

    assert findings == []
