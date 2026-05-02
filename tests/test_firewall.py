"""Tests for registry firewall interceptor."""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from depfence.firewall.interceptor import (
    FirewallDecision,
    check_package,
    disable_firewall,
    enable_npm_firewall,
    get_status,
)


@pytest.fixture
def threat_db(tmp_path):
    """Create a temporary threat DB with test data."""
    db_path = tmp_path / "threat_intel.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE threat_entries (
            source TEXT, ecosystem TEXT, package_name TEXT,
            version_range TEXT, threat_type TEXT, severity TEXT,
            title TEXT, detail TEXT, cve TEXT,
            first_seen TEXT, last_updated TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE crawl_results (
            ecosystem TEXT, package_name TEXT, version TEXT,
            score INTEGER, signals TEXT, verdict TEXT, crawled_at TEXT
        )
    """)
    conn.execute(
        "INSERT INTO threat_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("test", "npm", "evil-package", "*", "malware", "critical",
         "Known malware", "Steals credentials", None, "2024-01-01", "2024-01-01"),
    )
    conn.execute(
        "INSERT INTO crawl_results VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("npm", "suspicious-pkg", "1.0.0", 85, "[]", "suspicious", "2024-01-01"),
    )
    conn.execute(
        "INSERT INTO crawl_results VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("npm", "medium-risk", "1.0.0", 55, "[]", "review", "2024-01-01"),
    )
    conn.commit()
    conn.close()
    return db_path


def test_block_malicious(threat_db, monkeypatch):
    monkeypatch.setattr("depfence.firewall.interceptor.ThreatDB.__init__",
                        lambda self: setattr(self, "_db_path", threat_db) or None)
    result = check_package("npm", "evil-package")
    assert result["decision"] == FirewallDecision.BLOCK
    assert "malicious" in result["reason"].lower()


def test_block_high_score(threat_db, monkeypatch):
    monkeypatch.setattr("depfence.firewall.interceptor.ThreatDB.__init__",
                        lambda self: setattr(self, "_db_path", threat_db) or None)
    result = check_package("npm", "suspicious-pkg")
    assert result["decision"] == FirewallDecision.BLOCK
    assert "85" in result["reason"]


def test_warn_medium_score(threat_db, monkeypatch):
    monkeypatch.setattr("depfence.firewall.interceptor.ThreatDB.__init__",
                        lambda self: setattr(self, "_db_path", threat_db) or None)
    result = check_package("npm", "medium-risk")
    assert result["decision"] == FirewallDecision.WARN


def test_allow_clean_package(threat_db, monkeypatch):
    monkeypatch.setattr("depfence.firewall.interceptor.ThreatDB.__init__",
                        lambda self: setattr(self, "_db_path", threat_db) or None)
    result = check_package("npm", "lodash")
    assert result["decision"] == FirewallDecision.ALLOW


def test_enable_npm_firewall():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        result = enable_npm_firewall(project)
        assert "enabled" in result.lower()
        assert (project / ".npmrc").exists()
        assert "depfence" in (project / ".npmrc").read_text()


def test_enable_npm_firewall_existing_npmrc():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        (project / ".npmrc").write_text("registry=https://npm.pkg.github.com\n")
        enable_npm_firewall(project)
        content = (project / ".npmrc").read_text()
        assert "registry=https://npm.pkg.github.com" in content
        assert "depfence" in content


def test_enable_npm_firewall_idempotent():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        enable_npm_firewall(project)
        result = enable_npm_firewall(project)
        assert "already" in result.lower()


def test_disable_firewall():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        enable_npm_firewall(project)
        disable_firewall(project)
        npmrc = project / ".npmrc"
        if npmrc.exists():
            assert "depfence" not in npmrc.read_text()


def test_get_status():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        status = get_status(project)
        assert not status["active"]

        enable_npm_firewall(project)
        status = get_status(project)
        assert status["npm"]
        assert status["active"]
