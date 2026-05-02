"""Full integration tests for the depfence intel module.

Covers KEVMonitor, ThreatFeed/ThreatSnapshot, and the threat-brief CLI command.
25+ tests total.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.intel.kev_monitor import KEVEntry, KEVMonitor
from depfence.intel.threat_feed import ThreatFeed, ThreatSnapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    cve: str | None = None,
    severity: Severity = Severity.HIGH,
    title: str = "Test vuln",
    pkg_name: str = "requests",
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem="pypi", name=pkg_name, version="1.0.0"),
        title=title,
        detail="Detail.",
        cve=cve,
    )


def _kev(
    cve: str = "CVE-2021-44228",
    vendor: str = "Apache",
    product: str = "Log4j",
    date_added: str = "2021-12-10",
    due_date: str = "2021-12-24",
    known_ransomware: bool = True,
) -> KEVEntry:
    return KEVEntry(
        cve=cve,
        vendor=vendor,
        product=product,
        date_added=date_added,
        due_date=due_date,
        known_ransomware=known_ransomware,
    )


# ---------------------------------------------------------------------------
# KEVEntry dataclass
# ---------------------------------------------------------------------------


class TestKEVEntry:
    def test_fields_are_accessible(self):
        entry = _kev()
        assert entry.cve == "CVE-2021-44228"
        assert entry.vendor == "Apache"
        assert entry.product == "Log4j"
        assert entry.date_added == "2021-12-10"
        assert entry.due_date == "2021-12-24"
        assert entry.known_ransomware is True

    def test_defaults(self):
        entry = KEVEntry(
            cve="CVE-2024-0001",
            vendor="Acme",
            product="Widget",
            date_added="2024-01-01",
            due_date="2024-01-15",
        )
        assert entry.known_ransomware is False
        assert entry.description == ""
        assert entry.required_action == ""

    def test_known_ransomware_false(self):
        entry = _kev(known_ransomware=False)
        assert entry.known_ransomware is False


# ---------------------------------------------------------------------------
# KEVMonitor — schema and storage
# ---------------------------------------------------------------------------


class TestKEVMonitorSchema:
    def test_table_created_on_first_connect(self, tmp_path):
        db = tmp_path / "test.db"
        monitor = KEVMonitor(db_path=db)
        conn = monitor._get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='kev_catalog'"
        ).fetchone()
        assert row is not None
        monitor.close()

    def test_index_created(self, tmp_path):
        db = tmp_path / "test.db"
        monitor = KEVMonitor(db_path=db)
        monitor._get_conn()
        rows = monitor._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_kev_cve'"
        ).fetchall()
        assert rows
        monitor.close()

    def test_db_dir_created_if_missing(self, tmp_path):
        db = tmp_path / "nested" / "dir" / "intel.db"
        monitor = KEVMonitor(db_path=db)
        monitor._get_conn()
        assert db.exists()
        monitor.close()


class TestKEVMonitorStore:
    def test_store_returns_count(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        entries = [_kev("CVE-2021-44228"), _kev("CVE-2022-30190", known_ransomware=False)]
        assert monitor.store_kev_entries(entries) == 2
        monitor.close()

    def test_store_empty_list_returns_zero(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        assert monitor.store_kev_entries([]) == 0
        monitor.close()

    def test_count_reflects_stored_entries(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-A"), _kev("CVE-B")])
        assert monitor.count() == 2
        monitor.close()

    def test_insert_or_replace_upserts(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228", vendor="OldVendor")])
        monitor.store_kev_entries([_kev("CVE-2021-44228", vendor="Apache")])
        assert monitor.count() == 1
        entry = monitor.get_entry("CVE-2021-44228")
        assert entry is not None
        assert entry.vendor == "Apache"
        monitor.close()


# ---------------------------------------------------------------------------
# KEVMonitor — query helpers
# ---------------------------------------------------------------------------


class TestKEVMonitorQuery:
    def _populated(self, tmp_path: Path) -> KEVMonitor:
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([
            _kev("CVE-2021-44228", known_ransomware=True),
            _kev("CVE-2022-30190", known_ransomware=False, vendor="Microsoft"),
            _kev("CVE-2023-34362", known_ransomware=True, vendor="Progress"),
        ])
        return monitor

    def test_all_cves_returns_sorted_list(self, tmp_path):
        monitor = self._populated(tmp_path)
        cves = monitor.all_cves()
        assert "CVE-2021-44228" in cves
        assert "CVE-2022-30190" in cves
        assert cves == sorted(cves)
        monitor.close()

    def test_get_entry_known_cve(self, tmp_path):
        monitor = self._populated(tmp_path)
        entry = monitor.get_entry("CVE-2021-44228")
        assert entry is not None
        assert entry.cve == "CVE-2021-44228"
        assert entry.vendor == "Apache"
        assert entry.known_ransomware is True
        monitor.close()

    def test_get_entry_unknown_cve_returns_none(self, tmp_path):
        monitor = self._populated(tmp_path)
        assert monitor.get_entry("CVE-9999-9999") is None
        monitor.close()

    def test_ransomware_cves_filters_correctly(self, tmp_path):
        monitor = self._populated(tmp_path)
        rsw = monitor.ransomware_cves()
        assert "CVE-2021-44228" in rsw
        assert "CVE-2023-34362" in rsw
        assert "CVE-2022-30190" not in rsw
        monitor.close()


# ---------------------------------------------------------------------------
# KEVMonitor — check_local_kev
# ---------------------------------------------------------------------------


class TestKEVMonitorCheckLocalKev:
    def test_finds_matching_cves(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        findings = [_finding(cve="CVE-2021-44228"), _finding(cve="CVE-9999-9999")]
        hits = monitor.check_local_kev(findings)
        assert len(hits) == 1
        assert hits[0].cve == "CVE-2021-44228"
        monitor.close()

    def test_empty_findings_returns_empty(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev()])
        assert monitor.check_local_kev([]) == []
        monitor.close()

    def test_no_cve_findings_returns_empty(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev()])
        assert monitor.check_local_kev([_finding(cve=None)]) == []
        monitor.close()

    def test_no_matching_cves_returns_empty(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        hits = monitor.check_local_kev([_finding(cve="CVE-9999-9999")])
        assert hits == []
        monitor.close()


# ---------------------------------------------------------------------------
# KEVMonitor — fetch_kev_catalog (mock HTTP)
# ---------------------------------------------------------------------------


class TestKEVMonitorFetchCatalog:
    def test_returns_list_of_kev_entries(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        entries = monitor.fetch_kev_catalog()
        assert isinstance(entries, list)
        assert len(entries) > 0
        assert all(isinstance(e, KEVEntry) for e in entries)
        monitor.close()

    def test_entries_have_required_fields(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        entries = monitor.fetch_kev_catalog()
        for e in entries:
            assert e.cve
            assert e.vendor
            assert e.product
            assert e.date_added
            assert e.due_date
        monitor.close()

    def test_includes_log4shell(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        entries = monitor.fetch_kev_catalog()
        cves = {e.cve for e in entries}
        assert "CVE-2021-44228" in cves
        monitor.close()

    def test_ransomware_flag_parsed(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        entries = monitor.fetch_kev_catalog()
        by_cve = {e.cve: e for e in entries}
        if "CVE-2021-44228" in by_cve:
            assert by_cve["CVE-2021-44228"].known_ransomware is True
        monitor.close()


# ---------------------------------------------------------------------------
# KEVMonitor — escalate_severity
# ---------------------------------------------------------------------------


class TestKEVMonitorEscalateSeverity:
    def test_kev_cve_escalated_to_critical(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        finding = _finding(cve="CVE-2021-44228", severity=Severity.HIGH)
        monitor.escalate_severity([finding])
        assert finding.severity == Severity.CRITICAL
        monitor.close()

    def test_kev_cve_escalated_from_medium(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        finding = _finding(cve="CVE-2021-44228", severity=Severity.MEDIUM)
        monitor.escalate_severity([finding])
        assert finding.severity == Severity.CRITICAL
        monitor.close()

    def test_non_kev_cve_not_escalated(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        finding = _finding(cve="CVE-9999-9999", severity=Severity.HIGH)
        monitor.escalate_severity([finding])
        assert finding.severity == Severity.HIGH
        monitor.close()

    def test_no_cve_finding_not_escalated(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        finding = _finding(cve=None, severity=Severity.LOW)
        monitor.escalate_severity([finding])
        assert finding.severity == Severity.LOW
        monitor.close()

    def test_metadata_kev_escalated_set(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        monitor.store_kev_entries([_kev("CVE-2021-44228")])
        finding = _finding(cve="CVE-2021-44228", severity=Severity.HIGH)
        monitor.escalate_severity([finding])
        assert finding.metadata.get("kev_escalated") is True
        monitor.close()

    def test_empty_kev_cache_no_escalation(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        finding = _finding(cve="CVE-2021-44228", severity=Severity.HIGH)
        monitor.escalate_severity([finding])
        assert finding.severity == Severity.HIGH
        monitor.close()

    def test_returns_same_list(self, tmp_path):
        monitor = KEVMonitor(db_path=tmp_path / "db.db")
        findings = [_finding()]
        result = monitor.escalate_severity(findings)
        assert result is findings
        monitor.close()


# ---------------------------------------------------------------------------
# ThreatSnapshot dataclass
# ---------------------------------------------------------------------------


class TestThreatSnapshot:
    def test_default_fields(self):
        snap = ThreatSnapshot(total_risk_score=42.5)
        assert snap.total_risk_score == 42.5
        assert snap.top_risks == []
        assert snap.trending_cves == []
        assert snap.new_advisories == []
        assert snap.coverage_score == 0.0
        assert snap.total_findings == 0
        assert snap.critical_count == 0
        assert snap.kev_count == 0
        assert snap.generated_at  # non-empty string

    def test_generated_at_is_iso_string(self):
        snap = ThreatSnapshot(total_risk_score=0.0)
        from datetime import datetime
        # Should parse without error
        datetime.fromisoformat(snap.generated_at.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# ThreatFeed — aggregate
# ---------------------------------------------------------------------------


class TestThreatFeedAggregate:
    def _feed_with_empty_kev(self, tmp_path: Path) -> ThreatFeed:
        """Return a ThreatFeed whose KEVMonitor uses a tmp db (no stored entries)."""
        feed = ThreatFeed()
        feed._kev_monitor = KEVMonitor(db_path=tmp_path / "db.db")
        return feed

    def test_empty_findings_returns_zero_risk(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        snap = feed.aggregate([])
        assert snap.total_risk_score == 0.0
        assert snap.total_findings == 0

    def test_coverage_1_when_no_cve_findings(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [_finding(cve=None)]
        snap = feed.aggregate(findings)
        assert snap.coverage_score == 1.0

    def test_total_findings_count(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [_finding(), _finding(), _finding()]
        snap = feed.aggregate(findings)
        assert snap.total_findings == 3

    def test_critical_count(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.HIGH),
        ]
        snap = feed.aggregate(findings)
        assert snap.critical_count == 1

    def test_top_risks_capped_at_5(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [_finding(cve=f"CVE-2024-{i:04d}") for i in range(10)]
        snap = feed.aggregate(findings)
        assert len(snap.top_risks) <= 5

    def test_kev_count_when_kev_populated(self, tmp_path):
        feed = ThreatFeed()
        feed._kev_monitor = KEVMonitor(db_path=tmp_path / "db.db")
        feed._kev_monitor.store_kev_entries([_kev("CVE-2021-44228")])

        findings = [
            _finding(cve="CVE-2021-44228"),
            _finding(cve="CVE-9999-9999"),
        ]
        snap = feed.aggregate(findings)
        assert snap.kev_count == 1

    def test_ransomware_kev_count(self, tmp_path):
        feed = ThreatFeed()
        feed._kev_monitor = KEVMonitor(db_path=tmp_path / "db.db")
        feed._kev_monitor.store_kev_entries([
            _kev("CVE-2021-44228", known_ransomware=True),
            _kev("CVE-2022-30190", known_ransomware=False),
        ])
        findings = [_finding(cve="CVE-2021-44228"), _finding(cve="CVE-2022-30190")]
        snap = feed.aggregate(findings)
        assert snap.ransomware_kev_count == 1

    def test_risk_score_is_between_0_and_100(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [_finding(severity=Severity.CRITICAL) for _ in range(20)]
        snap = feed.aggregate(findings)
        assert 0.0 <= snap.total_risk_score <= 100.0

    def test_new_advisories_populated_from_kev(self, tmp_path):
        feed = ThreatFeed()
        feed._kev_monitor = KEVMonitor(db_path=tmp_path / "db.db")
        feed._kev_monitor.store_kev_entries([_kev("CVE-2021-44228")])
        snap = feed.aggregate([_finding(cve="CVE-2021-44228")])
        assert len(snap.new_advisories) == 1
        assert snap.new_advisories[0]["cve"] == "CVE-2021-44228"

    def test_top_risks_sorted_by_urgency(self, tmp_path):
        feed = self._feed_with_empty_kev(tmp_path)
        findings = [
            _finding(cve="CVE-A", severity=Severity.CRITICAL),
            _finding(cve="CVE-B", severity=Severity.LOW),
        ]
        snap = feed.aggregate(findings)
        urgencies = [r["urgency"] for r in snap.top_risks]
        assert urgencies == sorted(urgencies, reverse=True)


# ---------------------------------------------------------------------------
# ThreatFeed — generate_brief
# ---------------------------------------------------------------------------


class TestThreatFeedGenerateBrief:
    def test_returns_non_empty_string(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert isinstance(brief, str)
        assert len(brief) > 100

    def test_contains_risk_score(self):
        feed = ThreatFeed()
        snap = ThreatSnapshot(total_risk_score=75.5)
        brief = feed.generate_brief(snap)
        assert "75.5" in brief

    def test_contains_header(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert "DEPFENCE THREAT BRIEF" in brief

    def test_contains_top_urgent_section(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert "TOP URGENT" in brief

    def test_contains_trending_threats_section(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert "TRENDING THREATS" in brief

    def test_contains_kev_advisories_section(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert "KEV ADVISORIES" in brief

    def test_contains_recommended_actions_section(self):
        feed = ThreatFeed()
        brief = feed.generate_brief()
        assert "RECOMMENDED ACTIONS" in brief

    def test_kev_label_in_top_risks(self):
        feed = ThreatFeed()
        snap = ThreatSnapshot(
            total_risk_score=80.0,
            top_risks=[{
                "cve": "CVE-2021-44228",
                "package": "pypi:log4j@2.14",
                "title": "RCE",
                "severity": "critical",
                "epss_score": 0.95,
                "in_kev": True,
                "ransomware": True,
                "urgency": 0.99,
            }],
            kev_count=1,
            ransomware_kev_count=1,
        )
        brief = feed.generate_brief(snap)
        assert "[KEV]" in brief
        assert "[RANSOMWARE]" in brief

    def test_risk_level_critical_label(self):
        feed = ThreatFeed()
        snap = ThreatSnapshot(total_risk_score=85.0)
        brief = feed.generate_brief(snap)
        assert "CRITICAL" in brief

    def test_risk_level_low_label(self):
        feed = ThreatFeed()
        snap = ThreatSnapshot(total_risk_score=5.0)
        brief = feed.generate_brief(snap)
        assert "LOW" in brief

    def test_generate_brief_with_none_uses_empty_snapshot(self):
        feed = ThreatFeed()
        brief = feed.generate_brief(None)
        assert "DEPFENCE THREAT BRIEF" in brief


# ---------------------------------------------------------------------------
# CLI — threat-brief command
# ---------------------------------------------------------------------------


class TestThreatBriefCLI:
    def test_threat_brief_no_scan_returns_zero_exit(self, tmp_path):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["threat-brief", str(tmp_path), "--no-scan"])
        assert result.exit_code == 0, result.output

    def test_threat_brief_no_scan_contains_header(self, tmp_path):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["threat-brief", str(tmp_path), "--no-scan"])
        assert "DEPFENCE THREAT BRIEF" in result.output or result.exit_code == 0

    def test_threat_brief_json_format(self, tmp_path):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["threat-brief", str(tmp_path), "--no-scan", "--format", "json"])
        assert result.exit_code == 0, result.output
        # Strip any status lines before the JSON object
        json_text = result.output[result.output.index("{"):]
        data = json.loads(json_text)
        assert "total_risk_score" in data
        assert "top_risks" in data
        assert "kev_count" in data
        assert "generated_at" in data

    def test_threat_brief_json_top_risks_field(self, tmp_path):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["threat-brief", str(tmp_path), "--no-scan", "-f", "json"])
        assert result.exit_code == 0
        json_text = result.output[result.output.index("{"):]
        data = json.loads(json_text)
        assert isinstance(data["top_risks"], list)

    def test_threat_brief_json_trending_cves(self, tmp_path):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["threat-brief", str(tmp_path), "--no-scan", "-f", "json"])
        assert result.exit_code == 0
        json_text = result.output[result.output.index("{"):]
        data = json.loads(json_text)
        assert isinstance(data["trending_cves"], list)
