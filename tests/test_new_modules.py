"""Tests for simulate, remediate, intel, and watcher modules."""

import pytest
import tempfile
from pathlib import Path
from depfence.simulate.attacks import AttackSimulator, SimulationResult, RiskLevel
from depfence.simulate.red_team import RedTeamReport, AttackOutcome
from depfence.remediate.pr_generator import RemediationPR, PullRequestDraft
from depfence.remediate.strategies import VersionBumpStrategy, ReplaceStrategy, RemoveStrategy
from depfence.intel.epss_tracker import EPSSTracker, EPSSTrend
from depfence.core.watcher import FileWatcher
from depfence.core.models import Finding, FindingType, Severity, PackageId


class TestAttackSimulator:
    def test_init(self):
        sim = AttackSimulator()
        assert sim is not None

    def test_simulate_typosquat_returns_result(self):
        sim = AttackSimulator()
        result = sim.simulate_typosquat("requests", "pypi")
        assert isinstance(result, SimulationResult)
        assert result.attack_type == "typosquatting"
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.CRITICAL)

    def test_simulate_typosquat_detection(self):
        sim = AttackSimulator()
        result = sim.simulate_typosquat("lodash", "npm")
        assert result.would_be_detected is True
        assert result.detection_coverage > 0

    def test_simulate_typosquat_has_candidates(self):
        sim = AttackSimulator()
        result = sim.simulate_typosquat("numpy", "pypi")
        assert "squatted_candidates" in result.attacker_artifacts
        assert len(result.attacker_artifacts["squatted_candidates"]) > 0

    def test_simulate_dep_confusion(self):
        sim = AttackSimulator()
        result = sim.simulate_dep_confusion("acme")
        assert isinstance(result, SimulationResult)
        assert result.attack_type == "dependency_confusion"

    def test_simulate_dep_confusion_mitigations(self):
        sim = AttackSimulator()
        result = sim.simulate_dep_confusion("mycompany")
        assert len(result.mitigations) > 0
        assert len(result.detection_methods) > 0

    def test_simulate_typosquat_different_ecosystems(self):
        sim = AttackSimulator()
        npm_result = sim.simulate_typosquat("express", "npm")
        pypi_result = sim.simulate_typosquat("flask", "pypi")
        assert npm_result.attacker_artifacts["ecosystem"] == "npm"
        assert pypi_result.attacker_artifacts["ecosystem"] == "pypi"


class TestRedTeam:
    def test_report_has_score(self):
        report = RedTeamReport(
            project_dir=Path("."),
            outcomes=[],
            configuration_improvements=[],
            score=85.0,
        )
        assert report.score == 85.0

    def test_report_with_outcomes(self):
        sim = AttackSimulator()
        result = sim.simulate_typosquat("requests", "pypi")
        outcome = AttackOutcome(
            simulation=result,
            configuration_gap=None,
        )
        report = RedTeamReport(
            project_dir=Path("."),
            outcomes=[outcome],
            configuration_improvements=[],
            score=75.0,
        )
        assert len(report.outcomes) == 1


class TestRemediation:
    def test_pr_draft_structure(self):
        draft = PullRequestDraft(
            title="Fix CVE-2024-1234 in requests",
            body="Updates requests from 2.28.0 to 2.31.0",
            branch="depfence/fix-CVE-2024-1234",
            files_changed=["requirements.txt"],
            findings_fixed=1,
        )
        assert "CVE-2024-1234" in draft.title
        assert draft.findings_fixed == 1

    def test_version_bump_strategy_from_finding(self):
        finding = Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package=PackageId("pypi", "requests", "2.28.0"),
            title="CVE-2024-1234",
            detail="RCE in requests",
            fix_version="2.31.0",
        )
        strategy = VersionBumpStrategy.from_finding(finding)
        assert strategy.package == "requests"
        assert strategy.fix_version == "2.31.0"

    def test_remove_strategy(self):
        strategy = RemoveStrategy(package="malicious-pkg", ecosystem="npm")
        assert strategy.package == "malicious-pkg"

    def test_remediation_pr_init(self):
        rpr = RemediationPR()
        assert rpr is not None


class TestEPSSTracker:
    def test_init_creates_db(self):
        with tempfile.TemporaryDirectory() as td:
            tracker = EPSSTracker(db_path=Path(td) / "test.db")
            assert tracker is not None

    def test_record_and_get(self):
        with tempfile.TemporaryDirectory() as td:
            tracker = EPSSTracker(db_path=Path(td) / "test.db")
            tracker.record("CVE-2024-1234", 0.85, 0.97)
            trend = tracker.get_trend("CVE-2024-1234")
            assert trend is not None
            assert trend.current_score == 0.85

    def test_record_multiple(self):
        with tempfile.TemporaryDirectory() as td:
            tracker = EPSSTracker(db_path=Path(td) / "test.db")
            tracker.record("CVE-2024-1234", 0.5, 0.7)
            tracker.record("CVE-2024-1234", 0.6, 0.75)
            tracker.record("CVE-2024-1234", 0.85, 0.97)
            trend = tracker.get_trend("CVE-2024-1234")
            assert trend.current_score == 0.85

    def test_get_rising(self):
        with tempfile.TemporaryDirectory() as td:
            tracker = EPSSTracker(db_path=Path(td) / "test.db")
            tracker.record("CVE-2024-1111", 0.1, 0.3)
            tracker.record("CVE-2024-1111", 0.9, 0.99)
            rising = tracker.get_rising(threshold=0.1)
            assert isinstance(rising, list)

    def test_nonexistent_cve(self):
        with tempfile.TemporaryDirectory() as td:
            tracker = EPSSTracker(db_path=Path(td) / "test.db")
            trend = tracker.get_trend("CVE-9999-0000")
            assert trend is None or trend.current_score == 0.0


class TestFileWatcher:
    def test_init(self):
        with tempfile.TemporaryDirectory() as td:
            watcher = FileWatcher(Path(td), on_change=lambda e: None)
            assert watcher is not None

    def test_debounce_default(self):
        with tempfile.TemporaryDirectory() as td:
            watcher = FileWatcher(Path(td), on_change=lambda e: None)
            assert watcher.debounce_seconds == 2.0

    def test_custom_debounce(self):
        with tempfile.TemporaryDirectory() as td:
            watcher = FileWatcher(Path(td), on_change=lambda e: None, debounce_seconds=5.0)
            assert watcher.debounce_seconds == 5.0

    def test_force_polling(self):
        with tempfile.TemporaryDirectory() as td:
            watcher = FileWatcher(Path(td), on_change=lambda e: None, force_polling=True)
            assert watcher.force_polling is True
