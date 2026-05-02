"""Tests for depfence.core.drift and depfence.core.history."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfence.core.drift import (
    DriftDetector,
    DriftReport,
    LockfileDiff,
    VersionChange,
    _parse_packages_from_bytes,
    _run_git,
)
from depfence.core.history import ScanDelta, ScanHistory, ScanSnapshot, _project_hash
from depfence.core.models import Finding, FindingType, PackageId, Severity, ScanResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a minimal git repository with a requirements.txt lockfile."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, capture_output=True)

    req = repo / "requirements.txt"
    req.write_text("requests==2.28.0\nflask==2.2.0\n")
    subprocess.run(["git", "add", "requirements.txt"], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True)
    return repo


@pytest.fixture
def history_db(tmp_path: Path) -> ScanHistory:
    return ScanHistory(db_dir=tmp_path)


def _make_scan_result(
    target: str = "/fake/project",
    ecosystem: str = "pypi",
    pkg_count: int = 3,
    critical: int = 0,
    high: int = 0,
) -> ScanResult:
    result = ScanResult(target=target, ecosystem=ecosystem)
    result.packages_scanned = pkg_count
    result.completed_at = datetime.now(timezone.utc)
    findings = []
    for i in range(critical):
        findings.append(
            Finding(
                finding_type=FindingType.KNOWN_VULN,
                severity=Severity.CRITICAL,
                package=PackageId("pypi", f"vuln-pkg-{i}", "1.0.0"),
                title="CVE",
                detail="critical",
            )
        )
    for i in range(high):
        findings.append(
            Finding(
                finding_type=FindingType.KNOWN_VULN,
                severity=Severity.HIGH,
                package=PackageId("pypi", f"high-pkg-{i}", "1.0.0"),
                title="CVE",
                detail="high",
            )
        )
    result.findings = findings
    return result


def _make_snapshot(
    history: ScanHistory,
    project_path: str,
    packages: list[PackageId],
    findings: list[dict] | None = None,
    ts: datetime | None = None,
) -> ScanSnapshot:
    result = ScanResult(
        target=project_path,
        ecosystem="pypi",
        completed_at=ts or datetime.now(timezone.utc),
    )
    result.packages_scanned = len(packages)
    result.findings = []
    sid = history.record_scan(result, packages=packages, project_path=project_path)
    snap = history.get_snapshot_by_id(sid)
    assert snap is not None
    return snap


# ===========================================================================
# VersionChange tests
# ===========================================================================

class TestVersionChange:
    def test_major_bump_detected(self):
        vc = VersionChange("requests", "pypi", "1.9.0", "2.0.0")
        assert vc.is_major_bump is True

    def test_minor_bump_not_major(self):
        vc = VersionChange("requests", "pypi", "2.27.0", "2.28.0")
        assert vc.is_major_bump is False

    def test_patch_bump_not_major(self):
        vc = VersionChange("requests", "pypi", "2.28.0", "2.28.1")
        assert vc.is_major_bump is False

    def test_same_version_not_major(self):
        vc = VersionChange("requests", "pypi", "2.28.0", "2.28.0")
        assert vc.is_major_bump is False

    def test_str_representation(self):
        vc = VersionChange("flask", "pypi", "2.0.0", "3.0.0")
        assert "flask" in str(vc)
        assert "2.0.0" in str(vc)
        assert "3.0.0" in str(vc)

    def test_none_version_graceful(self):
        vc = VersionChange("pkg", "pypi", None, "1.0.0")
        # Should not raise
        _ = vc.is_major_bump


# ===========================================================================
# LockfileDiff tests
# ===========================================================================

class TestLockfileDiff:
    def test_is_clean_when_empty(self):
        diff = LockfileDiff()
        assert diff.is_clean is True
        assert diff.total_changes == 0

    def test_not_clean_with_additions(self):
        diff = LockfileDiff(additions=[PackageId("pypi", "evil", "1.0")])
        assert diff.is_clean is False
        assert diff.total_changes == 1

    def test_major_bumps_filtered(self):
        diff = LockfileDiff(
            version_changes=[
                VersionChange("a", "pypi", "1.0.0", "2.0.0"),
                VersionChange("b", "pypi", "2.0.0", "2.1.0"),
            ]
        )
        assert len(diff.major_bumps) == 1
        assert diff.major_bumps[0].name == "a"

    def test_to_dict_structure(self):
        pkg = PackageId("npm", "lodash", "4.17.21")
        diff = LockfileDiff(additions=[pkg])
        d = diff.to_dict()
        assert "additions" in d
        assert "removals" in d
        assert "version_changes" in d
        assert "new_ecosystems" in d
        assert d["is_clean"] is False

    def test_new_ecosystems_tracked(self):
        diff = LockfileDiff(new_ecosystems=["cargo"])
        assert "cargo" in diff.new_ecosystems


# ===========================================================================
# DriftReport tests
# ===========================================================================

class TestDriftReport:
    def test_clean_report(self):
        report = DriftReport(is_clean=True)
        assert report.is_clean is True
        assert report.supply_chain_risk_packages == []
        assert report.major_version_jumps == []

    def test_supply_chain_risk_packages(self):
        pkg = PackageId("pypi", "evil-pkg", "1.0.0")
        report = DriftReport(added=[pkg], is_clean=False)
        assert pkg in report.supply_chain_risk_packages

    def test_major_version_jumps(self):
        vc_major = VersionChange("requests", "pypi", "1.0.0", "2.0.0")
        vc_minor = VersionChange("flask", "pypi", "2.0.0", "2.1.0")
        report = DriftReport(updated=[vc_major, vc_minor], is_clean=False)
        assert len(report.major_version_jumps) == 1

    def test_to_dict_has_all_keys(self):
        report = DriftReport(is_clean=True)
        d = report.to_dict()
        for key in ("lockfile_path", "is_clean", "git_available", "added", "removed", "updated"):
            assert key in d

    def test_render_table_clean(self):
        report = DriftReport(is_clean=True)
        out = report.render_table()
        assert "No drift" in out

    def test_render_table_with_additions(self):
        report = DriftReport(
            added=[PackageId("pypi", "evil", "1.0.0")],
            is_clean=False,
        )
        out = report.render_table()
        assert "evil" in out
        assert "added" in out.lower() or "+" in out

    def test_render_table_with_error(self):
        report = DriftReport(error="git not found", is_clean=True)
        out = report.render_table()
        assert "Error" in out

    def test_render_table_with_removals(self):
        report = DriftReport(
            removed=[PackageId("pypi", "old-pkg", "0.9.0")],
            is_clean=False,
        )
        out = report.render_table()
        assert "old-pkg" in out

    def test_render_table_with_version_changes(self):
        vc = VersionChange("requests", "pypi", "2.27.0", "3.0.0")
        report = DriftReport(updated=[vc], is_clean=False)
        out = report.render_table()
        assert "requests" in out
        assert "MAJOR" in out


# ===========================================================================
# DriftDetector._compute_lockfile_diff tests
# ===========================================================================

class TestComputeLockfileDiff:
    def _diff(self, old, new):
        return DriftDetector._compute_lockfile_diff(old, new)

    def test_addition_detected(self):
        old = [PackageId("pypi", "requests", "2.28.0")]
        new = [PackageId("pypi", "requests", "2.28.0"), PackageId("pypi", "evil", "1.0.0")]
        diff = self._diff(old, new)
        assert len(diff.additions) == 1
        assert diff.additions[0].name == "evil"

    def test_removal_detected(self):
        old = [PackageId("pypi", "requests", "2.28.0"), PackageId("pypi", "old", "1.0.0")]
        new = [PackageId("pypi", "requests", "2.28.0")]
        diff = self._diff(old, new)
        assert len(diff.removals) == 1
        assert diff.removals[0].name == "old"

    def test_version_change_detected(self):
        old = [PackageId("pypi", "flask", "2.0.0")]
        new = [PackageId("pypi", "flask", "3.0.0")]
        diff = self._diff(old, new)
        assert len(diff.version_changes) == 1
        assert diff.version_changes[0].old_version == "2.0.0"
        assert diff.version_changes[0].new_version == "3.0.0"

    def test_no_changes(self):
        pkgs = [PackageId("pypi", "requests", "2.28.0")]
        diff = self._diff(pkgs, pkgs)
        assert diff.is_clean is True

    def test_multiple_ecosystems(self):
        old = [PackageId("pypi", "flask", "2.0.0")]
        new = [PackageId("npm", "lodash", "4.17.21")]
        diff = self._diff(old, new)
        assert len(diff.additions) == 1
        assert len(diff.removals) == 1


# ===========================================================================
# DriftDetector.detect_drift tests (mocked git)
# ===========================================================================

class TestDriftDetectorDetectDrift:
    def test_no_lockfiles_returns_clean_with_error(self, tmp_dir):
        detector = DriftDetector()
        report = detector.detect_drift(tmp_dir)
        assert report.error is not None

    def test_not_git_repo_sets_flag(self, tmp_dir):
        (tmp_dir / "requirements.txt").write_text("requests==2.28.0\n")
        detector = DriftDetector()
        with patch("depfence.core.drift._run_git") as mock_git:
            mock_git.return_value = (False, b"", "not a git repository")
            report = detector.detect_drift(tmp_dir)
        assert report.git_available is False

    def test_untracked_lockfile_all_packages_added(self, tmp_dir):
        (tmp_dir / "requirements.txt").write_text("requests==2.28.0\n")
        detector = DriftDetector()
        with patch("depfence.core.drift._run_git") as mock_git:
            # File not in git
            mock_git.return_value = (False, b"", "does not exist in HEAD")
            report = detector.detect_drift(tmp_dir)
        # Current packages treated as additions
        assert len(report.added) > 0

    def test_clean_when_lockfile_matches_head(self, git_repo):
        detector = DriftDetector()
        # File on disk matches HEAD (no changes made after commit)
        report = detector.detect_drift(git_repo)
        assert report.is_clean is True
        assert report.error is None

    def test_drift_detected_after_modification(self, git_repo):
        req = git_repo / "requirements.txt"
        req.write_text("requests==2.28.0\nflask==2.2.0\nevil-package==1.0.0\n")
        detector = DriftDetector()
        report = detector.detect_drift(git_repo)
        assert report.is_clean is False
        names = [p.name for p in report.added]
        assert "evil-package" in names


# ===========================================================================
# DriftDetector.detect_ci_drift tests
# ===========================================================================

class TestDetectCiDrift:
    def test_no_drift_when_matches_head(self, git_repo):
        detector = DriftDetector()
        lf = git_repo / "requirements.txt"
        assert detector.detect_ci_drift(lf) is False

    def test_drift_detected_when_file_modified(self, git_repo):
        lf = git_repo / "requirements.txt"
        lf.write_text("requests==2.28.0\nevil==1.0.0\n")
        detector = DriftDetector()
        assert detector.detect_ci_drift(lf) is True

    def test_non_git_repo_returns_false(self, tmp_dir):
        lf = tmp_dir / "requirements.txt"
        lf.write_text("requests==2.28.0\n")
        detector = DriftDetector()
        result = detector.detect_ci_drift(lf)
        assert result is False  # graceful — not a git repo

    def test_untracked_file_returns_false(self, git_repo):
        # A file not committed to git
        lf = git_repo / "new_requirements.txt"
        lf.write_text("somepackage==1.0.0\n")
        detector = DriftDetector()
        result = detector.detect_ci_drift(lf)
        assert result is False


# ===========================================================================
# DriftDetector.compare_lockfiles tests
# ===========================================================================

class TestCompareLockfiles:
    def test_compare_two_requirements_files(self, tmp_dir):
        # Use canonical filenames so _guess_ecosystem_from_path recognises them
        old_dir = tmp_dir / "old"
        new_dir = tmp_dir / "new"
        old_dir.mkdir()
        new_dir.mkdir()
        old = old_dir / "requirements.txt"
        new = new_dir / "requirements.txt"
        old.write_text("requests==2.28.0\nflask==2.2.0\n")
        new.write_text("requests==2.28.0\nflask==3.0.0\nevil==1.0.0\n")

        detector = DriftDetector()
        diff = detector.compare_lockfiles(old, new)
        assert len(diff.additions) == 1
        assert diff.additions[0].name == "evil"
        assert len(diff.version_changes) == 1
        assert diff.version_changes[0].new_version == "3.0.0"

    def test_identical_files_clean(self, tmp_dir):
        lf = tmp_dir / "requirements.txt"
        lf.write_text("requests==2.28.0\n")
        detector = DriftDetector()
        diff = detector.compare_lockfiles(lf, lf)
        assert diff.is_clean is True


# ===========================================================================
# ScanHistory tests
# ===========================================================================

class TestScanHistory:
    def test_db_created(self, tmp_dir):
        h = ScanHistory(db_dir=tmp_dir)
        assert (tmp_dir / "scan_history.db").exists()

    def test_record_scan_returns_id(self, history_db, tmp_dir):
        result = _make_scan_result(target=str(tmp_dir))
        sid = history_db.record_scan(result, project_path=str(tmp_dir))
        assert isinstance(sid, int)
        assert sid > 0

    def test_get_last_returns_snapshots(self, history_db, tmp_dir):
        result = _make_scan_result(target=str(tmp_dir))
        history_db.record_scan(result, project_path=str(tmp_dir))
        snaps = history_db.get_last(project_path=str(tmp_dir))
        assert len(snaps) == 1

    def test_get_last_respects_n_limit(self, history_db, tmp_dir):
        for _ in range(5):
            result = _make_scan_result(target=str(tmp_dir))
            history_db.record_scan(result, project_path=str(tmp_dir))
        snaps = history_db.get_last(project_path=str(tmp_dir), n=3)
        assert len(snaps) == 3

    def test_get_last_empty_when_no_scans(self, history_db, tmp_dir):
        snaps = history_db.get_last(project_path=str(tmp_dir))
        assert snaps == []

    def test_snapshot_has_correct_fields(self, history_db, tmp_dir):
        pkgs = [PackageId("pypi", "requests", "2.28.0")]
        result = _make_scan_result(target=str(tmp_dir))
        sid = history_db.record_scan(result, packages=pkgs, project_path=str(tmp_dir))
        snap = history_db.get_snapshot_by_id(sid)
        assert snap is not None
        assert snap.packages_scanned == 3  # from _make_scan_result default
        assert snap.ecosystem == "pypi"

    def test_snapshot_packages_roundtrip(self, history_db, tmp_dir):
        pkgs = [PackageId("pypi", "flask", "2.2.0"), PackageId("npm", "lodash", "4.17.21")]
        result = _make_scan_result(target=str(tmp_dir))
        sid = history_db.record_scan(result, packages=pkgs, project_path=str(tmp_dir))
        snap = history_db.get_snapshot_by_id(sid)
        assert len(snap.packages) == 2

    def test_finding_counts_stored(self, history_db, tmp_dir):
        result = _make_scan_result(target=str(tmp_dir), critical=2, high=1)
        sid = history_db.record_scan(result, project_path=str(tmp_dir))
        snap = history_db.get_snapshot_by_id(sid)
        assert snap.critical_count == 2
        assert snap.high_count == 1
        assert snap.finding_count == 3

    def test_delete_project_history(self, history_db, tmp_dir):
        result = _make_scan_result(target=str(tmp_dir))
        history_db.record_scan(result, project_path=str(tmp_dir))
        deleted = history_db.delete_project_history(project_path=str(tmp_dir))
        assert deleted == 1
        snaps = history_db.get_last(project_path=str(tmp_dir))
        assert snaps == []

    def test_different_projects_isolated(self, history_db, tmp_path):
        proj_a = tmp_path / "proj_a"
        proj_b = tmp_path / "proj_b"
        proj_a.mkdir()
        proj_b.mkdir()
        history_db.record_scan(_make_scan_result(target=str(proj_a)), project_path=str(proj_a))
        history_db.record_scan(_make_scan_result(target=str(proj_b)), project_path=str(proj_b))
        snaps_a = history_db.get_last(project_path=str(proj_a))
        snaps_b = history_db.get_last(project_path=str(proj_b))
        assert len(snaps_a) == 1
        assert len(snaps_b) == 1

    def test_get_all_returns_all_snapshots(self, history_db, tmp_dir):
        for _ in range(7):
            history_db.record_scan(_make_scan_result(target=str(tmp_dir)), project_path=str(tmp_dir))
        all_snaps = history_db.get_all(project_path=str(tmp_dir))
        assert len(all_snaps) == 7


# ===========================================================================
# ScanHistory.compare tests
# ===========================================================================

class TestScanHistoryCompare:
    def test_no_changes(self, history_db, tmp_dir):
        pkgs = [PackageId("pypi", "requests", "2.28.0")]
        snap1 = _make_snapshot(history_db, str(tmp_dir), pkgs)
        snap2 = _make_snapshot(history_db, str(tmp_dir), pkgs)
        delta = history_db.compare(snap1, snap2)
        assert delta.is_clean is True

    def test_new_package_detected(self, history_db, tmp_dir):
        old_pkgs = [PackageId("pypi", "requests", "2.28.0")]
        new_pkgs = [PackageId("pypi", "requests", "2.28.0"), PackageId("pypi", "evil", "1.0.0")]
        snap1 = _make_snapshot(history_db, str(tmp_dir), old_pkgs)
        snap2 = _make_snapshot(history_db, str(tmp_dir), new_pkgs)
        delta = history_db.compare(snap1, snap2)
        assert len(delta.new_packages) == 1
        assert delta.new_packages[0].name == "evil"

    def test_removed_package_detected(self, history_db, tmp_dir):
        old_pkgs = [PackageId("pypi", "requests", "2.28.0"), PackageId("pypi", "old", "1.0.0")]
        new_pkgs = [PackageId("pypi", "requests", "2.28.0")]
        snap1 = _make_snapshot(history_db, str(tmp_dir), old_pkgs)
        snap2 = _make_snapshot(history_db, str(tmp_dir), new_pkgs)
        delta = history_db.compare(snap1, snap2)
        assert len(delta.removed_packages) == 1
        assert delta.removed_packages[0].name == "old"

    def test_version_change_detected(self, history_db, tmp_dir):
        snap1 = _make_snapshot(history_db, str(tmp_dir), [PackageId("pypi", "flask", "2.0.0")])
        snap2 = _make_snapshot(history_db, str(tmp_dir), [PackageId("pypi", "flask", "3.0.0")])
        delta = history_db.compare(snap1, snap2)
        assert len(delta.version_changes) == 1
        assert delta.version_changes[0]["old"] == "2.0.0"
        assert delta.version_changes[0]["new"] == "3.0.0"

    def test_regression_flag(self, history_db, tmp_dir):
        snap1 = _make_snapshot(history_db, str(tmp_dir), [])
        snap2 = _make_snapshot(history_db, str(tmp_dir), [])
        # Manually inject a critical finding into snap2 summary
        snap2.findings_summary = [
            {"finding_type": "known_vulnerability", "severity": "critical", "package": "pypi:evil@1.0"}
        ]
        delta = history_db.compare(snap1, snap2)
        assert delta.regression is True

    def test_compare_last_two_none_when_insufficient(self, history_db, tmp_dir):
        result = _make_scan_result(target=str(tmp_dir))
        history_db.record_scan(result, project_path=str(tmp_dir))
        delta = history_db.compare_last_two(str(tmp_dir))
        assert delta is None

    def test_compare_last_two_returns_delta(self, history_db, tmp_dir):
        history_db.record_scan(_make_scan_result(target=str(tmp_dir)), project_path=str(tmp_dir))
        history_db.record_scan(_make_scan_result(target=str(tmp_dir)), project_path=str(tmp_dir))
        delta = history_db.compare_last_two(str(tmp_dir))
        assert delta is not None
        assert isinstance(delta, ScanDelta)


# ===========================================================================
# ScanDelta tests
# ===========================================================================

class TestScanDelta:
    def test_is_clean_when_empty(self):
        delta = ScanDelta(old_snapshot_id=1, new_snapshot_id=2)
        assert delta.is_clean is True

    def test_not_clean_with_new_packages(self):
        delta = ScanDelta(
            old_snapshot_id=1,
            new_snapshot_id=2,
            new_packages=[PackageId("pypi", "evil", "1.0.0")],
        )
        assert delta.is_clean is False

    def test_render_table_clean(self):
        delta = ScanDelta(old_snapshot_id=1, new_snapshot_id=2)
        out = delta.render_table()
        assert "No changes" in out

    def test_render_table_shows_packages(self):
        delta = ScanDelta(
            old_snapshot_id=1,
            new_snapshot_id=2,
            new_packages=[PackageId("pypi", "evil", "1.0.0")],
            removed_packages=[PackageId("pypi", "old", "0.9.0")],
        )
        out = delta.render_table()
        assert "evil" in out
        assert "old" in out

    def test_to_dict_structure(self):
        delta = ScanDelta(old_snapshot_id=1, new_snapshot_id=2)
        d = delta.to_dict()
        for key in ("new_findings", "resolved_findings", "new_packages", "removed_packages", "is_clean"):
            assert key in d


# ===========================================================================
# _project_hash tests
# ===========================================================================

class TestProjectHash:
    def test_same_path_same_hash(self, tmp_dir):
        h1 = _project_hash(str(tmp_dir))
        h2 = _project_hash(str(tmp_dir))
        assert h1 == h2

    def test_different_paths_different_hash(self, tmp_path):
        p1 = tmp_path / "a"
        p2 = tmp_path / "b"
        assert _project_hash(str(p1)) != _project_hash(str(p2))


# ===========================================================================
# _run_git helper tests
# ===========================================================================

class TestRunGit:
    def test_valid_command(self, tmp_dir):
        # git --version always works
        ok, out, err = _run_git(["--version"], cwd=tmp_dir)
        assert ok is True
        assert b"git" in out.lower()

    def test_failing_command(self, tmp_dir):
        ok, out, err = _run_git(["show", "HEAD:nonexistent_file.txt"], cwd=tmp_dir)
        assert ok is False

    def test_no_git_binary(self, tmp_dir):
        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            ok, out, err = _run_git(["--version"], cwd=tmp_dir)
        assert ok is False
        assert out == b""
