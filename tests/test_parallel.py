"""Tests for the parallel/concurrent monorepo scan orchestrator.

Covers:
- discover_lockfiles (recursive tree walk, depth limiting, exclusions)
- group_by_ecosystem
- _merge_results (deduplication logic)
- parallel_scan (async, semaphore, progress callback, empty-tree, error handling)
- CLI --parallel / -j flag wiring
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.parallel import (
    LockfileEntry,
    ParallelScanResult,
    _merge_results,
    discover_lockfiles,
    group_by_ecosystem,
    parallel_scan,
)
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _touch(path: Path, content: str = "") -> Path:
    """Create *path* (and parents) with optional *content*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _make_scan_result(
    target: str = ".",
    ecosystem: str = "npm",
    packages: int = 3,
    findings: list[Finding] | None = None,
    errors: list[str] | None = None,
) -> ScanResult:
    result = ScanResult(target=target, ecosystem=ecosystem)
    result.packages_scanned = packages
    result.findings = findings or []
    result.errors = errors or []
    return result


def _finding(
    name: str = "lodash",
    ecosystem: str = "npm",
    cve: str | None = "CVE-2021-0001",
    title: str = "Prototype Pollution",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem=ecosystem, name=name, version="1.0.0"),
        title=title,
        detail="Some detail",
        cve=cve,
    )


# ---------------------------------------------------------------------------
# discover_lockfiles
# ---------------------------------------------------------------------------

class TestDiscoverLockfiles:
    def test_finds_single_lockfile_at_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json", "{}")
            entries = discover_lockfiles(root)
            assert len(entries) == 1
            assert entries[0].ecosystem == "npm"
            assert entries[0].path == (root / "package-lock.json").resolve()

    def test_finds_nested_lockfiles(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            _touch(root / "backend" / "Cargo.lock")
            _touch(root / "infra" / "go.sum")
            entries = discover_lockfiles(root)
            names = {e.path.name for e in entries}
            assert names == {"package-lock.json", "Cargo.lock", "go.sum"}

    def test_excludes_node_modules(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            # lockfile inside node_modules must be ignored
            _touch(root / "node_modules" / "some-pkg" / "package-lock.json")
            entries = discover_lockfiles(root)
            assert len(entries) == 1

    def test_excludes_hidden_directories(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            _touch(root / ".git" / "package-lock.json")
            entries = discover_lockfiles(root)
            assert len(entries) == 1

    def test_respects_max_depth(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            deep = root / "a" / "b" / "c" / "d"
            deep.mkdir(parents=True)
            _touch(deep / "Cargo.lock")
            # depth 4 → should be found
            entries = discover_lockfiles(root, max_depth=10)
            assert len(entries) == 1
            # restrict to depth 2 → should be missed
            entries_shallow = discover_lockfiles(root, max_depth=2)
            assert len(entries_shallow) == 0

    def test_returns_empty_on_empty_directory(self):
        with tempfile.TemporaryDirectory() as d:
            entries = discover_lockfiles(Path(d))
            assert entries == []

    def test_sorted_shallower_first(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "sub" / "Cargo.lock")
            _touch(root / "package-lock.json")
            entries = discover_lockfiles(root)
            assert entries[0].path.name == "package-lock.json"

    def test_multiple_ecosystem_types(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            _touch(root / "poetry.lock")
            _touch(root / "Cargo.lock")
            _touch(root / "go.sum")
            entries = discover_lockfiles(root)
            ecosystems = {e.ecosystem for e in entries}
            assert ecosystems == {"npm", "pypi", "cargo", "go"}


# ---------------------------------------------------------------------------
# group_by_ecosystem
# ---------------------------------------------------------------------------

class TestGroupByEcosystem:
    def test_groups_correctly(self):
        entries = [
            LockfileEntry("npm", Path("a/package-lock.json")),
            LockfileEntry("npm", Path("b/yarn.lock")),
            LockfileEntry("cargo", Path("c/Cargo.lock")),
        ]
        groups = group_by_ecosystem(entries)
        assert set(groups.keys()) == {"npm", "cargo"}
        assert len(groups["npm"]) == 2
        assert len(groups["cargo"]) == 1

    def test_empty_input(self):
        assert group_by_ecosystem([]) == {}


# ---------------------------------------------------------------------------
# LockfileEntry
# ---------------------------------------------------------------------------

class TestLockfileEntry:
    def test_directory_property(self):
        entry = LockfileEntry("npm", Path("/repo/frontend/package-lock.json"))
        assert entry.directory == Path("/repo/frontend")

    def test_str_representation(self):
        entry = LockfileEntry("cargo", Path("/repo/Cargo.lock"))
        assert "cargo" in str(entry)
        assert "Cargo.lock" in str(entry)


# ---------------------------------------------------------------------------
# _merge_results
# ---------------------------------------------------------------------------

class TestMergeResults:
    def test_sums_packages_scanned(self):
        sub1 = _make_scan_result(packages=10)
        sub2 = _make_scan_result(packages=5)
        entry1 = LockfileEntry("npm", Path("a/package-lock.json"))
        entry2 = LockfileEntry("cargo", Path("b/Cargo.lock"))
        merged = _merge_results("/repo", [(entry1, sub1), (entry2, sub2)])
        assert merged.packages_scanned == 15

    def test_deduplicates_identical_findings(self):
        f = _finding("lodash", cve="CVE-2021-0001")
        sub1 = _make_scan_result(findings=[f])
        sub2 = _make_scan_result(findings=[f])  # same finding in two sub-results
        entry1 = LockfileEntry("npm", Path("a/package-lock.json"))
        entry2 = LockfileEntry("npm", Path("b/package-lock.json"))
        merged = _merge_results("/repo", [(entry1, sub1), (entry2, sub2)])
        assert len(merged.findings) == 1

    def test_keeps_distinct_findings(self):
        f1 = _finding("lodash", cve="CVE-2021-0001")
        f2 = _finding("express", cve="CVE-2022-9999")
        sub1 = _make_scan_result(findings=[f1])
        sub2 = _make_scan_result(findings=[f2])
        entry1 = LockfileEntry("npm", Path("a/package-lock.json"))
        entry2 = LockfileEntry("npm", Path("b/package-lock.json"))
        merged = _merge_results("/repo", [(entry1, sub1), (entry2, sub2)])
        assert len(merged.findings) == 2

    def test_dedup_uses_title_when_no_cve(self):
        f1 = _finding("lodash", cve=None, title="Behavioural risk")
        f2 = _finding("lodash", cve=None, title="Behavioural risk")
        sub1 = _make_scan_result(findings=[f1])
        sub2 = _make_scan_result(findings=[f2])
        entry1 = LockfileEntry("npm", Path("a/package-lock.json"))
        entry2 = LockfileEntry("npm", Path("b/package-lock.json"))
        merged = _merge_results("/repo", [(entry1, sub1), (entry2, sub2)])
        assert len(merged.findings) == 1

    def test_collects_errors(self):
        sub1 = _make_scan_result(errors=["parse error"])
        sub2 = _make_scan_result(errors=["network timeout"])
        entry1 = LockfileEntry("npm", Path("a/package-lock.json"))
        entry2 = LockfileEntry("cargo", Path("b/Cargo.lock"))
        merged = _merge_results("/repo", [(entry1, sub1), (entry2, sub2)])
        assert "parse error" in merged.errors
        assert "network timeout" in merged.errors

    def test_ecosystem_set_to_multi(self):
        sub = _make_scan_result()
        entry = LockfileEntry("npm", Path("a/package-lock.json"))
        merged = _merge_results("/repo", [(entry, sub)])
        assert merged.ecosystem == "multi"

    def test_empty_sub_results(self):
        merged = _merge_results("/repo", [])
        assert merged.packages_scanned == 0
        assert merged.findings == []


# ---------------------------------------------------------------------------
# ParallelScanResult
# ---------------------------------------------------------------------------

class TestParallelScanResult:
    def test_findings_delegates_to_merged(self):
        psr = ParallelScanResult(target="/repo")
        merged = _make_scan_result(findings=[_finding()])
        psr.merged = merged
        assert len(psr.findings) == 1

    def test_findings_empty_without_merged(self):
        psr = ParallelScanResult(target="/repo")
        assert psr.findings == []

    def test_packages_scanned_sums_sub_results(self):
        psr = ParallelScanResult(target="/repo")
        psr.sub_results = [
            (LockfileEntry("npm", Path("a/package-lock.json")), _make_scan_result(packages=7)),
            (LockfileEntry("cargo", Path("b/Cargo.lock")), _make_scan_result(packages=3)),
        ]
        assert psr.packages_scanned == 10

    def test_errors_aggregated_from_sub_results(self):
        psr = ParallelScanResult(target="/repo")
        psr.sub_results = [
            (LockfileEntry("npm", Path("a/package-lock.json")), _make_scan_result(errors=["err1"])),
        ]
        psr.merged = _make_scan_result(errors=["err2"])
        errs = psr.errors
        assert "err1" in errs
        assert "err2" in errs


# ---------------------------------------------------------------------------
# parallel_scan (async)
# ---------------------------------------------------------------------------

class TestParallelScan:
    """Tests that mock scan_directory so no real network calls are made."""

    def _make_mock_scan(self, packages: int = 5, findings: list[Finding] | None = None):
        result = _make_scan_result(packages=packages, findings=findings or [])

        async def _fake_scan_directory(*args, **kwargs):
            return result

        return _fake_scan_directory

    def test_returns_parallel_scan_result(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")

            with patch(
                "depfence.core.engine.scan_directory",
                new=self._make_mock_scan(),
            ):
                result = asyncio.run(parallel_scan(root, workers=2))

        assert isinstance(result, ParallelScanResult)
        assert result.merged is not None

    def test_no_lockfiles_returns_error(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = asyncio.run(parallel_scan(root))

        assert result.merged is not None
        assert any("No lockfiles" in e for e in result.merged.errors)

    def test_progress_callback_called(self):
        calls = []

        def cb(entry, done, total):
            calls.append((done, total))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            _touch(root / "backend" / "Cargo.lock")

            with patch(
                "depfence.core.engine.scan_directory",
                new=self._make_mock_scan(),
            ):
                asyncio.run(parallel_scan(root, workers=2, progress_callback=cb))

        # Two unique directories → two callbacks
        assert len(calls) == 2
        # Last call should say done==total
        assert calls[-1][0] == calls[-1][1]

    def test_ecosystem_filter(self):
        scanned_dirs = []

        async def _fake_scan(directory, **kwargs):
            scanned_dirs.append(directory)
            return _make_scan_result(target=str(directory))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")
            _touch(root / "backend" / "Cargo.lock")

            with patch("depfence.core.engine.scan_directory", new=_fake_scan):
                asyncio.run(parallel_scan(root, workers=2, ecosystems=["cargo"]))

        # Only the cargo directory should have been scanned
        assert len(scanned_dirs) == 1
        assert "backend" in str(scanned_dirs[0])

    def test_deduplicates_same_directory(self):
        """Two lockfiles in the same dir → scan that dir only once."""
        scanned = []

        async def _fake_scan(directory, **kwargs):
            scanned.append(directory)
            return _make_scan_result(target=str(directory))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Both lockfiles share the same parent directory
            _touch(root / "package-lock.json")
            _touch(root / "yarn.lock")

            with patch("depfence.core.engine.scan_directory", new=_fake_scan):
                asyncio.run(parallel_scan(root, workers=2))

        assert len(scanned) == 1

    def test_scan_error_captured_in_result(self):
        async def _erroring_scan(directory, **kwargs):
            raise RuntimeError("simulated failure")

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")

            with patch("depfence.core.engine.scan_directory", new=_erroring_scan):
                result = asyncio.run(parallel_scan(root, workers=1))

        all_errors = result.errors
        assert any("simulated failure" in e for e in all_errors)

    def test_semaphore_limits_concurrency(self):
        """Verify that with workers=1 scans are serialised (no overlap)."""
        active = []
        peak = []

        async def _fake_scan(directory, **kwargs):
            active.append(1)
            peak.append(len(active))
            await asyncio.sleep(0)  # yield
            active.pop()
            return _make_scan_result(target=str(directory))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "pkg1" / "package-lock.json")
            _touch(root / "pkg2" / "Cargo.lock")

            with patch("depfence.core.engine.scan_directory", new=_fake_scan):
                asyncio.run(parallel_scan(root, workers=1))

        # With 1 worker, peak concurrency should never exceed 1
        assert max(peak) <= 1

    def test_merged_findings_deduplicated(self):
        shared_finding = _finding("lodash", cve="CVE-2021-0001")

        async def _fake_scan(directory, **kwargs):
            return _make_scan_result(
                target=str(directory), findings=[shared_finding]
            )

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "pkg1" / "package-lock.json")
            _touch(root / "pkg2" / "yarn.lock")

            with patch("depfence.core.engine.scan_directory", new=_fake_scan):
                result = asyncio.run(parallel_scan(root, workers=2))

        # Same finding from two directories → deduplicated to 1
        assert len(result.findings) == 1

    def test_completed_at_set(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _touch(root / "package-lock.json")

            with patch(
                "depfence.core.engine.scan_directory",
                new=self._make_mock_scan(),
            ):
                result = asyncio.run(parallel_scan(root))

        assert result.completed_at is not None


# ---------------------------------------------------------------------------
# CLI integration — --parallel / -j flags
# ---------------------------------------------------------------------------

class TestCLIParallelFlags:
    """Smoke-test the CLI flags without running real scans."""

    def test_parallel_flag_triggers_parallel_scan(self):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        called_with = {}

        async def _fake_parallel_scan(root, workers, **kwargs):
            called_with["root"] = root
            called_with["workers"] = workers
            psr = ParallelScanResult(target=str(root))
            psr.merged = _make_scan_result()
            return psr

        with tempfile.TemporaryDirectory() as d:
            _touch(Path(d) / "package-lock.json")
            runner = CliRunner()

            with patch("depfence.core.parallel.parallel_scan", new=_fake_parallel_scan):
                result = runner.invoke(cli, ["scan", d, "--parallel", "--no-fetch", "--no-enrich"])

        assert result.exit_code == 0
        assert called_with.get("workers") == 1  # default

    def test_j_flag_sets_workers(self):
        from click.testing import CliRunner
        from depfence.cli.main import cli

        called_with = {}

        async def _fake_parallel_scan(root, workers, **kwargs):
            called_with["workers"] = workers
            psr = ParallelScanResult(target=str(root))
            psr.merged = _make_scan_result()
            return psr

        with tempfile.TemporaryDirectory() as d:
            _touch(Path(d) / "package-lock.json")
            runner = CliRunner()

            with patch("depfence.core.parallel.parallel_scan", new=_fake_parallel_scan):
                result = runner.invoke(cli, ["scan", d, "-j", "8", "--no-fetch", "--no-enrich"])

        assert result.exit_code == 0
        assert called_with.get("workers") == 8

    def test_no_parallel_uses_normal_scan(self):
        """Without --parallel or -j > 1, scan_directory is called directly."""
        from click.testing import CliRunner
        from depfence.cli.main import cli

        scan_dir_called = []

        async def _fake_scan_directory(project_dir, **kwargs):
            scan_dir_called.append(project_dir)
            return _make_scan_result()

        with tempfile.TemporaryDirectory() as d:
            _touch(Path(d) / "package-lock.json")
            runner = CliRunner()

            with patch("depfence.core.engine.scan_directory", new=_fake_scan_directory):
                result = runner.invoke(cli, ["scan", d, "--no-fetch", "--no-enrich"])

        assert result.exit_code == 0
        assert len(scan_dir_called) == 1

    def test_j_1_does_not_trigger_parallel(self):
        """-j 1 (the minimum) should NOT activate the parallel path."""
        from click.testing import CliRunner
        from depfence.cli.main import cli

        parallel_called = []

        async def _fake_parallel_scan(root, workers, **kwargs):
            parallel_called.append(True)
            psr = ParallelScanResult(target=str(root))
            psr.merged = _make_scan_result()
            return psr

        async def _fake_scan_directory(project_dir, **kwargs):
            return _make_scan_result()

        with tempfile.TemporaryDirectory() as d:
            _touch(Path(d) / "package-lock.json")
            runner = CliRunner()

            with (
                patch("depfence.core.parallel.parallel_scan", new=_fake_parallel_scan),
                patch("depfence.core.engine.scan_directory", new=_fake_scan_directory),
            ):
                result = runner.invoke(cli, ["scan", d, "-j", "1", "--no-fetch", "--no-enrich"])

        assert result.exit_code == 0
        assert len(parallel_called) == 0
