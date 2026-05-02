"""Tests for the async scan orchestrator.

All network calls are mocked — no real HTTP is made.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.core.orchestrator import EnrichmentResult, ScanOrchestrator, ScanPipelineResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg(name: str = "requests", ecosystem: str = "pypi", version: str = "2.28.0") -> PackageId:
    return PackageId(ecosystem=ecosystem, name=name, version=version)


def _finding(
    name: str = "requests",
    cve: str | None = "CVE-2024-0001",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=_pkg(name),
        title="Test vulnerability",
        detail="Some detail.",
        cve=cve,
    )


def _make_lockfile(tmp_path: Path, content: str | None = None) -> Path:
    req = tmp_path / "requirements.txt"
    req.write_text(content or "requests==2.28.0\n")
    return req


# Patch targets
_SCANNER_PATCH_TARGETS = [
    "depfence.scanners.dockerfile_scanner.DockerfileScanner.scan_project",
    "depfence.scanners.terraform_scanner.TerraformScanner.scan_project",
    "depfence.scanners.gha_workflow_scanner.GhaWorkflowScanner.scan_project",
    "depfence.scanners.secrets_scanner.SecretsScanner.scan_project",
    "depfence.scanners.pinning_scanner.PinningScanner.scan_project",
]
_EPSS_TARGET = "depfence.core.epss_enricher.enrich_findings"
_KEV_TARGET = "depfence.core.kev_enricher.enrich_with_kev"
_TI_LOAD_TARGET = "depfence.core.threat_intel.ThreatIntelDB.load"
_TI_LOOKUP_TARGET = "depfence.core.threat_intel.ThreatIntelDB.lookup_batch"


def _all_mocks(
    stack,
    *,
    epss=None,
    kev=None,
    ti_lookup_val=None,
    scanner_rv=None,
):
    """Enter all standard mocks into an ExitStack; return (epss_mock, kev_mock)."""
    epss_mock = epss if epss is not None else AsyncMock(return_value=[])
    kev_mock = kev if kev is not None else AsyncMock(return_value=[])
    lookup = {} if ti_lookup_val is None else ti_lookup_val
    rv = [] if scanner_rv is None else scanner_rv

    stack.enter_context(patch(_EPSS_TARGET, new=epss_mock))
    stack.enter_context(patch(_KEV_TARGET, new=kev_mock))
    stack.enter_context(patch(_TI_LOAD_TARGET))
    stack.enter_context(patch(_TI_LOOKUP_TARGET, return_value=lookup))
    for t in _SCANNER_PATCH_TARGETS:
        stack.enter_context(patch(t, new=AsyncMock(return_value=rv)))
    return epss_mock, kev_mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_project(tmp_path):
    _make_lockfile(tmp_path)
    return tmp_path


@pytest.fixture
def empty_project(tmp_path):
    return tmp_path


# ---------------------------------------------------------------------------
# EnrichmentResult dataclass
# ---------------------------------------------------------------------------


class TestEnrichmentResult:
    def test_default_values(self):
        r = EnrichmentResult(source="epss", success=True)
        assert r.findings_added == 0
        assert r.findings_modified == 0
        assert r.duration_ms == 0
        assert r.error is None

    def test_failure_fields(self):
        r = EnrichmentResult(source="kev", success=False, error="timeout")
        assert r.success is False
        assert r.error == "timeout"


# ---------------------------------------------------------------------------
# ScanPipelineResult dataclass
# ---------------------------------------------------------------------------


class TestScanPipelineResult:
    def test_fields(self):
        sr = ScanResult(target="/tmp/proj", ecosystem="pypi")
        er = EnrichmentResult(source="epss", success=True)
        result = ScanPipelineResult(
            scan_result=sr,
            enrichments=[er],
            total_duration_ms=123.4,
            packages_scanned=5,
            enrichment_coverage={"epss": True},
        )
        assert result.packages_scanned == 5
        assert result.enrichment_coverage == {"epss": True}
        assert len(result.enrichments) == 1


# ---------------------------------------------------------------------------
# Full pipeline — happy path
# ---------------------------------------------------------------------------


class TestFullPipelineHappyPath:
    @pytest.mark.asyncio
    async def test_returns_scan_pipeline_result(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator(timeout=5.0).run_full_pipeline(tmp_project)
        assert isinstance(result, ScanPipelineResult)
        assert isinstance(result.scan_result, ScanResult)
        assert result.total_duration_ms > 0

    @pytest.mark.asyncio
    async def test_enrichment_coverage_shows_all_enabled(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)
        coverage = result.enrichment_coverage
        assert coverage.get("epss") is True
        assert coverage.get("kev") is True
        assert coverage.get("threat_intel") is True

    @pytest.mark.asyncio
    async def test_packages_scanned_counts_lockfile_packages(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)
        assert result.packages_scanned >= 1


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestTimeoutHandling:
    @pytest.mark.asyncio
    async def test_timed_out_enrichment_marked_as_failed(self, tmp_project):
        async def _slow_epss(findings):
            await asyncio.sleep(10)

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_slow_epss)
            result = await ScanOrchestrator(timeout=0.05).run_full_pipeline(tmp_project)

        epss_r = next(r for r in result.enrichments if r.source == "epss")
        kev_r = next(r for r in result.enrichments if r.source == "kev")
        assert epss_r.success is False
        assert "timed out" in epss_r.error.lower()
        assert kev_r.success is True

    @pytest.mark.asyncio
    async def test_timed_out_enrichment_has_duration(self, tmp_project):
        async def _slow(findings):
            await asyncio.sleep(10)

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_slow)
            result = await ScanOrchestrator(timeout=0.05).run_full_pipeline(tmp_project)

        epss_r = next(r for r in result.enrichments if r.source == "epss")
        assert epss_r.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_overall_result_returned_despite_timeout(self, tmp_project):
        async def _slow(findings):
            await asyncio.sleep(10)

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_slow)
            result = await ScanOrchestrator(timeout=0.05).run_full_pipeline(tmp_project)

        assert isinstance(result, ScanPipelineResult)
        assert result.total_duration_ms > 0


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_failing_enrichment_does_not_abort_pipeline(self, tmp_project):
        async def _broken(findings):
            raise RuntimeError("Network is down")

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_broken)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        assert isinstance(result, ScanPipelineResult)
        epss_r = next(r for r in result.enrichments if r.source == "epss")
        assert epss_r.success is False
        assert "Network is down" in epss_r.error

    @pytest.mark.asyncio
    async def test_kev_failure_epss_still_succeeds(self, tmp_project):
        async def _broken_kev(findings):
            raise ConnectionError("KEV unreachable")

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, kev=_broken_kev)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        epss_r = next(r for r in result.enrichments if r.source == "epss")
        kev_r = next(r for r in result.enrichments if r.source == "kev")
        assert epss_r.success is True
        assert kev_r.success is False
        assert result.enrichment_coverage["kev"] is False
        assert result.enrichment_coverage["epss"] is True

    @pytest.mark.asyncio
    async def test_all_enrichments_fail_scan_still_returns(self, tmp_project):
        async def _fail(findings):
            raise Exception("boom")

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_fail, kev=_fail)
            # Re-patch lookup_batch to raise after _all_mocks set it to {}
            stack.enter_context(
                patch(_TI_LOOKUP_TARGET, side_effect=Exception("ti boom"))
            )
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        assert isinstance(result, ScanPipelineResult)
        for name in ("epss", "kev", "threat_intel"):
            assert result.enrichment_coverage.get(name) is False, f"{name} should have failed"


# ---------------------------------------------------------------------------
# Sequential enrichment (parallel_enrichment=False)
# ---------------------------------------------------------------------------


class TestSequentialEnrichment:
    @pytest.mark.asyncio
    async def test_sequential_mode_produces_same_result_shape(self, tmp_project):
        call_order: list[str] = []

        async def _track_epss(findings):
            call_order.append("epss")
            return findings

        async def _track_kev(findings):
            call_order.append("kev")
            return findings

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_track_epss, kev=_track_kev)
            result = await ScanOrchestrator(parallel_enrichment=False).run_full_pipeline(
                tmp_project
            )

        assert isinstance(result, ScanPipelineResult)
        assert "epss" in call_order
        assert "kev" in call_order
        assert call_order.index("epss") < call_order.index("kev")

    @pytest.mark.asyncio
    async def test_sequential_mode_coverage(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator(parallel_enrichment=False).run_full_pipeline(
                tmp_project
            )
        assert result.enrichment_coverage.get("epss") is True
        assert result.enrichment_coverage.get("kev") is True


# ---------------------------------------------------------------------------
# Enrichment timing
# ---------------------------------------------------------------------------


class TestEnrichmentTiming:
    @pytest.mark.asyncio
    async def test_each_enrichment_result_has_duration(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)
        for enrichment in result.enrichments:
            assert enrichment.duration_ms >= 0, f"{enrichment.source} missing duration"

    @pytest.mark.asyncio
    async def test_total_duration_ms_is_positive(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)
        assert result.total_duration_ms > 0


# ---------------------------------------------------------------------------
# enrichment_coverage
# ---------------------------------------------------------------------------


class TestEnrichmentCoverage:
    @pytest.mark.asyncio
    async def test_disabled_enrichment_appears_in_coverage_map(self, tmp_project):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(_KEV_TARGET, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_TI_LOAD_TARGET))
            stack.enter_context(patch(_TI_LOOKUP_TARGET, return_value={}))
            for t in _SCANNER_PATCH_TARGETS:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            result = await ScanOrchestrator().run_full_pipeline(
                tmp_project, enable_epss=False
            )
        assert "epss" in result.enrichment_coverage

    @pytest.mark.asyncio
    async def test_all_disabled_all_three_in_coverage(self, tmp_project):
        with contextlib.ExitStack() as stack:
            for t in _SCANNER_PATCH_TARGETS:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            result = await ScanOrchestrator().run_full_pipeline(
                tmp_project,
                enable_epss=False,
                enable_kev=False,
                enable_threat_intel=False,
            )
        for name in ("epss", "kev", "threat_intel"):
            assert name in result.enrichment_coverage

    @pytest.mark.asyncio
    async def test_coverage_false_for_failed_enrichment(self, tmp_project):
        async def _fail(findings):
            raise RuntimeError("dead")

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=_fail)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        assert result.enrichment_coverage["epss"] is False
        assert result.enrichment_coverage["kev"] is True


# ---------------------------------------------------------------------------
# Project scanners run in parallel
# ---------------------------------------------------------------------------


class TestProjectScanners:
    @pytest.mark.asyncio
    async def test_all_five_scanners_are_invoked(self, tmp_project):
        call_log: list[str] = []

        def _make_mock(label):
            async def _scan(*args, **kwargs):
                call_log.append(label)
                return []
            return _scan

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "depfence.scanners.dockerfile_scanner.DockerfileScanner.scan_project",
                new=_make_mock("dockerfile"),
            ))
            stack.enter_context(patch(
                "depfence.scanners.terraform_scanner.TerraformScanner.scan_project",
                new=_make_mock("terraform"),
            ))
            stack.enter_context(patch(
                "depfence.scanners.gha_workflow_scanner.GhaWorkflowScanner.scan_project",
                new=_make_mock("gha"),
            ))
            stack.enter_context(patch(
                "depfence.scanners.secrets_scanner.SecretsScanner.scan_project",
                new=_make_mock("secrets"),
            ))
            stack.enter_context(patch(
                "depfence.scanners.pinning_scanner.PinningScanner.scan_project",
                new=_make_mock("pinning"),
            ))
            stack.enter_context(patch(_EPSS_TARGET, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_KEV_TARGET, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_TI_LOAD_TARGET))
            stack.enter_context(patch(_TI_LOOKUP_TARGET, return_value={}))
            await ScanOrchestrator().run_full_pipeline(tmp_project)

        assert set(call_log) == {"dockerfile", "terraform", "gha", "secrets", "pinning"}

    @pytest.mark.asyncio
    async def test_scanner_findings_appear_in_scan_result(self, tmp_project):
        dockerfile_finding = _finding("nginx", cve=None)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "depfence.scanners.dockerfile_scanner.DockerfileScanner.scan_project",
                new=AsyncMock(return_value=[dockerfile_finding]),
            ))
            for t in _SCANNER_PATCH_TARGETS[1:]:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_EPSS_TARGET, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_KEV_TARGET, new=AsyncMock(return_value=[])))
            stack.enter_context(patch(_TI_LOAD_TARGET))
            stack.enter_context(patch(_TI_LOOKUP_TARGET, return_value={}))
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        assert dockerfile_finding in result.scan_result.findings

    @pytest.mark.asyncio
    async def test_scanner_enrichment_results_included(self, tmp_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(tmp_project)

        scanner_sources = {r.source for r in result.enrichments}
        assert "scanner:dockerfile" in scanner_sources
        assert "scanner:terraform" in scanner_sources
        assert "scanner:gha_workflow" in scanner_sources
        assert "scanner:secrets" in scanner_sources
        assert "scanner:pinning" in scanner_sources


# ---------------------------------------------------------------------------
# Empty project (no lockfiles)
# ---------------------------------------------------------------------------


class TestEmptyProject:
    @pytest.mark.asyncio
    async def test_empty_project_returns_clean_result(self, empty_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(empty_project)
        assert isinstance(result, ScanPipelineResult)
        assert result.packages_scanned == 0
        assert result.scan_result.findings == []

    @pytest.mark.asyncio
    async def test_empty_project_enrichments_still_run(self, empty_project):
        epss_mock = AsyncMock(return_value=[])
        kev_mock = AsyncMock(return_value=[])

        with contextlib.ExitStack() as stack:
            _all_mocks(stack, epss=epss_mock, kev=kev_mock)
            await ScanOrchestrator().run_full_pipeline(empty_project)

        epss_mock.assert_awaited_once()
        kev_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_project_enrichment_coverage_all_present(self, empty_project):
        with contextlib.ExitStack() as stack:
            _all_mocks(stack)
            result = await ScanOrchestrator().run_full_pipeline(empty_project)
        for name in ("epss", "kev", "threat_intel"):
            assert name in result.enrichment_coverage


# ---------------------------------------------------------------------------
# All enrichments disabled
# ---------------------------------------------------------------------------


class TestAllEnrichmentsDisabled:
    @pytest.mark.asyncio
    async def test_all_disabled_still_returns_pipeline_result(self, tmp_project):
        with contextlib.ExitStack() as stack:
            for t in _SCANNER_PATCH_TARGETS:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            result = await ScanOrchestrator().run_full_pipeline(
                tmp_project,
                enable_epss=False,
                enable_kev=False,
                enable_threat_intel=False,
            )
        assert isinstance(result, ScanPipelineResult)
        assert result.total_duration_ms > 0

    @pytest.mark.asyncio
    async def test_all_disabled_no_network_calls(self, tmp_project):
        epss_mock = AsyncMock(return_value=[])
        kev_mock = AsyncMock(return_value=[])

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(_EPSS_TARGET, new=epss_mock))
            stack.enter_context(patch(_KEV_TARGET, new=kev_mock))
            for t in _SCANNER_PATCH_TARGETS:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            await ScanOrchestrator().run_full_pipeline(
                tmp_project,
                enable_epss=False,
                enable_kev=False,
                enable_threat_intel=False,
            )

        epss_mock.assert_not_awaited()
        kev_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_all_disabled_enrichments_have_disabled_error(self, tmp_project):
        with contextlib.ExitStack() as stack:
            for t in _SCANNER_PATCH_TARGETS:
                stack.enter_context(patch(t, new=AsyncMock(return_value=[])))
            result = await ScanOrchestrator().run_full_pipeline(
                tmp_project,
                enable_epss=False,
                enable_kev=False,
                enable_threat_intel=False,
            )
        for name in ("epss", "kev", "threat_intel"):
            r = next((e for e in result.enrichments if e.source == name), None)
            assert r is not None, f"Missing EnrichmentResult for {name}"
            assert r.error == "disabled"


# ---------------------------------------------------------------------------
# _run_with_timeout unit tests
# ---------------------------------------------------------------------------


class TestRunWithTimeout:
    @pytest.mark.asyncio
    async def test_success_returns_enrichment_result(self):
        async def _good():
            return EnrichmentResult(source="epss", success=True, findings_modified=3)

        orch = ScanOrchestrator(timeout=5.0)
        result = await orch._run_with_timeout(_good(), "epss", 5.0)
        assert result.success is True
        assert result.findings_modified == 3
        assert result.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_timeout_returns_failed_enrichment_result(self):
        async def _slow():
            await asyncio.sleep(10)
            return EnrichmentResult(source="epss", success=True)

        orch = ScanOrchestrator(timeout=0.01)
        result = await orch._run_with_timeout(_slow(), "epss", 0.01)
        assert result.success is False
        assert result.source == "epss"
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_exception_returns_failed_enrichment_result(self):
        async def _broken():
            raise ValueError("something went wrong")

        orch = ScanOrchestrator()
        result = await orch._run_with_timeout(_broken(), "kev", 5.0)
        assert result.success is False
        assert result.source == "kev"
        assert "something went wrong" in result.error

    @pytest.mark.asyncio
    async def test_tuple_result_unwrapped_correctly(self):
        async def _returns_tuple():
            return ([], EnrichmentResult(source="threat_intel", success=True, findings_added=2))

        orch = ScanOrchestrator()
        result = await orch._run_with_timeout(_returns_tuple(), "threat_intel", 5.0)
        assert result.success is True
        assert result.findings_added == 2
        assert result.duration_ms >= 0
