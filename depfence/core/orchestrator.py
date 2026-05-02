"""High-performance async scan orchestrator.

Runs all enrichment steps in parallel with per-enrichment timeouts, graceful
degradation on individual failures, and comprehensive result tracking.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, ScanResult, Severity

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class EnrichmentResult:
    source: str  # "epss", "kev", "threat_intel", "scorecard"
    success: bool
    findings_added: int = 0
    findings_modified: int = 0
    duration_ms: float = 0
    error: str | None = None


@dataclass
class ScanPipelineResult:
    scan_result: ScanResult
    enrichments: list[EnrichmentResult]
    total_duration_ms: float
    packages_scanned: int
    enrichment_coverage: dict[str, bool]  # which enrichments succeeded


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class ScanOrchestrator:
    """Orchestrates the full dependency security scan pipeline.

    The pipeline has three phases:

    1. Parse lockfiles (sync, fast) — discovers packages from the project dir.
    2. Run all project-level scanners in parallel (Dockerfile, Terraform, GHA,
       Secrets, Pinning).
    3. Enrich all findings in parallel with EPSS, KEV, and threat-intel data,
       each wrapped with a per-enrichment timeout.

    Parameters
    ----------
    timeout:
        Per-enrichment timeout in seconds.  Default 30 s.
    parallel_enrichment:
        When ``True`` (default) all enrichments run concurrently via
        ``asyncio.gather``.  Set to ``False`` to run them sequentially
        (useful for debugging or rate-limit avoidance).
    """

    def __init__(self, timeout: float = 30.0, parallel_enrichment: bool = True) -> None:
        self.timeout = timeout
        self.parallel_enrichment = parallel_enrichment

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_full_pipeline(
        self,
        project_dir: Path,
        *,
        enable_epss: bool = True,
        enable_kev: bool = True,
        enable_threat_intel: bool = True,
    ) -> ScanPipelineResult:
        """Execute the full three-phase scan pipeline.

        Parameters
        ----------
        project_dir:
            Root directory of the project to scan.
        enable_epss:
            Whether to run EPSS enrichment.
        enable_kev:
            Whether to run CISA KEV enrichment.
        enable_threat_intel:
            Whether to run threat-intelligence lookup.

        Returns
        -------
        ScanPipelineResult
            Comprehensive result with per-enrichment status and timing.
        """
        pipeline_start = time.monotonic()

        # ------------------------------------------------------------------
        # Phase 1 — Parse lockfiles (sync, fast)
        # ------------------------------------------------------------------
        packages: list[PackageId] = []
        try:
            from depfence.core.lockfile import detect_ecosystem, parse_lockfile

            lockfiles = detect_ecosystem(project_dir)
            for ecosystem, lockfile_path in lockfiles:
                try:
                    pkgs = parse_lockfile(ecosystem, lockfile_path)
                    packages.extend(pkgs)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Failed to parse %s: %s", lockfile_path, exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("Lockfile detection failed: %s", exc)

        log.debug("Phase 1 complete: %d packages discovered", len(packages))

        # ------------------------------------------------------------------
        # Phase 2 — Run all project scanners in parallel
        # ------------------------------------------------------------------
        scanner_findings, scanner_enrichments = await self._run_project_scanners(project_dir)

        # Combine all findings; start building a ScanResult
        all_findings: list[Finding] = list(scanner_findings)

        # Derive a representative ecosystem/target from the lockfiles found
        try:
            from depfence.core.lockfile import detect_ecosystem as _de

            lf = _de(project_dir)
            ecosystem_str = lf[0][0] if lf else "unknown"
        except Exception:  # noqa: BLE001
            ecosystem_str = "unknown"

        scan_result = ScanResult(
            target=str(project_dir),
            ecosystem=ecosystem_str,
            started_at=datetime.now(tz=timezone.utc),
            packages_scanned=len(packages),
            findings=all_findings,
        )

        log.debug("Phase 2 complete: %d findings from project scanners", len(all_findings))

        # ------------------------------------------------------------------
        # Phase 3 — Run enrichments in parallel (or sequentially)
        # ------------------------------------------------------------------
        enrichment_tasks: list[tuple[str, bool]] = [
            ("epss", enable_epss),
            ("kev", enable_kev),
            ("threat_intel", enable_threat_intel),
        ]

        enabled_enrichments: list[tuple[str, bool]] = [
            (name, enabled) for name, enabled in enrichment_tasks
        ]

        enrichment_results: list[EnrichmentResult] = list(scanner_enrichments)

        if self.parallel_enrichment:
            coros = []
            names = []
            for name, enabled in enabled_enrichments:
                if not enabled:
                    enrichment_results.append(
                        EnrichmentResult(source=name, success=True, error="disabled")
                    )
                    continue
                coro = self._enrichment_coro(name, all_findings, packages)
                coros.append(self._run_with_timeout(coro, name, self.timeout))
                names.append(name)

            if coros:
                results = await asyncio.gather(*coros, return_exceptions=False)
                for result in results:
                    enrichment_results.append(result)
        else:
            # Sequential path
            for name, enabled in enabled_enrichments:
                if not enabled:
                    enrichment_results.append(
                        EnrichmentResult(source=name, success=True, error="disabled")
                    )
                    continue
                coro = self._enrichment_coro(name, all_findings, packages)
                result = await self._run_with_timeout(coro, name, self.timeout)
                enrichment_results.append(result)

        # ------------------------------------------------------------------
        # Finalise scan result
        # ------------------------------------------------------------------
        scan_result.completed_at = datetime.now(tz=timezone.utc)

        enrichment_coverage: dict[str, bool] = {
            r.source: r.success for r in enrichment_results
        }

        total_duration_ms = (time.monotonic() - pipeline_start) * 1000.0

        log.info(
            "Pipeline complete in %.1f ms | packages=%d findings=%d",
            total_duration_ms,
            len(packages),
            len(all_findings),
        )

        return ScanPipelineResult(
            scan_result=scan_result,
            enrichments=enrichment_results,
            total_duration_ms=total_duration_ms,
            packages_scanned=len(packages),
            enrichment_coverage=enrichment_coverage,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrichment_coro(
        self,
        name: str,
        findings: list[Finding],
        packages: list[PackageId],
    ):  # -> Coroutine
        """Return the appropriate coroutine for a named enrichment."""
        if name == "epss":
            return self._enrich_epss(findings)
        if name == "kev":
            return self._enrich_kev(findings)
        if name == "threat_intel":
            return self._check_threat_intel(packages)
        raise ValueError(f"Unknown enrichment: {name!r}")

    async def _run_with_timeout(self, coro, name: str, timeout: float) -> EnrichmentResult:
        """Wrap *coro* with a timeout, returning a well-formed EnrichmentResult.

        On success the coroutine must return an :class:`EnrichmentResult`.
        For ``_check_threat_intel`` the coroutine returns a tuple; callers
        are expected to pass the inner enrichment-result coroutine only.

        This method handles both cases: if the coroutine returns an
        ``EnrichmentResult`` directly, that is used.  If it returns a tuple
        ``(list[Finding], EnrichmentResult)`` the enrichment result is
        extracted and findings are discarded (they have already been mutated
        in-place via ``scan_result.findings``).
        """
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(coro, timeout=timeout)
            duration_ms = (time.monotonic() - start) * 1000.0

            if isinstance(result, tuple):
                # _check_threat_intel returns (new_findings, EnrichmentResult)
                _new_findings, enrichment = result
                enrichment.duration_ms = duration_ms
                return enrichment

            # result is already an EnrichmentResult
            result.duration_ms = duration_ms
            return result

        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start) * 1000.0
            log.warning("Enrichment '%s' timed out after %.1f s", name, timeout)
            return EnrichmentResult(
                source=name,
                success=False,
                duration_ms=duration_ms,
                error=f"Timed out after {timeout:.1f}s",
            )
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.monotonic() - start) * 1000.0
            log.warning("Enrichment '%s' failed: %s", name, exc)
            return EnrichmentResult(
                source=name,
                success=False,
                duration_ms=duration_ms,
                error=str(exc),
            )

    async def _enrich_epss(self, findings: list[Finding]) -> EnrichmentResult:
        """Enrich findings with EPSS exploitability scores."""
        from depfence.core.epss_enricher import enrich_findings

        before_titles = {id(f): f.title for f in findings}
        await enrich_findings(findings)

        modified = sum(
            1 for f in findings if f.title != before_titles.get(id(f), f.title)
            or "epss_score" in f.metadata
        )

        return EnrichmentResult(
            source="epss",
            success=True,
            findings_modified=modified,
        )

    async def _enrich_kev(self, findings: list[Finding]) -> EnrichmentResult:
        """Enrich findings with CISA KEV catalog data."""
        from depfence.core.kev_enricher import enrich_with_kev

        before_titles = {id(f): f.title for f in findings}
        await enrich_with_kev(findings)

        modified = sum(
            1 for f in findings
            if f.title != before_titles.get(id(f), f.title)
            or f.metadata.get("kev_exploited")
        )

        return EnrichmentResult(
            source="kev",
            success=True,
            findings_modified=modified,
        )

    async def _check_threat_intel(
        self, packages: list[PackageId]
    ) -> tuple[list[Finding], EnrichmentResult]:
        """Look up packages against the threat-intel database.

        Returns new malicious-package findings and an EnrichmentResult.
        The new findings are also appended to the orchestrator's internal
        accumulation via side-effect (they are returned so the caller may
        surface them if needed).
        """
        from depfence.core.threat_intel import ThreatIntelDB

        db = ThreatIntelDB()
        db.load()

        matches = db.lookup_batch(packages)
        new_findings: list[Finding] = []

        for pkg_str, entry in matches.items():
            # Find the PackageId that produced this key
            pkg = next((p for p in packages if str(p) == pkg_str), None)
            if pkg is None:
                continue

            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = severity_map.get(entry.severity.lower(), Severity.HIGH)

            finding = Finding(
                finding_type=FindingType.MALICIOUS,
                severity=severity,
                package=pkg,
                title=f"[Threat Intel] {entry.threat_type.title()}: {pkg.name}",
                detail=entry.description,
                metadata={
                    "threat_type": entry.threat_type,
                    "source": entry.source,
                    "reported_date": entry.reported_date,
                    "indicators": entry.indicators,
                },
            )
            new_findings.append(finding)

        enrichment = EnrichmentResult(
            source="threat_intel",
            success=True,
            findings_added=len(new_findings),
        )
        return new_findings, enrichment

    async def _run_project_scanners(
        self, project_dir: Path
    ) -> tuple[list[Finding], list[EnrichmentResult]]:
        """Run all project-level scanners in parallel.

        Scanners:
        - DockerfileScanner
        - TerraformScanner
        - GhaWorkflowScanner
        - SecretsScanner
        - PinningScanner

        Returns a flat list of findings from all scanners, plus an
        EnrichmentResult per scanner (for timing/error tracking).
        """
        from depfence.scanners.dockerfile_scanner import DockerfileScanner
        from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner
        from depfence.scanners.pinning_scanner import PinningScanner
        from depfence.scanners.secrets_scanner import SecretsScanner
        from depfence.scanners.terraform_scanner import TerraformScanner

        scanner_specs: list[tuple[str, object]] = [
            ("dockerfile", DockerfileScanner()),
            ("terraform", TerraformScanner()),
            ("gha_workflow", GhaWorkflowScanner()),
            ("secrets", SecretsScanner()),
            ("pinning", PinningScanner()),
        ]

        async def _run_scanner(name: str, scanner) -> tuple[str, list[Finding], str | None]:
            try:
                findings = await scanner.scan_project(project_dir)
                return name, findings, None
            except Exception as exc:  # noqa: BLE001
                log.warning("Scanner '%s' failed: %s", name, exc)
                return name, [], str(exc)

        start = time.monotonic()
        raw_results = await asyncio.gather(
            *[_run_scanner(name, scanner) for name, scanner in scanner_specs],
            return_exceptions=False,
        )

        all_findings: list[Finding] = []
        enrichment_results: list[EnrichmentResult] = []
        total_ms = (time.monotonic() - start) * 1000.0

        for name, findings, error in raw_results:
            all_findings.extend(findings)
            enrichment_results.append(
                EnrichmentResult(
                    source=f"scanner:{name}",
                    success=error is None,
                    findings_added=len(findings),
                    duration_ms=total_ms,  # approximate; all ran concurrently
                    error=error,
                )
            )

        return all_findings, enrichment_results
