"""Scan engine — orchestrates scanners, analyzers, and reporters."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.fetcher import fetch_batch
from depfence.core.inline_suppress import filter_findings as _inline_filter
from depfence.core.inline_suppress import parse_suppressions
from depfence.core.lockfile import detect_ecosystem, parse_lockfile
from depfence.core.models import (
    Finding,
    FindingType,
    PackageId,
    PackageMeta,
    ScannerOutcome,
    ScannerReasonCode,
    ScanResult,
    ScanState,
    Severity,
    merge_scan_state,
)
from depfence.core.registry import (
    SCANNER_PROFILES,
    SHIPPED_SCANNERS,
    PluginRegistry,
    get_registry,
    run_shipped_project_scanners,
)
from depfence.core.scanner_outcome import from_legacy

log = logging.getLogger(__name__)


def _merge_scanner_coverage(
    target: dict[str, ScanState],
    incoming: dict[str, ScanState],
) -> None:
    """Merge package/project lanes without overwriting incomplete coverage."""
    for name, status in incoming.items():
        target[name] = merge_scan_state(target.get(name), status)


def _parse_lockfiles(
    project_dir: Path,
    ecosystems: list[str] | None,
) -> tuple[list, list[PackageId], list[str]]:
    """Detect, filter, and parse lockfiles. Returns (lockfiles, packages, errors)."""
    lockfiles = detect_ecosystem(project_dir)
    if not lockfiles:
        return [], [], [f"No lockfiles found in {project_dir}"]
    if ecosystems:
        lockfiles = [(eco, p) for eco, p in lockfiles if eco in ecosystems]
    packages: list[PackageId] = []
    errors: list[str] = []
    for eco, lockfile_path in lockfiles:
        try:
            packages.extend(parse_lockfile(eco, lockfile_path))
        except Exception as e:
            errors.append(f"Error parsing {lockfile_path}: {e}")
    return lockfiles, packages, errors


def _configure_cache(registry: object, use_cache: bool) -> None:
    if use_cache:
        return
    for scanner in registry.scanners.values():  # type: ignore[attr-defined]
        if hasattr(scanner, "_use_cache"):
            scanner._use_cache = False
        if hasattr(scanner, "_cache"):
            scanner._cache = None


async def _run_scanners(
    registry: object,
    metas: list,
    skip_advisory: bool,
    skip_behavioral: bool,
    skip_reputation: bool,
    scanner_names: frozenset[str] | set[str] | None = None,
    outcomes: dict[str, ScannerOutcome] | None = None,
) -> tuple[list[Finding], list[str], dict[str, ScanState], dict[str, str]]:
    skip = {
        "behavioral": skip_behavioral,
        "reputation": skip_reputation,
    }

    def record_skip(name: str, reason: ScannerReasonCode) -> None:
        if outcomes is not None:
            outcomes[name] = ScannerOutcome(
                state=ScanState.PASS,
                reason_code=reason,
                evaluated=False,
                skipped=True,
                duration_ms=0.0,
            )

    async def timed_scan(
        operation: Awaitable[list[Finding]],
        timeout: float,
    ) -> tuple[list[Finding] | Exception, float]:
        started = time.monotonic()
        try:
            value: list[Finding] | Exception = await asyncio.wait_for(operation, timeout=timeout)
        except Exception as exc:  # scanner failures are typed below
            value = exc
        return value, (time.monotonic() - started) * 1000.0

    tasks: list[tuple[str, Awaitable[tuple[list[Finding] | Exception, float]]]] = []
    errors: list[str] = []
    coverage: dict[str, ScanState] = {}
    scanner_errors: dict[str, str] = {}
    shipped_by_name = {spec.name: spec for spec in SHIPPED_SCANNERS}
    from depfence.core.fetcher import fetch_enabled

    for name, scanner in registry.scanners.items():  # type: ignore[attr-defined]
        if scanner_names is not None and name not in scanner_names:
            record_skip(name, ScannerReasonCode.DISABLED_BY_POLICY)
            continue
        spec = shipped_by_name.get(name)
        if spec is not None and not spec.package:
            continue
        if skip_advisory and (spec.advisory if spec else "advisory" in name):
            record_skip(name, ScannerReasonCode.DISABLED_BY_POLICY)
            continue
        if skip.get(name, False):
            record_skip(name, ScannerReasonCode.DISABLED_BY_POLICY)
            continue
        if not hasattr(scanner, 'scan') or not hasattr(scanner, 'ecosystems'):
            continue
        relevant = [m for m in metas if m.pkg.ecosystem in scanner.ecosystems]
        if relevant:
            if spec and spec.requires_network and not fetch_enabled():
                message = f"Scanner {name} not run: network disabled by offline policy"
                coverage[name] = ScanState.INDETERMINATE
                scanner_errors[name] = message
                errors.append(message)
                if outcomes is not None:
                    legacy = from_legacy(ScanState.INDETERMINATE, message)
                    outcomes[name] = ScannerOutcome(
                        state=legacy.state,
                        reason_code=ScannerReasonCode.DISABLED_BY_POLICY,
                        error_code=legacy.error_code,
                        evaluated=False,
                        skipped=True,
                    )
                continue
            timeout = spec.timeout_seconds if spec else 60.0
            tasks.append((name, timed_scan(scanner.scan(relevant), timeout)))
        else:
            record_skip(name, ScannerReasonCode.NOT_APPLICABLE)
    if not tasks:
        return [], errors, coverage, scanner_errors
    findings: list[Finding] = []
    raw_results = await asyncio.gather(*(task for _name, task in tasks))
    for (name, _task), (sr, duration_ms) in zip(tasks, raw_results, strict=True):
        if isinstance(sr, list):
            findings.extend(sr)
            scanner = registry.scanners[name]  # type: ignore[attr-defined]
            scanner_error = getattr(scanner, "last_error", None)
            if isinstance(scanner_error, str) and scanner_error:
                message = f"Scanner {name} incomplete: {scanner_error}"
                errors.append(message)
                scanner_errors[name] = message
                coverage[name] = ScanState.INDETERMINATE
                if outcomes is not None:
                    legacy = from_legacy(ScanState.INDETERMINATE, message)
                    outcomes[name] = ScannerOutcome(
                        state=ScanState.INDETERMINATE,
                        reason_code=(
                            ScannerReasonCode.PARTIAL_COVERAGE
                            if legacy.reason_code == ScannerReasonCode.RUNTIME_FAILURE
                            else legacy.reason_code
                        ),
                        error_code=legacy.error_code,
                        findings_preserved=len(sr),
                        duration_ms=duration_ms,
                        evaluated=True,
                        skipped=False,
                    )
            else:
                coverage[name] = ScanState.PASS
                if outcomes is not None:
                    outcomes[name] = from_legacy(
                        ScanState.PASS,
                        findings_preserved=len(sr),
                        duration_ms=duration_ms,
                    )
        elif isinstance(sr, Exception):
            message = f"Scanner {name} failed: {type(sr).__name__}: {sr}"
            errors.append(message)
            scanner_errors[name] = message
            coverage[name] = ScanState.INDETERMINATE
            if outcomes is not None:
                outcomes[name] = from_legacy(
                    ScanState.INDETERMINATE,
                    message,
                    duration_ms=duration_ms,
                )
    return findings, errors, coverage, scanner_errors


async def _run_analyzers(registry: object, metas: list) -> tuple[list[Finding], list[str]]:
    tasks = [
        analyzer.analyze(meta, None)
        for _name, analyzer in registry.analyzers.items()  # type: ignore[attr-defined]
        for meta in metas
    ]
    if not tasks:
        return [], []
    findings: list[Finding] = []
    errors: list[str] = []
    for ar in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(ar, list):
            findings.extend(ar)
        elif isinstance(ar, Exception):
            errors.append(str(ar))
    return findings, errors


async def _run_project_scanners(
    project_dir: Path,
    registry: PluginRegistry | None = None,
    *,
    skip_advisory: bool = False,
    scanner_names: frozenset[str] | set[str] | None = None,
    max_workers: int = 4,
    deadline_seconds: float | None = None,
    outcomes: dict[str, ScannerOutcome] | None = None,
) -> tuple[list[Finding], list[str], dict[str, ScanState], dict[str, str]]:
    """Run the canonical shipped project-scanner catalog.

    Compatibility note: the catalog includes ObfuscationScanner,
    PreinstallScanner, NetworkScanner, GitMessageScanner,
    PayloadBehaviorScanner, RubyLifecycleScanner, EditorConfigScanner, and
    BindingGypScanner.  The names remain here for older wiring assertions while
    their executable declarations live only in ``registry.SHIPPED_SCANNERS``.
    """
    registry = registry or get_registry()
    runs = await run_shipped_project_scanners(
        registry,
        project_dir,
        skip_advisory=skip_advisory,
        scanner_names=scanner_names,
        max_workers=max_workers,
        deadline_seconds=deadline_seconds,
    )
    findings: list[Finding] = []
    errors: list[str] = []
    coverage: dict[str, ScanState] = {}
    scanner_errors: dict[str, str] = {}
    for run in runs:
        findings.extend(run.findings)
        coverage[run.name] = run.status
        if outcomes is not None:
            outcome = from_legacy(
                run.status,
                run.error,
                findings_preserved=len(run.findings),
                duration_ms=run.duration_ms,
            )
            if run.skipped:
                outcome = ScannerOutcome(
                    state=run.status,
                    reason_code=ScannerReasonCode.NOT_APPLICABLE,
                    findings_preserved=len(run.findings),
                    evaluated=run.evaluated,
                    skipped=True,
                    duration_ms=run.duration_ms,
                )
            elif outcome.error_code and outcome.error_code.value == "network.disabled":
                outcome = ScannerOutcome(
                    state=run.status,
                    reason_code=ScannerReasonCode.DISABLED_BY_POLICY,
                    error_code=outcome.error_code,
                    findings_preserved=len(run.findings),
                    evaluated=False,
                    skipped=True,
                    duration_ms=run.duration_ms,
                )
            outcomes[run.name] = outcome
        if run.error:
            message = f"Project scanner {run.name} incomplete: {run.error}"
            errors.append(message)
            scanner_errors[run.name] = message
    return findings, errors, coverage, scanner_errors


async def _enrich_findings(
    all_packages: list[PackageId],
    all_findings: list[Finding],
) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []

    try:
        from depfence.core.threat_intel import ThreatIntelDB

        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        db = ThreatIntelDB()
        db.load()
        for pkg in all_packages:
            entry = db.lookup(pkg.name, pkg.ecosystem)
            if entry:
                all_findings.append(
                    Finding(
                        finding_type=FindingType.MALICIOUS,
                        severity=sev_map.get(entry.severity.lower(), Severity.HIGH),
                        package=pkg,
                        title=f"Known malicious package: {entry.threat_type}",
                        detail=entry.description,
                        metadata={
                            "threat_type": entry.threat_type,
                            "source": entry.source,
                            "reported_date": entry.reported_date,
                            "indicators": entry.indicators,
                        },
                    )
                )
    except Exception as exc:
        log.debug("Threat intel lookup failed: %s", exc)
        errors.append(f"Threat intel lookup error: {exc}")

    try:
        from depfence.core.epss_enricher import enrich_findings

        all_findings = await enrich_findings(all_findings)
    except Exception as exc:
        log.debug("EPSS enrichment failed: %s", exc)
        errors.append(f"EPSS enrichment error: {exc}")

    try:
        from depfence.core.kev_enricher import enrich_with_kev

        all_findings = await enrich_with_kev(all_findings)
    except Exception as exc:
        log.debug("KEV enrichment failed: %s", exc)
        errors.append(f"KEV enrichment error: {exc}")

    return all_findings, errors


def _merge_suppressions(lockfiles: list) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for _eco, lf_path in lockfiles:
        for pkg, tokens in parse_suppressions(lf_path).items():
            if pkg not in merged:
                merged[pkg] = tokens
            elif not merged[pkg] or not tokens:
                merged[pkg] = []
            else:
                merged[pkg] = list(dict.fromkeys(merged[pkg] + tokens))
    return merged


async def scan_directory(
    project_dir: Path,
    ecosystems: list[str] | None = None,
    skip_advisory: bool = False,
    skip_behavioral: bool = False,
    skip_reputation: bool = False,
    fetch_metadata: bool = True,
    project_scanners: bool = True,
    enrich: bool = True,
    use_cache: bool = True,
    progress_callback: Callable[[str], None] | None = None,
    profile: str = "full",
    project_workers: int = 4,
    project_deadline: float | None = None,
) -> ScanResult:
    if profile not in SCANNER_PROFILES:
        raise ValueError(f"unknown scanner profile {profile!r}")
    selected_scanners = SCANNER_PROFILES[profile]
    result = ScanResult(target=str(project_dir), ecosystem="multi")
    _progress = progress_callback or (lambda _msg: None)

    # Tell network-doing scanners (e.g. version_existence) whether fetching is allowed,
    # so --no-fetch is genuinely offline rather than just skipping the metadata pre-fetch.
    from depfence.core.fetcher import set_fetch_enabled
    set_fetch_enabled(fetch_metadata)

    _progress("Detecting lockfiles...")
    lockfiles, all_packages, parse_errors = _parse_lockfiles(project_dir, ecosystems)
    result.errors.extend(parse_errors)
    result.packages_scanned = len(all_packages)

    registry = get_registry()
    for issue in getattr(registry, "issues", ()):
        result.errors.append(f"Plugin load error: {issue}")
    _configure_cache(registry, use_cache)

    all_findings: list[Finding] = []

    # Package/dependency scanners only have work when packages were discovered.
    # Project scanners (workflows, secrets, IaC, action-pin existence) are
    # file-based and MUST run even when the tree has no lockfile at all — a
    # GitHub-Actions-only repo still has pins to verify.
    if all_packages:
        if fetch_metadata:
            _progress(f"Fetching metadata for {len(all_packages)} packages...")
            metas = await fetch_batch(all_packages, concurrency=20)
        else:
            metas = [PackageMeta(pkg=p) for p in all_packages]

        _progress("Running entry-point scanners...")
        scanner_findings, scanner_errors, scanner_coverage, scanner_error_map = await _run_scanners(
            registry,
            metas,
            skip_advisory,
            skip_behavioral,
            skip_reputation,
            None if profile == "full" else selected_scanners,
            result.scanner_outcomes,
        )
        all_findings.extend(scanner_findings)
        result.errors.extend(scanner_errors)
        _merge_scanner_coverage(result.scanner_coverage, scanner_coverage)
        result.scanner_errors.update(scanner_error_map)

        if profile == "full":
            _progress("Running analyzers...")
            analyzer_findings, analyzer_errors = await _run_analyzers(registry, metas)
            all_findings.extend(analyzer_findings)
            result.errors.extend(analyzer_errors)

        hook_errors = await registry.fire_hook("post_scan", findings=all_findings, metas=metas)
        if hook_errors:
            result.errors.extend(hook_errors)

    if project_scanners:
        _progress("Running project scanners...")
        proj_findings, proj_errors, proj_coverage, proj_error_map = await _run_project_scanners(
            project_dir,
            registry,
            skip_advisory=skip_advisory,
            scanner_names=selected_scanners,
            max_workers=project_workers,
            deadline_seconds=project_deadline,
            outcomes=result.scanner_outcomes,
        )
        all_findings.extend(proj_findings)
        result.errors.extend(proj_errors)
        _merge_scanner_coverage(result.scanner_coverage, proj_coverage)
        result.scanner_errors.update(proj_error_map)

    if enrich:
        _progress("Enriching findings (EPSS, KEV, threat intel)...")
        all_findings, enrich_errors = await _enrich_findings(all_packages, all_findings)
        result.errors.extend(enrich_errors)

    merged_suppressions = _merge_suppressions(lockfiles)
    if merged_suppressions:
        all_findings, suppressed = _inline_filter(all_findings, merged_suppressions)
        result.suppressed_findings = suppressed
        if suppressed:
            log.info(
                "Inline suppression: %d finding(s) suppressed via depfence:ignore directives",
                len(suppressed),
            )

    result.findings = all_findings
    result.completed_at = datetime.now(tz=timezone.utc)
    return result


def render_result(result: ScanResult, format: str = "table", *, max_rows: int | None = None) -> str:
    registry = get_registry()
    for reporter in registry.reporters.values():
        if getattr(reporter, "format", None) == format:
            if max_rows is not None and hasattr(reporter, "render"):
                import inspect
                sig = inspect.signature(reporter.render)
                if "max_rows" in sig.parameters:
                    return reporter.render(result, max_rows=max_rows)  # type: ignore[call-arg]
            return reporter.render(result)
    return f"{len(result.findings)} findings in {result.packages_scanned} packages"
