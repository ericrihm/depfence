"""Scan engine — orchestrates scanners, analyzers, and reporters."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.fetcher import fetch_batch
from depfence.core.inline_suppress import filter_findings as _inline_filter, parse_suppressions
from depfence.core.lockfile import detect_ecosystem, parse_lockfile
from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, ScanResult, Severity
from depfence.core.registry import get_registry

log = logging.getLogger(__name__)


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
) -> ScanResult:
    result = ScanResult(
        target=str(project_dir),
        ecosystem="multi",
    )

    lockfiles = detect_ecosystem(project_dir)
    if not lockfiles:
        result.errors.append(f"No lockfiles found in {project_dir}")
        result.completed_at = datetime.now(tz=timezone.utc)
        return result

    if ecosystems:
        lockfiles = [(eco, p) for eco, p in lockfiles if eco in ecosystems]

    all_packages: list[PackageId] = []
    for eco, lockfile_path in lockfiles:
        try:
            packages = parse_lockfile(eco, lockfile_path)
            all_packages.extend(packages)
        except Exception as e:
            result.errors.append(f"Error parsing {lockfile_path}: {e}")

    result.packages_scanned = len(all_packages)
    if not all_packages:
        result.completed_at = datetime.now(tz=timezone.utc)
        return result

    if fetch_metadata:
        metas = await fetch_batch(all_packages, concurrency=20)
    else:
        metas = [PackageMeta(pkg=p) for p in all_packages]

    registry = get_registry()
    all_findings: list[Finding] = []

    # Propagate cache preference to scanners that support it
    if not use_cache:
        for scanner in registry.scanners.values():
            if hasattr(scanner, "_use_cache"):
                scanner._use_cache = False
            if hasattr(scanner, "_cache"):
                scanner._cache = None

    scanner_tasks = []
    for name, scanner in registry.scanners.items():
        if skip_advisory and "advisory" in name:
            continue
        if skip_behavioral and name == "behavioral":
            continue
        if skip_reputation and name == "reputation":
            continue
        relevant = [m for m in metas if m.pkg.ecosystem in scanner.ecosystems]
        if relevant:
            scanner_tasks.append(scanner.scan(relevant))

    if scanner_tasks:
        scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
        for sr in scanner_results:
            if isinstance(sr, list):
                all_findings.extend(sr)
            elif isinstance(sr, Exception):
                result.errors.append(str(sr))

    analyzer_tasks = []
    for name, analyzer in registry.analyzers.items():
        for meta in metas:
            analyzer_tasks.append(analyzer.analyze(meta, None))

    if analyzer_tasks:
        analyzer_results = await asyncio.gather(*analyzer_tasks, return_exceptions=True)
        for ar in analyzer_results:
            if isinstance(ar, list):
                all_findings.extend(ar)
            elif isinstance(ar, Exception):
                result.errors.append(str(ar))

    await registry.fire_hook("post_scan", findings=all_findings, metas=metas)

    # Step 4: Run project-level scanners (Dockerfile, Terraform, GHA workflow, secrets, pinning)
    if project_scanners:
        from depfence.scanners.dockerfile_scanner import DockerfileScanner
        from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner
        from depfence.scanners.pinning_scanner import PinningScanner
        from depfence.scanners.secrets_scanner import SecretsScanner
        from depfence.scanners.terraform_scanner import TerraformScanner

        proj_scanner_instances = [
            DockerfileScanner(),
            TerraformScanner(),
            GhaWorkflowScanner(),
            SecretsScanner(),
            PinningScanner(),
        ]
        proj_tasks = [s.scan_project(project_dir) for s in proj_scanner_instances]
        proj_results = await asyncio.gather(*proj_tasks, return_exceptions=True)
        for pr in proj_results:
            if isinstance(pr, list):
                all_findings.extend(pr)
            elif isinstance(pr, Exception):
                log.debug("Project scanner error: %s", pr)
                result.errors.append(str(pr))

    if enrich:
        # Step 5: Threat intel DB lookup — instantly flag known-malicious packages
        try:
            from depfence.core.threat_intel import ThreatIntelDB

            db = ThreatIntelDB()
            db.load()
            for pkg in all_packages:
                entry = db.lookup(pkg.name, pkg.ecosystem)
                if entry:
                    sev_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    severity = sev_map.get(entry.severity.lower(), Severity.HIGH)
                    all_findings.append(
                        Finding(
                            finding_type=FindingType.MALICIOUS,
                            severity=severity,
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
            result.errors.append(f"Threat intel lookup error: {exc}")

        # Step 6: Enrich findings with EPSS scores (CVE-backed findings only)
        try:
            from depfence.core.epss_enricher import enrich_findings

            all_findings = await enrich_findings(all_findings)
        except Exception as exc:
            log.debug("EPSS enrichment failed: %s", exc)
            result.errors.append(f"EPSS enrichment error: {exc}")

        # Step 7: Enrich findings with CISA KEV data (CVE-backed findings only)
        try:
            from depfence.core.kev_enricher import enrich_with_kev

            all_findings = await enrich_with_kev(all_findings)
        except Exception as exc:
            log.debug("KEV enrichment failed: %s", exc)
            result.errors.append(f"KEV enrichment error: {exc}")

    # Apply inline suppression: parse depfence:ignore comments from all lockfiles.
    merged_suppressions: dict[str, list[str]] = {}
    for _eco, _lf_path in lockfiles:
        _file_suppressions = parse_suppressions(_lf_path)
        for _pkg, _tokens in _file_suppressions.items():
            if _pkg not in merged_suppressions:
                merged_suppressions[_pkg] = _tokens
            else:
                # Merge: empty list (wildcard) dominates.
                existing_tokens = merged_suppressions[_pkg]
                if not existing_tokens or not _tokens:
                    merged_suppressions[_pkg] = []
                else:
                    merged_suppressions[_pkg] = list(dict.fromkeys(existing_tokens + _tokens))

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


def render_result(result: ScanResult, format: str = "table") -> str:
    registry = get_registry()
    for reporter in registry.reporters.values():
        if getattr(reporter, "format", None) == format:
            return reporter.render(result)
    return f"{len(result.findings)} findings in {result.packages_scanned} packages"
