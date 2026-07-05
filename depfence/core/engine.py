"""Scan engine — orchestrates scanners, analyzers, and reporters."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.fetcher import fetch_batch
from depfence.core.inline_suppress import filter_findings as _inline_filter
from depfence.core.inline_suppress import parse_suppressions
from depfence.core.lockfile import detect_ecosystem, parse_lockfile
from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, ScanResult, Severity
from depfence.core.registry import get_registry

log = logging.getLogger(__name__)


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
) -> tuple[list[Finding], list[str]]:
    skip = {
        "behavioral": skip_behavioral,
        "reputation": skip_reputation,
    }
    tasks = []
    for name, scanner in registry.scanners.items():  # type: ignore[attr-defined]
        if skip_advisory and "advisory" in name:
            continue
        if skip.get(name, False):
            continue
        if not hasattr(scanner, 'scan') or not hasattr(scanner, 'ecosystems'):
            continue
        relevant = [m for m in metas if m.pkg.ecosystem in scanner.ecosystems]
        if relevant:
            tasks.append(scanner.scan(relevant))
    if not tasks:
        return [], []
    findings: list[Finding] = []
    errors: list[str] = []
    for sr in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(sr, list):
            findings.extend(sr)
        elif isinstance(sr, Exception):
            errors.append(str(sr))
    return findings, errors


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


async def _run_project_scanners(project_dir: Path) -> tuple[list[Finding], list[str]]:
    from depfence.scanners.agent_skill_scanner import AgentSkillScanner
    from depfence.scanners.ai_bom_generator import AiBomGenerator
    from depfence.scanners.android_manifest_scanner import AndroidManifestScanner
    from depfence.scanners.binding_gyp_scanner import BindingGypScanner
    from depfence.scanners.cocoapods_hook_scanner import CocoaPodsHookScanner
    from depfence.scanners.composer_script_scanner import ComposerScriptScanner
    from depfence.scanners.dockerfile_scanner import DockerfileScanner
    from depfence.scanners.editor_config_scanner import EditorConfigScanner
    from depfence.scanners.flutter_pubspec_scanner import FlutterPubspecScanner
    from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner
    from depfence.scanners.git_message_scanner import GitMessageScanner
    from depfence.scanners.go_generate_scanner import GoGenerateScanner
    from depfence.scanners.gradle_plugin_scanner import GradlePluginScanner
    from depfence.scanners.maven_plugin_scanner import MavenPluginScanner
    from depfence.scanners.mcp_scanner import McpScanner
    from depfence.scanners.model_format_scanner import ModelFormatScanner
    from depfence.scanners.model_integrity import ModelIntegrityScanner
    from depfence.scanners.model_scanner import ModelScanner
    from depfence.scanners.network_scanner import NetworkScanner
    from depfence.scanners.obfuscation import ObfuscationScanner
    from depfence.scanners.payload_behavior_scanner import PayloadBehaviorScanner
    from depfence.scanners.pinning_scanner import PinningScanner
    from depfence.scanners.preinstall import PreinstallScanner
    from depfence.scanners.prompt_injection_scanner import PromptInjectionScanner
    from depfence.scanners.protestware_scanner import ProtestwareScanner
    from depfence.scanners.python_build_scanner import PythonBuildScanner
    from depfence.scanners.resolve_existence_scanner import ResolveExistenceScanner
    from depfence.scanners.ruby_lifecycle_scanner import RubyLifecycleScanner
    from depfence.scanners.rust_build_scanner import RustBuildScanner
    from depfence.scanners.secrets_scanner import SecretsScanner
    from depfence.scanners.spm_plugin_scanner import SpmPluginScanner
    from depfence.scanners.terraform_scanner import TerraformScanner

    instances = [
        DockerfileScanner(), TerraformScanner(), GhaWorkflowScanner(),
        SecretsScanner(), PinningScanner(), ResolveExistenceScanner(),
        EditorConfigScanner(), BindingGypScanner(),
        ObfuscationScanner(), PreinstallScanner(), NetworkScanner(),
        GitMessageScanner(), PayloadBehaviorScanner(), ProtestwareScanner(),
        RubyLifecycleScanner(),
        GradlePluginScanner(), AndroidManifestScanner(),
        CocoaPodsHookScanner(), FlutterPubspecScanner(), SpmPluginScanner(),
        RustBuildScanner(), GoGenerateScanner(), ComposerScriptScanner(),
        PythonBuildScanner(), MavenPluginScanner(),
        ModelScanner(), ModelFormatScanner(), ModelIntegrityScanner(),
        PromptInjectionScanner(), AgentSkillScanner(), McpScanner(),
        AiBomGenerator(),
    ]
    findings: list[Finding] = []
    errors: list[str] = []
    proj_tasks = [s.scan_project(project_dir) for s in instances]
    for pr in await asyncio.gather(*proj_tasks, return_exceptions=True):
        if isinstance(pr, list):
            findings.extend(pr)
        elif isinstance(pr, Exception):
            log.debug("Project scanner error: %s", pr)
            errors.append(str(pr))
    return findings, errors


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
) -> ScanResult:
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
        scanner_findings, scanner_errors = await _run_scanners(
            registry, metas, skip_advisory, skip_behavioral, skip_reputation
        )
        all_findings.extend(scanner_findings)
        result.errors.extend(scanner_errors)

        _progress("Running analyzers...")
        analyzer_findings, analyzer_errors = await _run_analyzers(registry, metas)
        all_findings.extend(analyzer_findings)
        result.errors.extend(analyzer_errors)

        await registry.fire_hook("post_scan", findings=all_findings, metas=metas)

    if project_scanners:
        _progress("Running project scanners (32 scanners)...")
        proj_findings, proj_errors = await _run_project_scanners(project_dir)
        all_findings.extend(proj_findings)
        result.errors.extend(proj_errors)

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
                    return reporter.render(result, max_rows=max_rows)
            return reporter.render(result)
    return f"{len(result.findings)} findings in {result.packages_scanned} packages"
