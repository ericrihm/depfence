"""Parallel / concurrent scan orchestrator for monorepos.

Discovers all lockfiles in a directory tree, groups them by ecosystem,
and runs ``scan_directory`` concurrently across each lockfile's parent
directory — bounded by a semaphore so the host is never overwhelmed.

Usage (programmatic):
    from depfence.core.parallel import parallel_scan
    result = asyncio.run(parallel_scan(root, workers=8))

Usage (CLI):
    depfence scan /my/monorepo --parallel
    depfence scan /my/monorepo -j 8
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import (
    Finding,
    ScannerErrorCode,
    ScannerOutcome,
    ScannerReasonCode,
    ScanResult,
    ScanState,
    merge_scan_state,
)
from depfence.core.scanner_outcome import materialize, merge_outcome

log = logging.getLogger(__name__)

# All lockfile names recognised by detect_ecosystem(), keyed by filename → ecosystem
_LOCKFILE_MAP: dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lockb": "npm",
    "requirements.txt": "pypi",
    "poetry.lock": "pypi",
    "Pipfile.lock": "pypi",
    "uv.lock": "pypi",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "gradle.lockfile": "maven",
    "Package.resolved": "swift",
    "Podfile.lock": "swift",
    "packages.lock.json": "nuget",
    "Gemfile.lock": "rubygems",
    "composer.lock": "packagist",
}


@dataclass
class LockfileEntry:
    """A single discovered lockfile."""
    ecosystem: str
    path: Path

    @property
    def directory(self) -> Path:
        return self.path.parent

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.path}"


@dataclass
class ParallelScanResult:
    """Aggregated result from a parallel monorepo scan."""
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    completed_at: datetime | None = None

    # Per-lockfile results; kept for callers that want fine-grained data
    sub_results: list[tuple[LockfileEntry, ScanResult]] = field(default_factory=list)

    # Merged summary (combined across all sub-results)
    merged: ScanResult | None = None

    @property
    def findings(self) -> list[Finding]:
        return self.merged.findings if self.merged else []

    @property
    def errors(self) -> list[str]:
        errors = [error for _, result in self.sub_results for error in result.errors]
        if self.merged:
            errors.extend(self.merged.errors)
        return list(dict.fromkeys(errors))

    @property
    def packages_scanned(self) -> int:
        return sum(r.packages_scanned for _, r in self.sub_results)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_lockfiles(root: Path, max_depth: int = 10) -> list[LockfileEntry]:
    """Recursively discover all recognised lockfiles under *root*.

    Args:
        root: Directory to search from.
        max_depth: Maximum directory recursion depth (default 10).

    Returns:
        List of :class:`LockfileEntry` objects, one per lockfile found.
        The list is sorted so that shallower paths come first.
    """
    entries: list[LockfileEntry] = []
    root = root.resolve()

    def _walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            children = list(directory.iterdir())
        except PermissionError:
            return

        for child in children:
            if child.is_file() and child.name in _LOCKFILE_MAP:
                eco = _LOCKFILE_MAP[child.name]
                entries.append(LockfileEntry(ecosystem=eco, path=child))
            elif child.is_dir() and not child.name.startswith(".") and child.name != "node_modules":
                _walk(child, depth + 1)

    _walk(root, 0)
    entries.sort(key=lambda e: (len(e.path.parts), str(e.path)))
    return entries


def group_by_ecosystem(entries: list[LockfileEntry]) -> dict[str, list[LockfileEntry]]:
    """Group lockfile entries by ecosystem name."""
    groups: dict[str, list[LockfileEntry]] = {}
    for entry in entries:
        groups.setdefault(entry.ecosystem, []).append(entry)
    return groups


# ---------------------------------------------------------------------------
# Concurrent scan
# ---------------------------------------------------------------------------

async def parallel_scan(
    root: Path,
    workers: int = 4,
    ecosystems: list[str] | None = None,
    skip_advisory: bool = False,
    skip_behavioral: bool = False,
    skip_reputation: bool = False,
    fetch_metadata: bool = True,
    project_scanners: bool = True,
    enrich: bool = True,
    progress_callback: Callable[[LockfileEntry, int, int], None] | None = None,
    profile: str = "full",
) -> ParallelScanResult:
    """Scan a monorepo directory tree concurrently.

    Lockfiles are discovered recursively, then scanned in parallel using up
    to *workers* concurrent tasks.  Results are merged into a single
    :class:`ParallelScanResult`.

    Args:
        root: Root directory to scan.
        workers: Maximum number of concurrent scan tasks (semaphore limit).
        ecosystems: Optional filter — only scan these ecosystems.
        skip_advisory: Skip CVE/advisory checks.
        skip_behavioral: Skip behavioural analysis.
        skip_reputation: Skip reputation scoring.
        fetch_metadata: Fetch package metadata from registries.
        project_scanners: Run Dockerfile / Terraform / secrets scanners.
        enrich: Enrich findings with EPSS, KEV, threat-intel data.
        progress_callback: Called with ``(entry, done, total)`` after each
            lockfile scan completes.  Runs in the event-loop thread.

    Returns:
        A :class:`ParallelScanResult` with per-lockfile sub-results and a
        merged :class:`ScanResult`.
    """
    from depfence.core.engine import scan_directory
    from depfence.core.models import ScanResult as _SR

    root = root.resolve()
    result = ParallelScanResult(target=str(root))

    entries = discover_lockfiles(root)
    if ecosystems:
        eco_set = set(ecosystems)
        entries = [e for e in entries if e.ecosystem in eco_set]

    if not entries:
        log.warning("parallel_scan: no lockfiles found under %s", root)
        merged = _SR(target=str(root), ecosystem="multi")
        message = f"No lockfiles found under {root}"
        merged.errors.append(message)
        merged.scanner_coverage["parallel_discovery"] = ScanState.UNPROVEN
        merged.scanner_errors["parallel_discovery"] = message
        merged.scanner_outcomes["parallel_discovery"] = ScannerOutcome(
            state=ScanState.UNPROVEN,
            reason_code=ScannerReasonCode.NO_EVIDENCE,
            evaluated=False,
            skipped=False,
        )
        merged.completed_at = datetime.now(tz=timezone.utc)
        result.merged = merged
        result.completed_at = datetime.now(tz=timezone.utc)
        return result

    # Deduplicate: scan each *directory* once, not once per lockfile
    # (scan_directory already picks up all lockfiles in a given directory)
    seen_dirs: dict[Path, LockfileEntry] = {}
    for entry in entries:
        d = entry.directory
        if d not in seen_dirs:
            seen_dirs[d] = entry

    unique_entries = list(seen_dirs.values())
    total = len(unique_entries)

    log.info(
        "parallel_scan: scanning %d unique director(ies) with up to %d workers",
        total, workers,
    )

    semaphore = asyncio.Semaphore(workers)
    done_count = 0

    async def _scan_one(entry: LockfileEntry) -> tuple[LockfileEntry, ScanResult]:
        nonlocal done_count
        async with semaphore:
            log.debug("Scanning %s …", entry.directory)
            try:
                sub = await scan_directory(
                    entry.directory,
                    ecosystems=ecosystems,
                    skip_advisory=skip_advisory,
                    skip_behavioral=skip_behavioral,
                    skip_reputation=skip_reputation,
                    fetch_metadata=fetch_metadata,
                    project_scanners=project_scanners,
                    enrich=enrich,
                    profile=profile,
                    # The directory-level semaphore already consumes the CLI
                    # budget. One child per active directory keeps total
                    # project-scanner processes bounded by ``workers``.
                    project_workers=1,
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("Error scanning %s: %s", entry.directory, exc)
                sub = _SR(target=str(entry.directory), ecosystem=entry.ecosystem)
                message = str(exc)
                sub.errors.append(message)
                sub.scanner_coverage["parallel_worker"] = ScanState.INDETERMINATE
                sub.scanner_errors["parallel_worker"] = message
                sub.scanner_outcomes["parallel_worker"] = ScannerOutcome(
                    state=ScanState.INDETERMINATE,
                    reason_code=ScannerReasonCode.WORKER_CRASH,
                    error_code=ScannerErrorCode.WORKER_FAILURE,
                    evaluated=False,
                    skipped=False,
                )
                sub.completed_at = datetime.now(tz=timezone.utc)
            done_count += 1
            if progress_callback is not None:
                try:
                    progress_callback(entry, done_count, total)
                except Exception:  # noqa: BLE001
                    pass
            return entry, sub

    tasks = [_scan_one(e) for e in unique_entries]
    sub_results: list[tuple[LockfileEntry, ScanResult]] = await asyncio.gather(*tasks)

    result.sub_results = list(sub_results)
    result.merged = _merge_results(str(root), sub_results)
    result.completed_at = datetime.now(tz=timezone.utc)
    return result


# ---------------------------------------------------------------------------
# Merging helpers
# ---------------------------------------------------------------------------

def _merge_results(
    target: str,
    sub_results: list[tuple[LockfileEntry, ScanResult]],
) -> ScanResult:
    """Merge multiple per-directory :class:`ScanResult` objects into one."""
    from depfence.core.models import ScanResult as _SR

    merged = _SR(target=target, ecosystem="multi")
    seen_findings: set[tuple] = set()
    seen_suppressed: set[tuple] = set()

    def finding_key(finding: Finding) -> tuple[object, ...]:
        package = finding.package
        return (
            getattr(package, "name", str(package)),
            getattr(package, "ecosystem", ""),
            getattr(package, "version", None),
            finding.finding_type.value,
            finding.cve,
            finding.title,
            finding.metadata.get("file"),
            finding.metadata.get("line"),
        )

    for _entry, sub in sub_results:
        merged.packages_scanned += sub.packages_scanned
        for finding in sub.findings:
            key = finding_key(finding)
            if key not in seen_findings:
                seen_findings.add(key)
                merged.findings.append(finding)
        for finding in sub.suppressed_findings:
            key = finding_key(finding)
            if key not in seen_suppressed:
                seen_suppressed.add(key)
                merged.suppressed_findings.append(finding)
        merged.errors.extend(sub.errors)
        for name, status in sub.scanner_coverage.items():
            merged.scanner_coverage[name] = merge_scan_state(
                merged.scanner_coverage.get(name), status
            )
        for name, message in sub.scanner_errors.items():
            existing = merged.scanner_errors.get(name)
            merged.scanner_errors[name] = min(existing, message) if existing else message
        for name, outcome in materialize(
            sub.scanner_coverage,
            sub.scanner_errors,
            sub.scanner_outcomes,
        ).items():
            merged.scanner_coverage[name] = merge_scan_state(
                merged.scanner_coverage.get(name),
                outcome.state,
            )
            merged.scanner_outcomes[name] = merge_outcome(
                merged.scanner_outcomes.get(name),
                outcome,
            )

    merged.completed_at = datetime.now(tz=timezone.utc)
    return merged
