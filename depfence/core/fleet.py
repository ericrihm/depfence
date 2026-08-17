"""Privacy-preserving inventory and per-project fleet scanning."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import subprocess
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from depfence.core.finding_identity import finding_id
from depfence.core.local_state import PrivateState
from depfence.core.models import ScanResult, ScanState, Severity
from depfence.core.snapshot import redact_text

FLEET_SCHEMA_VERSION = "depfence.fleet/v1"
FLEET_CHECKPOINT_SCHEMA_VERSION = "depfence.fleet-checkpoint/v1"
FLEET_CHECKPOINT_MANIFEST_SCHEMA_VERSION = "depfence.fleet-checkpoint-manifest/v1"

_SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".tox",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_LOCKFILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
}


def _git_directory(project: Path) -> Path | None:
    marker = project / ".git"
    if marker.is_dir() and not marker.is_symlink():
        return marker
    if not marker.is_file() or marker.is_symlink():
        return None
    try:
        line = marker.read_text(encoding="utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        return None
    if not line.startswith("gitdir: "):
        return None
    requested = Path(line[8:])
    candidate = requested if requested.is_absolute() else project / requested
    resolved = candidate.resolve(strict=False)
    return resolved if resolved.is_dir() else None


def discover_worktrees(root: Path, *, max_projects: int = 10_000) -> tuple[list[Path], list[str]]:
    """Discover Git worktrees without invoking Git or repository-controlled code."""

    root = root.expanduser().resolve(strict=True)
    projects: list[Path] = []
    errors: list[str] = []
    for directory, names, _files in os.walk(root, followlinks=False):
        current = Path(directory)
        names[:] = [
            name
            for name in names
            if name not in _SKIP_DIRECTORIES and not (current / name).is_symlink()
        ]
        if _git_directory(current) is not None:
            projects.append(current)
            names[:] = []
            if len(projects) >= max_projects:
                errors.append(f"fleet discovery reached the {max_projects}-project budget")
                break
    return sorted(projects), errors


def _safe_git(
    project: Path,
    *arguments: str,
    timeout: float = 5.0,
    absent_exit_codes: frozenset[int] = frozenset(),
) -> tuple[str | None, str | None]:
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-C",
        str(project),
        *arguments,
    ]
    environment = {
        **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
    }
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"git evidence unavailable ({type(exc).__name__})"
    if completed.returncode in absent_exit_codes:
        return None, None
    if completed.returncode:
        return None, f"git evidence unavailable (exit {completed.returncode})"
    return completed.stdout.strip(), None


def _remote_host(remote: str | None) -> str | None:
    if not remote:
        return None
    if "://" in remote:
        return urlparse(remote).hostname
    if ":" in remote and "@" in remote.split(":", 1)[0]:
        return remote.split("@", 1)[1].split(":", 1)[0]
    return "local" if Path(remote).expanduser().is_absolute() else "unknown"


def _config_value(project: Path, key: str) -> str | None:
    value, _error = _safe_git(
        project,
        "config",
        "--local",
        "--get",
        key,
        absent_exit_codes=frozenset({1}),
    )
    return value


@dataclass(frozen=True)
class ProjectInventory:
    project_id: str
    remote_host: str | None
    remote_present: bool
    linked_worktree: bool
    hooks_path: bool
    hooks_path_external: bool
    fsmonitor: bool
    filters: bool
    alternates: bool
    workflow_files: int
    lockfiles: int
    env_files: int
    executable_files: int
    symlinks: int
    coverage: ScanState
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "project_id": self.project_id,
            "remote": {"present": self.remote_present, "host": self.remote_host},
            "git": {
                "linked_worktree": self.linked_worktree,
                "hooks_path": self.hooks_path,
                "hooks_path_external": self.hooks_path_external,
                "fsmonitor": self.fsmonitor,
                "filters": self.filters,
                "alternates": self.alternates,
            },
            "counts": {
                "workflow_files": self.workflow_files,
                "lockfiles": self.lockfiles,
                "env_files": self.env_files,
                "executable_files": self.executable_files,
                "symlinks": self.symlinks,
            },
            "coverage": self.coverage.value,
            "errors": list(self.errors),
        }


def inspect_project(project: Path, state: PrivateState, *, file_budget: int = 100_000) -> ProjectInventory:
    project = project.resolve(strict=True)
    errors: list[str] = []
    marker = project / ".git"
    git_directory = _git_directory(project)
    if git_directory is None:
        raise ValueError("project is not a readable Git worktree")
    # A directory named .git is only a candidate marker.  Validate it once
    # before issuing the several evidence queries below; otherwise malformed
    # or half-recovered trees can consume one timeout per query and turn a
    # bounded fleet inventory into an effectively unbounded operation.
    inside_worktree, validation_error = _safe_git(
        project, "rev-parse", "--is-inside-work-tree"
    )
    if validation_error or inside_worktree != "true":
        raise ValueError("project Git worktree evidence is unavailable")
    # A worktree does not need a remote. Git config exits 1 for an absent
    # value, which is complete negative evidence rather than an error.
    remote, remote_error = _safe_git(
        project,
        "config",
        "--local",
        "--get",
        "remote.origin.url",
        absent_exit_codes=frozenset({1}),
    )
    if remote_error:
        errors.append(remote_error)
    hooks_path = _config_value(project, "core.hooksPath")
    fsmonitor = bool(_config_value(project, "core.fsmonitor"))
    filters_text, _ = _safe_git(
        project,
        "config",
        "--local",
        "--get-regexp",
        r"^filter\.",
        absent_exit_codes=frozenset({1}),
    )
    hooks_external = False
    if hooks_path:
        requested = Path(hooks_path).expanduser()
        resolved = (project / requested).resolve(strict=False) if not requested.is_absolute() else requested.resolve(strict=False)
        try:
            resolved.relative_to(project)
        except ValueError:
            hooks_external = True
    alternate_file = git_directory / "objects" / "info" / "alternates"

    counts: Counter[str] = Counter()
    visited = 0
    for directory, names, files in os.walk(project, followlinks=False):
        current = Path(directory)
        symlink_directories = {name for name in names if (current / name).is_symlink()}
        counts["symlinks"] += len(symlink_directories)
        names[:] = [
            name
            for name in names
            if name not in _SKIP_DIRECTORIES and name not in symlink_directories
        ]
        counts["symlinks"] += sum((current / name).is_symlink() for name in files)
        for name in files:
            visited += 1
            if visited > file_budget:
                errors.append(f"project inventory reached the {file_budget}-file budget")
                names[:] = []
                break
            path = current / name
            if name in _LOCKFILES:
                counts["lockfiles"] += 1
            if name == ".env" or name.startswith(".env."):
                counts["env_files"] += 1
            if ".github" in path.parts and "workflows" in path.parts and path.suffix in {".yml", ".yaml"}:
                counts["workflow_files"] += 1
            try:
                mode = path.lstat().st_mode
            except OSError:
                errors.append("one or more project files were unreadable")
                continue
            if stat.S_ISREG(mode) and mode & 0o111:
                counts["executable_files"] += 1
        if visited > file_budget:
            break

    return ProjectInventory(
        project_id=state.project_id(project),
        remote_host=_remote_host(remote),
        remote_present=bool(remote),
        linked_worktree=marker.is_file(),
        hooks_path=bool(hooks_path),
        hooks_path_external=hooks_external,
        fsmonitor=fsmonitor,
        filters=bool(filters_text),
        alternates=alternate_file.exists(),
        workflow_files=counts["workflow_files"],
        lockfiles=counts["lockfiles"],
        env_files=counts["env_files"],
        executable_files=counts["executable_files"],
        symlinks=counts["symlinks"],
        coverage=ScanState.INDETERMINATE if errors else ScanState.PASS,
        errors=tuple(dict.fromkeys(errors)),
    )


@dataclass
class FleetDocument:
    root_id: str
    projects: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def status(self) -> ScanState:
        states = {str(project.get("status") or project.get("coverage")) for project in self.projects}
        if self.errors or "INDETERMINATE" in states or "UNPROVEN" in states:
            return ScanState.INDETERMINATE
        if "FAIL" in states:
            return ScanState.FAIL
        return ScanState.PASS if self.projects else ScanState.UNPROVEN

    def to_dict(self) -> dict[str, object]:
        counts = Counter(str(project.get("status") or project.get("coverage")) for project in self.projects)
        return {
            "schema_version": FLEET_SCHEMA_VERSION,
            "created_at": self.created_at,
            "root_id": self.root_id,
            "status": self.status.value,
            "summary": {"projects": len(self.projects), "states": dict(sorted(counts.items()))},
            "coverage": {"complete": self.status not in {ScanState.INDETERMINATE, ScanState.UNPROVEN}, "errors": self.errors},
            "projects": self.projects,
        }


def inventory_fleet(root: Path, *, state: PrivateState | None = None) -> FleetDocument:
    root = root.expanduser().resolve(strict=True)
    private = state or PrivateState.open(project_root=root)
    projects, errors = discover_worktrees(root)
    document = FleetDocument(root_id=private.opaque_id("fleet", root), errors=errors)
    for project in projects:
        try:
            document.projects.append(inspect_project(project, private).to_dict())
        except (OSError, ValueError) as exc:
            document.projects.append(
                {
                    "project_id": private.project_id(project),
                    "coverage": ScanState.INDETERMINATE.value,
                    "errors": [f"inventory unavailable ({type(exc).__name__})"],
                }
            )
    return document


def _coverage_reason(state: ScanState, error: str | None) -> str:
    """Return a stable, non-sensitive reason for one scanner coverage state."""

    lowered = (error or "").lower()
    if "offline policy" in lowered or "disabled by policy" in lowered:
        return "disabled_by_policy"
    if "timeout" in lowered or "timed out" in lowered:
        return "timed_out"
    if error or state is ScanState.INDETERMINATE:
        return "failed"
    if state is ScanState.UNPROVEN:
        return "unsupported"
    return "evaluated"


def _scan_summary(
    project_id: str,
    result: ScanResult,
    *,
    policy_disabled: tuple[str, ...] = (),
) -> dict[str, object]:
    incomplete = bool(result.errors) or bool(policy_disabled) or any(
        state in {ScanState.INDETERMINATE, ScanState.UNPROVEN}
        for state in result.scanner_coverage.values()
    )
    status = (
        ScanState.INDETERMINATE
        if incomplete
        else ScanState.FAIL
        if result.findings
        else ScanState.PASS
        if result.packages_scanned
        else ScanState.UNPROVEN
    )
    severities = Counter(finding.severity.value for finding in result.findings)
    rules = Counter(finding.finding_type.value for finding in result.findings)
    rule_severity: dict[str, Counter[str]] = {}
    for finding in result.findings:
        rule = finding.finding_type.value
        rule_severity.setdefault(rule, Counter())[finding.severity.value] += 1
    scanner_reasons = {
        name: _coverage_reason(state, result.scanner_errors.get(name))
        for name, state in sorted(result.scanner_coverage.items())
    }
    scanner_reasons.update({name: "disabled_by_policy" for name in policy_disabled})
    reason_counts = Counter(scanner_reasons.values())
    return {
        "project_id": project_id,
        "status": status.value,
        "packages_scanned": result.packages_scanned,
        "summary": {
            "findings": len(result.findings),
            "severity": {severity.value: severities[severity.value] for severity in Severity},
            "rules": dict(sorted(rules.items())),
            "rule_severity": {
                rule: {
                    severity.value: counts[severity.value]
                    for severity in Severity
                    if counts[severity.value]
                }
                for rule, counts in sorted(rule_severity.items())
            },
        },
        "finding_ids": sorted(finding_id(finding) for finding in result.findings),
        "coverage": {
            "scanners": {name: value.value for name, value in sorted(result.scanner_coverage.items())},
            "reasons": dict(sorted(scanner_reasons.items())),
            "reason_counts": dict(sorted(reason_counts.items())),
            "policy_disabled": list(policy_disabled),
            "errors": [redact_text(error) for error in result.errors],
            "scanner_errors": {
                name: redact_text(error) for name, error in sorted(result.scanner_errors.items())
            },
        },
    }


class _FleetCheckpointStore:
    """Atomically retain redacted project results during a fleet audit."""

    def __init__(
        self,
        state: PrivateState,
        *,
        root_id: str,
        project_ids: list[str],
        created_at: str,
        resume_manifest: dict[str, object] | None = None,
    ) -> None:
        self._state = state
        self._root_id = root_id
        self._project_ids = frozenset(project_ids)
        self._completed: dict[str, str] = {}
        self._created_at = created_at
        self._audit_id = state.opaque_id("fleet_audit", f"{root_id}\0{created_at}")
        if resume_manifest is not None:
            self._audit_id = str(resume_manifest["audit_id"])
            self._created_at = str(resume_manifest["created_at"])
            completed = resume_manifest.get("completed")
            if isinstance(completed, list):
                self._completed = {
                    str(entry["project_id"]): str(entry["checkpoint"])
                    for entry in completed
                    if isinstance(entry, dict)
                }
        self._directory = f"evidence/fleet-audit/{self._audit_id.rsplit(':', 1)[-1]}"
        self._lock = asyncio.Lock()
        self._write_manifest("ACTIVE", "audit has not completed")

    def _manifest(self, lifecycle: str, incomplete_cause: str) -> dict[str, object]:
        completed_ids = sorted(self._completed)
        unfinished_ids = sorted(self._project_ids.difference(self._completed))
        return {
            "schema_version": FLEET_CHECKPOINT_MANIFEST_SCHEMA_VERSION,
            "audit_id": self._audit_id,
            "root_id": self._root_id,
            "created_at": self._created_at,
            "lifecycle": lifecycle,
            "completed": [
                {"project_id": project_id, "checkpoint": self._completed[project_id]}
                for project_id in completed_ids
            ],
            "unfinished": [
                {
                    "project_id": project_id,
                    "status": ScanState.INDETERMINATE.value,
                    "cause": incomplete_cause,
                }
                for project_id in unfinished_ids
            ],
        }

    def _write_manifest(self, lifecycle: str, incomplete_cause: str) -> None:
        from depfence.schemas import validate_document

        manifest = self._manifest(lifecycle, incomplete_cause)
        validate_document(manifest)
        payload = json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + "\n"
        self._state.write_text(f"{self._directory}/manifest.json", payload)
        self._state.write_text("evidence/fleet-audit/latest.json", payload)

    async def record(self, project: dict[str, object]) -> None:
        from depfence.schemas import validate_document

        project_id = str(project["project_id"])
        if project_id not in self._project_ids:
            raise ValueError("fleet checkpoint project is outside the audit scope")
        relative = f"{self._directory}/projects/{project_id.rsplit(':', 1)[-1]}.json"
        coverage = project.get("coverage")
        safe_coverage: dict[str, object] = {}
        if isinstance(coverage, dict):
            scanners = coverage.get("scanners")
            safe_coverage["scanners"] = scanners if isinstance(scanners, dict) else {}
            reasons = coverage.get("reasons")
            safe_coverage["reasons"] = reasons if isinstance(reasons, dict) else {}
            reason_counts = coverage.get("reason_counts")
            safe_coverage["reason_counts"] = (
                reason_counts if isinstance(reason_counts, dict) else {}
            )
            policy_disabled = coverage.get("policy_disabled")
            safe_coverage["policy_disabled"] = (
                policy_disabled if isinstance(policy_disabled, list) else []
            )
            errors = coverage.get("errors")
            error_count = len(errors) if isinstance(errors, list) else 0
            safe_coverage["errors"] = (
                [f"{error_count} scan coverage error(s) reported"] if error_count else []
            )
            scanner_errors = coverage.get("scanner_errors")
            safe_coverage["scanner_errors"] = (
                {
                    str(name): "scanner reported incomplete coverage"
                    for name in sorted(scanner_errors)
                }
                if isinstance(scanner_errors, dict)
                else {}
            )
        safe_project = {
            "project_id": project_id,
            "status": project.get("status"),
            "packages_scanned": project.get("packages_scanned"),
            "summary": project.get("summary"),
            "finding_ids": project.get("finding_ids"),
            "coverage": safe_coverage,
        }
        checkpoint = {
            "schema_version": FLEET_CHECKPOINT_SCHEMA_VERSION,
            "audit_id": self._audit_id,
            "root_id": self._root_id,
            "project": safe_project,
        }
        validate_document(checkpoint)
        payload = json.dumps(checkpoint, sort_keys=True, indent=2, allow_nan=False) + "\n"
        async with self._lock:
            self._state.write_text(relative, payload)
            self._completed[project_id] = relative
            self._write_manifest("ACTIVE", "audit has not completed")

    async def finish(self) -> None:
        async with self._lock:
            if self._project_ids.difference(self._completed):
                self._write_manifest(
                    "INTERRUPTED",
                    "audit selection did not include this unfinished project",
                )
            else:
                self._write_manifest("COMPLETE", "")

    async def interrupt(self) -> None:
        async with self._lock:
            self._write_manifest(
                "INTERRUPTED",
                "audit interrupted before a durable project result was produced",
            )


async def audit_fleet(
    root: Path,
    *,
    workers: int = 4,
    project_deadline: float = 300.0,
    fleet_deadline: float | None = 1800.0,
    online: bool = False,
    state: PrivateState | None = None,
    scanner: Callable[[Path], Awaitable[ScanResult]] | None = None,
    resume: bool = False,
    project_ids: frozenset[str] | None = None,
) -> FleetDocument:
    """Scan worktrees independently under one global concurrency budget."""

    if fleet_deadline is not None and fleet_deadline <= 0:
        raise ValueError("fleet audit deadline must be positive")
    aggregate_deadline = (
        time.monotonic() + fleet_deadline if fleet_deadline is not None else None
    )
    root = root.expanduser().resolve(strict=True)
    private = state or PrivateState.open(project_root=root)
    candidates, errors = discover_worktrees(root)
    document = FleetDocument(root_id=private.opaque_id("fleet", root), errors=errors)
    candidate_by_id = {private.project_id(project): project for project in candidates}
    candidate_ids = frozenset(candidate_by_id)
    requested_ids = candidate_ids if project_ids is None else project_ids
    unknown_ids = requested_ids.difference(candidate_ids)
    if unknown_ids:
        document.errors.append(
            f"fleet selection contains {len(unknown_ids)} undiscovered project identifier(s)"
        )
        return document

    resume_manifest: dict[str, object] | None = None
    resumed_projects: list[dict[str, object]] = []
    completed_ids: frozenset[str] = frozenset()
    if resume:
        from depfence.schemas import validate_document

        latest = private.path("evidence/fleet-audit/latest.json")
        try:
            resume_manifest = json.loads(latest.read_text(encoding="utf-8"))
            validate_document(resume_manifest)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            document.errors.append(f"fleet resume unavailable ({type(exc).__name__})")
            return document
        if resume_manifest.get("root_id") != document.root_id:
            document.errors.append("fleet resume root does not match the requested fleet")
            return document
        document.created_at = str(resume_manifest["created_at"])
        manifest_entries: list[object] = []
        for key in ("completed", "unfinished"):
            entries = resume_manifest.get(key)
            if isinstance(entries, list):
                manifest_entries.extend(entries)
        manifest_ids = {
            str(entry.get("project_id"))
            for entry in manifest_entries
            if isinstance(entry, dict)
        }
        if manifest_ids != candidate_ids:
            document.errors.append("fleet resume candidate set changed since the checkpoint")
            return document
        completed_entries = resume_manifest.get("completed")
        if isinstance(completed_entries, list):
            for entry in completed_entries:
                if not isinstance(entry, dict):
                    continue
                checkpoint_path = entry.get("checkpoint")
                if not isinstance(checkpoint_path, str):
                    continue
                try:
                    checkpoint = json.loads(
                        private.path(checkpoint_path).read_text(encoding="utf-8")
                    )
                    validate_document(checkpoint)
                except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                    document.errors.append(
                        f"fleet resume checkpoint unavailable ({type(exc).__name__})"
                    )
                    return document
                if (
                    checkpoint.get("audit_id") != resume_manifest.get("audit_id")
                    or checkpoint.get("root_id") != document.root_id
                ):
                    document.errors.append("fleet resume checkpoint identity mismatch")
                    return document
                project = checkpoint.get("project")
                if not isinstance(project, dict) or project.get("project_id") != entry.get("project_id"):
                    document.errors.append("fleet resume project identity mismatch")
                    return document
                summary = project.get("summary")
                findings = summary.get("findings") if isinstance(summary, dict) else None
                # Checkpoints written before rule/severity cross-tabulation
                # cannot classify critical findings. Rescan positive projects
                # instead of treating their incomplete summaries as finished.
                if (
                    isinstance(summary, dict)
                    and isinstance(findings, int)
                    and findings > 0
                    and "rule_severity" not in summary
                ):
                    continue
                resumed_projects.append(project)
        completed_ids = frozenset(str(project["project_id"]) for project in resumed_projects)
        # Drop stale positive checkpoints from the store's completed set. If a
        # replacement scan is interrupted, they must remain unfinished rather
        # than falling back to evidence that cannot classify severity by rule.
        completed_entries = resume_manifest.get("completed")
        resume_manifest = {
            **resume_manifest,
            "completed": [
                entry
                for entry in completed_entries
                if isinstance(entry, dict) and entry.get("project_id") in completed_ids
            ]
            if isinstance(completed_entries, list)
            else [],
        }

    selected_ids = requested_ids.difference(completed_ids)
    checkpoints = _FleetCheckpointStore(
        private,
        root_id=document.root_id,
        project_ids=list(candidate_ids),
        created_at=(
            str(resume_manifest["created_at"])
            if resume_manifest is not None
            else document.created_at
        ),
        resume_manifest=resume_manifest,
    )
    semaphore = asyncio.Semaphore(max(1, workers))

    projects: list[Path] = []
    invalid_summaries: list[dict[str, object]] = []
    for project_id, project in candidate_by_id.items():
        if project_id not in selected_ids:
            continue
        inside_worktree, validation_error = _safe_git(
            project, "rev-parse", "--is-inside-work-tree"
        )
        if validation_error is None and inside_worktree == "true":
            projects.append(project)
            continue
        invalid_summaries.append(
            {
                "project_id": project_id,
                "status": ScanState.INDETERMINATE.value,
                "coverage": {
                    "scanners": {},
                    "errors": ["project scan unavailable (invalid Git worktree evidence)"],
                    "scanner_errors": {
                        "fleet": "project scan unavailable (invalid Git worktree evidence)"
                    },
                },
                "packages_scanned": 0,
                "summary": {
                    "findings": 0,
                    "severity": {severity.value: 0 for severity in Severity},
                    "rules": {},
                    "rule_severity": {},
                },
                "finding_ids": [],
            }
        )

    uses_default_scanner = scanner is None
    policy_disabled: tuple[str, ...] = ()
    if uses_default_scanner and not online:
        from depfence.core.registry import SHIPPED_SCANNERS

        policy_disabled = tuple(
            sorted(
                spec.name
                for spec in SHIPPED_SCANNERS
                if spec.advisory or spec.requires_network
            )
        )

    if scanner is None:
        from depfence.core.engine import scan_directory

        async def scanner(project: Path) -> ScanResult:
            return await scan_directory(
                project,
                fetch_metadata=online,
                skip_advisory=not online,
                skip_reputation=not online,
                enrich=online,
                project_scanners=True,
                project_workers=1,
                project_deadline=project_deadline,
                profile="full",
            )

    async def run(project: Path) -> dict[str, object]:
        project_id = private.project_id(project)
        async with semaphore:
            try:
                result = await asyncio.wait_for(scanner(project), timeout=project_deadline)
            except (OSError, RuntimeError, ValueError, TypeError, asyncio.TimeoutError) as exc:
                summary = {
                    "project_id": project_id,
                    "status": ScanState.INDETERMINATE.value,
                    "coverage": {
                        "scanners": {},
                        "errors": [f"project scan unavailable ({type(exc).__name__})"],
                        "scanner_errors": {"fleet": f"project scan unavailable ({type(exc).__name__})"},
                    },
                    "packages_scanned": 0,
                    "summary": {
                        "findings": 0,
                        "severity": {severity.value: 0 for severity in Severity},
                        "rules": {},
                        "rule_severity": {},
                    },
                    "finding_ids": [],
                }
            else:
                summary = _scan_summary(
                    project_id,
                    result,
                    policy_disabled=policy_disabled,
                )
            await checkpoints.record(summary)
            return summary

    for summary in invalid_summaries:
        await checkpoints.record(summary)
    task_projects = {
        asyncio.create_task(run(project)): private.project_id(project)
        for project in projects
    }
    tasks = list(task_projects)
    try:
        if not tasks:
            scanned_projects = []
        elif aggregate_deadline is None:
            scanned_projects = list(await asyncio.gather(*tasks))
        else:
            remaining = max(0.0, aggregate_deadline - time.monotonic())
            done, pending = await asyncio.wait(tasks, timeout=remaining)
            if pending:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            scanned_projects = [task.result() for task in tasks if task in done]
            if pending:
                await checkpoints.interrupt()
                document.errors.append("fleet audit reached its aggregate deadline")
                timed_out = [
                    {
                        "project_id": task_projects[task],
                        "status": ScanState.INDETERMINATE.value,
                        "coverage": {
                            "scanners": {},
                            "reasons": {"fleet": "timed_out"},
                            "reason_counts": {"timed_out": 1},
                            "policy_disabled": [],
                            "errors": ["project not evaluated before the fleet deadline"],
                            "scanner_errors": {
                                "fleet": "project not evaluated before the fleet deadline"
                            },
                        },
                        "packages_scanned": 0,
                        "summary": {
                            "findings": 0,
                            "severity": {severity.value: 0 for severity in Severity},
                            "rules": {},
                            "rule_severity": {},
                        },
                        "finding_ids": [],
                    }
                    for task in tasks
                    if task in pending
                ]
                document.projects = [
                    *resumed_projects,
                    *invalid_summaries,
                    *scanned_projects,
                    *timed_out,
                ]
                return document
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await checkpoints.interrupt()
        raise
    unselected_ids = candidate_ids.difference(completed_ids).difference(selected_ids)
    unselected = [
        {
            "project_id": project_id,
            "status": ScanState.INDETERMINATE.value,
            "coverage": {
                "scanners": {},
                "reasons": {"fleet": "disabled_by_policy"},
                "reason_counts": {"disabled_by_policy": 1},
                "policy_disabled": ["fleet"],
                "errors": ["project not evaluated by this explicit fleet selection"],
                "scanner_errors": {
                    "fleet": "project not evaluated by this explicit fleet selection"
                },
            },
            "packages_scanned": 0,
            "summary": {
                "findings": 0,
                "severity": {severity.value: 0 for severity in Severity},
                "rules": {},
                "rule_severity": {},
            },
            "finding_ids": [],
        }
        for project_id in sorted(unselected_ids)
    ]
    document.projects = [*resumed_projects, *invalid_summaries, *scanned_projects, *unselected]
    await checkpoints.finish()
    return document


__all__ = [
    "FLEET_SCHEMA_VERSION",
    "FLEET_CHECKPOINT_MANIFEST_SCHEMA_VERSION",
    "FLEET_CHECKPOINT_SCHEMA_VERSION",
    "FleetDocument",
    "ProjectInventory",
    "audit_fleet",
    "discover_worktrees",
    "inspect_project",
    "inventory_fleet",
]
