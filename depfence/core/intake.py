"""Quarantine-first repository intake without checkout or repository execution."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlparse

from depfence.core.local_state import PrivateState
from depfence.core.models import ScanState

INTAKE_SCHEMA_VERSION = "depfence.intake/v1"
DEFAULT_FILE_BUDGET = 100_000
DEFAULT_BYTE_BUDGET = 512 * 1024 * 1024


def _source_host(source: str) -> str:
    if "://" in source:
        return urlparse(source).hostname or "unknown"
    prefix = source.split(":", 1)[0]
    if "@" in prefix:
        return prefix.split("@", 1)[1]
    return "local" if Path(source).expanduser().exists() else "unknown"


def _git_environment() -> dict[str, str]:
    return {
        **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run_git(
    arguments: list[str], *, timeout: float, cwd: Path | None = None, binary: bool = False
) -> subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str]:
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.required=false",
        *arguments,
    ]
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        check=False,
        env=_git_environment(),
        text=not binary,
        timeout=timeout,
    )


def _tree_budget(repository: Path, *, timeout: float) -> tuple[int, int, list[str]]:
    completed = _run_git(
        ["-C", str(repository), "ls-tree", "-rlz", "HEAD"], timeout=timeout, binary=True
    )
    if completed.returncode:
        return 0, 0, ["Git tree inventory failed"]
    assert isinstance(completed.stdout, bytes)
    files = size = 0
    errors: list[str] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, _name = record.split(b"\t", 1)
            mode, object_type, _object_id, raw_size = metadata.split(b" ", 3)
            if object_type == b"blob":
                files += 1
                size += int(raw_size)
            if mode == b"160000":
                errors.append("repository contains an uninspected submodule")
        except (ValueError, TypeError):
            errors.append("Git tree contained malformed inventory data")
    return files, size, list(dict.fromkeys(errors))


def _safe_archive_extract(archive: bytes, destination: Path) -> tuple[int, int]:
    file_count = total_size = 0
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        for member in handle:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError("archive member escapes the quarantine root")
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive contains a link or device entry")
            target = destination.joinpath(*pure.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("archive contains an unsupported entry type")
            file_count += 1
            total_size += member.size
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = handle.extractfile(member)
            if source is None:
                raise ValueError("archive file could not be read")
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
    return file_count, total_size


@dataclass
class IntakeResult:
    intake_id: str
    source_id: str
    source_host: str
    commit: str | None = None
    tree_digest: str | None = None
    file_count: int = 0
    byte_count: int = 0
    status: ScanState = ScanState.UNPROVEN
    errors: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": INTAKE_SCHEMA_VERSION,
            "intake_id": self.intake_id,
            "created_at": self.created_at,
            "source_id": self.source_id,
            "source_host": self.source_host,
            "commit": self.commit,
            "tree_digest": self.tree_digest,
            "status": self.status.value,
            "counts": {"files": self.file_count, "bytes": self.byte_count},
            "coverage": {"complete": self.status is ScanState.PASS, "errors": self.errors},
            "approved": False,
        }


def inspect_source(
    source: str,
    *,
    state: PrivateState,
    timeout: float = 120.0,
    file_budget: int = DEFAULT_FILE_BUDGET,
    byte_budget: int = DEFAULT_BYTE_BUDGET,
) -> IntakeResult:
    """Clone and materialize a bounded tree without running checkout machinery."""

    intake_id = str(uuid.uuid4())
    source_id = state.opaque_id("source", source)
    result = IntakeResult(
        intake_id=intake_id,
        source_id=source_id,
        source_host=_source_host(source),
    )
    quarantine = state.path(Path("intake") / "quarantine" / intake_id)
    repository = quarantine / "repository"
    tree = quarantine / "tree"
    quarantine.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(quarantine, 0o700)

    def finish() -> IntakeResult:
        state.write_text(
            Path("intake") / "records" / f"{intake_id}.json",
            json.dumps(result.to_dict(), sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        return result

    clone_arguments = ["clone", "--no-checkout", "--no-recurse-submodules"]
    if Path(source).expanduser().exists():
        clone_arguments.append("--no-local")
    clone_arguments.extend([source, str(repository)])
    try:
        clone = _run_git(clone_arguments, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.errors.append(f"clone unavailable ({type(exc).__name__})")
        result.status = ScanState.INDETERMINATE
        return finish()
    if clone.returncode:
        result.errors.append(f"clone failed (exit {clone.returncode})")
        result.status = ScanState.INDETERMINATE
        return finish()

    verification = _run_git(
        ["-C", str(repository), "fsck", "--no-progress", "--connectivity-only"],
        timeout=timeout,
    )
    if verification.returncode:
        result.errors.append("Git object connectivity verification failed")
    commit = _run_git(["-C", str(repository), "rev-parse", "--verify", "HEAD^{commit}"], timeout=timeout)
    if commit.returncode:
        result.errors.append("source has no verifiable HEAD commit")
        result.status = ScanState.INDETERMINATE
        return finish()
    result.commit = str(commit.stdout).strip()

    files, bytes_total, tree_errors = _tree_budget(repository, timeout=timeout)
    result.file_count, result.byte_count = files, bytes_total
    result.errors.extend(tree_errors)
    if files > file_budget:
        result.errors.append(f"tree exceeds the {file_budget}-file intake budget")
    if bytes_total > byte_budget:
        result.errors.append(f"tree exceeds the {byte_budget}-byte intake budget")
    if result.errors:
        result.status = ScanState.UNPROVEN
        return finish()

    archive = _run_git(
        ["-C", str(repository), "archive", "--format=tar", "HEAD"],
        timeout=timeout,
        binary=True,
    )
    if archive.returncode:
        result.errors.append("Git tree materialization failed")
        result.status = ScanState.INDETERMINATE
        return finish()
    assert isinstance(archive.stdout, bytes)
    if len(archive.stdout) > byte_budget + max(10 * 1024 * 1024, byte_budget // 10):
        result.errors.append("materialized archive exceeded its aggregate byte budget")
        result.status = ScanState.INDETERMINATE
        return finish()
    try:
        extracted_files, extracted_bytes = _safe_archive_extract(archive.stdout, tree)
    except (OSError, tarfile.TarError, ValueError) as exc:
        result.errors.append(f"safe tree materialization failed ({type(exc).__name__})")
        result.status = ScanState.INDETERMINATE
        return finish()
    if extracted_files != files or extracted_bytes != bytes_total:
        result.errors.append("materialized tree does not match Git inventory")
        result.status = ScanState.INDETERMINATE
        return finish()

    result.tree_digest = "git:" + result.commit
    result.status = ScanState.PASS
    return finish()


def approve_intake(
    intake_id: str,
    *,
    state: PrivateState,
    approved_by: str,
    reason: str,
) -> Path:
    """Record an operator decision; promotion remains a separate manual action."""

    try:
        uuid.UUID(intake_id)
    except ValueError as exc:
        raise ValueError("intake_id must be a UUID") from exc
    record = state.path(Path("intake") / "records" / f"{intake_id}.json")
    if not record.is_file() or record.is_symlink():
        raise ValueError("intake record does not exist")
    data = json.loads(record.read_text(encoding="utf-8"))
    if data.get("status") != ScanState.PASS.value:
        raise ValueError("only a complete intake inspection can be approved")
    approval = {
        "schema_version": "depfence.intake-approval/v1",
        "intake_id": intake_id,
        "source_id": data["source_id"],
        "commit": data["commit"],
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "approved_by": str(approved_by)[:120],
        "reason": str(reason)[:500],
        "promotes_automatically": False,
    }
    return cast(Path, state.write_text(
        Path("intake") / "approvals" / f"{intake_id}.json",
        json.dumps(approval, sort_keys=True, indent=2, allow_nan=False) + "\n",
    ))


__all__ = [
    "DEFAULT_BYTE_BUDGET",
    "DEFAULT_FILE_BUDGET",
    "INTAKE_SCHEMA_VERSION",
    "IntakeResult",
    "approve_intake",
    "inspect_source",
]
