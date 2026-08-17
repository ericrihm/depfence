"""Bounded, privacy-preserving machine-local signal persistence."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from depfence.core.local_state import PrivateState, PrivateStateError

MAX_EVENT_BYTES = 16 * 1024
MAX_QUEUE_BYTES = 1024 * 1024
_DEFAULT_RELATIVE = Path("signals") / "pending.jsonl"


class SignalBusError(RuntimeError):
    """A signal could not be persisted with the required assurance."""


def _queue() -> tuple[PrivateState, Path]:
    override = os.environ.get("DEPFENCE_SIGNAL_BUS")
    if override:
        requested = Path(override).expanduser()
        if not requested.is_absolute():
            raise SignalBusError("DEPFENCE_SIGNAL_BUS must be an absolute path")
        state = PrivateState.open(project_root=Path.cwd(), root=requested.parent)
        return state, state.path(requested.name)
    state = PrivateState.open(project_root=Path.cwd())
    return state, state.path(_DEFAULT_RELATIVE)


def _lock(descriptor: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)


def _unlock(descriptor: int) -> None:
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _append_bounded(destination: Path, line: bytes) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    if destination.is_symlink():
        raise SignalBusError(f"signal queue is a symlink: {destination}")
    flags = os.O_APPEND | os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        _lock(descriptor)
        try:
            current_size = os.fstat(descriptor).st_size
            if current_size + len(line) > MAX_QUEUE_BYTES:
                os.lseek(descriptor, 0, os.SEEK_SET)
                existing = os.read(descriptor, MAX_QUEUE_BYTES)
                keep = existing[-max(0, MAX_QUEUE_BYTES - len(line)) :]
                newline = keep.find(b"\n")
                keep = keep[newline + 1 :] if newline >= 0 else b""
                os.ftruncate(descriptor, 0)
                if keep:
                    os.write(descriptor, keep)
            os.write(descriptor, line)
            os.fsync(descriptor)
        finally:
            _unlock(descriptor)
    finally:
        os.close(descriptor)


def emit_signal(
    *,
    name: str,
    value: dict[str, Any],
    source: str,
    file_path: str | None = None,
) -> str | None:
    """Persist a redacted signal; return a named error instead of swallowing it."""
    try:
        state, destination = _queue()
        safe_value = dict(value)
        if file_path:
            absolute = Path(file_path).expanduser()
            if not absolute.is_absolute():
                absolute = Path.cwd() / absolute
            safe_value["file_id"] = state.opaque_id("path", absolute.resolve(strict=False))
        record = {
            "name": name,
            "value": safe_value,
            "source": source,
            "timestamp": time.time(),
            "schema": "depfence.signal/v1",
        }
        line = (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(line) > MAX_EVENT_BYTES:
            raise SignalBusError(f"signal exceeds {MAX_EVENT_BYTES}-byte event limit")
        _append_bounded(destination, line)
    except (OSError, TypeError, ValueError, PrivateStateError, SignalBusError) as exc:
        return f"signal persistence UNPROVEN ({type(exc).__name__}: {exc})"
    return None
