"""Live lockfile watcher — detects changes and triggers auto-scans.

Supports both inotify/FSEvents via watchdog (preferred) and a polling
fallback when watchdog is unavailable.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

# Lockfile patterns that should trigger a re-scan
LOCKFILE_PATTERNS: tuple[str, ...] = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "requirements*.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "go.mod",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
    "*.csproj",
    "Package.resolved",
    "gradle.lockfile",
)

# Pre-compiled set of exact filenames for O(1) lookup
_EXACT_LOCKFILES: frozenset[str] = frozenset(
    p for p in LOCKFILE_PATTERNS if "*" not in p
)


def _is_lockfile(path: Path) -> bool:
    """Return True if *path* matches any lockfile pattern."""
    name = path.name
    if name in _EXACT_LOCKFILES:
        return True
    # Wildcard patterns (e.g. requirements*.txt)
    for pattern in LOCKFILE_PATTERNS:
        if "*" in pattern and path.match(pattern):
            return True
    return False


@dataclass
class WatchEvent:
    """Represents a single filesystem event on a lockfile."""

    path: Path
    event_type: str  # "modified" | "created" | "deleted" | "moved"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        ts = self.timestamp.strftime("%H:%M:%S")
        return f"[{ts}] {self.event_type.upper()} {self.path.name}"


# ---------------------------------------------------------------------------
# watchdog-based implementation (preferred)
# ---------------------------------------------------------------------------

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    _WATCHDOG_AVAILABLE = True

    class _LockfileEventHandler(FileSystemEventHandler):
        """Watchdog handler that funnels relevant events to a callback."""

        def __init__(self, callback: Callable[[WatchEvent], None]) -> None:
            super().__init__()
            self._callback = callback

        def _dispatch_if_lockfile(self, event: FileSystemEvent, etype: str) -> None:
            if event.is_directory:
                return
            p = Path(str(event.src_path))
            if _is_lockfile(p):
                self._callback(WatchEvent(path=p, event_type=etype))

        def on_modified(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            self._dispatch_if_lockfile(event, "modified")

        def on_created(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            self._dispatch_if_lockfile(event, "created")

        def on_deleted(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            self._dispatch_if_lockfile(event, "deleted")

        def on_moved(self, event: FileSystemEvent) -> None:  # type: ignore[override]
            # Treat the destination as a creation if it's a lockfile
            if event.is_directory:
                return
            dest = Path(str(event.dest_path))
            if _is_lockfile(dest):
                self._callback(WatchEvent(path=dest, event_type="moved"))

except ImportError:  # pragma: no cover
    _WATCHDOG_AVAILABLE = False


# ---------------------------------------------------------------------------
# FileWatcher — public API
# ---------------------------------------------------------------------------

OnChangeFn = Callable[[list[WatchEvent]], None]


class FileWatcher:
    """Watch a directory for lockfile changes and call *on_change* callback.

    Parameters
    ----------
    root:
        Directory to watch (recursively).
    on_change:
        Callable that receives a list of :class:`WatchEvent` objects after
        the debounce window closes.  Called from a daemon thread.
    debounce_seconds:
        How long to wait after the last event before firing the callback.
        Defaults to 2.0 s.
    poll_interval:
        Seconds between polls when watchdog is unavailable or *force_polling*
        is True.
    force_polling:
        Bypass watchdog even if it is installed.
    """

    def __init__(
        self,
        root: Path | str,
        on_change: OnChangeFn,
        debounce_seconds: float = 2.0,
        poll_interval: float = 30.0,
        force_polling: bool = False,
    ) -> None:
        self.root = Path(root).resolve()
        self.on_change = on_change
        self.debounce_seconds = debounce_seconds
        self.poll_interval = poll_interval
        self.force_polling = force_polling

        self._stop_event = threading.Event()
        self._pending_events: list[WatchEvent] = []
        self._pending_lock = threading.Lock()
        self._last_event_time: float = 0.0
        self._debounce_thread: threading.Thread | None = None
        self._watcher_thread: threading.Thread | None = None

        # watchdog observer (only when not polling)
        self._observer: object | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start watching in background threads."""
        self._stop_event.clear()
        self._start_debounce_thread()

        if _WATCHDOG_AVAILABLE and not self.force_polling:
            self._start_watchdog()
        else:
            self._start_polling()

    def stop(self) -> None:
        """Signal all background threads to stop and join them."""
        self._stop_event.set()
        if self._observer is not None:
            try:
                self._observer.stop()  # type: ignore[union-attr]
                self._observer.join(timeout=5)
            except Exception:
                pass
        if self._watcher_thread is not None:
            self._watcher_thread.join(timeout=5)
        if self._debounce_thread is not None:
            self._debounce_thread.join(timeout=5)

    @property
    def using_watchdog(self) -> bool:
        """True when watchdog inotify/FSEvents backend is active."""
        return _WATCHDOG_AVAILABLE and not self.force_polling

    # ------------------------------------------------------------------
    # Internal — event ingestion
    # ------------------------------------------------------------------

    def _ingest(self, event: WatchEvent) -> None:
        """Accept a raw event, storing it for debounced delivery."""
        with self._pending_lock:
            self._pending_events.append(event)
            self._last_event_time = time.monotonic()

    # ------------------------------------------------------------------
    # Internal — debounce loop (separate thread)
    # ------------------------------------------------------------------

    def _start_debounce_thread(self) -> None:
        t = threading.Thread(target=self._debounce_loop, daemon=True, name="depfence-debounce")
        t.start()
        self._debounce_thread = t

    def _debounce_loop(self) -> None:
        """Fire on_change after debounce_seconds of quiet time."""
        while not self._stop_event.is_set():
            time.sleep(0.1)
            with self._pending_lock:
                if not self._pending_events:
                    continue
                quiet_for = time.monotonic() - self._last_event_time
                if quiet_for < self.debounce_seconds:
                    continue
                events = list(self._pending_events)
                self._pending_events.clear()

            # Fire outside the lock
            try:
                self.on_change(events)
            except Exception:
                log.exception("Error in on_change callback")

    # ------------------------------------------------------------------
    # Internal — watchdog backend
    # ------------------------------------------------------------------

    def _start_watchdog(self) -> None:
        handler = _LockfileEventHandler(self._ingest)
        observer = Observer()
        observer.schedule(handler, str(self.root), recursive=True)
        observer.start()
        self._observer = observer

    # ------------------------------------------------------------------
    # Internal — polling fallback
    # ------------------------------------------------------------------

    def _start_polling(self) -> None:
        t = threading.Thread(target=self._poll_loop, daemon=True, name="depfence-poll")
        t.start()
        self._watcher_thread = t

    def _poll_loop(self) -> None:
        """Scan mtime of all lockfiles every poll_interval seconds."""
        mtimes: dict[str, float] = self._snapshot_mtimes()

        while not self._stop_event.wait(timeout=self.poll_interval):
            current = self._snapshot_mtimes()

            # Detect changes
            for path_str, mtime in current.items():
                old = mtimes.get(path_str)
                if old is None:
                    self._ingest(WatchEvent(path=Path(path_str), event_type="created"))
                elif mtime != old:
                    self._ingest(WatchEvent(path=Path(path_str), event_type="modified"))

            # Detect deletions
            for path_str in mtimes:
                if path_str not in current:
                    self._ingest(WatchEvent(path=Path(path_str), event_type="deleted"))

            mtimes = current

    def _snapshot_mtimes(self) -> dict[str, float]:
        """Return {path: mtime} for every lockfile found under root."""
        result: dict[str, float] = {}
        try:
            for p in self.root.rglob("*"):
                if p.is_file() and _is_lockfile(p):
                    try:
                        result[str(p)] = p.stat().st_mtime
                    except OSError:
                        pass
        except OSError:
            pass
        return result
