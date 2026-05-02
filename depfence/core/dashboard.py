"""Terminal dashboard for depfence watch mode.

Uses ANSI escape codes only — no curses, no external dependencies.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TextIO

from depfence.core.models import ScanResult, Severity


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_RESET = "\033[0m"
_DIM = "\033[2m"

_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_MAGENTA = "\033[35m"
_WHITE = "\033[37m"
_BRIGHT_RED = "\033[91m"
_BRIGHT_YELLOW = "\033[93m"
_BRIGHT_GREEN = "\033[92m"

# Severity → colour
_SEV_COLOUR: dict[str, str] = {
    "critical": _BRIGHT_RED + _BOLD,
    "high": _RED,
    "medium": _YELLOW,
    "low": _BRIGHT_YELLOW,
    "info": _DIM,
}

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _c(text: str, colour: str) -> str:
    """Wrap *text* in an ANSI colour sequence if stdout supports it."""
    if not _supports_colour():
        return text
    return f"{colour}{text}{_RESET}"


def _supports_colour() -> bool:
    """Return True when the terminal can render ANSI colours."""
    if os.environ.get("NO_COLOR") or os.environ.get("DEPFENCE_NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# State types
# ---------------------------------------------------------------------------

@dataclass
class ScanSnapshot:
    """Captured state of one completed scan."""

    completed_at: datetime
    packages_scanned: int
    findings_by_severity: dict[str, int]  # e.g. {"critical": 2, "high": 5}
    ecosystems: list[str]
    triggered_by: str  # filename that changed, or "manual"
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_scan_result(
        cls,
        result: ScanResult,
        triggered_by: str = "manual",
        duration_seconds: float = 0.0,
    ) -> "ScanSnapshot":
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        # Derive ecosystems from package IDs
        ecosystems = sorted({f.package.ecosystem for f in result.findings})
        if not ecosystems and result.ecosystem:
            ecosystems = [result.ecosystem]

        completed = result.completed_at or datetime.now(timezone.utc)
        return cls(
            completed_at=completed,
            packages_scanned=result.packages_scanned,
            findings_by_severity=counts,
            ecosystems=ecosystems,
            triggered_by=triggered_by,
            duration_seconds=duration_seconds,
            errors=result.errors[:],
        )

    @property
    def total_findings(self) -> int:
        return sum(self.findings_by_severity.values())

    @property
    def critical(self) -> int:
        return self.findings_by_severity.get("critical", 0)

    @property
    def high(self) -> int:
        return self.findings_by_severity.get("high", 0)


@dataclass
class DashboardState:
    """Mutable state shared between the watcher loop and renderer."""

    watch_root: str
    scan_history: list[ScanSnapshot] = field(default_factory=list)  # newest first
    is_scanning: bool = False
    scan_status_line: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_event_path: str = ""
    using_watchdog: bool = True
    poll_interval: int = 0  # 0 → event-driven

    MAX_HISTORY: int = 5

    def add_snapshot(self, snap: ScanSnapshot) -> None:
        self.scan_history.insert(0, snap)
        self.scan_history = self.scan_history[: self.MAX_HISTORY]

    @property
    def latest(self) -> ScanSnapshot | None:
        return self.scan_history[0] if self.scan_history else None


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

_DIVIDER = _DIM + "─" * 70 + _RESET


def render_dashboard(state: DashboardState) -> str:
    """Return a full ANSI terminal dashboard as a single string.

    Intended to be printed after clearing the terminal, or appended
    when the terminal is in scrolling mode with a status-line header.
    """
    lines: list[str] = []
    _sep = _DIVIDER

    # --- Header ---
    lines.append("")
    header = _c(" depfence watch ", _BOLD + _CYAN)
    lines.append(f"  {header}  {_c(state.watch_root, _DIM)}")
    backend = "watchdog" if state.using_watchdog else f"polling ({state.poll_interval}s)"
    lines.append(f"  {_c('backend:', _DIM)} {backend}   "
                 f"{_c('started:', _DIM)} {_fmt_dt(state.started_at)}")
    lines.append(_sep)

    # --- Scan status ---
    if state.is_scanning:
        spinner = _c("⟳", _CYAN)
        status = state.scan_status_line or "Scanning…"
        lines.append(f"  {spinner} {_c(status, _BOLD)}")
    elif state.latest:
        snap = state.latest
        age = _elapsed(snap.completed_at)
        lines.append(
            f"  {_c('Last scan:', _DIM)} {_fmt_dt(snap.completed_at)}  "
            f"({_c(age, _GREEN)})  "
            f"{_c(f'{snap.duration_seconds:.1f}s', _DIM)}"
        )
    else:
        lines.append(f"  {_c('Waiting for first change…', _DIM)}")
    lines.append(_sep)

    # --- Current findings summary ---
    if state.latest:
        snap = state.latest
        lines.append(f"  {_c('Packages scanned:', _DIM)} {snap.packages_scanned}   "
                     f"{_c('Ecosystems:', _DIM)} {', '.join(snap.ecosystems) or 'n/a'}")
        lines.append("")
        lines.append(f"  {_c('Findings', _BOLD)}")
        for sev in _SEVERITY_ORDER:
            count = snap.findings_by_severity.get(sev, 0)
            colour = _SEV_COLOUR.get(sev, "")
            bar = _severity_bar(count)
            lines.append(f"    {_c(sev.upper():8s}, colour)}  {bar}  {count}")
        total = snap.total_findings
        status_colour = _BRIGHT_RED if snap.critical > 0 else (_RED if snap.high > 0 else _BRIGHT_GREEN)
        lines.append("")
        lines.append(f"  {_c('Total findings:', _BOLD)} {_c(str(total), status_colour)}")
        if snap.errors:
            lines.append(f"  {_c('Errors:', _YELLOW)} {len(snap.errors)}")
    else:
        lines.append(f"  {_c('No scan results yet.', _DIM)}")

    lines.append(_sep)

    # --- History table ---
    if len(state.scan_history) > 1:
        lines.append(f"  {_c('Scan history (last 5)', _BOLD)}")
        lines.append(
            f"  {_c('TIME      PKGS  CRIT  HIGH  MED   LOW   TRIGGER', _DIM)}"
        )
        for snap in state.scan_history:
            ts = snap.completed_at.strftime("%H:%M:%S")
            crit = snap.findings_by_severity.get("critical", 0)
            high = snap.findings_by_severity.get("high", 0)
            med = snap.findings_by_severity.get("medium", 0)
            low = snap.findings_by_severity.get("low", 0)
            crit_s = _c(f"{crit:4d}", _BRIGHT_RED if crit else _DIM)
            high_s = _c(f"{high:4d}", _RED if high else _DIM)
            trigger = snap.triggered_by[:20]
            lines.append(
                f"  {ts}  {snap.packages_scanned:4d}  {crit_s}  {high_s}  "
                f"{_c(f'{med:4d}', _YELLOW if med else _DIM)}  "
                f"{_c(f'{low:4d}', _DIM)}  {_c(trigger, _DIM)}"
            )
        lines.append(_sep)

    # --- Footer ---
    lines.append(f"  {_c('Ctrl+C to stop', _DIM)}")
    lines.append("")

    return "\n".join(lines)


def render_status_line(state: DashboardState) -> str:
    """Single-line status suitable for a quiet-mode or scrolling display."""
    if state.is_scanning:
        return _c(f"[SCAN] {state.scan_status_line or 'running…'}", _CYAN)
    if state.latest:
        snap = state.latest
        crit = snap.critical
        high = snap.high
        total = snap.total_findings
        colour = _BRIGHT_RED if crit else (_RED if high else _BRIGHT_GREEN)
        ts = snap.completed_at.strftime("%H:%M:%S")
        return (
            f"[{ts}] "
            + _c(f"{total} finding(s)", colour)
            + f" ({snap.packages_scanned} pkgs)"
        )
    return _c("watching…", _DIM)


# ---------------------------------------------------------------------------
# Live-update helpers
# ---------------------------------------------------------------------------

def print_dashboard(state: DashboardState, file: TextIO | None = None) -> None:
    """Clear screen and reprint the full dashboard."""
    out = file or sys.stdout
    # Move cursor to top-left and clear screen
    if _supports_colour():
        out.write("\033[2J\033[H")
    out.write(render_dashboard(state))
    out.flush()


def print_quiet_status(state: DashboardState, file: TextIO | None = None) -> None:
    """Print a single-line status update (quiet mode)."""
    out = file or sys.stdout
    out.write(render_status_line(state) + "\n")
    out.flush()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _elapsed(dt: datetime) -> str:
    """Human-readable elapsed time since *dt*."""
    now = datetime.now(timezone.utc)
    # Make dt tz-aware if it's naive
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    secs = int((now - dt).total_seconds())
    if secs < 5:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m ago"
    hours = mins // 60
    return f"{hours}h ago"


def _severity_bar(count: int, width: int = 20) -> str:
    """Return a short ASCII bar proportional to *count* (capped at width)."""
    filled = min(count, width)
    return "█" * filled + _c("░" * (width - filled), _DIM)
