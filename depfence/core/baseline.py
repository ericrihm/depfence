"""Baseline management — suppress known/accepted findings.

Stores acknowledged findings in .depfence-baseline.json so they don't
block CI after team review. Supports expiry dates for temporary suppressions.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding


def finding_fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for a finding (survives minor detail changes)."""
    key = f"{finding.finding_type.value}:{finding.package}:{finding.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class Baseline:
    """Manages suppressed/baselined findings."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        if path and path.exists():
            self._load()

    @classmethod
    def from_project(cls, project_dir: Path) -> "Baseline":
        path = project_dir / ".depfence-baseline.json"
        return cls(path)

    @property
    def count(self) -> int:
        return len(self._entries)

    def is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding is in the baseline (and not expired)."""
        fp = finding_fingerprint(finding)
        entry = self._entries.get(fp)
        if not entry:
            return False

        expires = entry.get("expires")
        if expires:
            try:
                exp_date = datetime.fromisoformat(expires)
                if exp_date < datetime.now(timezone.utc):
                    return False
            except ValueError:
                pass

        return True

    def suppress(self, finding: Finding, reason: str = "", expires: str | None = None) -> None:
        """Add a finding to the baseline."""
        fp = finding_fingerprint(finding)
        self._entries[fp] = {
            "fingerprint": fp,
            "package": str(finding.package),
            "title": finding.title,
            "severity": finding.severity.value,
            "finding_type": finding.finding_type.value,
            "reason": reason,
            "suppressed_at": datetime.now(timezone.utc).isoformat(),
            "expires": expires,
        }

    def remove(self, finding: Finding) -> bool:
        """Remove a finding from the baseline."""
        fp = finding_fingerprint(finding)
        if fp in self._entries:
            del self._entries[fp]
            return True
        return False

    def filter_findings(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Split findings into active and suppressed lists."""
        active = []
        suppressed = []
        for f in findings:
            if self.is_suppressed(f):
                suppressed.append(f)
            else:
                active.append(f)
        return active, suppressed

    def save(self) -> None:
        """Write baseline to disk."""
        if not self._path:
            return
        data = {
            "version": 1,
            "entries": list(self._entries.values()),
        }
        self._path.write_text(json.dumps(data, indent=2) + "\n")

    def _load(self) -> None:
        """Load baseline from disk."""
        try:
            data = json.loads(self._path.read_text())
            for entry in data.get("entries", []):
                fp = entry.get("fingerprint", "")
                if fp:
                    self._entries[fp] = entry
        except (json.JSONDecodeError, OSError):
            pass
