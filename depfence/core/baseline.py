"""Baseline management — suppress known/accepted findings.

Stores acknowledged findings in .depfence-baseline.json so they don't
block CI after team review. Supports expiry dates for temporary suppressions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")
_BASELINE_NAME = ".depfence-baseline.json"
_EVIDENCE_LIMIT = 2 * 1024 * 1024


class BaselineEvidenceError(ValueError):
    """A suppression baseline exists but cannot be safely evaluated."""


def _git_environment() -> dict[str, str]:
    """Remove ambient Git redirection and user configuration from trust checks."""
    return {
        **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
    }


def finding_fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for a finding (survives minor detail changes)."""
    key = f"{finding.finding_type.value}:{finding.package}:{finding.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class Baseline:
    """Manages suppressed/baselined findings."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        if path and (path.exists() or path.is_symlink()):
            self._load()

    @classmethod
    def from_project(cls, project_dir: Path) -> Baseline:
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
                if exp_date.tzinfo is None:
                    exp_date = exp_date.replace(tzinfo=timezone.utc)
                if exp_date < datetime.now(timezone.utc):
                    return False
            except ValueError:
                return False

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
        """Load and validate a bounded, regular, versioned baseline."""
        path = self._path
        if path is None:
            return
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise BaselineEvidenceError("baseline must be a regular non-symlink file")
            if info.st_size > _EVIDENCE_LIMIT:
                raise BaselineEvidenceError(
                    f"baseline exceeds the {_EVIDENCE_LIMIT} byte limit"
                )
            data = json.loads(path.read_text(encoding="utf-8"))
        except BaselineEvidenceError:
            raise
        except json.JSONDecodeError as exc:
            raise BaselineEvidenceError("baseline is malformed JSON") from exc
        except UnicodeError as exc:
            raise BaselineEvidenceError("baseline is not valid UTF-8") from exc
        except OSError as exc:
            raise BaselineEvidenceError(
                f"cannot read baseline ({type(exc).__name__})"
            ) from exc
        if not isinstance(data, dict):
            raise BaselineEvidenceError("baseline root must be an object")
        if data.get("version") != 1:
            raise BaselineEvidenceError("baseline version must be 1")
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise BaselineEvidenceError("baseline entries must be an array")
        for entry in entries:
            if not isinstance(entry, dict):
                raise BaselineEvidenceError("baseline entry must be an object")
            fp = entry.get("fingerprint")
            if not isinstance(fp, str) or not _FINGERPRINT_RE.fullmatch(fp):
                raise BaselineEvidenceError("baseline entry has an invalid fingerprint")
            if fp in self._entries:
                raise BaselineEvidenceError("baseline contains a duplicate fingerprint")
            expires = entry.get("expires")
            if expires is not None:
                if not isinstance(expires, str):
                    raise BaselineEvidenceError("baseline expiry must be an ISO-8601 string")
                try:
                    datetime.fromisoformat(expires)
                except ValueError as exc:
                    raise BaselineEvidenceError("baseline expiry is not valid ISO-8601") from exc
            self._entries[fp] = entry


def _supported_suppression_paths(project_dir: Path) -> set[str]:
    """Return lexical paths whose contents can suppress scan findings."""
    from depfence.core.lockfile import detect_ecosystem

    paths = {_BASELINE_NAME}
    for _ecosystem, path in detect_ecosystem(project_dir):
        try:
            paths.add(path.relative_to(project_dir).as_posix())
        except ValueError:
            # An escaped/symlinked lockfile is handled by the scan itself. It
            # cannot be accepted as trustworthy suppression evidence here.
            continue
    return paths


def _base_blob(project_dir: Path, base: str, relative: str) -> bytes | None:
    """Read one bounded blob from the trusted base without shell interpolation."""
    object_name = f"{base}:./{relative}"
    exists = subprocess.run(
        ["git", "cat-file", "-e", object_name],
        cwd=project_dir,
        env=_git_environment(),
        check=False,
        capture_output=True,
        timeout=10,
    )
    if exists.returncode != 0:
        return None
    size_result = subprocess.run(
        ["git", "cat-file", "-s", object_name],
        cwd=project_dir,
        env=_git_environment(),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    size = int(size_result.stdout.strip())
    if size > _EVIDENCE_LIMIT:
        raise ValueError(f"trusted suppression input exceeds {_EVIDENCE_LIMIT} bytes")
    return subprocess.run(
        ["git", "show", object_name],
        cwd=project_dir,
        env=_git_environment(),
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout


def _worktree_blob(project_dir: Path, relative: str) -> bytes:
    candidate = project_dir / relative
    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"suppression input is not a regular file: {relative}")
    if info.st_size > _EVIDENCE_LIMIT:
        raise ValueError(f"suppression input exceeds {_EVIDENCE_LIMIT} bytes: {relative}")
    return candidate.read_bytes()


def _suppression_lines(value: bytes) -> Counter[bytes]:
    return Counter(
        line
        for line in value.splitlines()
        if re.search(rb"depfence\s*:\s*ignore", line, re.IGNORECASE)
    )


def ci_suppressions_trusted(project_dir: Path) -> tuple[bool, str]:
    """Bind PR suppressions to the trusted base revision.

    Non-PR and local runs preserve the established behavior. In a GitHub PR,
    a changed baseline or newly added inline ignore is attacker-controlled and
    cannot hide findings without a separate approval event.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return True, "not running in GitHub Actions"
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return False, "GITHUB_EVENT_PATH is unavailable"
    try:
        event_file = Path(event_path)
        if event_file.is_symlink() or event_file.stat().st_size > _EVIDENCE_LIMIT:
            return False, "GitHub event evidence is unsafe or oversized"
        event = json.loads(event_file.read_text())
        pull_request = event.get("pull_request") if isinstance(event, dict) else None
        if not isinstance(pull_request, dict):
            return True, "workflow event is not a pull request"
        base = str((pull_request.get("base") or {}).get("sha") or "")
        if not _COMMIT_RE.fullmatch(base):
            return False, "pull request base SHA is missing or invalid"
        subprocess.run(
            ["git", "cat-file", "-e", f"{base}^{{commit}}"],
            cwd=project_dir,
            env=_git_environment(),
            check=True,
            capture_output=True,
            timeout=10,
        )
        supported_paths = _supported_suppression_paths(project_dir)
        for relative in sorted(supported_paths):
            candidate = project_dir / relative
            if not (candidate.exists() or candidate.is_symlink()):
                continue
            current = _worktree_blob(project_dir, relative)
            trusted = _base_blob(project_dir, base, relative)
            if relative == _BASELINE_NAME:
                if trusted is None:
                    return False, "pull request adds untracked .depfence-baseline.json"
                if current != trusted:
                    return False, "pull request changes .depfence-baseline.json"
                continue
            current_suppressions = _suppression_lines(current)
            trusted_suppressions = _suppression_lines(trusted or b"")
            if current_suppressions - trusted_suppressions:
                kind = "untracked " if trusted is None else ""
                return False, f"pull request adds an inline suppression in {kind}{relative}"
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as bad:
        return False, f"cannot establish trusted suppression base: {bad}"
    return True, "suppression controls match the trusted base"
