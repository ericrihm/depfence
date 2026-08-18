"""Bounded filesystem access for scanners.

Scanners consume hostile repositories.  This module keeps the filesystem
boundary, size limits, and structured parsing rules in one place so a symlink
or malformed configuration cannot quietly turn into a clean scan.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path


class ScanIncompleteError(RuntimeError):
    """The requested input could not be safely and completely evaluated."""


class ScopeEscapeError(ScanIncompleteError):
    """A repository path resolved outside the declared scan root."""


class InputLimitError(ScanIncompleteError):
    """A scanner input exceeded a configured resource limit."""


class MalformedInputError(ScanIncompleteError):
    """A scanner input was present but could not be parsed safely."""


class PartialScanError(ScanIncompleteError):
    """A scanner produced findings but could not establish complete coverage."""

    def __init__(self, message: str, findings: Sequence[object]):
        super().__init__(message)
        self.findings = list(findings)


@dataclass(frozen=True)
class ScanScope:
    """A canonical project root with safe walk/read/parse primitives."""

    root: Path
    max_file_bytes: int = 4 * 1024 * 1024
    max_files: int = 50_000

    def __post_init__(self) -> None:
        root = Path(self.root).resolve(strict=True)
        if not root.is_dir():
            raise ScanIncompleteError(f"scan root is not a directory: {root}")
        if self.max_file_bytes <= 0 or self.max_files <= 0:
            raise ValueError("scan scope limits must be positive")
        object.__setattr__(self, "root", root)

    def __fspath__(self) -> str:
        """Expose the canonical root to legacy path consumers.

        Project scanners are passed a :class:`ScanScope` by the canonical
        runner.  The path protocol keeps older scanners source-compatible
        while they migrate their reads to the bounded helpers below.
        """
        return os.fspath(self.root)

    def __str__(self) -> str:
        return str(self.root)

    def __truediv__(self, child: Path | str) -> Path:
        return self.root / child

    def __getattr__(self, name: str):
        """Delegate read-only Path conveniences during the scope migration."""
        try:
            root = object.__getattribute__(self, "root")
        except AttributeError as exc:
            raise AttributeError(name) from exc
        return getattr(root, name)

    def _reject_symlink_components(self, candidate: Path) -> None:
        """Reject symlinks in an input path before resolving it.

        Checking every component prevents an in-scope-looking path from
        traversing a symlinked directory.  ``resolve`` still performs the
        canonical containment check, which also handles races and ``..``.
        """
        absolute = candidate if candidate.is_absolute() else self.root / candidate
        try:
            relative = absolute.relative_to(self.root)
        except ValueError:
            return
        current = self.root
        for part in relative.parts:
            current /= part
            try:
                if current.is_symlink():
                    raise ScopeEscapeError(
                        f"symlinked scanner input escapes project root assurance and is unsupported: {current}"
                    )
            except OSError as exc:
                raise ScanIncompleteError(
                    f"cannot inspect scanner input {current}: {exc}"
                ) from exc

    def resolve(
        self,
        path: Path | str | None = None,
        *,
        must_exist: bool = True,
    ) -> Path:
        # ``Path.resolve()`` compatibility is required while legacy scanners
        # migrate to the explicit bounded helpers. The no-argument form only
        # returns the already-canonical root and performs no filesystem read.
        if path is None:
            return self.root
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        self._reject_symlink_components(candidate)
        try:
            resolved = candidate.resolve(strict=must_exist)
        except (OSError, RuntimeError) as exc:
            raise ScanIncompleteError(f"cannot resolve scanner input {candidate}: {exc}") from exc
        if not resolved.is_relative_to(self.root):
            raise ScopeEscapeError(
                f"scanner input escapes project root: {candidate} -> {resolved}"
            )
        return resolved

    def read_text(
        self,
        path: Path | str,
        *,
        encoding: str = "utf-8",
        max_bytes: int | None = None,
    ) -> str:
        resolved = self.resolve(path)
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        try:
            size = resolved.stat().st_size
            if size > limit:
                raise InputLimitError(
                    f"scanner input exceeds {limit} byte limit: {resolved} ({size} bytes)"
                )
            return resolved.read_text(encoding=encoding)
        except ScanIncompleteError:
            raise
        except (OSError, UnicodeError) as exc:
            raise ScanIncompleteError(f"cannot read scanner input {resolved}: {exc}") from exc

    def read_bytes(self, path: Path | str, *, max_bytes: int | None = None) -> bytes:
        """Read a bounded binary scanner input without following symlinks."""
        resolved = self.resolve(path)
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        if limit <= 0:
            raise ValueError("scanner input limit must be positive")
        try:
            size = resolved.stat().st_size
            if size > limit:
                raise InputLimitError(
                    f"scanner input exceeds {limit} byte limit: {resolved} ({size} bytes)"
                )
            return resolved.read_bytes()
        except ScanIncompleteError:
            raise
        except OSError as exc:
            raise ScanIncompleteError(f"cannot read scanner input {resolved}: {exc}") from exc

    def parse_json(self, path: Path | str) -> dict:
        resolved = self.resolve(path)
        try:
            value = json.loads(self.read_text(resolved))
        except json.JSONDecodeError as exc:
            raise MalformedInputError(f"malformed JSON in {resolved}: {exc}") from exc
        if not isinstance(value, dict):
            raise MalformedInputError(f"expected a JSON object in {resolved}")
        return value

    def parse_yaml(self, path: Path | str) -> dict:
        resolved = self.resolve(path)
        try:
            import yaml

            value = yaml.safe_load(self.read_text(resolved)) or {}
        except ScanIncompleteError:
            raise
        except Exception as exc:  # PyYAML exposes several parser exception types
            raise MalformedInputError(f"malformed YAML in {resolved}: {exc}") from exc
        if not isinstance(value, dict):
            raise MalformedInputError(f"expected a YAML mapping in {resolved}")
        return value

    def walk_files(self) -> Iterator[Path]:
        """Yield regular files without following directory or file symlinks."""
        count = 0
        for directory, dirnames, filenames in os.walk(self.root, followlinks=False):
            base = Path(directory)
            for name in dirnames:
                candidate = base / name
                if candidate.is_symlink():
                    raise ScopeEscapeError(
                        f"symlinked scanner directory is unsupported: {candidate}"
                    )
            for name in filenames:
                candidate = base / name
                if candidate.is_symlink():
                    raise ScopeEscapeError(
                        f"symlinked scanner input is unsupported: {candidate}"
                    )
                resolved = self.resolve(candidate)
                if not resolved.is_file():
                    continue
                count += 1
                if count > self.max_files:
                    raise InputLimitError(
                        f"project exceeds scanner file limit of {self.max_files}: {self.root}"
                    )
                yield resolved

