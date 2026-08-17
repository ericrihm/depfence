"""Fail-closed scanner used by the generated Git pre-commit hook.

Paths arrive as argv entries from ``xargs -0``.  Keeping filename transport out
of generated Python source avoids both shell word-splitting and code injection.
"""

from __future__ import annotations

import sys
from pathlib import Path

from depfence.scanners.secrets import SecretsScanner

_MAX_STAGED_FILE_SIZE = 10 * 1024 * 1024
_BLOCKING_SEVERITIES = {"critical", "high"}


def scan_paths(raw_paths: list[str]) -> int:
    """Scan staged file paths, returning 0 clean, 1 findings, or 2 incomplete."""
    scanner = SecretsScanner()
    blocked = False
    incomplete = False

    for raw_path in raw_paths:
        path = Path(raw_path)
        try:
            if path.is_symlink():
                raise OSError("refusing to follow a staged symlink")
            if not path.is_file():
                raise OSError("staged path is not a readable regular file")
            size = path.stat().st_size
            if size > _MAX_STAGED_FILE_SIZE:
                raise OSError(f"staged file exceeds {_MAX_STAGED_FILE_SIZE} bytes")
            content = path.read_text(encoding="utf-8")
            matches = scanner.scan_file_content(content, raw_path)
        except (OSError, UnicodeError) as exc:
            print(f"[depfence] INDETERMINATE: could not scan {raw_path!r}: {exc}", file=sys.stderr)
            incomplete = True
            continue

        for match in matches:
            if match.severity.value not in _BLOCKING_SEVERITIES:
                continue
            blocked = True
            print(
                f"  BLOCKED [{match.severity.value.upper()}] "
                f"{match.path}:L{match.line_num}: {match.secret_type}"
            )

    if incomplete:
        return 2
    return 1 if blocked else 0


def main() -> int:
    paths = sys.argv[1:]
    if paths and paths[0] == "--":
        paths = paths[1:]
    return scan_paths(paths)


if __name__ == "__main__":
    raise SystemExit(main())
