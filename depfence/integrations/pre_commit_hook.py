"""Pre-commit hook for depfence.

Runs a quick scan on changed lockfiles and blocks commits that introduce
known-vulnerable or malicious dependencies.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


LOCKFILE_PATTERNS = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "uv.lock",
}


def get_staged_lockfiles() -> list[str]:
    """Return list of staged lockfile paths."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    staged = []
    for line in result.stdout.strip().splitlines():
        filename = Path(line).name
        if filename in LOCKFILE_PATTERNS:
            staged.append(line)
    return staged


def main() -> int:
    """Entry point for the pre-commit hook."""
    staged = get_staged_lockfiles()
    if not staged:
        return 0

    print(f"depfence: scanning {len(staged)} changed lockfile(s)...")

    try:
        result = subprocess.run(
            ["depfence", "scan", ".", "--fail-on", "high", "--no-fetch", "--no-behavioral"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        print("depfence: not installed, skipping check")
        return 0
    except subprocess.TimeoutExpired:
        print("depfence: scan timed out, allowing commit")
        return 0

    if result.returncode != 0:
        print("depfence: vulnerabilities detected in dependencies!")
        print(result.stdout[:2000] if result.stdout else "")
        print("\nRun 'depfence scan .' for details. Use 'git commit --no-verify' to skip.")
        return 1

    print("depfence: lockfile scan passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
