"""Pre-commit hook for depfence.

Runs a quick scan on changed lockfiles and blocks commits that introduce
known-vulnerable or malicious dependencies.
"""

from __future__ import annotations

import re
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

# GitHub Actions workflows — so a fabricated/hallucinated action pin (resolve_existence
# -> FABRICATED_REF/CRITICAL) blocks the commit. Path-anchored, not a bare *.yml, to
# avoid triggering on unrelated YAML (configs, docker-compose, etc).
WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")


def get_staged_lockfiles() -> list[str]:
    """Return staged paths that should trigger a scan (lockfiles + GHA workflows)."""
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
        if Path(line).name in LOCKFILE_PATTERNS or WORKFLOW_RE.search(line):
            staged.append(line)
    return staged


def main() -> int:
    """Entry point for the pre-commit hook."""
    staged = get_staged_lockfiles()
    if not staged:
        return 0

    print(f"depfence: scanning {len(staged)} changed file(s)...")

    try:
        # NB: do NOT pass --no-fetch — it disables ALL project scanners (workflow,
        # secrets, action-pin existence). Skip only the slow package-network passes
        # (advisory/reputation/enrichment) instead, keeping project scanners on.
        result = subprocess.run(
            ["depfence", "scan", ".", "--fail-on", "high",
             "--no-advisory", "--no-behavioral", "--no-reputation", "--no-enrich"],
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
