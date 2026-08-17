from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def test_private_depfence_state_is_ignored() -> None:
    root = Path(__file__).resolve().parents[1]
    candidates = (
        ".depfence/private/v1/install.key",
        ".depfence/signals/pending.jsonl",
        "nested/.depfence/private/observed.jsonld",
        "nested/.depfence/signals/pending.jsonl",
    )

    with tempfile.TemporaryDirectory() as temporary:
        repo = Path(temporary)
        (repo / ".gitignore").write_text((root / ".gitignore").read_text())
        subprocess.run(
            ["git", "init", "--quiet"], cwd=repo, check=True, capture_output=True, timeout=10
        )
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "-z", "--stdin"],
            cwd=repo,
            check=False,
            capture_output=True,
            input="\0".join(candidates) + "\0",
            text=True,
            timeout=10,
        )

    assert result.returncode == 0
    assert set(result.stdout.rstrip("\0").split("\0")) == set(candidates)
