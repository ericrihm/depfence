"""Argument parsing and validation tests for sealed Git worker entry points."""

from __future__ import annotations

import pytest


def test_acquire_main_rejects_missing_args() -> None:
    from depfence.sealed_git_worker import acquire_main

    with pytest.raises(SystemExit) as exc_info:
        acquire_main()
    assert exc_info.value.code != 0


def test_inventory_main_rejects_missing_args() -> None:
    from depfence.sealed_git_worker import inventory_main

    with pytest.raises(SystemExit) as exc_info:
        inventory_main()
    assert exc_info.value.code != 0


def test_analyze_main_rejects_missing_args() -> None:
    from depfence.sealed_git_worker import analyze_main

    with pytest.raises(SystemExit) as exc_info:
        analyze_main()
    assert exc_info.value.code != 0


def test_acquire_main_rejects_invalid_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    from depfence.sealed_git_worker import acquire_main

    monkeypatch.setattr(
        "sys.argv",
        [
            "depfence-sealed-git-acquire",
            "--source", "https://github.com/example/repo.git",
            "--commit", "not-a-hex-sha",
            "--allowed-host", "github.com",
            "--no-redirects", "--no-checkout", "--no-submodules", "--no-lfs",
            "--destination", "/quarantine/repository",
        ],
    )
    with pytest.raises(SystemExit, match="commit"):
        acquire_main()


def test_inventory_main_rejects_invalid_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    from depfence.sealed_git_worker import inventory_main

    monkeypatch.setattr(
        "sys.argv",
        [
            "depfence-sealed-git-inventory",
            "--repository", "/quarantine/repository",
            "--commit", "xyz",
            "--format", "json",
        ],
    )
    with pytest.raises(SystemExit, match="commit"):
        inventory_main()
