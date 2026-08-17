from pathlib import Path

from click.testing import CliRunner

from depfence.cli.main import cli
from depfence.integrations.secrets_hook import scan_paths


def test_scan_paths_handles_crafted_filename_as_data(tmp_path: Path) -> None:
    crafted = tmp_path / "odd '); raise RuntimeError('injected') #\nname.py"
    crafted.write_text("value = 'ordinary configuration'\n", encoding="utf-8")

    assert scan_paths([str(crafted)]) == 0


def test_scan_paths_blocks_secret(tmp_path: Path) -> None:
    candidate = tmp_path / "credential.py"
    candidate.write_text("token = '" + "sk-proj-" + ("A" * 80) + "'\n", encoding="utf-8")

    assert scan_paths([str(candidate)]) == 1


def test_scan_paths_exposes_unreadable_candidate(tmp_path: Path) -> None:
    assert scan_paths([str(tmp_path / "missing.py")]) == 2


def test_generated_hook_uses_nul_filenames_and_argv(tmp_path: Path) -> None:
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    result = CliRunner().invoke(cli, ["secrets", "hook", "install", str(tmp_path)])
    assert result.exit_code == 0

    script = (hooks / "pre-commit").read_text(encoding="utf-8")
    assert "--diff-filter=ACM -z" in script
    assert "xargs -0 python3 -m depfence.integrations.secrets_hook --" in script
    assert "python3 -c" not in script
    assert "except Exception" not in script
