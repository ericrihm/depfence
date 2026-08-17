import json
import subprocess
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from depfence.cli.main import cli
from depfence.core.baseline import Baseline, BaselineEvidenceError, ci_suppressions_trusted
from depfence.core.models import ScanResult


def _git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _pr_event(tmp_path, base):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"sha": base}}}))
    return event


def test_pr_changed_baseline_is_not_trusted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / ".depfence-baseline.json").write_text('{"version":1,"entries":[]}\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / ".depfence-baseline.json").write_text(
        '{"version":1,"entries":[{"fingerprint":"attacker"}]}\n'
    )
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "untrusted suppression")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is False
    assert ".depfence-baseline.json" in reason


def test_pr_added_inline_ignore_is_not_trusted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    source = tmp_path / "requirements.txt"
    source.write_text("requests==2.32.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    source.write_text("requests==2.32.0  # depfence: ignore CVE-1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "untrusted inline ignore")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is False
    assert "inline suppression" in reason


def test_pr_uncommitted_inline_ignore_is_not_trusted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    source = tmp_path / "requirements.txt"
    source.write_text("requests==2.32.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    source.write_text("requests==2.32.0  # depfence: ignore CVE-1\n")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is False
    assert "inline suppression" in reason


def test_pr_untracked_baseline_is_not_trusted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / ".depfence-baseline.json").write_text(
        '{"version":1,"entries":[{"fingerprint":"attacker"}]}\n'
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is False
    assert "untracked .depfence-baseline.json" in reason


def test_pr_untracked_supported_inline_ignore_is_not_trusted(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "README.md").write_text("base\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "requirements-extra.txt").write_text(
        "requests==2.32.0  # depfence: ignore CVE-1\n"
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is False
    assert "untracked requirements-extra.txt" in reason


def test_pr_untracked_unrelated_file_does_not_poison_suppression_evidence(
    tmp_path, monkeypatch
):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "notes.txt").write_text("depfence: ignore is documentation here\n")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))

    trusted, _reason = ci_suppressions_trusted(tmp_path)

    assert trusted is True


def test_pr_trust_check_ignores_ambient_git_redirection(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(_pr_event(tmp_path, base)))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker-controlled-git-dir"))

    trusted, reason = ci_suppressions_trusted(tmp_path)

    assert trusted is True
    assert reason == "suppression controls match the trusted base"


@pytest.mark.parametrize(
    "payload",
    [
        "{",
        '[]',
        '{"version":2,"entries":[]}',
        '{"version":1,"entries":"bad"}',
        '{"version":1,"entries":[{"fingerprint":"not-a-fingerprint"}]}',
    ],
)
def test_malformed_baseline_is_named_incomplete(tmp_path, payload):
    (tmp_path / ".depfence-baseline.json").write_text(payload)

    with pytest.raises(BaselineEvidenceError):
        Baseline.from_project(tmp_path)


def test_symlinked_baseline_is_named_incomplete(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"version":1,"entries":[]}')
    (tmp_path / ".depfence-baseline.json").symlink_to(outside)

    with pytest.raises(BaselineEvidenceError, match="non-symlink"):
        Baseline.from_project(tmp_path)


def test_oversized_baseline_is_named_incomplete(tmp_path):
    (tmp_path / ".depfence-baseline.json").write_bytes(b" " * (2 * 1024 * 1024 + 1))

    with pytest.raises(BaselineEvidenceError, match="exceeds"):
        Baseline.from_project(tmp_path)


def test_unreadable_baseline_is_named_incomplete(tmp_path, monkeypatch):
    baseline = tmp_path / ".depfence-baseline.json"
    baseline.write_text('{"version":1,"entries":[]}')
    original = type(baseline).read_text

    def refuse(path, *args, **kwargs):
        if path == baseline:
            raise PermissionError("synthetic permission denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(type(baseline), "read_text", refuse)
    with pytest.raises(BaselineEvidenceError, match="cannot read baseline"):
        Baseline.from_project(tmp_path)


def test_malformed_baseline_has_stable_machine_error_and_exit_two(tmp_path, monkeypatch):
    (tmp_path / ".depfence-baseline.json").write_text("{")
    scan_result = ScanResult(target=str(tmp_path), ecosystem="multi", packages_scanned=1)
    monkeypatch.setattr(
        "depfence.core.engine.scan_directory", AsyncMock(return_value=scan_result)
    )

    invocation = CliRunner().invoke(
        cli,
        ["scan", str(tmp_path), "--format", "json", "--no-enrich"],
    )

    assert invocation.exit_code == 2
    document = json.loads(invocation.stdout)
    assert document["status"] == "INDETERMINATE"
    assert document["coverage"]["scanners"]["suppression_controls"] == "INDETERMINATE"
    error = document["coverage"]["scanner_errors"]["suppression_controls"]
    assert error.startswith("Suppression baseline incomplete:")
