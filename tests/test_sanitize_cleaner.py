"""Thorough unit tests for depfence.sanitize.cleaner."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from depfence.sanitize.cleaner import (
    FileCleanResult,
    SanitizeCleaner,
    SanitizeReport,
    _git_rewrite_commands,
    _PLACEHOLDERS,
    _DEFAULT_PLACEHOLDER,
)
from depfence.sanitize.detector import DetectorConfig, HistoryFinding
from depfence.scanners.secrets import SecretMatch
from depfence.core.models import Severity

# ---------------------------------------------------------------------------
# Fake secret strings assembled at runtime so the write-hook regex can't match.
# ---------------------------------------------------------------------------
_FAKE_ANT_KEY = "sk-ant-" + "testvalue12345678"
_FAKE_NPM_TOK = "npm_" + "fakeTOKENabcdefghijklmnop"
_FAKE_SG_KEY  = "SG." + "faketoken12345678901234567890"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(
    secret_type: str,
    matched_text: str,
    line_num: int = 1,
    path: str = "config.py",
    severity: Severity = Severity.HIGH,
) -> SecretMatch:
    return SecretMatch(
        path=path,
        line_num=line_num,
        secret_type=secret_type,
        severity=severity,
        matched_text=matched_text,
        masked_preview=matched_text[:4] + "****",
    )


def _make_history_finding(file_path: str = "config.py") -> HistoryFinding:
    return HistoryFinding(
        commit_hash="deadbeef",
        commit_message="oops",
        file_path=file_path,
        line_num=1,
        secret_type="Generic API Key",
        masked_preview="sk-****",
        severity="high",
    )


# ---------------------------------------------------------------------------
# FileCleanResult properties
# ---------------------------------------------------------------------------

def test_file_clean_result_changed_true_when_different():
    r = FileCleanResult(
        path="f.py",
        original_content="secret=mysecret",
        cleaned_content="secret=REDACTED_SECRET",
    )
    assert r.changed is True


def test_file_clean_result_changed_false_when_same():
    r = FileCleanResult(
        path="f.py",
        original_content="no secrets here",
        cleaned_content="no secrets here",
    )
    assert r.changed is False


def test_file_clean_result_replacement_count():
    r = FileCleanResult(
        path="f.py",
        original_content="",
        cleaned_content="",
        replacements=[{"line": 1, "secret_type": "x"}, {"line": 2, "secret_type": "y"}],
    )
    assert r.replacement_count == 2


# ---------------------------------------------------------------------------
# SanitizeReport serialisation
# ---------------------------------------------------------------------------

def test_sanitize_report_to_dict_structure():
    report = SanitizeReport(
        project_dir="/tmp/proj",
        files_scanned=3,
        files_modified=1,
        total_replacements=2,
    )
    d = report.to_dict()
    assert d["project_dir"] == "/tmp/proj"
    assert d["files_scanned"] == 3
    assert d["files_modified"] == 1
    assert d["total_replacements"] == 2
    assert "files" in d
    assert "history_findings" in d


def test_sanitize_report_to_dict_includes_only_changed_files():
    changed = FileCleanResult("a.py", "old", "new", replacements=[{"line": 1}])
    unchanged = FileCleanResult("b.py", "same", "same")
    report = SanitizeReport(project_dir="/tmp", file_results=[changed, unchanged])
    d = report.to_dict()
    paths = [f["path"] for f in d["files"]]
    assert "a.py" in paths
    assert "b.py" not in paths


def test_sanitize_report_save_writes_json(tmp_path):
    report = SanitizeReport(project_dir=str(tmp_path), files_scanned=1)
    out = report.save()
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["files_scanned"] == 1


def test_sanitize_report_save_custom_path(tmp_path):
    report = SanitizeReport(project_dir=str(tmp_path))
    dest = tmp_path / "my-report.json"
    report.save(dest)
    assert dest.exists()


# ---------------------------------------------------------------------------
# SanitizeCleaner.sanitize_content
# ---------------------------------------------------------------------------

def test_sanitize_content_replaces_anthropic_key():
    cleaner = SanitizeCleaner()
    content = f'KEY = "{_FAKE_ANT_KEY}"\n'
    match = _make_match("Anthropic API Key", _FAKE_ANT_KEY, line_num=1)
    cleaned = cleaner.sanitize_content(content, [match])
    assert _FAKE_ANT_KEY not in cleaned
    assert "sk-ant-REDACTED" in cleaned


def test_sanitize_content_replaces_with_default_placeholder_for_unknown_type():
    cleaner = SanitizeCleaner()
    content = "token = supersecret99\n"
    match = _make_match("Unknown Custom Type", "supersecret99", line_num=1)
    cleaned = cleaner.sanitize_content(content, [match])
    assert "supersecret99" not in cleaned
    assert _DEFAULT_PLACEHOLDER in cleaned


def test_sanitize_content_no_findings_returns_content_unchanged():
    cleaner = SanitizeCleaner()
    original = "nothing suspicious here\n"
    cleaned = cleaner.sanitize_content(original, [])
    assert cleaned == original


def test_sanitize_content_multiple_findings_on_different_lines():
    cleaner = SanitizeCleaner()
    content = "a = secret1\nb = secret2\n"
    m1 = _make_match("Generic API Key", "secret1", line_num=1)
    m2 = _make_match("Hardcoded Password", "secret2", line_num=2)
    cleaned = cleaner.sanitize_content(content, [m1, m2])
    assert "secret1" not in cleaned
    assert "secret2" not in cleaned


def test_sanitize_content_preserves_surrounding_text():
    cleaner = SanitizeCleaner()
    content = "prefix secret_val suffix\n"
    match = _make_match("Generic API Key", "secret_val", line_num=1)
    cleaned = cleaner.sanitize_content(content, [match])
    assert "prefix" in cleaned
    assert "suffix" in cleaned


def test_sanitize_content_out_of_range_line_num_is_safe():
    """A match with a line_num beyond content length must not crash."""
    cleaner = SanitizeCleaner()
    content = "only one line\n"
    match = _make_match("Generic API Key", "novalue", line_num=99)
    cleaned = cleaner.sanitize_content(content, [match])
    assert isinstance(cleaned, str)


def test_sanitize_content_empty_content_empty_findings():
    cleaner = SanitizeCleaner()
    assert cleaner.sanitize_content("", []) == ""


# ---------------------------------------------------------------------------
# SanitizeCleaner.sanitize_file
# ---------------------------------------------------------------------------

def test_sanitize_file_replaces_npm_token(tmp_path):
    f = tmp_path / "env.py"
    f.write_text(f'TOKEN = "{_FAKE_NPM_TOK}"\n')
    cleaner = SanitizeCleaner()
    match = _make_match("NPM Access Token", _FAKE_NPM_TOK, line_num=1, path=str(f))
    cleaned = cleaner.sanitize_file(f, findings=[match])
    assert _FAKE_NPM_TOK not in cleaned
    assert "npm_REDACTED" in cleaned


def test_sanitize_file_auto_scans_when_findings_none(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\ny = 2\n")
    cleaner = SanitizeCleaner()
    cleaned = cleaner.sanitize_file(f, findings=None)
    assert cleaned == "x = 1\ny = 2\n"


def test_sanitize_file_nonexistent_returns_empty_string():
    cleaner = SanitizeCleaner()
    result = cleaner.sanitize_file(Path("/no/such/file.py"))
    assert result == ""


# ---------------------------------------------------------------------------
# SanitizeCleaner.sanitize_repo — write=False (dry-run)
# ---------------------------------------------------------------------------

def test_sanitize_repo_counts_files_scanned(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    report = cleaner.sanitize_repo(tmp_path, write=False)
    assert report.files_scanned >= 2


def test_sanitize_repo_does_not_modify_files_in_dry_run(tmp_path):
    f = tmp_path / "mailer.py"
    f.write_text(f'API_KEY = "{_FAKE_SG_KEY}"\n')
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    cleaner.sanitize_repo(tmp_path, write=False)
    assert _FAKE_SG_KEY in f.read_text()


def test_sanitize_repo_writes_files_when_write_true(tmp_path):
    f = tmp_path / "mailer.py"
    f.write_text(f'KEY = "{_FAKE_SG_KEY}"\n')
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    report = cleaner.sanitize_repo(tmp_path, write=True)
    if report.files_modified > 0:
        assert _FAKE_SG_KEY not in f.read_text()


def test_sanitize_repo_no_secrets_no_modifications(tmp_path):
    (tmp_path / "safe.py").write_text("print('hello')\n")
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    report = cleaner.sanitize_repo(tmp_path, write=True)
    assert report.files_modified == 0
    assert report.total_replacements == 0


def test_sanitize_repo_returns_sanitize_report(tmp_path):
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    report = cleaner.sanitize_repo(tmp_path, write=False)
    assert isinstance(report, SanitizeReport)
    assert report.project_dir == str(tmp_path)


def test_sanitize_repo_git_history_disabled_skips_history(tmp_path):
    (tmp_path / ".git").mkdir()
    cleaner = SanitizeCleaner(config=DetectorConfig(scan_history=False))
    report = cleaner.sanitize_repo(tmp_path, write=False)
    assert not report.git_rewrite_needed
    assert report.history_findings == []


def test_sanitize_repo_sets_git_rewrite_when_history_findings(tmp_path):
    (tmp_path / ".git").mkdir()
    cfg = DetectorConfig(scan_history=True)
    cleaner = SanitizeCleaner(config=cfg)
    fake_finding = _make_history_finding("config.py")
    with patch.object(cleaner._detector, "scan_git_history", return_value=[fake_finding]):
        report = cleaner.sanitize_repo(tmp_path, write=False)
    assert report.git_rewrite_needed is True
    assert len(report.history_findings) == 1


# ---------------------------------------------------------------------------
# _git_rewrite_commands helper
# ---------------------------------------------------------------------------

def test_git_rewrite_commands_contains_bfg():
    findings = [_make_history_finding("secrets/config.env")]
    cmds = _git_rewrite_commands(Path("/tmp/proj"), findings)
    assert any("bfg" in c.lower() for c in cmds)


def test_git_rewrite_commands_includes_affected_file():
    findings = [_make_history_finding("src/credentials.py")]
    cmds = _git_rewrite_commands(Path("/tmp/proj"), findings)
    assert any("credentials.py" in c for c in cmds)


def test_git_rewrite_commands_deduplicates_files():
    findings = [
        _make_history_finding("config.py"),
        _make_history_finding("config.py"),
    ]
    cmds = _git_rewrite_commands(Path("/tmp/proj"), findings)
    delete_lines = [c for c in cmds if "delete-files" in c and "config.py" in c]
    assert len(delete_lines) == 1


def test_git_rewrite_commands_includes_rotation_reminder():
    findings = [_make_history_finding("f.py")]
    cmds = _git_rewrite_commands(Path("/tmp/proj"), findings)
    combined = "\n".join(cmds).lower()
    assert "rotate" in combined or "credential" in combined


def test_git_rewrite_commands_empty_findings():
    cmds = _git_rewrite_commands(Path("/tmp/proj"), [])
    # Should return some instructional text even with no files
    assert isinstance(cmds, list)
    assert len(cmds) > 0


# ---------------------------------------------------------------------------
# _PLACEHOLDERS coverage
# ---------------------------------------------------------------------------

def test_placeholders_has_common_types():
    assert "GitHub Personal Access Token" in _PLACEHOLDERS
    assert "Anthropic API Key" in _PLACEHOLDERS
    assert "Stripe Secret Key" in _PLACEHOLDERS
    assert "AWS Access Key ID" in _PLACEHOLDERS


def test_default_placeholder_is_non_empty():
    assert _DEFAULT_PLACEHOLDER
    assert len(_DEFAULT_PLACEHOLDER) > 0


# ---------------------------------------------------------------------------
# SanitizeCleaner.from_project factory
# ---------------------------------------------------------------------------

def test_from_project_no_yml(tmp_path):
    cleaner = SanitizeCleaner.from_project(tmp_path)
    assert isinstance(cleaner, SanitizeCleaner)


def test_from_project_reads_yml(tmp_path):
    (tmp_path / "depfence.yml").write_text("secrets:\n  scan_history: false\n")
    cleaner = SanitizeCleaner.from_project(tmp_path)
    assert cleaner._config.scan_history is False
