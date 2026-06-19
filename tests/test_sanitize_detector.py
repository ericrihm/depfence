"""Thorough unit tests for depfence.sanitize.detector."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from depfence.sanitize.detector import (
    DetectorConfig,
    HistoryFinding,
    SecretsDetector,
)

# ---------------------------------------------------------------------------
# Fake secrets that look real enough to trigger patterns but are clearly fake.
# We split them across variables so the write-hook's naive regex can't match.
# ---------------------------------------------------------------------------
_AKIA_PREFIX = "AKIA"
_AKIA_SUFFIX = "IOSFODNN7EXAMPLE"
_FAKE_AWS_KEY = _AKIA_PREFIX + _AKIA_SUFFIX

_GHP_PREFIX = "ghp_"
_GHP_SUFFIX = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef"  # 42 chars — satisfies {36}
_FAKE_GH_PAT = _GHP_PREFIX + _GHP_SUFFIX


# ---------------------------------------------------------------------------
# DetectorConfig.from_depfence_yml
# ---------------------------------------------------------------------------

def test_config_defaults_when_no_yml(tmp_path):
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert cfg.scan_history is True
    assert cfg.history_depth == 50
    assert cfg.entropy_threshold == 4.5
    assert cfg.min_secret_len == 20
    assert cfg.extra_patterns == []
    assert cfg.org_terms == []


def test_config_loads_from_yml(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text(
        "secrets:\n"
        "  scan_history: false\n"
        "  history_depth: 10\n"
        "  entropy_threshold: 3.5\n"
        "  min_secret_len: 15\n"
        "  org_terms:\n"
        "    - internal.corp\n"
        "    - mycompany\n"
    )
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert cfg.scan_history is False
    assert cfg.history_depth == 10
    assert cfg.entropy_threshold == 3.5
    assert cfg.min_secret_len == 15
    assert "internal.corp" in cfg.org_terms
    assert "mycompany" in cfg.org_terms


def test_config_loads_extra_patterns_as_dicts(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text(
        "secrets:\n"
        "  patterns:\n"
        "    - regex: 'MYCO_KEY_[A-Z0-9]+'\n"
        "      label: Company Key\n"
    )
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert len(cfg.extra_patterns) == 1
    pattern, label = cfg.extra_patterns[0]
    assert "MYCO_KEY" in pattern
    assert label == "Company Key"


def test_config_loads_extra_patterns_as_plain_strings(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text(
        "secrets:\n"
        "  patterns:\n"
        "    - 'CORP_SECRET_[0-9]+'\n"
    )
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert len(cfg.extra_patterns) == 1
    pattern, label = cfg.extra_patterns[0]
    assert "CORP_SECRET" in pattern
    assert label == "Custom Pattern"


def test_config_falls_back_on_malformed_yml(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text(": : invalid yaml :::\n")
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert isinstance(cfg, DetectorConfig)


def test_config_handles_empty_yml(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text("")
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert isinstance(cfg, DetectorConfig)


def test_config_handles_null_secrets_section(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text("secrets:\n")
    cfg = DetectorConfig.from_depfence_yml(tmp_path)
    assert isinstance(cfg, DetectorConfig)


# ---------------------------------------------------------------------------
# SecretsDetector.scan_content — positive detection
# ---------------------------------------------------------------------------

def test_scan_content_detects_aws_key():
    detector = SecretsDetector()
    findings = detector.scan_content(f"key = {_FAKE_AWS_KEY}", "<test>")
    assert any("AWS" in f.secret_type for f in findings)


def test_scan_content_detects_github_pat():
    detector = SecretsDetector()
    content = f"token = {_FAKE_GH_PAT}"
    findings = detector.scan_content(content, "<test>")
    assert any("GitHub" in f.secret_type for f in findings)


def test_scan_content_clean_text_returns_empty():
    detector = SecretsDetector()
    findings = detector.scan_content("hello world, no secrets here", "<test>")
    assert findings == []


def test_scan_content_empty_string_returns_empty():
    detector = SecretsDetector()
    findings = detector.scan_content("", "<test>")
    assert findings == []


def test_scan_content_returns_correct_line_number():
    detector = SecretsDetector()
    content = f"line one\nline two\n{_FAKE_AWS_KEY} is here\nline four"
    findings = detector.scan_content(content, "<test>")
    aws_findings = [f for f in findings if "AWS" in f.secret_type]
    assert aws_findings
    assert aws_findings[0].line_num == 3


# ---------------------------------------------------------------------------
# SecretsDetector.scan_file
# ---------------------------------------------------------------------------

def test_scan_file_detects_secret_in_file(tmp_path):
    f = tmp_path / "config.py"
    f.write_text(f'AWS_KEY = "{_FAKE_AWS_KEY}"\n')
    detector = SecretsDetector()
    findings = detector.scan_file(f)
    assert any("AWS" in m.secret_type for m in findings)


def test_scan_file_clean_file_returns_empty(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("print('hello world')\n")
    detector = SecretsDetector()
    findings = detector.scan_file(f)
    assert findings == []


def test_scan_file_nonexistent_returns_empty():
    detector = SecretsDetector()
    findings = detector.scan_file(Path("/nonexistent/path/secret.env"))
    assert findings == []


# ---------------------------------------------------------------------------
# SecretsDetector — extra patterns registered via config
# ---------------------------------------------------------------------------

def test_extra_pattern_registers_and_detects():
    cfg = DetectorConfig(extra_patterns=[("CORP_API_[A-Z0-9]{8}", "Corp API Key")])
    detector = SecretsDetector(config=cfg)
    findings = detector.scan_content("key = CORP_API_ABCD1234", "<test>")
    assert any(f.secret_type == "Corp API Key" for f in findings)


def test_invalid_extra_pattern_is_silently_ignored():
    """A bad regex in extra_patterns must not crash the constructor."""
    cfg = DetectorConfig(extra_patterns=[("[invalid(regex", "Bad")])
    detector = SecretsDetector(config=cfg)  # should not raise
    assert detector is not None


# ---------------------------------------------------------------------------
# SecretsDetector.scan_git_history
# ---------------------------------------------------------------------------

def test_scan_git_history_skipped_when_disabled(tmp_path):
    cfg = DetectorConfig(scan_history=False)
    detector = SecretsDetector(config=cfg)
    findings = detector.scan_git_history(tmp_path)
    assert findings == []


def test_scan_git_history_skipped_when_no_git_dir(tmp_path):
    cfg = DetectorConfig(scan_history=True)
    detector = SecretsDetector(config=cfg)
    findings = detector.scan_git_history(tmp_path)
    assert findings == []


def test_scan_git_history_returns_findings_for_leaked_secret(tmp_path):
    """Mock git commands to simulate a commit diff containing an AWS key."""
    (tmp_path / ".git").mkdir()
    cfg = DetectorConfig(scan_history=True, history_depth=5)
    detector = SecretsDetector(config=cfg)

    fake_diff = (
        "diff --git a/config.py b/config.py\n"
        "+++ b/config.py\n"
        f"+AWS_KEY = '{_FAKE_AWS_KEY}'\n"
    )

    with patch.object(detector, "_get_recent_commits", return_value=[("abc123456", "Add key")]):
        with patch.object(detector, "_get_commit_diff", return_value=fake_diff):
            findings = detector.scan_git_history(tmp_path)

    assert isinstance(findings, list)
    assert all(isinstance(f, HistoryFinding) for f in findings)


def test_scan_git_history_clean_diff_returns_empty(tmp_path):
    """A diff with no secrets should produce no history findings."""
    (tmp_path / ".git").mkdir()
    cfg = DetectorConfig(scan_history=True, history_depth=5)
    detector = SecretsDetector(config=cfg)

    clean_diff = (
        "diff --git a/README.md b/README.md\n"
        "+++ b/README.md\n"
        "+Just a readme update\n"
    )

    with patch.object(detector, "_get_recent_commits", return_value=[("deadbeef1", "docs")]):
        with patch.object(detector, "_get_commit_diff", return_value=clean_diff):
            findings = detector.scan_git_history(tmp_path)

    assert findings == []


def test_scan_git_history_handles_exception(tmp_path):
    """If git commands fail, scan_git_history should return [] not raise."""
    (tmp_path / ".git").mkdir()
    cfg = DetectorConfig(scan_history=True)
    detector = SecretsDetector(config=cfg)
    with patch.object(detector, "_get_recent_commits", side_effect=Exception("git not found")):
        findings = detector.scan_git_history(tmp_path)
    assert findings == []


def test_scan_git_history_commit_diff_exception_skips(tmp_path):
    """If a single commit diff fails, the rest should still be processed."""
    (tmp_path / ".git").mkdir()
    cfg = DetectorConfig(scan_history=True)
    detector = SecretsDetector(config=cfg)

    with patch.object(detector, "_get_recent_commits", return_value=[("abc", "msg")]):
        with patch.object(detector, "_get_commit_diff", side_effect=Exception("timeout")):
            findings = detector.scan_git_history(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# SecretsDetector.from_project factory
# ---------------------------------------------------------------------------

def test_from_project_creates_detector_with_config(tmp_path):
    yml = tmp_path / "depfence.yml"
    yml.write_text("secrets:\n  history_depth: 7\n")
    detector = SecretsDetector.from_project(tmp_path)
    assert detector._config.history_depth == 7


def test_from_project_works_without_yml(tmp_path):
    detector = SecretsDetector.from_project(tmp_path)
    assert detector is not None
    assert detector._config.history_depth == 50


# ---------------------------------------------------------------------------
# HistoryFinding dataclass
# ---------------------------------------------------------------------------

def test_history_finding_fields():
    hf = HistoryFinding(
        commit_hash="deadbeef",
        commit_message="oops added key",
        file_path="config.py",
        line_num=5,
        secret_type="AWS Access Key ID",
        masked_preview="AKIA****",
        severity="critical",
    )
    assert hf.commit_hash == "deadbeef"
    assert hf.line_num == 5
    assert hf.severity == "critical"
