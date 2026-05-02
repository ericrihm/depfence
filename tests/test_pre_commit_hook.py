"""Tests for pre-commit hook integration."""

from unittest.mock import MagicMock, patch
import subprocess
import pytest

from depfence.integrations.pre_commit_hook import get_staged_lockfiles, main


class TestGetStagedLockfiles:
    @patch("subprocess.run")
    def test_detects_lockfiles(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="package-lock.json\nsrc/app.js\nyarn.lock\n",
            returncode=0,
        )
        result = get_staged_lockfiles()
        assert "package-lock.json" in result
        assert "yarn.lock" in result
        assert len(result) == 2

    @patch("subprocess.run")
    def test_ignores_non_lockfiles(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="src/index.js\nREADME.md\n",
            returncode=0,
        )
        result = get_staged_lockfiles()
        assert result == []

    @patch("subprocess.run")
    def test_handles_git_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "git")
        result = get_staged_lockfiles()
        assert result == []

    @patch("subprocess.run")
    def test_handles_no_git(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        result = get_staged_lockfiles()
        assert result == []

    @patch("subprocess.run")
    def test_nested_lockfile_paths(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="packages/api/package-lock.json\napps/web/yarn.lock\n",
            returncode=0,
        )
        result = get_staged_lockfiles()
        assert len(result) == 2


class TestMain:
    @patch("depfence.integrations.pre_commit_hook.get_staged_lockfiles")
    def test_no_lockfiles_passes(self, mock_staged):
        mock_staged.return_value = []
        assert main() == 0

    @patch("subprocess.run")
    @patch("depfence.integrations.pre_commit_hook.get_staged_lockfiles")
    def test_clean_scan_passes(self, mock_staged, mock_run):
        mock_staged.return_value = ["package-lock.json"]
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert main() == 0

    @patch("subprocess.run")
    @patch("depfence.integrations.pre_commit_hook.get_staged_lockfiles")
    def test_vuln_scan_fails(self, mock_staged, mock_run):
        mock_staged.return_value = ["package-lock.json"]
        mock_run.return_value = MagicMock(returncode=1, stdout="Found vulns", stderr="")
        assert main() == 1

    @patch("subprocess.run")
    @patch("depfence.integrations.pre_commit_hook.get_staged_lockfiles")
    def test_depfence_not_installed(self, mock_staged, mock_run):
        mock_staged.return_value = ["package-lock.json"]
        mock_run.side_effect = FileNotFoundError()
        assert main() == 0

    @patch("subprocess.run")
    @patch("depfence.integrations.pre_commit_hook.get_staged_lockfiles")
    def test_scan_timeout_passes(self, mock_staged, mock_run):
        mock_staged.return_value = ["requirements.txt"]
        mock_run.side_effect = subprocess.TimeoutExpired("depfence", 60)
        assert main() == 0
