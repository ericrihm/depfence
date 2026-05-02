"""Tests for CI/CD configuration generator."""

import tempfile
from pathlib import Path

import pytest

from depfence.integrations.ci_generator import (
    generate_bitbucket_pipelines,
    generate_github_actions,
    generate_gitlab_ci,
    generate_pre_commit_hook,
    write_ci_config,
)


class TestGitHubActions:
    def test_basic_workflow(self):
        output = generate_github_actions()
        assert "depfence scan" in output
        assert "sarif" in output
        assert "actions/checkout" in output
        assert "fail-on high" in output

    def test_custom_fail_on(self):
        output = generate_github_actions(fail_on="critical")
        assert "fail-on critical" in output

    def test_docker_scan_included(self):
        output = generate_github_actions(scan_docker=True)
        assert "scan-docker" in output

    def test_compliance_report(self):
        output = generate_github_actions(compliance_report=True)
        assert "compliance" in output
        assert "upload-artifact" in output


class TestGitLabCI:
    def test_basic_config(self):
        output = generate_gitlab_ci()
        assert "depfence-scan" in output
        assert "dependency_scanning" in output
        assert "pip install depfence" in output

    def test_custom_fail_on(self):
        output = generate_gitlab_ci(fail_on="medium")
        assert "fail-on medium" in output


class TestPreCommit:
    def test_generates_hooks(self):
        output = generate_pre_commit_hook()
        assert "depfence-scan" in output
        assert "depfence-secrets" in output
        assert "stages: [commit]" in output


class TestBitbucket:
    def test_basic_config(self):
        output = generate_bitbucket_pipelines()
        assert "depfence scan" in output
        assert "pull-requests" in output


class TestWriteConfig:
    def test_writes_github_actions(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_ci_config(Path(d), "github")
            assert path.exists()
            assert ".github/workflows/depfence.yml" in str(path)
            content = path.read_text()
            assert "depfence" in content

    def test_writes_gitlab_ci(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_ci_config(Path(d), "gitlab")
            assert path.exists()

    def test_invalid_type_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with pytest.raises(ValueError, match="Unknown CI type"):
                write_ci_config(Path(d), "jenkins")
