"""Tests for CI/CD configuration generator."""

import tempfile
from pathlib import Path

import pytest

from depfence import __version__
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

    def test_invalid_fail_on_rejected(self):
        with pytest.raises(ValueError, match="Unsupported failure threshold"):
            generate_github_actions(fail_on="high\nrun: echo injected")

    def test_docker_scan_included(self):
        output = generate_github_actions(scan_docker=True)
        assert "scan-docker" in output

    def test_compliance_report(self):
        output = generate_github_actions(compliance_report=True)
        assert "compliance" in output
        assert "upload-artifact" in output

    def test_generated_workflow_is_pinned_and_fail_closed(self):
        output = generate_github_actions()
        assert f'pip install "depfence=={__version__}"' in output
        assert "actions/checkout@v" not in output
        assert "actions/setup-python@v" not in output
        assert "github/codeql-action/upload-sarif@v" not in output
        assert "Enforce scan result" in output
        assert "SCAN_EXIT_CODE" in output

    def test_privileged_sarif_upload_is_not_in_pull_request_job(self):
        output = generate_github_actions()
        scan_job, upload_job = output.split("  upload-sarif:", 1)
        assert "security-events: write" not in scan_job
        assert "github.event_name != 'pull_request'" in upload_job
        assert "security-events: write" in upload_job


class TestGitLabCI:
    def test_basic_config(self):
        output = generate_gitlab_ci()
        assert "depfence-scan" in output
        assert "dependency_scanning" not in output
        assert "depfence-results.json" in output
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
