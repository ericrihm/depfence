"""Tests for GitHub Actions workflow security scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner


@pytest.fixture
def scanner():
    return GhaWorkflowScanner()


def _write_workflow(tmpdir: Path, content: str, name: str = "ci.yml") -> Path:
    wf_dir = tmpdir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    f = wf_dir / name
    f.write_text(content)
    return f


class TestScriptInjection:
    @pytest.mark.asyncio
    async def test_detects_event_title_injection(self, scanner):
        workflow = """
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "PR title is ${{ github.event.pull_request.title }}"
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert any("injection" in f.title.lower() or "inject" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_safe_context_no_injection(self, scanner):
        workflow = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "SHA is ${{ github.sha }}"
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert not any("injection" in f.title.lower() for f in findings)


class TestUnpinnedActions:
    @pytest.mark.asyncio
    async def test_detects_tag_ref(self, scanner):
        workflow = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert any("npin" in f.title.lower() or "pin" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_sha_pinned_no_finding(self, scanner):
        workflow = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert not any("npin" in f.title.lower() for f in findings)


class TestPermissions:
    @pytest.mark.asyncio
    async def test_write_all_flagged(self, scanner):
        workflow = """
name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert any("permission" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_read_all_no_finding(self, scanner):
        workflow = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert not any("permission" in f.title.lower() for f in findings)


class TestPullRequestTarget:
    @pytest.mark.asyncio
    async def test_dangerous_pr_target_checkout(self, scanner):
        workflow = """
name: CI
on: pull_request_target
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert any("pull_request_target" in f.title.lower() or "request_target" in f.detail.lower() for f in findings)


class TestSelfHosted:
    @pytest.mark.asyncio
    async def test_self_hosted_flagged(self, scanner):
        workflow = """
name: CI
on: push
permissions: read-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            assert any("self-hosted" in f.title.lower() or "self-hosted" in f.detail.lower() for f in findings)


class TestScanInterface:
    @pytest.mark.asyncio
    async def test_scan_returns_empty(self, scanner):
        result = await scanner.scan([])
        assert result == []

    @pytest.mark.asyncio
    async def test_no_workflows_no_findings(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            findings = await scanner.scan_project(Path(d))
            assert findings == []
