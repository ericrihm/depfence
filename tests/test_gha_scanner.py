"""Tests for GitHub Actions workflow scanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.gha_scanner import GhaScanner


@pytest.fixture
def scanner():
    return GhaScanner()


def _write_workflow(tmpdir: Path, filename: str, content: str) -> Path:
    workflows_dir = tmpdir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    wf = workflows_dir / filename
    wf.write_text(content)
    return wf


@pytest.mark.asyncio
async def test_unpinned_official_action_medium(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.MEDIUM and "checkout" in f.title.lower()
            for f in findings
        )


@pytest.mark.asyncio
async def test_unpinned_third_party_action_high(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@v1
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.HIGH and "some-org/some-action" in f.title
            for f in findings
        )


@pytest.mark.asyncio
async def test_known_compromised_action_critical(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v44
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.finding_type == FindingType.KNOWN_VULN
            and f.severity == Severity.CRITICAL
            and "tj-actions/changed-files" in f.title
            for f in findings
        )


@pytest.mark.asyncio
async def test_sha_pinned_action_clean(scanner):
    with tempfile.TemporaryDirectory() as d:
        sha = "a" * 40
        _write_workflow(Path(d), "ci.yml", f"""\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha}
      - uses: some-org/some-action@{sha}
""")
        findings = await scanner.scan_project(Path(d))
        # No unpinned-tag or known-vuln findings expected
        risky = [
            f for f in findings
            if f.finding_type in (FindingType.KNOWN_VULN, FindingType.BEHAVIORAL)
            and "unpinned" in f.title.lower() or "sha" in f.title.lower()
        ]
        assert len(risky) == 0


@pytest.mark.asyncio
async def test_script_injection_in_run_step_high(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on:
  issue_comment:
    types: [created]
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Echo body
        run: |
          echo "${{ github.event.issue.body }}"
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.HIGH
            and f.finding_type == FindingType.BEHAVIORAL
            and "injection" in f.title.lower()
            for f in findings
        )


@pytest.mark.asyncio
async def test_write_all_permissions_medium(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.MEDIUM
            and "permissions" in f.title.lower()
            for f in findings
        )


@pytest.mark.asyncio
async def test_no_workflows_dir_returns_empty(scanner):
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_codecov_action_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", """\
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: codecov/codecov-action@v4
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.finding_type == FindingType.KNOWN_VULN
            and f.severity == Severity.CRITICAL
            for f in findings
        )


@pytest.mark.asyncio
async def test_pr_title_injection_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "label.yml", """\
on:
  pull_request:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.HIGH and "injection" in f.title.lower()
            for f in findings
        )


@pytest.mark.asyncio
async def test_contents_write_permission_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "release.yml", """\
on: [push]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""")
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.MEDIUM and "permissions" in f.title.lower()
            for f in findings
        )
