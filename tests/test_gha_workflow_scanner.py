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


# ---------------------------------------------------------------------------
# Cordyceps-class checks
# ---------------------------------------------------------------------------


class TestWorkflowRunEscalation:
    @pytest.mark.asyncio
    async def test_detects_artifact_download_in_workflow_run(self, scanner):
        workflow = """
name: Deploy
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            cordyceps = [f for f in findings if "workflow_run" in f.title and "Cordyceps" in f.title]
            assert len(cordyceps) >= 1
            assert cordyceps[0].severity.value == "critical"

    @pytest.mark.asyncio
    async def test_no_finding_without_artifact_download(self, scanner):
        workflow = """
name: Deploy
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: echo "deploying"
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            cordyceps = [f for f in findings if "workflow_run" in f.title and "Cordyceps" in f.title]
            assert len(cordyceps) == 0

    @pytest.mark.asyncio
    async def test_detects_third_party_download_action(self, scanner):
        workflow = """
name: Deploy
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: dawidd6/action-download-artifact@v3
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            cordyceps = [f for f in findings if "workflow_run" in f.title and "Cordyceps" in f.title]
            assert len(cordyceps) >= 1


class TestIssueCommentCheckout:
    @pytest.mark.asyncio
    async def test_detects_issue_comment_with_checkout(self, scanner):
        workflow = """
name: Approve
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            toctou = [f for f in findings if "issue_comment" in f.title and "TOCTOU" in f.title]
            assert len(toctou) >= 1

    @pytest.mark.asyncio
    async def test_detects_mutable_head_ref(self, scanner):
        workflow = """
name: Approve
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            toctou = [f for f in findings if "TOCTOU" in f.title]
            assert len(toctou) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_on_push_trigger(self, scanner):
        workflow = """
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            toctou = [f for f in findings if "TOCTOU" in f.title]
            assert len(toctou) == 0


class TestGithubScriptInjection:
    @pytest.mark.asyncio
    async def test_detects_event_in_github_script(self, scanner):
        workflow = """
name: Triage
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const title = `${{ github.event.issue.title }}`;
            if (title.includes('bug')) {
              github.rest.issues.addLabels({labels: ['bug']});
            }
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            script_inj = [f for f in findings if "Code injection" in f.title and "github-script" in f.title]
            assert len(script_inj) >= 1
            assert script_inj[0].severity.value == "critical"

    @pytest.mark.asyncio
    async def test_no_finding_without_event_interpolation(self, scanner):
        workflow = """
name: Triage
on: issues
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const issues = await github.rest.issues.list();
            console.log(issues.data.length);
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            script_inj = [f for f in findings if "Code injection" in f.title and "github-script" in f.title]
            assert len(script_inj) == 0


class TestArtifactTrustBoundary:
    @pytest.mark.asyncio
    async def test_detects_unvalidated_download_in_prt(self, scanner):
        workflow = """
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: bash ./deploy.sh
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            artifact = [f for f in findings if "artifact" in f.title.lower() and "poisoning" in f.title.lower()]
            assert len(artifact) >= 1

    @pytest.mark.asyncio
    async def test_safe_with_name_and_path(self, scanner):
        workflow = """
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: test-results
          path: /tmp/artifacts
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            artifact = [f for f in findings if "artifact" in f.title.lower() and "poisoning" in f.title.lower()]
            assert len(artifact) == 0

    @pytest.mark.asyncio
    async def test_no_finding_on_push_trigger(self, scanner):
        workflow = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            artifact = [f for f in findings if "artifact" in f.title.lower() and "poisoning" in f.title.lower()]
            assert len(artifact) == 0


class TestCheckoutVersion:
    @pytest.mark.asyncio
    async def test_detects_old_checkout_in_prt(self, scanner):
        workflow = """
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            checkout = [f for f in findings if "checkout@v4" in f.title and "fork-PR" in f.title]
            assert len(checkout) >= 1

    @pytest.mark.asyncio
    async def test_v7_no_finding(self, scanner):
        workflow = """
name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            checkout = [f for f in findings if "fork-PR" in f.title]
            assert len(checkout) == 0

    @pytest.mark.asyncio
    async def test_no_finding_on_push_trigger(self, scanner):
        workflow = """
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        with tempfile.TemporaryDirectory() as d:
            _write_workflow(Path(d), workflow)
            findings = await scanner.scan_project(Path(d))
            checkout = [f for f in findings if "fork-PR" in f.title]
            assert len(checkout) == 0
