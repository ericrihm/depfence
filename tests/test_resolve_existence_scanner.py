"""Tests for the resolve-never-predict existence scanner."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import httpx

from depfence.core.models import FindingType, Severity
from depfence.scanners import resolve_existence_scanner as mod
from depfence.scanners.resolve_existence_scanner import ResolveExistenceScanner

REAL = "1" * 40          # pretend-real commit (200)
FAB = "f" * 40           # fabricated commit (422)
REAL_V4 = "a" * 40       # what tag v4 actually points to


def _write_workflow(d: Path, name: str, body: str) -> None:
    wf = d / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body, encoding="utf-8")


def _make_client(
    commit_status: dict[str, int],
    *,
    repo_exists: bool = True,
    tags: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    tags = tags or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if m := re.match(r"/repos/[^/]+/[^/]+/commits/([0-9a-fA-F]+)$", path):
            sha = m.group(1).lower()
            status = commit_status.get(sha, 200)
            if status == 200:
                return httpx.Response(200, json={"sha": sha})
            return httpx.Response(status, json={"message": "No commit found for SHA"})
        if re.match(r"/repos/[^/]+/[^/]+/git/ref/tags/(.+)$", path):
            tag = path.rsplit("/", 1)[1]
            if tag in tags:
                return httpx.Response(200, json={"object": {"type": "commit", "sha": tags[tag]}})
            return httpx.Response(404, json={})
        if re.match(r"/repos/[^/]+/[^/]+$", path):
            return httpx.Response(200 if repo_exists else 404, json={})
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _patch(monkeypatch, client: httpx.AsyncClient) -> None:
    monkeypatch.setattr(mod, "_get_client", lambda: client)
    monkeypatch.delenv("DEPFENCE_RESOLVE_EXISTENCE", raising=False)


async def _scan(body: str, client: httpx.AsyncClient, monkeypatch) -> list:
    _patch(monkeypatch, client)
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", body)
        return await ResolveExistenceScanner().scan_project(Path(d))


def _wf(line: str) -> str:
    return f"on: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - {line}\n"


async def test_real_pin_no_finding(monkeypatch):
    client = _make_client({REAL: 200})
    findings = await _scan(_wf(f"uses: actions/checkout@{REAL} # v4"), client, monkeypatch)
    assert findings == []


async def test_fabricated_commit_is_critical(monkeypatch):
    client = _make_client({FAB: 422})
    findings = await _scan(_wf(f"uses: actions/checkout@{FAB} # v4"), client, monkeypatch)
    fab = [f for f in findings if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1
    assert fab[0].severity == Severity.CRITICAL
    assert fab[0].metadata["http_status"] == 422


async def test_fabricated_repo_disambiguated(monkeypatch):
    # commit 404 + repo 404 => the action repo itself doesn't exist.
    client = _make_client({FAB: 404}, repo_exists=False)
    findings = await _scan(_wf(f"uses: nope/ghost@{FAB} # v1"), client, monkeypatch)
    fab = [f for f in findings if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1
    assert fab[0].metadata["fault_class"] == "fabricated_repo"
    assert "non-existent repository" in fab[0].title


async def test_conflation_fault_class(monkeypatch):
    # Fabricated SHA that shares v1.12.4's real prefix, then diverges (the incident).
    real_v1124 = "76f52bc884231f62b9a034ebfe128415bbaabdfc"
    fake = "76f52bc884231f62b54e755450e7d4b840b0e27b"  # shares 17-char prefix
    client = _make_client({fake.lower(): 422}, tags={"v1.12.4": real_v1124})
    findings = await _scan(
        _wf(f"uses: pypa/gh-action-pypi-publish@{fake} # v1.12.4"), client, monkeypatch
    )
    fab = [f for f in findings if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1
    assert fab[0].metadata["fault_class"] == "conflation"


async def test_moved_tag_is_not_false_positive(monkeypatch):
    # Commit exists but the `# v4` tag has since advanced to a newer patch. This is the
    # NORMAL, correct pinning case (pin an older real commit; tag moves on) and must NOT
    # be flagged — guards against the false positive that would fire on nearly every pin.
    client = _make_client({REAL: 200}, tags={"v4": REAL_V4})
    findings = await _scan(_wf(f"uses: actions/checkout@{REAL} # v4"), client, monkeypatch)
    assert findings == []


async def test_rate_limited_is_unverified_info(monkeypatch):
    client = _make_client({REAL: 403})
    findings = await _scan(_wf(f"uses: actions/checkout@{REAL} # v4"), client, monkeypatch)
    unv = [f for f in findings if f.finding_type == FindingType.UNVERIFIED_REF]
    assert len(unv) == 1
    assert unv[0].severity == Severity.INFO
    assert not any(f.finding_type == FindingType.FABRICATED_REF for f in findings)


async def test_kill_switch_disables(monkeypatch):
    client = _make_client({FAB: 422})
    monkeypatch.setattr(mod, "_get_client", lambda: client)
    monkeypatch.setenv("DEPFENCE_RESOLVE_EXISTENCE", "0")
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "ci.yml", _wf(f"uses: actions/checkout@{FAB} # v4"))
        findings = await ResolveExistenceScanner().scan_project(Path(d))
    assert findings == []


async def test_dedup_same_pin_across_files(monkeypatch):
    client = _make_client({FAB: 422})
    _patch(monkeypatch, client)
    with tempfile.TemporaryDirectory() as d:
        _write_workflow(Path(d), "a.yml", _wf(f"uses: actions/checkout@{FAB} # v4"))
        _write_workflow(Path(d), "b.yml", _wf(f"uses: actions/checkout@{FAB} # v4"))
        findings = await ResolveExistenceScanner().scan_project(Path(d))
    fab = [f for f in findings if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1  # de-duplicated


async def test_subpath_action_repo_parsed(monkeypatch):
    # github/codeql-action/upload-sarif@<sha> -> repo is github/codeql-action.
    client = _make_client({FAB: 422})
    findings = await _scan(
        _wf(f"uses: github/codeql-action/upload-sarif@{FAB} # v3"), client, monkeypatch
    )
    fab = [f for f in findings if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1
    assert fab[0].metadata["repo"] == "github/codeql-action"


async def test_no_workflows_dir(monkeypatch):
    client = _make_client({})
    _patch(monkeypatch, client)
    with tempfile.TemporaryDirectory() as d:
        findings = await ResolveExistenceScanner().scan_project(Path(d))
    assert findings == []
