"""Tests for reachability scanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.reachability import ReachabilityScanner, _extract_calls, _extract_imports


@pytest.fixture
def scanner():
    return ReachabilityScanner()


def _write(tmp: str, filename: str, content: str) -> None:
    (Path(tmp) / filename).write_text(content)


# --- Unit tests for helpers ---

def test_extract_imports_simple():
    source = "import yaml\nimport os\n"
    names = _extract_imports(source)
    assert "yaml" in names
    assert "os" in names


def test_extract_imports_from_style():
    source = "from yaml import load, dump\n"
    names = _extract_imports(source)
    assert "yaml" in names
    assert "load" in names


def test_extract_imports_dotted():
    source = "import xml.etree.ElementTree as ET\n"
    names = _extract_imports(source)
    assert "xml.etree" in names
    assert "xml" in names


def test_extract_calls_attr_style():
    source = "import yaml\ndata = yaml.load(f, Loader=yaml.SafeLoader)\n"
    calls = _extract_calls(source, "yaml")
    fns = [fn for fn, _ in calls]
    assert "load" in fns


def test_extract_calls_bare_after_from_import():
    source = "from yaml import load\nload(f)\n"
    calls = _extract_calls(source, "yaml")
    fns = [fn for fn, _ in calls]
    assert "load" in fns


def test_extract_calls_builtin_eval():
    source = "result = eval(user_input)\n"
    calls = _extract_calls(source, "eval")
    assert len(calls) >= 1
    assert calls[0][0] == "eval"


def test_extract_calls_no_match():
    source = "import yaml\ndata = yaml.safe_load(f)\n"
    calls = _extract_calls(source, "yaml")
    assert calls == []


# --- Integration tests via scan_project ---

@pytest.mark.asyncio
async def test_direct_import_and_call_reachable(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "app.py", "import yaml\ndata = yaml.load(open('f'), Loader=None)\n")
        findings = await scanner.scan_project(Path(tmp))
        yaml_findings = [f for f in findings if f.package.name == "yaml"]
        assert yaml_findings, "Expected a finding for yaml"
        reachable = [f for f in yaml_findings if f.metadata.get("reachability") == "reachable"]
        assert reachable, "Expected reachable verdict"
        assert reachable[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_import_without_call_reduced(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "app.py", "import yaml\ndata = yaml.safe_load(open('f'))\n")
        findings = await scanner.scan_project(Path(tmp))
        yaml_findings = [f for f in findings if f.package.name == "yaml"]
        assert yaml_findings
        not_called = [f for f in yaml_findings if f.metadata.get("reachability") == "imported_not_called"]
        assert not_called, "Expected imported_not_called verdict"
        assert not_called[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_not_imported_at_all(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "app.py", "import json\ndata = json.loads('{}')\n")
        findings = await scanner.scan_project(Path(tmp))
        yaml_findings = [f for f in findings if f.package.name == "yaml"]
        assert yaml_findings
        not_reachable = [f for f in yaml_findings if f.metadata.get("reachability") == "not_reachable"]
        assert not_reachable, "Expected not_reachable verdict"
        assert not_reachable[0].severity == Severity.LOW
        assert "not reachable" in not_reachable[0].title.lower()


@pytest.mark.asyncio
async def test_pickle_load_reachable(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "model.py", "import pickle\nobj = pickle.loads(data)\n")
        findings = await scanner.scan_project(Path(tmp))
        pickle_findings = [f for f in findings if f.package.name == "pickle"]
        reachable = [f for f in pickle_findings if f.metadata.get("reachability") == "reachable"]
        assert reachable
        sites = reachable[0].metadata["call_sites"]
        assert any(s["function"] == "loads" for s in sites)


@pytest.mark.asyncio
async def test_eval_always_reachable(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "risky.py", "result = eval(user_input)\n")
        findings = await scanner.scan_project(Path(tmp))
        eval_findings = [f for f in findings if f.package.name == "eval"]
        reachable = [f for f in eval_findings if f.metadata.get("reachability") == "reachable"]
        assert reachable


@pytest.mark.asyncio
async def test_torch_load_detected(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "infer.py", "import torch\nmodel = torch.load('model.pt')\n")
        findings = await scanner.scan_project(Path(tmp))
        torch_findings = [f for f in findings if f.package.name == "torch"]
        reachable = [f for f in torch_findings if f.metadata.get("reachability") == "reachable"]
        assert reachable
        sites = reachable[0].metadata["call_sites"]
        assert any(s["function"] == "load" for s in sites)


@pytest.mark.asyncio
async def test_no_python_files_clean(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        findings = await scanner.scan_project(Path(tmp))
        assert findings == []


@pytest.mark.asyncio
async def test_call_site_metadata_populated(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "app.py", "import yaml\nresult = yaml.load(stream)\n")
        findings = await scanner.scan_project(Path(tmp))
        reachable = [
            f for f in findings
            if f.package.name == "yaml" and f.metadata.get("reachability") == "reachable"
        ]
        assert reachable
        f = reachable[0]
        assert f.metadata["source_file"] == "app.py"
        assert f.metadata["line"] > 0
        assert f.metadata["call_sites"]


@pytest.mark.asyncio
async def test_from_import_call_reachable(scanner):
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "app.py", "from pickle import loads\nobj = loads(data)\n")
        findings = await scanner.scan_project(Path(tmp))
        pickle_findings = [f for f in findings if f.package.name == "pickle"]
        reachable = [f for f in pickle_findings if f.metadata.get("reachability") == "reachable"]
        assert reachable
