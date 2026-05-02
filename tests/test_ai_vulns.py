"""Tests for AI framework vulnerability scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import Severity
from depfence.scanners.ai_vulns import AiVulnScanner


@pytest.fixture
def scanner():
    return AiVulnScanner()


def test_langchain_vuln(scanner):
    findings = scanner.check_package_version("langchain", "0.0.300")
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("CVE" in (f.cve or "") for f in findings)


def test_torch_vuln(scanner):
    findings = scanner.check_package_version("torch", "1.13.0")
    assert len(findings) >= 1
    assert any("torch.load" in f.title for f in findings)


def test_safe_version_no_findings(scanner):
    findings = scanner.check_package_version("langchain", "0.1.0")
    assert len(findings) == 0


def test_mlflow_rce(scanner):
    findings = scanner.check_package_version("mlflow", "2.8.0")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_ray_rce(scanner):
    findings = scanner.check_package_version("ray", "2.7.0")
    assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_unsafe_torch_load(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "model.py"
        f.write_text('model = torch.load("model.bin")')
        findings = await scanner.scan_project(Path(d))
        assert any("torch.load" in f.title for f in findings)


@pytest.mark.asyncio
async def test_safe_torch_load_not_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "model.py"
        f.write_text('model = torch.load("model.bin", weights_only=True)')
        findings = await scanner.scan_project(Path(d))
        assert not any("torch.load" in f.title for f in findings)


@pytest.mark.asyncio
async def test_trust_remote_code(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "load.py"
        f.write_text('model = AutoModel.from_pretrained("evil/model", trust_remote_code=True)')
        findings = await scanner.scan_project(Path(d))
        assert any("trust_remote_code" in f.title for f in findings)


@pytest.mark.asyncio
async def test_eval_llm_output(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "agent.py"
        f.write_text('result = eval(response.text)')
        findings = await scanner.scan_project(Path(d))
        assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_exec_llm_output(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "agent.py"
        f.write_text('exec(completion)')
        findings = await scanner.scan_project(Path(d))
        assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_subprocess_llm_output(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "tool_use.py"
        f.write_text('subprocess.run(response.split())')
        findings = await scanner.scan_project(Path(d))
        assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_clean_code(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "app.py"
        f.write_text("""
from transformers import AutoModel
model = AutoModel.from_pretrained("bert-base-uncased")
output = model(input_ids)
""")
        findings = await scanner.scan_project(Path(d))
        assert len(findings) == 0


def test_unknown_package_no_findings(scanner):
    findings = scanner.check_package_version("some-random-pkg", "1.0.0")
    assert len(findings) == 0
