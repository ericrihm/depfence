"""Tests for AI framework vulnerability scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import PackageId, PackageMeta, Severity
from depfence.core.scan_scope import PartialScanError
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
async def test_subprocess_capture_output_is_not_llm_dataflow(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "git_helper.py"
        f.write_text(
            "result = subprocess.run(['git', 'status'], capture_output=True, text=True)\n"
        )
        findings = await scanner.scan_project(Path(d))
        assert not any(f.title == "LLM output passed to subprocess" for f in findings)


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


@pytest.mark.asyncio
async def test_oversized_python_input_is_named_incomplete(scanner, tmp_path):
    (tmp_path / "model.py").write_text("#" + ("a" * 1_000_001))

    with pytest.raises(PartialScanError, match="exceeds"):
        await scanner.scan_project(tmp_path)


@pytest.mark.asyncio
async def test_file_budget_preserves_findings_and_names_incomplete(
    scanner, tmp_path, monkeypatch
):
    (tmp_path / "000_attack.py").write_text("exec(completion)\n")
    (tmp_path / "001_benign.py").write_text("value = 1\n")
    monkeypatch.setattr("depfence.scanners.ai_vulns._MAX_PYTHON_FILES", 1)

    with pytest.raises(PartialScanError, match="1 Python files") as captured:
        await scanner.scan_project(tmp_path)

    assert any(finding.severity == Severity.CRITICAL for finding in captured.value.findings)


@pytest.mark.asyncio
async def test_symlinked_python_input_is_named_incomplete(scanner, tmp_path):
    outside = tmp_path.parent / "external-ai-vuln.py"
    outside.write_text("exec(completion)\n")
    (tmp_path / "linked.py").symlink_to(outside)

    with pytest.raises(PartialScanError, match="symlinked"):
        await scanner.scan_project(tmp_path)


def test_unknown_package_no_findings(scanner):
    findings = scanner.check_package_version("some-random-pkg", "1.0.0")
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_standard_package_scan_correlates_exact_resolved_version(scanner):
    packages = [
        PackageMeta(pkg=PackageId("pypi", "langchain", "0.0.300")),
        PackageMeta(pkg=PackageId("pypi", "requests", "2.32.0")),
    ]

    findings = await scanner.scan(packages)

    assert findings
    assert all(str(finding.package) == "pypi:langchain@0.0.300" for finding in findings)


@pytest.mark.asyncio
async def test_standard_package_scan_without_version_is_benign_not_a_match(scanner):
    packages = [
        PackageMeta(pkg=PackageId("pypi", "langchain")),
        PackageMeta(pkg=PackageId("npm", "langchain", "0.0.300")),
    ]

    assert await scanner.scan(packages) == []


def test_sglang_vuln_detected(scanner):
    findings = scanner.check_package_version("sglang", "0.3.5")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cve == "CVE-2026-5760"


def test_sglang_fixed_version(scanner):
    findings = scanner.check_package_version("sglang", "0.4.1")
    assert len(findings) == 0


def test_transformers_old_vuln(scanner):
    findings = scanner.check_package_version("transformers", "4.45.0")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_gradio_5_safe(scanner):
    findings = scanner.check_package_version("gradio", "5.1.0")
    assert len(findings) == 0


def test_autogpt_vuln(scanner):
    findings = scanner.check_package_version("auto-gpt", "0.5.0")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
