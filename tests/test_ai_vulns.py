"""Tests for AI framework vulnerability scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.ai_vulns import AiVulnScanner


@pytest.fixture
def scanner():
    return AiVulnScanner()


# Expectations are pinned to the primary-source adjudication in the native W1
# audit section, not to the catalogue's row count or its historical assertions.
@pytest.mark.parametrize(
    "name,affected,excluded,cve,severity,fix_version",
    [
        ("langchain", "0.0.246", "0.0.247", "CVE-2023-36188", Severity.CRITICAL, "0.0.247"),
        ("langchain-experimental", "0.0.14", "0.0.15", "CVE-2023-44467", Severity.CRITICAL, None),
        ("transformers", "4.35.2", "4.36.0", "CVE-2023-7018", Severity.CRITICAL, "4.36.0"),
        ("langchain-core", "0.1.34", "0.1.35", "CVE-2024-1455", Severity.MEDIUM, "0.1.35"),
        ("gradio", "4.10.0", "4.11.0", "CVE-2023-51449", Severity.MEDIUM, "4.11.0"),
        ("tensorflow", "2.11.0", "2.11.1", "CVE-2023-25668", Severity.MEDIUM, "2.11.1"),
        ("mlflow", "2.9.1", "2.9.2", "CVE-2023-6831", Severity.HIGH, "2.9.2"),
        ("lerobot", "0.5.1", "0.5.2", "CVE-2026-25874", Severity.CRITICAL, None),
        ("onnx", "1.20.1", "1.21.0", "CVE-2026-28500", Severity.MEDIUM, "1.21.0"),
        ("gradio", "5.5.0", "5.6.0", "CVE-2025-23042", Severity.HIGH, "5.6.0"),
    ],
)
def test_adjudicated_boundaries(scanner, name, affected, excluded, cve, severity, fix_version):
    findings = scanner.check_package_version(name, affected)
    finding = next(f for f in findings if f.cve == cve)
    assert finding.finding_type == FindingType.KNOWN_VULN
    assert finding.severity == severity
    assert finding.fix_version == fix_version
    assert finding.references
    assert not any(f.cve == cve for f in scanner.check_package_version(name, excluded))
    # Excluded means no matching entry, not a claim that this package is safe.


@pytest.mark.parametrize(
    "name,version",
    [
        ("pytorch-lightning", "2.4.0"),
        ("litellm", "1.54.0"),
        ("torch", "1.13.0"),
        ("llama-index", "0.8.0"),
        ("auto-gpt", "0.5.0"),
        ("auto-gpt", "0.6.48"),
        ("sglang", "0.3.5"),
        ("sglang", "0.5.9"),
        ("transformers", "4.45.0"),
        ("langchain", "0.0.300"),
    ],
)
def test_unsupported_claims_are_not_promoted(scanner, name, version):
    assert scanner.check_package_version(name, version) == []


@pytest.mark.parametrize("version", ["2.6.3", "2.8.0"])
def test_ray_report_does_not_invent_a_patch(scanner, version):
    findings = scanner.check_package_version("ray", version)
    finding = next(f for f in findings if f.cve == "CVE-2023-48022")
    assert finding.severity == Severity.CRITICAL
    assert finding.fix_version is None
    assert finding.references == [
        "https://cveawg.mitre.org/api/cve/CVE-2023-48022",
        "https://docs.ray.io/en/latest/ray-security/index.html",
    ]


@pytest.mark.parametrize("version", ["2.7.0", "2.8.1", "2.52.0"])
def test_ray_unestablished_versions_are_not_asserted(scanner, version):
    assert scanner.check_package_version("ray", version) == []


@pytest.mark.parametrize("name", ["langchain-core", "LangChain_Core", "langchain.core"])
def test_pypi_package_identity_normalization(scanner, name):
    assert any(f.cve == "CVE-2024-1455"
               for f in scanner.check_package_version(name, "0.1.34"))


def test_pep440_version_semantics(scanner):
    assert any(f.cve == "CVE-2023-6831"
               for f in scanner.check_package_version("mlflow", "2.9.1rc1"))
    assert scanner.check_package_version("mlflow", "2.9.2+local") == []
    assert scanner.check_package_version("mlflow", "not-a-release") == []
    assert scanner.check_package_version("mlflow", "") == []


def test_wrong_product_cve_is_not_assigned_to_onnx(scanner):
    findings = scanner.check_package_version("onnx", "1.13.0")
    assert any(f.cve == "CVE-2026-28500" for f in findings)
    assert all(f.cve != "CVE-2023-32577" for f in findings)


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


@pytest.mark.asyncio
async def test_behavioral_findings_do_not_claim_a_cve(scanner, tmp_path):
    (tmp_path / "model.py").write_text('model = torch.load("model.bin")')
    findings = await scanner.scan_project(tmp_path)
    assert findings
    assert all(f.finding_type == FindingType.BEHAVIORAL for f in findings)
    assert all(f.cve is None and f.fix_version is None for f in findings)
