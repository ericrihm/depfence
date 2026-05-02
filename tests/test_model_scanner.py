"""Tests for the model registry / weight file scanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.model_scanner import ModelScanner, _extract_model_refs


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> ModelScanner:
    return ModelScanner()


# ---------------------------------------------------------------------------
# Unit tests: _extract_model_refs
# ---------------------------------------------------------------------------

def test_from_pretrained_single_line_double_quotes():
    refs = _extract_model_refs('model = AutoModel.from_pretrained("bert-base-uncased")')
    assert ("bert-base-uncased", 1) in refs


def test_from_pretrained_single_quotes():
    refs = _extract_model_refs("tok = AutoTokenizer.from_pretrained('gpt2')")
    assert ("gpt2", 1) in refs


def test_pipeline_model_kwarg():
    refs = _extract_model_refs(
        'pipe = pipeline("text-generation", model="meta-llama/Llama-3-8B")'
    )
    assert ("meta-llama/Llama-3-8B", 1) in refs


def test_hf_hub_download_repo_id():
    refs = _extract_model_refs(
        'hf_hub_download(repo_id="suspicious/model", filename="model.bin")'
    )
    assert ("suspicious/model", 1) in refs


def test_snapshot_download_positional():
    refs = _extract_model_refs('snapshot_download("mistralai/Mistral-7B-v0.1")')
    assert ("mistralai/Mistral-7B-v0.1", 1) in refs


def test_multi_line_source():
    source = """\
import transformers

# First model
tok = AutoTokenizer.from_pretrained("bert-base-uncased")
# Second model
model = AutoModel.from_pretrained("random-user/sketchy-model")
"""
    refs = _extract_model_refs(source)
    model_ids = [r[0] for r in refs]
    assert "bert-base-uncased" in model_ids
    assert "random-user/sketchy-model" in model_ids


# ---------------------------------------------------------------------------
# Integration tests: ModelScanner.scan_project
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_from_pretrained_detected(scanner: ModelScanner):
    """A .py file containing AutoModel.from_pretrained should produce a finding."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "train.py"
        src.write_text('model = AutoModel.from_pretrained("bert-base")\n')
        findings = await scanner.scan_project(Path(d))
        model_ids = [f.metadata.get("model_id") for f in findings]
        assert "bert-base" in model_ids


@pytest.mark.asyncio
async def test_pickle_model_file_high(scanner: ModelScanner):
    """>1 MB .bin file should produce a HIGH finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "pytorch_model.bin"
        model_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.HIGH
            and "pytorch_model.bin" in f.title
            for f in findings
        ), f"Expected HIGH for .bin file; got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_pkl_file_critical(scanner: ModelScanner):
    """>1 MB .pkl file should produce a CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        pkl_file = Path(d) / "weights.pkl"
        pkl_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.CRITICAL
            and "weights.pkl" in f.title
            for f in findings
        ), f"Expected CRITICAL for .pkl file; got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_pickle_extension_critical(scanner: ModelScanner):
    """>1 MB .pickle file should produce a CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        pkl_file = Path(d) / "embeddings.pickle"
        pkl_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.CRITICAL
            and "embeddings.pickle" in f.title
            for f in findings
        )


@pytest.mark.asyncio
async def test_safetensors_low(scanner: ModelScanner):
    """>1 MB .safetensors file should only produce LOW/informational findings."""
    with tempfile.TemporaryDirectory() as d:
        safe_file = Path(d) / "model.safetensors"
        safe_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        file_findings = [
            f for f in findings
            if "model.safetensors" in f.title
        ]
        assert file_findings, "Expected at least one finding for .safetensors file"
        assert all(
            f.severity in (Severity.LOW, Severity.INFO)
            for f in file_findings
        ), f"Expected only LOW/INFO for .safetensors; got: {[f.severity for f in file_findings]}"


@pytest.mark.asyncio
async def test_gguf_low(scanner: ModelScanner):
    """>1 MB .gguf file should produce only LOW findings."""
    with tempfile.TemporaryDirectory() as d:
        gguf_file = Path(d) / "llama.gguf"
        gguf_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        file_findings = [f for f in findings if "llama.gguf" in f.title]
        assert file_findings
        assert all(f.severity in (Severity.LOW, Severity.INFO) for f in file_findings)


@pytest.mark.asyncio
async def test_onnx_medium(scanner: ModelScanner):
    """>1 MB .onnx file should produce a MEDIUM finding."""
    with tempfile.TemporaryDirectory() as d:
        onnx_file = Path(d) / "model.onnx"
        onnx_file.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.MEDIUM
            and "model.onnx" in f.title
            for f in findings
        )


@pytest.mark.asyncio
async def test_small_bin_file_skipped(scanner: ModelScanner):
    """A .bin file under 1 MB should not be flagged (likely not model weights)."""
    with tempfile.TemporaryDirectory() as d:
        small_file = Path(d) / "config.bin"
        small_file.write_bytes(b"\x00" * 100)
        findings = await scanner.scan_project(Path(d))
        assert not any("config.bin" in f.title for f in findings)


@pytest.mark.asyncio
async def test_known_safe_org_reduced(scanner: ModelScanner):
    """A model from a known-safe org (meta-llama/…) should NOT produce a MEDIUM/HIGH finding."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "infer.py"
        src.write_text(
            'model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3-8B")\n'
        )
        findings = await scanner.scan_project(Path(d))
        risky = [
            f for f in findings
            if f.metadata.get("model_id") == "meta-llama/Llama-3-8B"
            and f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        ]
        assert not risky, (
            f"Expected no MEDIUM+ findings for meta-llama model; got: {[f.title for f in risky]}"
        )


@pytest.mark.asyncio
async def test_unknown_org_flagged(scanner: ModelScanner):
    """A model from an unknown org should produce a MEDIUM+ finding."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "infer.py"
        src.write_text(
            'model = AutoModel.from_pretrained("random-user/sketchy-model")\n'
        )
        findings = await scanner.scan_project(Path(d))
        risky = [
            f for f in findings
            if f.metadata.get("model_id") == "random-user/sketchy-model"
            and f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        ]
        assert risky, (
            "Expected at least one MEDIUM+ finding for unknown org 'random-user'"
        )


@pytest.mark.asyncio
async def test_no_models_clean(scanner: ModelScanner):
    """A project with no model refs and no weight files should return no findings."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "utils.py"
        src.write_text("def add(a, b):\n    return a + b\n")
        findings = await scanner.scan_project(Path(d))
        assert findings == [], f"Expected no findings; got: {findings}"


@pytest.mark.asyncio
async def test_pipeline_call_detected(scanner: ModelScanner):
    """pipeline() with a model= kwarg pointing to a suspicious org should be flagged."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "app.py"
        src.write_text(
            'pipe = pipeline("text-generation", model="suspicious/evil-llm")\n'
        )
        findings = await scanner.scan_project(Path(d))
        model_ids = [f.metadata.get("model_id") for f in findings]
        assert "suspicious/evil-llm" in model_ids, (
            f"Expected 'suspicious/evil-llm' in findings; got model_ids={model_ids}"
        )
        risky = [
            f for f in findings
            if f.metadata.get("model_id") == "suspicious/evil-llm"
            and f.severity >= Severity.MEDIUM
        ]
        assert risky


@pytest.mark.asyncio
async def test_pipeline_positional_model_detected(scanner: ModelScanner):
    """pipeline('task', 'model_id') positional syntax should also be detected."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "run.py"
        src.write_text('pipe = pipeline("fill-mask", "anon-hacker/poison-bert")\n')
        findings = await scanner.scan_project(Path(d))
        model_ids = [f.metadata.get("model_id") for f in findings]
        assert "anon-hacker/poison-bert" in model_ids


@pytest.mark.asyncio
async def test_venv_files_skipped(scanner: ModelScanner):
    """Model files inside .venv/ should not produce findings."""
    with tempfile.TemporaryDirectory() as d:
        venv_dir = Path(d) / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        fake_model = venv_dir / "pytorch_model.bin"
        fake_model.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        assert not any("pytorch_model.bin" in f.title for f in findings)


@pytest.mark.asyncio
async def test_metadata_fields_present(scanner: ModelScanner):
    """Findings from weight files should include expected metadata keys."""
    with tempfile.TemporaryDirectory() as d:
        pkl = Path(d) / "bad.pkl"
        pkl.write_bytes(b"\x00" * (1024 * 1024 + 100))
        findings = await scanner.scan_project(Path(d))
        pkl_finding = next(
            (f for f in findings if "bad.pkl" in f.title), None
        )
        assert pkl_finding is not None
        assert "format" in pkl_finding.metadata
        assert "source_file" in pkl_finding.metadata
        assert pkl_finding.finding_type == FindingType.BEHAVIORAL


@pytest.mark.asyncio
async def test_source_finding_metadata_fields(scanner: ModelScanner):
    """Findings from source scanning should include model_id, source_file, and line."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "train.py"
        src.write_text('model = AutoModel.from_pretrained("evil-corp/backdoored")\n')
        findings = await scanner.scan_project(Path(d))
        src_finding = next(
            (f for f in findings if f.metadata.get("model_id") == "evil-corp/backdoored"),
            None,
        )
        assert src_finding is not None
        assert src_finding.metadata["source_file"].endswith("train.py")
        assert src_finding.metadata["line"] == 1
