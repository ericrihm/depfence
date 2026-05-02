"""Tests for the model weight integrity scanner."""

from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.model_integrity import ModelIntegrityScanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> ModelIntegrityScanner:
    return ModelIntegrityScanner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_safetensors(header_json: dict) -> bytes:
    """Build a minimal valid SafeTensors byte blob from a header dict."""
    json_bytes = json.dumps(header_json).encode("utf-8")
    size_field = struct.pack("<Q", len(json_bytes))
    return size_field + json_bytes


# ---------------------------------------------------------------------------
# 1. Pickle opcode detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pickle_dangerous_opcodes(scanner: ModelIntegrityScanner):
    """A .bin file containing the REDUCE opcode (0x52) should get a CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "pytorch_model.bin"
        # Build a >1 MB file with a REDUCE opcode embedded
        payload = b"\x80\x02"          # pickle PROTO 2 header
        payload += b"\x00" * (1024 * 1024)  # padding to exceed 1 MB
        payload += b"\x52"             # REDUCE opcode
        model_file.write_bytes(payload)

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and "pytorch_model.bin" in f.title
            and f.finding_type == FindingType.MALICIOUS
        ]
        assert critical, (
            f"Expected CRITICAL finding for REDUCE opcode; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_pickle_global_opcode(scanner: ModelIntegrityScanner):
    """GLOBAL opcode (0x63) in a .pkl file should trigger a CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "weights.pkl"
        payload = b"\x00" * (1024 * 1024) + b"\x63"
        model_file.write_bytes(payload)

        findings = await scanner.scan_project(Path(d))
        assert any(
            f.severity == Severity.CRITICAL and "weights.pkl" in f.title
            for f in findings
        )


@pytest.mark.asyncio
async def test_pickle_clean_file_no_opcode_finding(scanner: ModelIntegrityScanner):
    """A .bin file with no dangerous opcodes should not get a pickle CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "pytorch_model.bin"
        # Use only safe bytes (avoid 0x52, 0x63, 0x69, 0x81)
        safe_byte = b"\x00"
        model_file.write_bytes(safe_byte * (2 * 1024 * 1024))

        findings = await scanner.scan_project(Path(d))
        pickle_critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and "pytorch_model.bin" in f.title
            and f.finding_type == FindingType.MALICIOUS
        ]
        assert not pickle_critical, (
            f"No CRITICAL pickle findings expected; got: {pickle_critical}"
        )


# ---------------------------------------------------------------------------
# 2. SafeTensors header validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safetensors_valid(scanner: ModelIntegrityScanner):
    """A .safetensors file with a valid header should produce no header-error finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "model.safetensors"
        # Valid minimal header: empty metadata dict
        header_json = {"__metadata__": {}}
        content = _make_safetensors(header_json)
        model_file.write_bytes(content)

        findings = await scanner.scan_project(Path(d))
        header_errors = [
            f for f in findings
            if "Invalid SafeTensors header" in f.title
        ]
        assert not header_errors, (
            f"Expected no header-error finding for valid safetensors; got: {header_errors}"
        )


@pytest.mark.asyncio
async def test_safetensors_invalid_header_truncated(scanner: ModelIntegrityScanner):
    """A .safetensors file that is only 3 bytes should get a HIGH finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "model.safetensors"
        model_file.write_bytes(b"\x00\x01\x02")  # Too short for an 8-byte header

        findings = await scanner.scan_project(Path(d))
        header_findings = [
            f for f in findings
            if "Invalid SafeTensors header" in f.title
            and f.severity == Severity.HIGH
        ]
        assert header_findings, (
            f"Expected HIGH finding for truncated safetensors; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_safetensors_invalid_header_bad_json(scanner: ModelIntegrityScanner):
    """A .safetensors file whose JSON header is garbage should be flagged."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "corrupt.safetensors"
        json_garbage = b"not-json!!!"
        header = struct.pack("<Q", len(json_garbage)) + json_garbage
        model_file.write_bytes(header)

        findings = await scanner.scan_project(Path(d))
        assert any(
            "Invalid SafeTensors header" in f.title and f.severity == Severity.HIGH
            for f in findings
        ), f"Expected HIGH for bad JSON header; got: {[f.title for f in findings]}"


@pytest.mark.asyncio
async def test_safetensors_invalid_header_zero_size(scanner: ModelIntegrityScanner):
    """A .safetensors file with header_size=0 should be flagged."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "zero.safetensors"
        # 8 zero bytes = header_size of 0
        model_file.write_bytes(b"\x00" * 8)

        findings = await scanner.scan_project(Path(d))
        assert any(
            "Invalid SafeTensors header" in f.title
            for f in findings
        ), f"Expected finding for zero header_size; got: {[f.title for f in findings]}"


# ---------------------------------------------------------------------------
# 3. Checksum verification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_checksum_match_no_mismatch_finding(scanner: ModelIntegrityScanner):
    """When sha256 in config.json matches the file, no mismatch finding is raised."""
    import hashlib
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "model.bin"
        content = b"\xAB" * (2 * 1024 * 1024)
        model_file.write_bytes(content)

        # Write config with correct hash
        correct_hash = hashlib.sha256(content).hexdigest()
        config = {"sha256": {"model.bin": correct_hash}}
        (Path(d) / "config.json").write_text(json.dumps(config))

        findings = await scanner.scan_project(Path(d))
        mismatch = [f for f in findings if "mismatch" in f.title.lower()]
        assert not mismatch, f"Expected no mismatch finding; got: {mismatch}"


@pytest.mark.asyncio
async def test_checksum_mismatch_critical(scanner: ModelIntegrityScanner):
    """When sha256 in config.json does not match the file, a CRITICAL finding is raised."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "model.bin"
        model_file.write_bytes(b"\xBB" * (2 * 1024 * 1024))

        # Deliberately wrong hash
        wrong_hash = "a" * 64
        config = {"sha256": {"model.bin": wrong_hash}}
        (Path(d) / "config.json").write_text(json.dumps(config))

        findings = await scanner.scan_project(Path(d))
        mismatch = [
            f for f in findings
            if "mismatch" in f.title.lower() and f.severity == Severity.CRITICAL
        ]
        assert mismatch, (
            f"Expected CRITICAL checksum mismatch finding; got: {[f.title for f in findings]}"
        )


# ---------------------------------------------------------------------------
# 4. Unsigned models (no integrity metadata)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unsigned_model_flagged(scanner: ModelIntegrityScanner):
    """A model file with no sha256 in any config should get a MEDIUM PROVENANCE finding."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "model.bin"
        model_file.write_bytes(b"\x00" * (2 * 1024 * 1024))
        # No config.json with sha256

        findings = await scanner.scan_project(Path(d))
        unsigned = [
            f for f in findings
            if f.finding_type == FindingType.PROVENANCE
            and f.severity == Severity.MEDIUM
            and "model.bin" in f.title
        ]
        assert unsigned, (
            f"Expected MEDIUM PROVENANCE finding for unsigned model; got: {[f.title for f in findings]}"
        )


# ---------------------------------------------------------------------------
# 5. Size anomaly detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_small_model_anomaly(scanner: ModelIntegrityScanner):
    """A file whose path claims 7B architecture but is only 1 KB should be flagged HIGH."""
    with tempfile.TemporaryDirectory() as d:
        model_dir = Path(d) / "llama-7b"
        model_dir.mkdir()
        # 1 KB — impossibly small for a 7B shard
        tiny_model = model_dir / "pytorch_model.bin"
        tiny_model.write_bytes(b"\x00" * 1024)

        findings = await scanner.scan_project(Path(d))
        size_findings = [
            f for f in findings
            if "Suspicious size" in f.title and f.severity == Severity.HIGH
        ]
        assert size_findings, (
            f"Expected HIGH size anomaly finding; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_large_7b_model_no_size_anomaly(scanner: ModelIntegrityScanner):
    """A file that meets the minimum size threshold for its architecture is not flagged."""
    with tempfile.TemporaryDirectory() as d:
        model_dir = Path(d) / "llama-1b"
        model_dir.mkdir()
        # 60 MB — above the 50 MB threshold for 1B
        ok_model = model_dir / "pytorch_model.bin"
        ok_model.write_bytes(b"\x00" * (60 * 1024 * 1024))

        findings = await scanner.scan_project(Path(d))
        size_findings = [f for f in findings if "Suspicious size" in f.title]
        assert not size_findings, (
            f"Expected no size anomaly for 60 MB 1B model; got: {size_findings}"
        )


# ---------------------------------------------------------------------------
# 6. Clean directory (no model files)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clean_directory(scanner: ModelIntegrityScanner):
    """A directory with no model files should produce no findings at all."""
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "train.py"
        src.write_text("import torch\n\nmodel = torch.nn.Linear(10, 1)\n")
        (Path(d) / "README.md").write_text("# My Model\n")

        findings = await scanner.scan_project(Path(d))
        assert findings == [], f"Expected zero findings; got: {findings}"


# ---------------------------------------------------------------------------
# 7. Skip virtualenv / hidden directories
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_venv_files_skipped(scanner: ModelIntegrityScanner):
    """Model files inside .venv/ should not produce any findings."""
    with tempfile.TemporaryDirectory() as d:
        venv_dir = Path(d) / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        fake_model = venv_dir / "pytorch_model.bin"
        # Include a dangerous opcode so it would fire if not skipped
        fake_model.write_bytes(b"\x52" * (2 * 1024 * 1024))

        findings = await scanner.scan_project(Path(d))
        assert not findings, f"Expected no findings for files in .venv/; got: {findings}"


# ---------------------------------------------------------------------------
# 8. Metadata fields present
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_finding_metadata_fields(scanner: ModelIntegrityScanner):
    """Findings should carry the standard metadata keys."""
    with tempfile.TemporaryDirectory() as d:
        model_file = Path(d) / "weights.pkl"
        model_file.write_bytes(b"\x52" * (2 * 1024 * 1024))

        findings = await scanner.scan_project(Path(d))
        pkl_finding = next(
            (f for f in findings if "weights.pkl" in f.title and f.severity == Severity.CRITICAL),
            None,
        )
        assert pkl_finding is not None
        assert "source_file" in pkl_finding.metadata
        assert "format" in pkl_finding.metadata
        assert "file_size_bytes" in pkl_finding.metadata
        assert pkl_finding.finding_type == FindingType.MALICIOUS
