"""Tests for the AI BOM generator scanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.scanners.ai_bom_generator import AiBomGenerator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> AiBomGenerator:
    return AiBomGenerator()


# Minimal synthetic pickle bytes — just enough to be a real file, never unpickled.
_FAKE_PICKLE = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x01X\x94."


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bom_includes_pth_files(scanner: AiBomGenerator):
    """A .pth model file should appear in the BOM models list."""
    with tempfile.TemporaryDirectory() as d:
        pth = Path(d) / "model.pth"
        pth.write_bytes(_FAKE_PICKLE * 10)  # comfortably above 64-byte floor

        findings = await scanner.scan_project(Path(d))
        assert findings, "Expected at least one finding"

        bom_finding = findings[0]
        bom = bom_finding.metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "model.pth" in model_paths

        # Verify it is marked as pickle-based
        pth_record = [m for m in bom["models"] if m["path"] == "model.pth"][0]
        assert pth_record["is_pickle"] is True
        assert pth_record["format"] == "pytorch-checkpoint (pickle)"


@pytest.mark.asyncio
async def test_bom_includes_small_model(scanner: AiBomGenerator):
    """A 500-byte .pkl file should be included (not skipped by old 1 MB gate)."""
    with tempfile.TemporaryDirectory() as d:
        pkl = Path(d) / "weights.pkl"
        pkl.write_bytes(b"\x80\x04" + b"\x00" * 498)  # 500 bytes total

        findings = await scanner.scan_project(Path(d))
        assert findings, "Expected at least one finding"

        bom_finding = findings[0]
        bom = bom_finding.metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "weights.pkl" in model_paths


@pytest.mark.asyncio
async def test_bom_includes_ckpt_files(scanner: AiBomGenerator):
    """A .ckpt file should appear in the BOM models list."""
    with tempfile.TemporaryDirectory() as d:
        ckpt = Path(d) / "epoch_10.ckpt"
        ckpt.write_bytes(_FAKE_PICKLE * 10)

        findings = await scanner.scan_project(Path(d))
        bom = findings[0].metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "epoch_10.ckpt" in model_paths

        rec = [m for m in bom["models"] if m["path"] == "epoch_10.ckpt"][0]
        assert rec["is_pickle"] is True
        assert rec["format"] == "checkpoint (pickle)"


@pytest.mark.asyncio
async def test_bom_includes_joblib_files(scanner: AiBomGenerator):
    """A .joblib file should appear in the BOM models list."""
    with tempfile.TemporaryDirectory() as d:
        jl = Path(d) / "classifier.joblib"
        jl.write_bytes(_FAKE_PICKLE * 10)

        findings = await scanner.scan_project(Path(d))
        bom = findings[0].metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "classifier.joblib" in model_paths

        rec = [m for m in bom["models"] if m["path"] == "classifier.joblib"][0]
        assert rec["is_pickle"] is True
        assert rec["format"] == "joblib (pickle)"


@pytest.mark.asyncio
async def test_bom_includes_npy(scanner: AiBomGenerator):
    """A .npy file above 64 bytes should appear in the BOM models list."""
    with tempfile.TemporaryDirectory() as d:
        npy = Path(d) / "embeddings.npy"
        # Minimal valid .npy header (magic + version + header) padded to >64 bytes
        npy.write_bytes(b"\x93NUMPY\x01\x00" + b"\x00" * 120)

        findings = await scanner.scan_project(Path(d))
        assert findings, "Expected at least one finding"

        bom = findings[0].metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "embeddings.npy" in model_paths

        rec = [m for m in bom["models"] if m["path"] == "embeddings.npy"][0]
        assert rec["is_pickle"] is False
        assert rec["format"] == "numpy"


@pytest.mark.asyncio
async def test_bom_includes_npz(scanner: AiBomGenerator):
    """A .npz file above 64 bytes should appear in the BOM models list."""
    with tempfile.TemporaryDirectory() as d:
        npz = Path(d) / "weights.npz"
        # .npz is a ZIP archive of .npy files; any bytes above threshold suffice
        npz.write_bytes(b"PK\x03\x04" + b"\x00" * 120)

        findings = await scanner.scan_project(Path(d))
        assert findings, "Expected at least one finding"

        bom = findings[0].metadata["ai_bom"]
        model_paths = [m["path"] for m in bom["models"]]
        assert "weights.npz" in model_paths

        rec = [m for m in bom["models"] if m["path"] == "weights.npz"][0]
        assert rec["is_pickle"] is False
        assert rec["format"] == "numpy-archive"


@pytest.mark.asyncio
async def test_bom_skips_tiny_files(scanner: AiBomGenerator):
    """Files below 64 bytes should still be skipped."""
    with tempfile.TemporaryDirectory() as d:
        tiny = Path(d) / "stub.pkl"
        tiny.write_bytes(b"\x80\x04")  # 2 bytes — below threshold

        findings = await scanner.scan_project(Path(d))
        bom_findings = [f for f in findings if f.metadata.get("ai_bom")]
        if bom_findings:
            assert len(bom_findings[0].metadata["ai_bom"]["models"]) == 0
        else:
            assert findings == []
