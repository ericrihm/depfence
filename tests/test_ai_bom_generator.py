"""Tests for the AI BOM generator scanner."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.scan_scope import PartialScanError
from depfence.scanners import ai_bom_generator as ai_bom_module
from depfence.scanners.ai_bom_generator import AiBomGenerator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> AiBomGenerator:
    return AiBomGenerator()


@pytest.mark.asyncio
async def test_host_global_mcp_inventory_requires_opt_in_and_is_redacted(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    global_config = tmp_path / "private-home" / "mcp.json"
    global_config.parent.mkdir()
    private_arg = "--token=host-private-marker"
    global_config.write_text(json.dumps({"mcpServers": {"private": {
        "command": "/private/bin/server", "args": [private_arg]
    }}}))
    monkeypatch.setattr(ai_bom_module, "_mcp_config_locations", lambda: [global_config])

    default_findings = await AiBomGenerator().scan_project(project)
    opted_in = await AiBomGenerator(include_global=True).scan_project(project)

    assert default_findings == []
    bom = opted_in[0].metadata["ai_bom"]
    record = bom["mcp_servers"][0]
    assert record["command"] == "server"
    assert record["arg_count"] == 1
    assert "args" not in record
    assert private_arg not in str(bom)
    assert str(global_config) not in str(bom)
    assert record["config_source"] == "global:mcp.json"


@pytest.mark.asyncio
async def test_malformed_candidate_preserves_partial_bom_findings(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "shell": {"command": "bash", "args": ["-c", "synthetic-private-arg"]}
    }}))
    (tmp_path / "package.json").write_text("{")

    with pytest.raises(PartialScanError) as raised:
        await AiBomGenerator().scan_project(tmp_path)

    assert "package.json" in str(raised.value)
    assert raised.value.findings
    assert "synthetic-private-arg" not in str(raised.value.findings)


@pytest.mark.asyncio
async def test_symlinked_candidate_is_incomplete(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside-mcp.json"
    outside.write_text('{"mcpServers":{}}')
    (tmp_path / ".mcp.json").symlink_to(outside)

    with pytest.raises(PartialScanError, match="symlink"):
        await AiBomGenerator().scan_project(tmp_path)


@pytest.mark.asyncio
async def test_malformed_global_config_only_matters_when_opted_in(tmp_path, monkeypatch):
    global_config = tmp_path.parent / f"{tmp_path.name}-global-mcp.json"
    global_config.write_text("{")
    monkeypatch.setattr(ai_bom_module, "_mcp_config_locations", lambda: [global_config])

    assert await AiBomGenerator().scan_project(tmp_path) == []
    with pytest.raises(PartialScanError, match="global:.*malformed"):
        await AiBomGenerator(include_global=True).scan_project(tmp_path)


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
