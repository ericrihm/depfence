"""Tests for the multi-format AI model file scanner (TFLite, HDF5, ONNX, GGUF)."""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.model_format_scanner import (
    ModelFormatScanner,
    _extract_tflite_custom_ops,
    _extract_onnx_custom_ops,
    _parse_protobuf_strings,
    _scan_gguf,
    _scan_hdf5,
    _scan_onnx,
    _scan_tflite,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> ModelFormatScanner:
    return ModelFormatScanner()


# ---------------------------------------------------------------------------
# Helpers — TFLite
# ---------------------------------------------------------------------------

def _build_tflite_with_ops(op_names: list[str]) -> bytes:
    """Build a minimal synthetic TFLite-like FlatBuffer with operator names.

    This builds a binary that:
    - Has a valid FlatBuffer root offset at byte 0
    - Has the 'TFL3' file identifier at bytes 4-7
    - Embeds operator names as FlatBuffer strings (uint32 LE length + data)
    """
    buf = bytearray()
    # FlatBuffer root table offset (placeholder — points past header)
    buf += struct.pack('<I', 16)
    # File identifier 'TFL3'
    buf += b'TFL3'
    # Padding to offset 16 (root table location)
    buf += b'\x00' * 8

    # Embed operator names as FlatBuffer-style strings
    for name in op_names:
        name_bytes = name.encode('ascii')
        buf += struct.pack('<I', len(name_bytes))
        buf += name_bytes
        # Align to 4 bytes
        padding = (4 - len(name_bytes) % 4) % 4
        buf += b'\x00' * padding

    return bytes(buf)


# ---------------------------------------------------------------------------
# Helpers — HDF5
# ---------------------------------------------------------------------------

_HDF5_MAGIC = b'\x89HDF\r\n\x1a\n'


def _build_hdf5_with_content(extra_content: bytes) -> bytes:
    """Build a minimal HDF5-like binary with embedded content."""
    buf = bytearray()
    buf += _HDF5_MAGIC
    # Minimal HDF5 superblock fields (enough to pass magic check)
    buf += b'\x00' * 56  # Superblock padding
    # Embed the extra content
    buf += extra_content
    return bytes(buf)


def _build_dangerous_pickle() -> bytes:
    """Build a minimal pickle2 stream with GLOBAL 'os.system' + REDUCE."""
    payload = bytearray()
    payload += b'\x80\x02'              # PROTO 2
    payload += b'\x63os\nsystem\n'      # GLOBAL
    payload += b'\x29'                  # EMPTY_TUPLE
    payload += b'\x52'                  # REDUCE
    payload += b'\x2e'                  # STOP
    return bytes(payload)


# ---------------------------------------------------------------------------
# Helpers — ONNX
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _encode_protobuf_field(field_number: int, wire_type: int, data: bytes) -> bytes:
    """Encode a protobuf field with tag + data."""
    tag = (field_number << 3) | wire_type
    return _encode_varint(tag) + data


def _encode_protobuf_string(field_number: int, value: str) -> bytes:
    """Encode a string field in protobuf format."""
    encoded = value.encode('utf-8')
    return _encode_protobuf_field(
        field_number, 2,  # wire type 2 = length-delimited
        _encode_varint(len(encoded)) + encoded
    )


def _encode_protobuf_varint_field(field_number: int, value: int) -> bytes:
    """Encode a varint field."""
    return _encode_protobuf_field(field_number, 0, _encode_varint(value))


def _build_onnx_model(domains: list[str] | None = None,
                      custom_nodes: list[tuple[str, str]] | None = None) -> bytes:
    """Build a minimal ONNX-like protobuf binary.

    ONNX ModelProto:
      field 1 (ir_version): int64
      field 8 (opset_import): repeated OperatorSetIdProto
        - field 1 (domain): string
        - field 2 (version): int64
      field 7 (graph): GraphProto
        - field 1 (node): repeated NodeProto
          - field 4 (op_type): string
          - field 7 (domain): string
    """
    buf = bytearray()

    # Field 1: ir_version = 9
    buf += _encode_protobuf_varint_field(1, 9)

    # Field 8: opset_import entries
    domains = domains or ['']
    for domain in domains:
        opset_msg = bytearray()
        if domain:
            opset_msg += _encode_protobuf_string(1, domain)
        opset_msg += _encode_protobuf_varint_field(2, 13)  # version
        buf += _encode_protobuf_field(8, 2,
                                      _encode_varint(len(opset_msg)) + bytes(opset_msg))

    # Field 7: graph with nodes
    graph_buf = bytearray()
    if custom_nodes:
        for op_type, domain in custom_nodes:
            node_msg = bytearray()
            node_msg += _encode_protobuf_string(4, op_type)
            if domain:
                node_msg += _encode_protobuf_string(7, domain)
            graph_buf += _encode_protobuf_field(1, 2,
                                                _encode_varint(len(node_msg)) + bytes(node_msg))

    if graph_buf:
        buf += _encode_protobuf_field(7, 2,
                                      _encode_varint(len(graph_buf)) + bytes(graph_buf))

    return bytes(buf)


# ---------------------------------------------------------------------------
# 1. TFLite — Custom Operator Detection
# ---------------------------------------------------------------------------

def test_extract_tflite_custom_ops_flex():
    """Flex operators are extracted from TFLite binary."""
    data = _build_tflite_with_ops(['FlexWriteFile', 'FlexReadFile', 'Conv2D'])
    ops = _extract_tflite_custom_ops(data)
    assert 'FlexWriteFile' in ops
    assert 'FlexReadFile' in ops
    # Conv2D is a built-in, not Flex — should not appear
    assert 'Conv2D' not in ops


def test_extract_tflite_custom_ops_eagerpyfunc():
    """EagerPyFunc is extracted from TFLite binary."""
    data = _build_tflite_with_ops(['EagerPyFunc'])
    ops = _extract_tflite_custom_ops(data)
    assert 'EagerPyFunc' in ops


def test_extract_tflite_custom_ops_clean():
    """A TFLite binary with no custom ops returns empty list."""
    data = _build_tflite_with_ops([])
    ops = _extract_tflite_custom_ops(data)
    assert ops == []


@pytest.mark.asyncio
async def test_tflite_dangerous_ops(scanner: ModelFormatScanner):
    """TFLite file with FlexWriteFile produces CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.tflite'
        path.write_bytes(_build_tflite_with_ops(['FlexWriteFile', 'FlexReadFile']))

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and 'model.tflite' in f.title
            and f.finding_type == FindingType.MALICIOUS
        ]
        assert critical, (
            f"Expected CRITICAL finding for FlexWriteFile; got: {[f.title for f in findings]}"
        )
        assert 'FlexWriteFile' in critical[0].detail


@pytest.mark.asyncio
async def test_tflite_flex_ops_high(scanner: ModelFormatScanner):
    """TFLite file with generic Flex ops produces HIGH finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.tflite'
        # Use a Flex op that is NOT in the dangerous list
        path.write_bytes(_build_tflite_with_ops(['FlexMatMul']))

        findings = await scanner.scan_project(Path(d))
        high = [
            f for f in findings
            if f.severity == Severity.HIGH
            and 'model.tflite' in f.title
            and 'Flex' in f.title
        ]
        assert high, (
            f"Expected HIGH finding for FlexMatMul; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_tflite_eagerpyfunc(scanner: ModelFormatScanner):
    """TFLite file with EagerPyFunc produces CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.tflite'
        path.write_bytes(_build_tflite_with_ops(['EagerPyFunc']))

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and 'model.tflite' in f.title
        ]
        assert critical, (
            f"Expected CRITICAL finding for EagerPyFunc; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_tflite_clean_no_finding(scanner: ModelFormatScanner):
    """TFLite file with no custom ops produces no MALICIOUS finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.tflite'
        # Build a TFLite file with just the header, no operator strings
        buf = bytearray()
        buf += struct.pack('<I', 16)
        buf += b'TFL3'
        buf += b'\x00' * 200
        path.write_bytes(bytes(buf))

        findings = await scanner.scan_project(Path(d))
        malicious = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'clean.tflite' in f.title
        ]
        assert not malicious, (
            f"Expected no MALICIOUS findings for clean TFLite; got: {malicious}"
        )


@pytest.mark.asyncio
async def test_tflite_not_tflite(scanner: ModelFormatScanner):
    """A .tflite file without TFL3 identifier produces no finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.tflite'
        path.write_bytes(b'\x00' * 200)

        findings = await scanner.scan_project(Path(d))
        assert not any('fake.tflite' in f.title for f in findings), (
            f"Expected no findings for non-TFLite file; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_tflite_truncated(scanner: ModelFormatScanner):
    """A truncated .tflite file does not crash."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'trunc.tflite'
        path.write_bytes(b'\x00\x00\x00\x00TFL3')  # Just header, truncated

        findings = await scanner.scan_project(Path(d))
        # Should not crash — may or may not produce findings
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# 2. HDF5/H5 — Pickle and Lambda Detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hdf5_pickle_payload(scanner: ModelFormatScanner):
    """HDF5 file with embedded pickle payload produces CRITICAL finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.h5'
        pickle_data = _build_dangerous_pickle()
        path.write_bytes(_build_hdf5_with_content(pickle_data))

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and 'model.h5' in f.title
            and f.finding_type == FindingType.MALICIOUS
        ]
        assert critical, (
            f"Expected CRITICAL finding for pickle in HDF5; got: {[f.title for f in findings]}"
        )
        assert 'pickle' in critical[0].title.lower() or 'Pickle' in critical[0].title


@pytest.mark.asyncio
async def test_hdf5_lambda_layer(scanner: ModelFormatScanner):
    """HDF5 file with Lambda layer produces finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.h5'
        lambda_json = b'{"class_name": "Lambda", "config": {"function": "lambda x: x * 2"}}'
        path.write_bytes(_build_hdf5_with_content(lambda_json))

        findings = await scanner.scan_project(Path(d))
        lambda_findings = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'model.h5' in f.title
            and any('Lambda' in p for p in f.metadata.get('dangerous_patterns', []))
        ]
        assert lambda_findings, (
            f"Expected finding for Lambda layer; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_hdf5_reduce_pattern(scanner: ModelFormatScanner):
    """HDF5 file with __reduce__ pattern produces finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.h5'
        content = b'\x00' * 100 + b'__reduce__' + b'\x00' * 100
        path.write_bytes(_build_hdf5_with_content(content))

        findings = await scanner.scan_project(Path(d))
        reduce_findings = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'model.h5' in f.title
        ]
        assert reduce_findings, (
            f"Expected finding for __reduce__; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_hdf5_clean_no_finding(scanner: ModelFormatScanner):
    """Clean HDF5 file produces no MALICIOUS finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.h5'
        # Just the magic + zeros (no pickle, no Lambda)
        path.write_bytes(_build_hdf5_with_content(b'\x00' * 1000))

        findings = await scanner.scan_project(Path(d))
        malicious = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'clean.h5' in f.title
        ]
        assert not malicious, (
            f"Expected no MALICIOUS findings for clean HDF5; got: {malicious}"
        )


@pytest.mark.asyncio
async def test_hdf5_not_hdf5(scanner: ModelFormatScanner):
    """A .h5 file without HDF5 magic produces no finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.h5'
        path.write_bytes(b'\x00' * 200)

        findings = await scanner.scan_project(Path(d))
        assert not any('fake.h5' in f.title for f in findings)


@pytest.mark.asyncio
async def test_hdf5_keras_extension(scanner: ModelFormatScanner):
    """A .keras file with HDF5 magic and Lambda is scanned."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.keras'
        lambda_json = b'{"class_name": "Lambda", "config": {}}'
        path.write_bytes(_build_hdf5_with_content(lambda_json))

        findings = await scanner.scan_project(Path(d))
        lambda_findings = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'model.keras' in f.title
        ]
        assert lambda_findings, (
            f"Expected finding for .keras with Lambda; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_hdf5_hdf5_extension(scanner: ModelFormatScanner):
    """A .hdf5 file is also scanned."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'weights.hdf5'
        pickle_data = _build_dangerous_pickle()
        path.write_bytes(_build_hdf5_with_content(pickle_data))

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and 'weights.hdf5' in f.title
        ]
        assert critical, (
            f"Expected CRITICAL finding for .hdf5 with pickle; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_hdf5_subprocess_pattern(scanner: ModelFormatScanner):
    """HDF5 with subprocess.Popen string produces finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.h5'
        content = b'\x00' * 50 + b'subprocess\nPopen' + b'\x00' * 50
        path.write_bytes(_build_hdf5_with_content(content))

        findings = await scanner.scan_project(Path(d))
        sub_findings = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'model.h5' in f.title
        ]
        assert sub_findings, (
            f"Expected finding for subprocess.Popen; got: {[f.title for f in findings]}"
        )


# ---------------------------------------------------------------------------
# 3. ONNX — Custom Operator Detection
# ---------------------------------------------------------------------------

def test_parse_protobuf_strings():
    """_parse_protobuf_strings extracts string fields from protobuf data."""
    # Build a simple protobuf with field 1 = varint 9, field 2 = string "hello"
    data = bytearray()
    data += b'\x08\x09'  # field 1, wire type 0, value 9
    data += b'\x12\x05hello'  # field 2, wire type 2, len 5, "hello"
    fields = _parse_protobuf_strings(bytes(data))
    assert 'hello' in fields.get(2, [])


def test_parse_protobuf_strings_empty():
    """Empty data returns empty dict."""
    assert _parse_protobuf_strings(b'') == {}


def test_parse_protobuf_strings_malformed():
    """Malformed data does not crash."""
    result = _parse_protobuf_strings(b'\xff\xff\xff')
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_onnx_custom_domain(scanner: ModelFormatScanner):
    """ONNX model with custom domain produces HIGH finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.onnx'
        onnx_data = _build_onnx_model(
            domains=['', 'com.evil.custom'],
            custom_nodes=[('MaliciousOp', 'com.evil.custom')]
        )
        path.write_bytes(onnx_data)

        findings = await scanner.scan_project(Path(d))
        high = [
            f for f in findings
            if f.severity == Severity.HIGH
            and 'model.onnx' in f.title
            and f.finding_type == FindingType.MALICIOUS
        ]
        assert high, (
            f"Expected HIGH finding for custom ONNX domain; got: {[f.title for f in findings]}"
        )
        assert 'com.evil.custom' in high[0].detail


@pytest.mark.asyncio
async def test_onnx_standard_domains_clean(scanner: ModelFormatScanner):
    """ONNX model with only standard domains produces no finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.onnx'
        onnx_data = _build_onnx_model(domains=['', 'ai.onnx.ml'])
        path.write_bytes(onnx_data)

        findings = await scanner.scan_project(Path(d))
        malicious = [
            f for f in findings
            if f.finding_type == FindingType.MALICIOUS
            and 'clean.onnx' in f.title
        ]
        assert not malicious, (
            f"Expected no MALICIOUS findings for standard ONNX; got: {malicious}"
        )


@pytest.mark.asyncio
async def test_onnx_not_protobuf(scanner: ModelFormatScanner):
    """A .onnx file that doesn't start with protobuf tag produces no finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.onnx'
        path.write_bytes(b'\x00' * 200)

        findings = await scanner.scan_project(Path(d))
        assert not any('fake.onnx' in f.title for f in findings)


@pytest.mark.asyncio
async def test_onnx_truncated(scanner: ModelFormatScanner):
    """Truncated .onnx file does not crash."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'trunc.onnx'
        path.write_bytes(b'\x08\x09')  # Just ir_version field, truncated

        findings = await scanner.scan_project(Path(d))
        assert isinstance(findings, list)


def test_extract_onnx_custom_ops_with_domain():
    """_extract_onnx_custom_ops detects non-standard domains."""
    data = _build_onnx_model(
        domains=['', 'com.custom.ops'],
        custom_nodes=[('CustomConv', 'com.custom.ops')]
    )
    custom_domains, custom_nodes = _extract_onnx_custom_ops(data)
    assert 'com.custom.ops' in custom_domains


def test_extract_onnx_custom_ops_standard_only():
    """_extract_onnx_custom_ops returns empty for standard domains."""
    data = _build_onnx_model(domains=[''])
    custom_domains, _ = _extract_onnx_custom_ops(data)
    assert custom_domains == []


# ---------------------------------------------------------------------------
# 4. Integration — scan_project
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_project_empty_dir(scanner: ModelFormatScanner):
    """Empty directory produces no findings."""
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_scan_project_skips_venv(scanner: ModelFormatScanner):
    """Model files inside .venv are skipped."""
    with tempfile.TemporaryDirectory() as d:
        venv_dir = Path(d) / '.venv' / 'lib'
        venv_dir.mkdir(parents=True)
        path = venv_dir / 'model.tflite'
        path.write_bytes(_build_tflite_with_ops(['FlexWriteFile']))

        findings = await scanner.scan_project(Path(d))
        assert not findings, (
            f"Expected no findings in .venv; got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_scan_project_tiny_file_skipped(scanner: ModelFormatScanner):
    """Files smaller than 8 bytes are skipped."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'tiny.h5'
        path.write_bytes(b'\x00' * 4)

        findings = await scanner.scan_project(Path(d))
        assert not findings


@pytest.mark.asyncio
async def test_scan_project_multiple_formats(scanner: ModelFormatScanner):
    """scan_project handles mixed format files."""
    with tempfile.TemporaryDirectory() as d:
        # TFLite with dangerous op
        tflite_path = Path(d) / 'model.tflite'
        tflite_path.write_bytes(_build_tflite_with_ops(['EagerPyFunc']))

        # HDF5 with pickle
        h5_path = Path(d) / 'model.h5'
        h5_path.write_bytes(_build_hdf5_with_content(_build_dangerous_pickle()))

        findings = await scanner.scan_project(Path(d))
        tflite_findings = [f for f in findings if 'model.tflite' in f.title]
        h5_findings = [f for f in findings if 'model.h5' in f.title]

        assert tflite_findings, "Expected findings for TFLite"
        assert h5_findings, "Expected findings for HDF5"


# ---------------------------------------------------------------------------
# 5. Unit test — _scan_tflite directly
# ---------------------------------------------------------------------------

def test_scan_tflite_direct_dangerous():
    """_scan_tflite returns findings for dangerous ops."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'test.tflite'
        path.write_bytes(_build_tflite_with_ops(['FlexWriteFile']))
        findings = _scan_tflite(path)
        assert len(findings) > 0
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_scan_tflite_direct_clean():
    """_scan_tflite returns no findings for clean file."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.tflite'
        buf = struct.pack('<I', 16) + b'TFL3' + b'\x00' * 200
        path.write_bytes(buf)
        findings = _scan_tflite(path)
        assert findings == []


# ---------------------------------------------------------------------------
# 6. Unit test — _scan_hdf5 directly
# ---------------------------------------------------------------------------

def test_scan_hdf5_direct_pickle():
    """_scan_hdf5 detects pickle payloads."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'test.h5'
        path.write_bytes(_build_hdf5_with_content(_build_dangerous_pickle()))
        findings = _scan_hdf5(path)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_scan_hdf5_direct_clean():
    """_scan_hdf5 returns nothing for clean file."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.h5'
        path.write_bytes(_build_hdf5_with_content(b'\x00' * 500))
        findings = _scan_hdf5(path)
        assert findings == []


def test_scan_hdf5_not_hdf5():
    """_scan_hdf5 returns nothing for non-HDF5 file."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.h5'
        path.write_bytes(b'not an hdf5 file')
        findings = _scan_hdf5(path)
        assert findings == []


# ---------------------------------------------------------------------------
# 7. Unit test — _scan_onnx directly
# ---------------------------------------------------------------------------

def test_scan_onnx_direct_custom_domain():
    """_scan_onnx detects custom domains."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'test.onnx'
        path.write_bytes(_build_onnx_model(
            domains=['', 'org.evil.backdoor'],
            custom_nodes=[('BackdoorOp', 'org.evil.backdoor')]
        ))
        findings = _scan_onnx(path)
        assert any(f.severity == Severity.HIGH for f in findings)


def test_scan_onnx_direct_clean():
    """_scan_onnx returns nothing for standard-only model."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.onnx'
        path.write_bytes(_build_onnx_model(domains=['']))
        findings = _scan_onnx(path)
        assert findings == []


def test_scan_onnx_not_protobuf():
    """_scan_onnx returns nothing for non-protobuf file."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.onnx'
        path.write_bytes(b'\xff' * 200)
        findings = _scan_onnx(path)
        assert findings == []


# ---------------------------------------------------------------------------
# 8. Edge cases — graceful handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nonexistent_file_no_crash(scanner: ModelFormatScanner):
    """Scanner handles missing files gracefully."""
    with tempfile.TemporaryDirectory() as d:
        # Dir exists but no model files
        findings = await scanner.scan_project(Path(d))
        assert findings == []


@pytest.mark.asyncio
async def test_hdf5_multiple_pickle_regions(scanner: ModelFormatScanner):
    """HDF5 with multiple pickle regions reports all threats."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'multi.h5'
        pickle1 = _build_dangerous_pickle()
        # Second pickle region with different global
        pickle2 = bytearray()
        pickle2 += b'\x80\x02'
        pickle2 += b'\x63subprocess\nPopen\n'
        pickle2 += b'\x29'
        pickle2 += b'\x52'
        pickle2 += b'\x2e'

        content = pickle1 + b'\x00' * 500 + bytes(pickle2)
        path.write_bytes(_build_hdf5_with_content(content))

        findings = await scanner.scan_project(Path(d))
        critical = [
            f for f in findings
            if f.severity == Severity.CRITICAL
            and 'multi.h5' in f.title
        ]
        assert critical, "Expected findings for multiple pickle regions"
        # Should report multiple dangerous ops
        ops = critical[0].metadata.get('dangerous_ops', [])
        assert len(ops) >= 2, f"Expected multiple ops; got {len(ops)}"


@pytest.mark.asyncio
async def test_standard_scan_interface(scanner: ModelFormatScanner):
    """The standard scan() interface returns empty list."""
    result = await scanner.scan([])
    assert result == []


def test_scanner_attributes():
    """Scanner has expected name and ecosystems."""
    s = ModelFormatScanner()
    assert s.name == 'model_format'
    assert 'tflite' in s.ecosystems
    assert 'keras' in s.ecosystems
    assert 'onnx' in s.ecosystems
    assert 'gguf' in s.ecosystems


# ---------------------------------------------------------------------------
# Helpers — GGUF
# ---------------------------------------------------------------------------

def _gguf_string(s: str) -> bytes:
    """Encode a gguf_string_t: uint64 LE length + UTF-8 bytes (no null)."""
    encoded = s.encode('utf-8')
    return struct.pack('<Q', len(encoded)) + encoded


def _gguf_kv(key: str, value_type: int, value_bytes: bytes) -> bytes:
    """Encode one gguf_metadata_kv_t entry."""
    return _gguf_string(key) + struct.pack('<I', value_type) + value_bytes


def _gguf_kv_string(key: str, value: str) -> bytes:
    """Encode a KV pair with a STRING value (type 8)."""
    return _gguf_kv(key, 8, _gguf_string(value))


def _gguf_kv_uint32(key: str, value: int) -> bytes:
    """Encode a KV pair with a UINT32 value (type 4)."""
    return _gguf_kv(key, 4, struct.pack('<I', value))


def _build_gguf(
    version: int = 3,
    tensor_count: int = 0,
    kv_count: int | None = None,
    kv_entries: bytes = b'',
    *,
    raw_kv_count: int | None = None,
) -> bytes:
    """Build a synthetic GGUF binary with the given header fields and KV entries.

    If *raw_kv_count* is provided it overrides the header kv_count field
    (useful for testing anomaly detection with mismatched counts).
    """
    buf = bytearray()
    buf += b'GGUF'                                  # magic
    buf += struct.pack('<I', version)                # version
    buf += struct.pack('<Q', tensor_count)           # tensor_count
    effective_kv_count = raw_kv_count if raw_kv_count is not None else (kv_count if kv_count is not None else 0)
    buf += struct.pack('<Q', effective_kv_count)     # metadata_kv_count
    buf += kv_entries
    return bytes(buf)


def _build_gguf_with_chat_template(template: str) -> bytes:
    """Build a GGUF file with a single tokenizer.chat_template KV entry."""
    kv = _gguf_kv_string('tokenizer.chat_template', template)
    return _build_gguf(kv_count=1, kv_entries=kv, raw_kv_count=1)


# ---------------------------------------------------------------------------
# 9. GGUF — Chat Template SSTI Detection
# ---------------------------------------------------------------------------

def test_gguf_clean_template():
    """A GGUF file with a benign chat template produces no SSTI finding."""
    template = (
        "{% for message in messages %}"
        "{{ message['role'] }}: {{ message['content'] }}\n"
        "{% endfor %}"
    )
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert not ssti, f"Expected no SSTI findings for clean template; got: {ssti}"


def test_gguf_ssti_class_subclasses():
    """GGUF with __class__.__subclasses__ triggers CRITICAL SSTI finding."""
    template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'evil.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, f"Expected SSTI finding; got: {[f.title for f in findings]}"
        assert ssti[0].severity == Severity.CRITICAL
        assert '__class__.__subclasses__' in ssti[0].metadata.get('ssti_patterns', [])


def test_gguf_ssti_import_os():
    """GGUF with {% import os %} triggers CRITICAL finding."""
    template = "{% import os %}{{ os.popen('id').read() }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'rce.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, f"Expected SSTI finding; got: {[f.title for f in findings]}"
        assert ssti[0].severity == Severity.CRITICAL
        patterns = ssti[0].metadata.get('ssti_patterns', [])
        assert 'import os' in patterns
        assert 'popen()' in patterns


def test_gguf_ssti_cycler_gadget():
    """GGUF with cycler.__init__.__globals__ Jinja2 gadget is detected."""
    template = "{{ cycler.__init__.__globals__.os.popen('whoami').read() }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'gadget.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding for cycler gadget"
        assert 'cycler gadget' in ssti[0].metadata.get('ssti_patterns', [])


def test_gguf_ssti_eval():
    """GGUF with eval() in template is detected."""
    template = "{{ eval('__import__(\"os\").system(\"id\")') }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'eval.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding for eval()"
        assert 'eval()' in ssti[0].metadata.get('ssti_patterns', [])


def test_gguf_ssti_open_file():
    """GGUF with open() in template is detected as HIGH."""
    template = "{{ open('/etc/passwd').read() }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fileread.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding for open()"
        # open() alone is HIGH, not CRITICAL
        assert ssti[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_gguf_ssti_config_access():
    """GGUF with config access is detected as MEDIUM."""
    template = "{{ config.items() }}"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'config.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding for config access"


# ---------------------------------------------------------------------------
# 10. GGUF — Header Anomaly Detection
# ---------------------------------------------------------------------------

def test_gguf_absurd_tensor_count():
    """GGUF with tensor_count > 100000 triggers HIGH anomaly finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'bomb.gguf'
        path.write_bytes(_build_gguf(tensor_count=999_999_999, raw_kv_count=0))
        findings = _scan_gguf(path)
        anomaly = [f for f in findings if 'tensor_count' in f.title]
        assert anomaly, f"Expected tensor_count anomaly; got: {[f.title for f in findings]}"
        assert anomaly[0].severity == Severity.HIGH


def test_gguf_absurd_kv_count():
    """GGUF with metadata_kv_count > 10000 triggers HIGH anomaly finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'bomb.gguf'
        path.write_bytes(_build_gguf(raw_kv_count=50_000))
        findings = _scan_gguf(path)
        anomaly = [f for f in findings if 'metadata_kv_count' in f.title]
        assert anomaly, f"Expected kv_count anomaly; got: {[f.title for f in findings]}"
        assert anomaly[0].severity == Severity.HIGH


def test_gguf_unknown_version():
    """GGUF with version > 3 triggers MEDIUM anomaly finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'future.gguf'
        path.write_bytes(_build_gguf(version=99, raw_kv_count=0))
        findings = _scan_gguf(path)
        anomaly = [f for f in findings if 'version' in f.title]
        assert anomaly, f"Expected version anomaly; got: {[f.title for f in findings]}"
        assert anomaly[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# 11. GGUF — Edge Cases
# ---------------------------------------------------------------------------

def test_gguf_not_gguf():
    """A .gguf file without GGUF magic produces no finding."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'fake.gguf'
        path.write_bytes(b'\x00' * 200)
        findings = _scan_gguf(path)
        assert not findings


def test_gguf_truncated():
    """A truncated .gguf file does not crash."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'trunc.gguf'
        # Only magic + partial header (< 24 bytes)
        path.write_bytes(b'GGUF' + b'\x03\x00\x00\x00')
        findings = _scan_gguf(path)
        assert isinstance(findings, list)  # No crash


def test_gguf_truncated_kv():
    """GGUF with kv_count=1 but no KV data does not crash."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'trunc_kv.gguf'
        path.write_bytes(_build_gguf(raw_kv_count=1))  # Claims 1 KV but has none
        findings = _scan_gguf(path)
        assert isinstance(findings, list)  # Graceful, no crash


def test_gguf_multiple_kv_finds_template():
    """Parser correctly walks past non-template KV pairs to find the template."""
    kv = bytearray()
    kv += _gguf_kv_uint32('general.alignment', 32)
    kv += _gguf_kv_string('general.name', 'TestModel')
    kv += _gguf_kv_string(
        'tokenizer.chat_template',
        "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    )
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'multi_kv.gguf'
        path.write_bytes(_build_gguf(kv_count=3, kv_entries=bytes(kv), raw_kv_count=3))
        findings = _scan_gguf(path)
        ssti = [f for f in findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding after walking multiple KV pairs"


def test_gguf_valid_v3_no_findings():
    """A well-formed GGUF v3 file with no template and normal counts is clean."""
    kv = _gguf_kv_string('general.name', 'CleanModel')
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'clean.gguf'
        path.write_bytes(_build_gguf(version=3, tensor_count=100, kv_count=1,
                                     kv_entries=kv, raw_kv_count=1))
        findings = _scan_gguf(path)
        assert not findings, f"Expected no findings for clean GGUF; got: {findings}"


@pytest.mark.asyncio
async def test_gguf_scan_project_integration(scanner: ModelFormatScanner):
    """scan_project picks up .gguf files and detects SSTI."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'model.gguf'
        template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        path.write_bytes(_build_gguf_with_chat_template(template))

        findings = await scanner.scan_project(Path(d))
        gguf_findings = [f for f in findings if 'model.gguf' in f.title]
        assert gguf_findings, (
            f"Expected findings for GGUF model; got: {[f.title for f in findings]}"
        )
        ssti = [f for f in gguf_findings if 'SSTI' in f.title]
        assert ssti, "Expected SSTI finding from scan_project"


@pytest.mark.asyncio
async def test_gguf_scan_project_skips_venv(scanner: ModelFormatScanner):
    """GGUF files inside .venv are skipped."""
    with tempfile.TemporaryDirectory() as d:
        venv_dir = Path(d) / '.venv' / 'models'
        venv_dir.mkdir(parents=True)
        path = venv_dir / 'evil.gguf'
        path.write_bytes(_build_gguf_with_chat_template(
            "{{ ''.__class__.__subclasses__() }}"
        ))

        findings = await scanner.scan_project(Path(d))
        assert not findings, f"Expected no findings in .venv; got: {findings}"


@pytest.mark.asyncio
async def test_gguf_scan_project_clean(scanner: ModelFormatScanner):
    """A clean GGUF in scan_project produces no findings."""
    template = (
        "{% for message in messages %}"
        "{{ message['role'] }}: {{ message['content'] }}\n"
        "{% endfor %}"
    )
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'safe.gguf'
        path.write_bytes(_build_gguf_with_chat_template(template))
        findings = await scanner.scan_project(Path(d))
        gguf_findings = [f for f in findings if 'safe.gguf' in f.title]
        assert not gguf_findings, f"Expected no findings for clean GGUF; got: {gguf_findings}"
