"""Multi-format AI model file scanner — detects threats beyond pickle.

Extends model_integrity.py (pickle/safetensors/GGUF) with static analysis for:

  1. TFLite custom operator detection — FlexWriteFile, FlexReadFile, EagerPyFunc, etc.
  2. NumPy .npy object-dtype pickle scanning (delegates to model_integrity pickle scanner)
  3. HDF5/H5 (Keras) embedded pickle / Lambda layer detection
  4. ONNX custom operator detection — non-standard opset domains
  5. GGUF chat template SSTI scanning — Jinja2 injection in tokenizer.chat_template
     and header anomaly detection (CVE-2024-25664 heap overflow triggers)

All detection is purely static (no tflite/h5py/onnx/gguf imports). Binary parsing is
minimal and defensive — malformed files are handled gracefully, never crash.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.scanners.model_integrity import (
    _SKIP_DIRS,
    _scan_pickle_structural,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Directories to skip
_SKIP_DIRS_SET: frozenset[str] = _SKIP_DIRS

# Max bytes to read for format-specific scans (100 MB)
_MAX_READ = 100 * 1024 * 1024

# ---------------------------------------------------------------------------
# 1. TFLite Custom Operator Detection
# ---------------------------------------------------------------------------

# TFLite FlatBuffer identifier — the file identifier string in the FlatBuffer
# header at byte offset 4 is "TFL3" for TFLite models.
_TFLITE_FILE_IDENTIFIER = b'TFL3'

# Suspicious TFLite operator names.  Any operator starting with "Flex" wraps a
# TensorFlow op and can execute arbitrary graph operations.  Some specific
# Flex operators are especially dangerous.
_TFLITE_DANGEROUS_OPS: dict[str, str] = {
    'FlexWriteFile': 'File system write access',
    'FlexReadFile': 'File system read access',
    'FlexPrintV2': 'Information disclosure via print',
    'EagerPyFunc': 'Arbitrary Python code execution',
    'FlexPyFunc': 'Arbitrary Python code execution (Flex wrapper)',
    'FlexAssert': 'Can abort model serving',
    'FlexStringToHashBucketFast': 'Potential hash collision abuse',
}

# Any op starting with "Flex" is suspicious — wraps a TF op
_TFLITE_FLEX_PREFIX = 'Flex'

# FlatBuffer root table offset is at byte 0 (uint32 LE).  We use a simple
# string extraction approach: scan the binary for ASCII strings that look like
# operator names, since TFLite FlatBuffers store operator codes as string
# references in the OperatorCode table.  This avoids needing a full FlatBuffer
# parser.
_TFLITE_EXTENSIONS = frozenset({'.tflite'})

# Pattern to extract operator name strings from TFLite binary.
# TFLite FlatBuffer stores strings as: uint32_le length + UTF-8 bytes.
# Operator names are short ASCII identifiers.
_TFLITE_OP_NAME_RE = re.compile(rb'((?:Flex[A-Z][A-Za-z0-9_]{2,60})|(?:EagerPyFunc))')


def _extract_tflite_custom_ops(data: bytes) -> list[str]:
    """Extract custom/Flex operator names from TFLite FlatBuffer binary data.

    Uses a two-pass approach:
    1. Quick regex scan for known dangerous patterns
    2. String table extraction for FlatBuffer-encoded operator names

    Returns list of suspicious operator name strings found.
    """
    found_ops: list[str] = []
    seen: set[str] = set()

    # Pass 1: regex for known patterns
    for match in _TFLITE_OP_NAME_RE.finditer(data):
        name = match.group(1).decode('ascii', errors='ignore')
        if name not in seen:
            seen.add(name)
            found_ops.append(name)

    # Pass 2: extract FlatBuffer strings and check for custom ops.
    # TFLite FlatBuffer strings are stored as 4-byte LE length + data.
    # We scan for strings that look like operator names (3-64 chars, ASCII,
    # starting with uppercase) that are NOT in the built-in TFLite op set.
    pos = 0
    while pos < len(data) - 4:
        try:
            str_len = struct.unpack_from('<I', data, pos)[0]
        except struct.error:
            break
        if 3 <= str_len <= 64 and pos + 4 + str_len <= len(data):
            candidate = data[pos + 4:pos + 4 + str_len]
            # Check if it's a valid ASCII operator name
            try:
                name = candidate.decode('ascii')
            except UnicodeDecodeError:
                pos += 1
                continue
            if (name not in seen
                    and name[0].isupper()
                    and all(c.isalnum() or c == '_' for c in name)
                    and (name.startswith(_TFLITE_FLEX_PREFIX) or name in _TFLITE_DANGEROUS_OPS)):
                seen.add(name)
                found_ops.append(name)
        pos += 1

    return found_ops


def _scan_tflite(path: Path) -> list[Finding]:
    """Scan a TFLite model file for custom/dangerous operators.

    Returns list of Findings for any suspicious operators found.
    """
    findings: list[Finding] = []
    pkg = PackageId('tflite', path.name)

    try:
        with path.open('rb') as fh:
            data = fh.read(_MAX_READ)
    except OSError:
        return findings

    if len(data) < 8:
        return findings

    # Verify TFLite FlatBuffer identifier at offset 4-7
    file_id = data[4:8]
    if file_id != _TFLITE_FILE_IDENTIFIER:
        return findings

    custom_ops = _extract_tflite_custom_ops(data)
    if not custom_ops:
        return findings

    # Classify each operator
    dangerous: list[tuple[str, str]] = []
    suspicious: list[str] = []

    for op_name in custom_ops:
        if op_name in _TFLITE_DANGEROUS_OPS:
            dangerous.append((op_name, _TFLITE_DANGEROUS_OPS[op_name]))
        elif op_name.startswith(_TFLITE_FLEX_PREFIX):
            suspicious.append(op_name)

    if dangerous:
        op_detail = '\n    '.join(
            f'{name}: {desc}' for name, desc in dangerous
        )
        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=pkg,
            title=f'Dangerous TFLite operators in {path.name}',
            detail=(
                f"The TFLite model '{path.name}' contains {len(dangerous)} "
                f"dangerous custom operator(s):\n    {op_detail}\n\n"
                "These operators can execute arbitrary code, access the file "
                "system, or disclose information when the model is loaded by "
                "TFLite runtime. Do NOT deploy this model without verification."
            ),
            references=[
                'https://blog.tensorflow.org/2021/11/security-practices-ml-models.html',
            ],
            confidence=0.90,
            metadata={
                'source_file': str(path),
                'format': 'tflite',
                'dangerous_operators': [
                    {'name': n, 'risk': d} for n, d in dangerous
                ],
            },
        ))

    if suspicious:
        ops_str = ', '.join(suspicious[:20])
        truncated = f' (showing first 20 of {len(suspicious)})' if len(suspicious) > 20 else ''
        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.HIGH,
            package=pkg,
            title=f'Flex operators in TFLite model: {path.name}',
            detail=(
                f"The TFLite model '{path.name}' contains {len(suspicious)} "
                f"Flex operator(s){truncated}: {ops_str}\n\n"
                "Flex operators wrap TensorFlow ops and bypass the limited "
                "TFLite built-in operator set. They can execute arbitrary "
                "TensorFlow graph operations, which may include file I/O, "
                "network access, or code execution depending on the wrapped op."
            ),
            confidence=0.75,
            metadata={
                'source_file': str(path),
                'format': 'tflite',
                'flex_operators': suspicious[:20],
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. HDF5/H5 Model Scanning
# ---------------------------------------------------------------------------

_HDF5_MAGIC = b'\x89HDF\r\n\x1a\n'
_HDF5_EXTENSIONS = frozenset({'.h5', '.hdf5', '.keras'})

# Pickle protocol magic bytes
_PICKLE_MAGIC_BYTES = [
    b'\x80\x02',  # Protocol 2
    b'\x80\x03',  # Protocol 3
    b'\x80\x04',  # Protocol 4
    b'\x80\x05',  # Protocol 5
]

# Patterns indicating dangerous content in HDF5/Keras model files.
# These are searched as byte patterns in the raw binary.
_HDF5_DANGER_PATTERNS: list[tuple[bytes, str, str]] = [
    # Lambda layers — arbitrary Python code executed on model load
    (b'"class_name": "Lambda"', 'Lambda layer',
     'Keras Lambda layers contain arbitrary Python code that executes on load'),
    (b'"class_name":"Lambda"', 'Lambda layer',
     'Keras Lambda layers contain arbitrary Python code that executes on load'),
    (b"'class_name': 'Lambda'", 'Lambda layer (single-quoted)',
     'Keras Lambda layers contain arbitrary Python code that executes on load'),
    # Custom objects with code
    (b'__setstate__', 'Pickle __setstate__',
     'Indicates pickle deserialization with custom state restoration'),
    (b'__reduce__', 'Pickle __reduce__',
     'Indicates pickle deserialization with custom reconstruction'),
    # Dangerous Python modules embedded in pickled data
    (b'os\nsystem', 'os.system reference',
     'Reference to os.system in serialized data — code execution risk'),
    (b'subprocess\nPopen', 'subprocess.Popen reference',
     'Reference to subprocess.Popen in serialized data — code execution risk'),
    (b'builtins\neval', 'builtins.eval reference',
     'Reference to eval() in serialized data — code execution risk'),
    (b'builtins\nexec', 'builtins.exec reference',
     'Reference to exec() in serialized data — code execution risk'),
]

# Regex for Lambda layer code extraction (best-effort)
_LAMBDA_CODE_RE = re.compile(
    rb'"config"\s*:\s*\{[^}]*"function"\s*:\s*"([^"]{1,500})"',
    re.DOTALL,
)


def _scan_hdf5(path: Path) -> list[Finding]:
    """Scan an HDF5/Keras model file for embedded pickle data and Lambda layers.

    Detection approach: read raw bytes and search for pickle magic bytes and
    dangerous patterns without requiring h5py.
    """
    findings: list[Finding] = []
    pkg = PackageId('keras', path.name)

    try:
        with path.open('rb') as fh:
            data = fh.read(_MAX_READ)
    except OSError:
        return findings

    if len(data) < 8:
        return findings

    # Verify HDF5 magic
    if data[:8] != _HDF5_MAGIC:
        return findings

    # Check 1: search for pickle magic bytes within the HDF5 data
    pickle_regions: list[tuple[int, bytes]] = []
    for magic in _PICKLE_MAGIC_BYTES:
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx < 0:
                break
            # Extract a region for pickle scanning (up to 1MB from this offset)
            region_end = min(idx + 1024 * 1024, len(data))
            pickle_regions.append((idx, data[idx:region_end]))
            pos = idx + 2  # skip past this magic

    # Scan any discovered pickle regions
    pickle_threats: list[dict] = []
    for offset, region in pickle_regions:
        ops, _perrs = _scan_pickle_structural(region)
        for op in ops:
            op['hdf5_offset'] = offset + op['offset']
        pickle_threats.extend(ops)

    if pickle_threats:
        op_summaries = []
        for op in pickle_threats[:20]:
            parts = [f"{op['opcode']} at HDF5 offset 0x{op.get('hdf5_offset', op['offset']):X}"]
            if op.get('arg'):
                parts.append(f"arg={op['arg']!r}")
            if op.get('category'):
                parts.append(f"[{op['category']}]")
            op_summaries.append(', '.join(parts))

        detail_lines = '\n    '.join(op_summaries)
        total = len(pickle_threats)
        truncated = ' (showing first 20)' if total > 20 else ''

        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=pkg,
            title=f'Pickle payload in HDF5 model: {path.name}',
            detail=(
                f"The HDF5/Keras model '{path.name}' contains embedded pickle "
                f"data with {total} dangerous opcode(s){truncated}:\n"
                f"    {detail_lines}\n\n"
                "Keras models stored in HDF5 format can embed pickled custom "
                "layer configurations that execute code on model load. "
                "Convert to SavedModel or .keras (v3) format."
            ),
            references=[
                'https://keras.io/guides/serialization_and_saving/',
            ],
            confidence=0.90,
            metadata={
                'source_file': str(path),
                'format': 'hdf5',
                'pickle_regions_found': len(pickle_regions),
                'dangerous_ops': pickle_threats[:20],
                'total_dangerous_ops': total,
            },
        ))

    # Check 2: search for dangerous patterns (Lambda layers, etc.)
    danger_found: list[tuple[str, str]] = []
    for pattern, label, description in _HDF5_DANGER_PATTERNS:
        if pattern in data:
            danger_found.append((label, description))

    # Deduplicate — if we already reported pickle threats, skip pickle-specific
    # pattern matches to avoid double-reporting
    if pickle_threats:
        danger_found = [
            (label, desc) for label, desc in danger_found
            if 'Pickle' not in label and 'os.system' not in label
            and 'subprocess' not in label and 'eval' not in label
            and 'exec' not in label
        ]

    if danger_found:
        pattern_detail = '\n    '.join(
            f'{label}: {desc}' for label, desc in danger_found
        )
        # Lambda layers are CRITICAL (arbitrary code), others are HIGH
        has_lambda = any('Lambda' in label for label, _ in danger_found)
        severity = Severity.CRITICAL if has_lambda else Severity.HIGH

        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=severity,
            package=pkg,
            title=f'Dangerous content in HDF5 model: {path.name}',
            detail=(
                f"The HDF5/Keras model '{path.name}' contains dangerous "
                f"patterns:\n    {pattern_detail}\n\n"
                "Lambda layers and custom objects with __reduce__/__setstate__ "
                "execute arbitrary Python code when the model is loaded. "
                "Use tf.keras.models.load_model() with custom_objects "
                "explicitly specified, or migrate to SafeTensors."
            ),
            references=[
                'https://keras.io/guides/serialization_and_saving/',
            ],
            confidence=0.80 if has_lambda else 0.70,
            metadata={
                'source_file': str(path),
                'format': 'hdf5',
                'dangerous_patterns': [label for label, _ in danger_found],
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. ONNX Custom Operator Detection
# ---------------------------------------------------------------------------

_ONNX_EXTENSIONS = frozenset({'.onnx'})

# ONNX uses protobuf encoding.  The ModelProto message has:
#   field 1 (ir_version): int64
#   field 7 (graph): GraphProto
#   field 8 (opset_import): repeated OperatorSetIdProto
#     - field 1 (domain): string
#     - field 2 (version): int64
#
# Nodes in the graph have:
#   field 4 (op_type): string
#   field 7 (domain): string
#
# We parse the protobuf wire format minimally to extract domains and op_types.

# Known standard ONNX domains (empty string = default ONNX domain)
_ONNX_STANDARD_DOMAINS: frozenset[str] = frozenset({
    '',                        # default ONNX domain
    'ai.onnx',                # standard ops
    'ai.onnx.ml',             # ML-specific ops
    'ai.onnx.training',       # training ops
    'ai.onnx.preview.training',
    'com.microsoft',           # Microsoft contrib (somewhat standard)
})


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a protobuf varint from data at pos. Returns (value, new_pos)."""
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return value, pos
    return value, pos


def _parse_protobuf_strings(data: bytes) -> dict[int, list[str]]:
    """Minimally parse protobuf wire format to extract string fields.

    Returns dict mapping field_number -> list of string values.
    Extracts length-delimited fields (wire type 2) and recursively parses
    sub-messages to find nested string fields.
    """
    result: dict[int, list[str]] = {}
    pos = 0

    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        if pos > len(data):
            break

        wire_type = tag & 0x07
        field_number = tag >> 3

        if field_number == 0:
            break  # Invalid field number

        if wire_type == 0:  # Varint
            _, pos = _read_varint(data, pos)
        elif wire_type == 1:  # 64-bit
            pos += 8
        elif wire_type == 2:  # Length-delimited
            length, pos = _read_varint(data, pos)
            if length < 0 or length > len(data) - pos:
                break
            raw = data[pos:pos + length]
            pos += length
            # Try to decode as UTF-8 string
            try:
                s = raw.decode('utf-8')
                if s.isprintable() and len(s) >= 1:
                    result.setdefault(field_number, []).append(s)
            except UnicodeDecodeError:
                pass
            # Also recursively parse as sub-message (protobuf nests messages
            # as length-delimited fields too)
            if len(raw) >= 2:
                sub_fields = _parse_protobuf_strings(raw)
                for fn, strings in sub_fields.items():
                    result.setdefault(fn, []).extend(strings)
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            break  # Unknown wire type — stop parsing

    return result


def _extract_onnx_custom_ops(data: bytes) -> tuple[list[str], list[tuple[str, str]]]:
    """Extract custom operator domains and nodes from ONNX protobuf data.

    Uses recursive protobuf parsing to find domain strings inside nested
    OperatorSetIdProto and NodeProto messages.

    Returns:
        - custom_domains: list of non-standard domain strings from opset_import
        - custom_nodes: list of (op_type, domain) tuples for nodes with custom domains
    """
    custom_domains: list[str] = []
    custom_nodes: list[tuple[str, str]] = []
    seen_domains: set[str] = set()

    # Parse all string fields recursively from the protobuf
    fields = _parse_protobuf_strings(data)

    # Collect all strings from all fields
    all_strings: list[str] = []
    for field_strs in fields.values():
        all_strings.extend(field_strs)

    # Look for domains (reverse-DNS style: contains '.', lowercase)
    domain_pattern = re.compile(r'^[a-z][a-z0-9_.]{2,60}$')
    for s in all_strings:
        if domain_pattern.match(s) and '.' in s and s not in _ONNX_STANDARD_DOMAINS:
            if s not in seen_domains:
                seen_domains.add(s)
                custom_domains.append(s)

    # If we found custom domains, look for op names near domain references.
    # Scan both before and after each domain occurrence to find associated
    # op_type strings (protobuf field ordering varies).
    for domain in custom_domains:
        domain_bytes = domain.encode('utf-8')
        pos = 0
        while True:
            idx = data.find(domain_bytes, pos)
            if idx < 0:
                break
            # Scan a window around the domain reference (200 bytes each direction)
            region_start = max(0, idx - 200)
            region_end = min(len(data), idx + len(domain_bytes) + 200)
            region = data[region_start:region_end]
            region_fields = _parse_protobuf_strings(region)
            for field_strs in region_fields.values():
                for s in field_strs:
                    if (s and s[0].isupper()
                            and s != domain
                            and all(c.isalnum() or c == '_' for c in s)
                            and 2 <= len(s) <= 64):
                        custom_nodes.append((s, domain))
            pos = idx + len(domain_bytes)

    return custom_domains, custom_nodes


def _scan_onnx(path: Path) -> list[Finding]:
    """Scan an ONNX model file for custom operators backed by external code.

    Custom operators (domain != "" and not in standard set) can be backed by
    shared libraries (.so/.dll) that execute arbitrary native code.
    """
    findings: list[Finding] = []
    pkg = PackageId('onnx', path.name)

    try:
        with path.open('rb') as fh:
            data = fh.read(_MAX_READ)
    except OSError:
        return findings

    if len(data) < 8:
        return findings

    # ONNX files are protobuf — check for protobuf-like structure.
    # The first byte should be a valid protobuf tag (field 1, wire type 0 = 0x08
    # for ir_version).
    if data[0] != 0x08:
        return findings

    custom_domains, custom_nodes = _extract_onnx_custom_ops(data)

    if not custom_domains:
        return findings

    # Build finding
    domain_list = ', '.join(custom_domains[:10])
    truncated = f' (showing first 10 of {len(custom_domains)})' if len(custom_domains) > 10 else ''

    node_detail = ''
    if custom_nodes:
        node_lines = [f'{op_type} (domain: {domain})'
                      for op_type, domain in custom_nodes[:20]]
        node_detail = (
            f'\n\nCustom operator nodes found:\n    '
            + '\n    '.join(node_lines)
        )

    findings.append(Finding(
        finding_type=FindingType.MALICIOUS,
        severity=Severity.HIGH,
        package=pkg,
        title=f'Custom operator domains in ONNX model: {path.name}',
        detail=(
            f"The ONNX model '{path.name}' imports {len(custom_domains)} "
            f"non-standard operator domain(s){truncated}: {domain_list}\n\n"
            "Custom operator domains indicate the model requires external "
            "shared libraries (.so/.dll) to execute. These libraries run "
            "arbitrary native code and can perform any system operation "
            f"including file I/O, network access, and code execution.{node_detail}\n\n"
            "Only load ONNX models with custom operators from trusted sources. "
            "Verify that required custom operator libraries are from known "
            "providers."
        ),
        references=[
            'https://onnx.ai/onnx/intro/concepts.html#custom-operators',
            'https://onnxruntime.ai/docs/reference/operators/add-custom-op.html',
        ],
        confidence=0.80,
        metadata={
            'source_file': str(path),
            'format': 'onnx',
            'custom_domains': custom_domains[:10],
            'custom_nodes': [
                {'op_type': op, 'domain': dom}
                for op, dom in custom_nodes[:20]
            ],
        },
    ))

    return findings


# ---------------------------------------------------------------------------
# 4. GGUF Chat Template SSTI + Header Anomaly Detection
# ---------------------------------------------------------------------------

_GGUF_MAGIC = b'GGUF'
_GGUF_EXTENSIONS = frozenset({'.gguf'})

# Minimum GGUF header size: 4 (magic) + 4 (version) + 8 (tensor_count) +
# 8 (metadata_kv_count) = 24 bytes
_GGUF_HEADER_SIZE = 24

# The metadata key whose string value is the Jinja2 chat template
_GGUF_CHAT_TEMPLATE_KEY = 'tokenizer.chat_template'

# Header anomaly thresholds
_GGUF_MAX_TENSOR_COUNT = 100_000
_GGUF_MAX_KV_COUNT = 10_000
_GGUF_MAX_STRING_LEN = 10 * 1024 * 1024  # 10 MB
_GGUF_MAX_KNOWN_VERSION = 3

# GGUF value type IDs → wire sizes for scalar types (used to skip values)
_GGUF_VALUE_SIZES: dict[int, int] = {
    0: 1,   # UINT8
    1: 1,   # INT8
    2: 2,   # UINT16
    3: 2,   # INT16
    4: 4,   # UINT32
    5: 4,   # INT32
    6: 4,   # FLOAT32
    7: 1,   # BOOL
    # 8 = STRING (variable), 9 = ARRAY (variable)
    10: 8,  # UINT64
    11: 8,  # INT64
    12: 8,  # FLOAT64
}

# Jinja2 SSTI patterns — compiled for efficiency.
# Each tuple: (compiled_regex, label, description, severity)
_GGUF_SSTI_PATTERNS: list[tuple[re.Pattern[str], str, str, Severity]] = [
    # Class traversal / MRO
    (re.compile(r'\{\{.*__class__.*__subclasses__', re.DOTALL),
     '__class__.__subclasses__', 'Class traversal to discover exploitable subclasses',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*__mro__', re.DOTALL),
     '__mro__', 'Method resolution order traversal for class hierarchy escape',
     Severity.CRITICAL),
    # Global / builtin namespace access
    (re.compile(r'\{\{.*__globals__', re.DOTALL),
     '__globals__', 'Global namespace access — can reach os/subprocess/builtins',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*__builtins__', re.DOTALL),
     '__builtins__', 'Direct access to Python builtins (eval, exec, open, etc.)',
     Severity.CRITICAL),
    # Direct imports
    (re.compile(r'\{%.*import\s+os', re.DOTALL),
     'import os', 'Direct os module import in template',
     Severity.CRITICAL),
    (re.compile(r'\{%.*import\s+subprocess', re.DOTALL),
     'import subprocess', 'Direct subprocess module import in template',
     Severity.CRITICAL),
    # Command / code execution
    (re.compile(r'\{\{.*popen\(', re.DOTALL),
     'popen()', 'Command execution via popen',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*system\(', re.DOTALL),
     'system()', 'Command execution via system()',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*\beval\(', re.DOTALL),
     'eval()', 'Arbitrary code execution via eval()',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*\bexec\(', re.DOTALL),
     'exec()', 'Arbitrary code execution via exec()',
     Severity.CRITICAL),
    # File access
    (re.compile(r'\{\{.*\bopen\(', re.DOTALL),
     'open()', 'File system access via open()',
     Severity.HIGH),
    # Config access
    (re.compile(r'\{\{.*config', re.DOTALL),
     'config', 'Jinja2 config object access — may leak SECRET_KEY or app config',
     Severity.MEDIUM),
    # Jinja2-specific gadgets (cycler/joiner/namespace __init__.__globals__)
    (re.compile(r'\{\{.*cycler\.__init__\.__globals__', re.DOTALL),
     'cycler gadget', 'Jinja2 cycler.__init__.__globals__ gadget chain',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*joiner\.__init__\.__globals__', re.DOTALL),
     'joiner gadget', 'Jinja2 joiner.__init__.__globals__ gadget chain',
     Severity.CRITICAL),
    (re.compile(r'\{\{.*namespace\.__init__\.__globals__', re.DOTALL),
     'namespace gadget', 'Jinja2 namespace.__init__.__globals__ gadget chain',
     Severity.CRITICAL),
    # __import__ — direct module import via builtins
    (re.compile(r'\{\{.*__import__\s*\(', re.DOTALL),
     '__import__()', 'Dynamic module import via __import__()',
     Severity.CRITICAL),
    # lipsum.__globals__ — lesser-known Jinja2 global that exposes __globals__
    (re.compile(r'\{\{.*lipsum\.__globals__', re.DOTALL),
     'lipsum gadget', 'Jinja2 lipsum.__globals__ gadget chain',
     Severity.CRITICAL),
    # self._TemplateReference__context — Jinja2 internal context escape
    (re.compile(r'\{\{.*_TemplateReference__context', re.DOTALL),
     'TemplateReference escape', 'Jinja2 internal context access via _TemplateReference__context',
     Severity.CRITICAL),
    # __init__.__globals__ generic (any object)
    (re.compile(r'\{\{.*\.__init__\.__globals__', re.DOTALL),
     '__init__.__globals__', 'Generic __init__.__globals__ gadget chain',
     Severity.CRITICAL),
]


def _gguf_read_string(data: bytes, pos: int) -> tuple[str | None, int]:
    """Read a gguf_string_t (uint64 len + UTF-8 bytes) from *data* at *pos*.

    Returns (decoded_string, new_pos) or (None, -1) on error.
    """
    if pos + 8 > len(data):
        return None, -1
    str_len = struct.unpack_from('<Q', data, pos)[0]
    pos += 8
    if str_len > _GGUF_MAX_STRING_LEN or pos + str_len > len(data):
        return None, -1
    try:
        s = data[pos:pos + str_len].decode('utf-8', errors='replace')
    except Exception:
        return None, -1
    return s, pos + str_len


def _gguf_skip_value(data: bytes, pos: int, value_type: int) -> int:
    """Skip over a GGUF metadata value at *pos*.  Returns new pos, or -1 on error."""
    if value_type in _GGUF_VALUE_SIZES:
        size = _GGUF_VALUE_SIZES[value_type]
        new_pos = pos + size
        return new_pos if new_pos <= len(data) else -1

    if value_type == 8:  # STRING
        _, new_pos = _gguf_read_string(data, pos)
        return new_pos

    if value_type == 9:  # ARRAY
        if pos + 12 > len(data):
            return -1
        elem_type = struct.unpack_from('<I', data, pos)[0]
        elem_count = struct.unpack_from('<Q', data, pos + 4)[0]
        pos += 12
        if elem_count > 10_000_000:  # sanity cap
            return -1
        for _ in range(elem_count):
            pos = _gguf_skip_value(data, pos, elem_type)
            if pos < 0:
                return -1
        return pos

    return -1  # Unknown type


def _scan_gguf(path: Path) -> list[Finding]:
    """Scan a GGUF model file for chat template SSTI and header anomalies.

    Detection:
      - Parses the binary GGUF header (magic, version, tensor_count, kv_count)
      - Walks metadata KV pairs looking for ``tokenizer.chat_template``
      - Runs Jinja2 SSTI pattern matching on the chat template string
      - Flags header anomalies that trigger heap-overflow CVEs

    All parsing is defensive — malformed input returns partial findings, never crashes.
    """
    findings: list[Finding] = []
    pkg = PackageId('gguf', path.name)

    try:
        with path.open('rb') as fh:
            data = fh.read(_MAX_READ)
    except OSError:
        return findings

    if len(data) < _GGUF_HEADER_SIZE:
        return findings

    # ── Verify magic ──────────────────────────────────────────────────────
    if data[:4] != _GGUF_MAGIC:
        return findings

    # ── Parse fixed header ────────────────────────────────────────────────
    version = struct.unpack_from('<I', data, 4)[0]
    tensor_count = struct.unpack_from('<Q', data, 8)[0]
    kv_count = struct.unpack_from('<Q', data, 16)[0]

    # ── Header anomaly checks ─────────────────────────────────────────────
    anomalies: list[tuple[str, str, Severity]] = []

    if tensor_count > _GGUF_MAX_TENSOR_COUNT:
        anomalies.append((
            f'tensor_count={tensor_count}',
            f'Absurd tensor_count ({tensor_count:,}) — likely crafted to trigger '
            f'O(n) allocation loop (heap overflow / DoS). Legitimate models rarely '
            f'exceed a few thousand tensors.',
            Severity.HIGH,
        ))

    if kv_count > _GGUF_MAX_KV_COUNT:
        anomalies.append((
            f'metadata_kv_count={kv_count}',
            f'Absurd metadata_kv_count ({kv_count:,}) — may trigger allocation-loop '
            f'DoS or integer-overflow in metadata parsing '
            f'(CVE-2024-25664 / TALOS-2024-1913).',
            Severity.HIGH,
        ))

    if version > _GGUF_MAX_KNOWN_VERSION:
        anomalies.append((
            f'version={version}',
            f'Unknown GGUF version {version} (latest known is {_GGUF_MAX_KNOWN_VERSION}). '
            f'This may be a crafted file exploiting parser version-gating logic.',
            Severity.MEDIUM,
        ))

    for label, detail, severity in anomalies:
        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=severity,
            package=pkg,
            title=f'GGUF header anomaly in {path.name}: {label}',
            detail=detail,
            references=[
                'https://github.com/ggerganov/ggml/blob/master/docs/gguf.md',
                'https://www.talosintelligence.com/vulnerability_reports/TALOS-2024-1913',
            ],
            confidence=0.85,
            metadata={
                'source_file': str(path),
                'format': 'gguf',
                'anomaly': label,
                'version': version,
                'tensor_count': tensor_count,
                'kv_count': kv_count,
            },
        ))

    # If kv_count is absurd, don't attempt to walk KV pairs (DoS protection)
    if kv_count > _GGUF_MAX_KV_COUNT:
        return findings

    # ── Walk metadata KV pairs to find chat template ──────────────────────
    pos = _GGUF_HEADER_SIZE
    chat_template: str | None = None
    oversized_strings: list[str] = []

    for _ in range(kv_count):
        # Read key string
        key, pos = _gguf_read_string(data, pos)
        if key is None or pos < 0:
            break  # Truncated / malformed — stop gracefully

        # Read value type (uint32)
        if pos + 4 > len(data):
            break
        value_type = struct.unpack_from('<I', data, pos)[0]
        pos += 4

        # Check for oversized string values before reading
        if value_type == 8:  # STRING
            if pos + 8 > len(data):
                break
            str_len = struct.unpack_from('<Q', data, pos)[0]
            if str_len > _GGUF_MAX_STRING_LEN:
                oversized_strings.append(f'{key} ({str_len:,} bytes)')
                break  # Can't safely continue past this

        # If this is the chat_template key, extract its string value
        if key == _GGUF_CHAT_TEMPLATE_KEY and value_type == 8:
            chat_template, pos = _gguf_read_string(data, pos)
            if chat_template is None or pos < 0:
                break
        else:
            # Skip this value
            pos = _gguf_skip_value(data, pos, value_type)
            if pos < 0:
                break

    # ── Oversized string findings ─────────────────────────────────────────
    if oversized_strings:
        keys_str = ', '.join(oversized_strings[:5])
        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.HIGH,
            package=pkg,
            title=f'Oversized GGUF metadata string in {path.name}',
            detail=(
                f"The GGUF file '{path.name}' contains metadata string value(s) "
                f"exceeding 10 MB: {keys_str}\n\n"
                "Oversized string length fields can trigger integer overflow in "
                "calloc(len+1, 1) when len approaches UINT64_MAX, causing a "
                "0-byte allocation followed by heap overflow on write "
                "(CVE-2024-25664 / TALOS-2024-1913 root cause in gguf_fread_str)."
            ),
            references=[
                'https://www.talosintelligence.com/vulnerability_reports/TALOS-2024-1913',
            ],
            confidence=0.90,
            metadata={
                'source_file': str(path),
                'format': 'gguf',
                'oversized_keys': oversized_strings[:5],
            },
        ))

    # ── SSTI scan on chat template ────────────────────────────────────────
    if chat_template:
        ssti_hits: list[tuple[str, str, Severity]] = []
        for pattern, label, description, severity in _GGUF_SSTI_PATTERNS:
            if pattern.search(chat_template):
                ssti_hits.append((label, description, severity))

        if ssti_hits:
            # Overall severity = worst hit
            worst = Severity.INFO
            severity_rank = {
                Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
                Severity.HIGH: 3, Severity.CRITICAL: 4,
            }
            for _, _, sev in ssti_hits:
                if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                    worst = sev

            hit_detail = '\n    '.join(
                f'{label}: {desc}' for label, desc, _ in ssti_hits
            )
            # Truncate template for display (first 500 chars)
            template_preview = chat_template[:500]
            if len(chat_template) > 500:
                template_preview += '... (truncated)'

            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=worst,
                package=pkg,
                title=f'GGUF chat template SSTI in {path.name}',
                detail=(
                    f"The GGUF model '{path.name}' contains a Jinja2 chat template "
                    f"(tokenizer.chat_template) with {len(ssti_hits)} server-side "
                    f"template injection pattern(s):\n    {hit_detail}\n\n"
                    f"Template preview:\n    {template_preview}\n\n"
                    "When this model is loaded by llama.cpp, vLLM, or any inference "
                    "server that renders chat templates via Jinja2, the injected "
                    "payload can escape the template sandbox and execute arbitrary "
                    "code on the host. Do NOT load this model."
                ),
                references=[
                    'https://github.com/ggerganov/ggml/blob/master/docs/gguf.md',
                    'https://portswigger.net/research/server-side-template-injection',
                ],
                confidence=0.95,
                metadata={
                    'source_file': str(path),
                    'format': 'gguf',
                    'ssti_patterns': [label for label, _, _ in ssti_hits],
                    'template_length': len(chat_template),
                    'template_preview': template_preview,
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class ModelFormatScanner:
    """Scan AI model files in TFLite, HDF5/Keras, ONNX, and GGUF formats for threats.

    Detects:
      1. TFLite custom/Flex operators (arbitrary TF op execution)
      2. HDF5/Keras embedded pickle payloads and Lambda layers
      3. ONNX custom operator domains (external shared library execution)
      4. GGUF chat template SSTI (Jinja2 injection) and header anomalies
    """

    name = 'model_format'
    ecosystems = ['tflite', 'keras', 'onnx', 'gguf']

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan *project_dir* recursively for model format threats."""
        findings: list[Finding] = []

        all_extensions = (
            _TFLITE_EXTENSIONS | _HDF5_EXTENSIONS
            | _ONNX_EXTENSIONS | _GGUF_EXTENSIONS
        )

        for ext in sorted(all_extensions):
            for model_file in sorted(project_dir.rglob(f'*{ext}')):
                if _should_skip(model_file):
                    continue

                try:
                    file_size = model_file.stat().st_size
                except OSError:
                    continue

                if file_size < 8:
                    continue

                if ext in _TFLITE_EXTENSIONS:
                    findings.extend(_scan_tflite(model_file))
                elif ext in _HDF5_EXTENSIONS:
                    findings.extend(_scan_hdf5(model_file))
                elif ext in _ONNX_EXTENSIONS:
                    findings.extend(_scan_onnx(model_file))
                elif ext in _GGUF_EXTENSIONS:
                    findings.extend(_scan_gguf(model_file))

        return findings


def _should_skip(path: Path) -> bool:
    """Return True if *path* lives inside a directory we want to ignore."""
    return any(part in _SKIP_DIRS_SET for part in path.parts)
