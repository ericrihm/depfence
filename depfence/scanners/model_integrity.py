"""Model weight integrity scanner — verifies downloaded AI model files are untampered.

AI developers pull model weights from HuggingFace and similar registries with no
built-in integrity guarantees.  A compromised or malicious model file can:
  - Embed pickle REDUCE/GLOBAL/INST opcodes that execute code on torch.load()
  - Claim to be a large model but deliver a tiny trojan payload
  - Advertise a known-good sha256 in config.json while the weights file differs

This scanner closes those gaps by inspecting model files directly:
  1. Pickle opcode scanning: detect dangerous execution opcodes in .bin/.pkl/.pt files
  2. SafeTensors header validation: verify magic-byte layout and JSON metadata integrity
  3. Checksum verification: cross-check sha256 hashes declared in config.json / model.json
  4. Unsigned model detection: flag models with no integrity metadata at all
  5. Size anomaly detection: flag files that are implausibly small for their claimed arch
"""

from __future__ import annotations

import hashlib
import io
import json
import pickletools
import re
import struct
import zipfile
import zlib
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pickle opcode NAMES that allow arbitrary code execution.
# Detection is opcode-presence-first (not module-name-blocklist) to avoid
# subclass blacklist evasion.
_DANGEROUS_OPCODE_NAMES: frozenset[str] = frozenset({
    'REDUCE',        # 0x52 - calls callable(*args) -- the primary RCE vector
    'GLOBAL',        # 0x63 - push module.name (Protocol 0-3)
    'INST',          # 0x69 - legacy class instantiation
    'NEWOBJ',        # 0x81 - cls.__new__(cls, *args) (Protocol 2)
    'NEWOBJ_EX',     # 0x92 - cls.__new__(cls, *args, **kwargs) (Protocol 4)
    'STACK_GLOBAL',  # 0x93 - push module.name from stack (Protocol 4)
    'OBJ',           # 0x6F - build & push class instance (Protocol 1)
    'BUILD',         # 0x62 - calls __setstate__ on top-of-stack object
    'EXT1',          # 0x82 - copyreg extension (Protocol 2)
    'EXT2',          # 0x83 - copyreg extension (Protocol 2)
    'EXT4',          # 0x84 - copyreg extension (Protocol 2)
    'PERSID',        # 0x50 - persistent_id (Protocol 0) -- can be abused
    'BINPERSID',     # 0x51 - persistent_id binary (Protocol 1)
})

# Dangerous module.callable patterns for enrichment (NOT the primary detection signal).
# Detection fires on opcode presence. Module classification is enrichment only.
_DANGEROUS_GLOBALS: dict[str, str] = {
    # Code execution — os module
    'os.system': 'code_execution',
    'os.popen': 'code_execution',
    'os.popen2': 'code_execution',
    'os.popen3': 'code_execution',
    'os.popen4': 'code_execution',
    'os.exec': 'code_execution',
    'os.execl': 'code_execution',
    'os.execlp': 'code_execution',
    'os.execle': 'code_execution',
    'os.execv': 'code_execution',
    'os.execvp': 'code_execution',
    'os.execve': 'code_execution',
    'os.execvpe': 'code_execution',
    'os.spawnl': 'code_execution',
    'os.spawnle': 'code_execution',
    'os.spawnlp': 'code_execution',
    'os.spawnlpe': 'code_execution',
    'os.spawnv': 'code_execution',
    'os.spawnve': 'code_execution',
    'os.spawnvp': 'code_execution',
    'os.spawnvpe': 'code_execution',
    'os.fork': 'code_execution',
    'os.forkpty': 'code_execution',
    'os.kill': 'code_execution',
    'os.killpg': 'code_execution',
    'posix.system': 'code_execution',
    'nt.system': 'code_execution',
    # Code execution — subprocess
    'subprocess.call': 'code_execution',
    'subprocess.check_call': 'code_execution',
    'subprocess.check_output': 'code_execution',
    'subprocess.Popen': 'code_execution',
    'subprocess.run': 'code_execution',
    'subprocess.getstatusoutput': 'code_execution',
    'subprocess.getoutput': 'code_execution',
    # Code execution — builtins
    'builtins.eval': 'code_execution',
    'builtins.exec': 'code_execution',
    'builtins.compile': 'code_execution',
    'builtins.execfile': 'code_execution',
    'builtins.__import__': 'code_execution',
    'builtins.input': 'code_execution',  # Python 2 input() calls eval()
    # Code execution — importlib / runpy / zipimport
    'importlib.import_module': 'code_execution',
    'runpy.run_module': 'code_execution',
    'runpy.run_path': 'code_execution',
    'zipimport.zipimporter': 'code_execution',
    # Code execution — ctypes (native code loading)
    'ctypes.CDLL': 'code_execution',
    'ctypes.cdll': 'code_execution',
    'ctypes.cdll.LoadLibrary': 'code_execution',
    'ctypes.windll': 'code_execution',
    'ctypes.pythonapi': 'code_execution',
    # Code execution — interactive / pty
    'code.interact': 'code_execution',
    'code.compile_command': 'code_execution',
    'codeop.compile_command': 'code_execution',
    'pty.spawn': 'code_execution',
    'pty.fork': 'code_execution',
    # Code execution — legacy commands module (Python 2)
    'commands.getoutput': 'code_execution',
    'commands.getstatusoutput': 'code_execution',
    # Code execution — platform (deprecated but exploitable)
    'platform.popen': 'code_execution',
    # Code execution — webbrowser
    'webbrowser.open': 'code_execution',
    'webbrowser.open_new': 'code_execution',
    'webbrowser.open_new_tab': 'code_execution',
    # Network
    'socket.socket': 'network',
    'socket.create_connection': 'network',
    'urllib.request.urlopen': 'network',
    'urllib.request.urlretrieve': 'network',
    'urllib.request.Request': 'network',
    'http.client.HTTPConnection': 'network',
    'http.client.HTTPSConnection': 'network',
    'xmlrpc.client.ServerProxy': 'network',
    'ftplib.FTP': 'network',
    'smtplib.SMTP': 'network',
    # File system — destructive operations
    'os.remove': 'filesystem',
    'os.unlink': 'filesystem',
    'os.rmdir': 'filesystem',
    'os.removedirs': 'filesystem',
    'os.rename': 'filesystem',
    'os.makedirs': 'filesystem',
    'shutil.rmtree': 'filesystem',
    'shutil.move': 'filesystem',
    'shutil.copy': 'filesystem',
    'shutil.copy2': 'filesystem',
    'shutil.copytree': 'filesystem',
    'shutil.make_archive': 'filesystem',
    'io.FileIO': 'filesystem',
    '_io.FileIO': 'filesystem',
    'builtins.open': 'filesystem',
    'pathlib.Path.write_bytes': 'filesystem',
    'pathlib.Path.write_text': 'filesystem',
    'tempfile.NamedTemporaryFile': 'filesystem',
    # File system — shelve (persistent dict backed by pickle)
    'shelve.open': 'filesystem',
    # Deserialization chains
    'pickle.loads': 'deserialization',
    'pickle.load': 'deserialization',
    '_pickle.loads': 'deserialization',
    '_pickle.load': 'deserialization',
    'marshal.loads': 'deserialization',
    'marshal.load': 'deserialization',
    'copyreg._reconstructor': 'deserialization',
    'copyreg.__newobj__': 'deserialization',
}

# Modules where ANY function is dangerous — wildcard match.
# If a GLOBAL/INST arg's top-level module is in this set, it is flagged at HIGH
# even if the specific function is not in _DANGEROUS_GLOBALS.
_DANGEROUS_MODULES: frozenset[str] = frozenset({
    'os', 'posix', 'nt', 'subprocess', 'ctypes', 'shutil', 'socket', 'ssl',
    'http.client', 'urllib.request', 'pickle', '_pickle', 'marshal', 'pty',
    'commands', 'runpy', 'webbrowser', 'code', 'cProfile', 'profile', 'pdb',
    'venv', 'pip', 'asyncio', 'sys', 'test', 'timeit', 'trace', 'pydoc',
    'idlelib',
})

# ---------------------------------------------------------------------------
# ML framework allowlist — legitimate classes/functions referenced in
# PyTorch, NumPy, scikit-learn model files.  These produce REDUCE/GLOBAL/
# BUILD opcodes that are normal deserialization, not attack payloads.
#
# Classification tiers:
#   1. Exact match in _DANGEROUS_GLOBALS → CRITICAL (unchanged)
#   2. Wildcard match in _DANGEROUS_MODULES → HIGH (unchanged)
#   3. Module in _ML_SAFE_MODULES AND name in safe set → SKIP (no finding)
#   4. Module in _ML_SAFE_MODULES but name NOT in safe set → MEDIUM
#   5. Unknown module → informational (currently emitted as part of CRITICAL)
# ---------------------------------------------------------------------------

_ML_SAFE_MODULES: dict[str, frozenset[str]] = {
    'torch': frozenset({
        'FloatStorage', 'LongStorage', 'IntStorage', 'ShortStorage',
        'DoubleStorage', 'HalfStorage', 'BFloat16Storage', 'ByteStorage',
        'CharStorage', 'BoolStorage', 'ComplexFloatStorage',
        'ComplexDoubleStorage', 'QInt8Storage', 'QInt32Storage',
        'QUInt8Storage', 'TypedStorage', 'UntypedStorage',
        'storage', '_utils',
    }),
    'torch._utils': frozenset({
        '_rebuild_tensor_v2', '_rebuild_parameter',
        '_rebuild_parameter_with_state', '_rebuild_sparse_tensor',
        '_rebuild_nested_tensor', '_rebuild_wrapper_subclass',
    }),
    'torch.nn.modules.linear': frozenset({'Linear'}),
    'torch.nn.modules.conv': frozenset({
        'Conv1d', 'Conv2d', 'Conv3d',
    }),
    'torch.nn.modules.activation': frozenset({
        'ReLU', 'GELU', 'SiLU', 'Sigmoid', 'Tanh', 'LeakyReLU', 'ELU',
        'Softmax', 'LogSoftmax', 'PReLU', 'Mish',
    }),
    'torch.nn.modules.batchnorm': frozenset({
        'BatchNorm1d', 'BatchNorm2d', 'BatchNorm3d',
    }),
    'torch.nn.modules.dropout': frozenset({
        'Dropout', 'Dropout2d', 'Dropout3d',
    }),
    'torch.nn.modules.loss': frozenset({
        'CrossEntropyLoss', 'MSELoss', 'L1Loss', 'NLLLoss',
        'BCELoss', 'BCEWithLogitsLoss', 'SmoothL1Loss',
    }),
    'torch.nn.modules.container': frozenset({
        'Sequential', 'ModuleList', 'ModuleDict',
    }),
    'torch.nn.modules.pooling': frozenset({
        'MaxPool1d', 'MaxPool2d', 'MaxPool3d',
        'AvgPool1d', 'AvgPool2d', 'AvgPool3d',
        'AdaptiveAvgPool1d', 'AdaptiveAvgPool2d', 'AdaptiveAvgPool3d',
    }),
    'torch.nn.modules.normalization': frozenset({
        'LayerNorm', 'GroupNorm', 'InstanceNorm1d', 'InstanceNorm2d',
    }),
    'torch.nn.modules.rnn': frozenset({
        'LSTM', 'GRU', 'RNN', 'LSTMCell', 'GRUCell', 'RNNCell',
    }),
    'torch.nn.modules.transformer': frozenset({
        'Transformer', 'TransformerEncoder', 'TransformerDecoder',
        'TransformerEncoderLayer', 'TransformerDecoderLayer',
        'MultiheadAttention',
    }),
    'collections': frozenset({
        'OrderedDict', 'defaultdict',
    }),
    'numpy': frozenset({
        'ndarray', 'dtype', 'float32', 'float64', 'int32', 'int64',
        'float16', 'uint8', 'int8', 'bool_', 'complex64', 'complex128',
        'array',
    }),
    'numpy.core.multiarray': frozenset({
        'scalar', '_reconstruct', 'array',
    }),
    '_codecs': frozenset({
        'encode',
    }),
    'copyreg': frozenset({
        '_reconstructor',
    }),
    'copy_reg': frozenset({
        '_reconstructor',
    }),
}

# File extensions treated as potential pickle-based model weights.
_PICKLE_EXTENSIONS: frozenset[str] = frozenset({
    ".bin", ".pkl", ".pickle", ".pt",
    ".pth",     # PyTorch checkpoint (identical format to .pt)
    ".ckpt",    # PyTorch Lightning / TF checkpoint (pickle-based)
    ".joblib",  # scikit-learn serialization (pickle-based)
    ".npy",     # numpy: may contain pickled objects (object dtype)
    ".npz",     # numpy ZIP archive: may contain .npy with pickled objects
})

# SafeTensors: the header is a little-endian u64 (8 bytes) giving JSON length,
# followed immediately by that many bytes of JSON.  There is no separate magic
# constant in the spec, but the header_size must be > 0 and < 100 MB for a
# valid file.  The JSON must contain at least an empty object.
_SAFETENSORS_MAX_HEADER_BYTES = 100 * 1024 * 1024  # 100 MB guard

# Chunk size for streaming reads — never load entire weight files into memory.
_READ_CHUNK_SIZE = 64 * 1024  # 64 KB

# Minimum file size to bother scanning — skip truly empty or stub files.
_MIN_WEIGHT_BYTES = 64

# Size thresholds for "7B" / "13B" / "70B" model families.  If a file's name
# or parent directory hints at one of these architectures but the file is
# suspiciously small, it is flagged.
_ARCH_MIN_BYTES: list[tuple[str, int]] = [
    # (substring that appears in path/name, minimum expected bytes)
    ("70b",  10 * 1024 * 1024 * 1024),   # 70B  → at least 10 GB per shard
    ("65b",  8  * 1024 * 1024 * 1024),
    ("34b",  4  * 1024 * 1024 * 1024),
    ("30b",  3  * 1024 * 1024 * 1024),
    ("13b",  1  * 1024 * 1024 * 1024),   # 13B  → at least 1 GB per shard
    ("7b",   500 * 1024 * 1024),          # 7B   → at least 500 MB per shard
    ("6b",   400 * 1024 * 1024),
    ("3b",   200 * 1024 * 1024),
    ("1b",   50  * 1024 * 1024),
]

# Config/model-card filenames that may contain sha256 checksums.
_CONFIG_FILENAMES: tuple[str, ...] = (
    "config.json",
    "model.json",
    "model_card.json",
    "metadata.json",
)

# Prompt injection patterns for model metadata scanning
_MODEL_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(previous|above|all|prior)\s+(instructions|prompts|rules)", re.I),
     "Instruction override in model metadata"),
    (re.compile(r"you\s+are\s+(now|a|an)\s+", re.I),
     "Identity override in model metadata"),
    (re.compile(r"<\|im_start\|>|</?system>|\[INST\]", re.I),
     "LLM delimiter in model metadata"),
    (re.compile(r"IMPORTANT\s*:\s*(ignore|disregard|override)", re.I),
     "Instruction override via IMPORTANT"),
    (re.compile(
        r"(?:remove|delete|erase|destroy)\s+(?:all|every|the)\s+(?:files?|code|tests?|data)",
        re.I),
     "Destructive instruction in model metadata"),
    (re.compile(r"(?:send|post|exfiltrate?|upload)\s+(?:to|the|all|this)", re.I),
     "Exfiltration instruction in model metadata"),
    (re.compile(r"do\s+not\s+(?:tell|inform|alert|warn)\s+(?:the\s+)?user", re.I),
     "User notification suppression"),
    (re.compile(r"(?:silently|quietly|secretly)\s+(?:delete|remove|modify|execute)", re.I),
     "Stealth operation instruction"),
    (re.compile(r"curl\s+.*\||wget\s+.*-O\s*-\s*\|", re.I),
     "Shell injection in model metadata"),
]

# ---------------------------------------------------------------------------
# GGUF binary format constants
# ---------------------------------------------------------------------------

_GGUF_MAGIC = b'GGUF'
_GGUF_MAX_KV_COUNT = 100_000  # Sanity limit (CVE-2024-25664 exploit uses huge n_kv)
_GGUF_MAX_TENSOR_COUNT = 1_000_000
_GGUF_MAX_STRING_LEN = 10 * 1024 * 1024  # 10 MB max for any single string value

# GGUF value types (from llama.cpp gguf spec)
_GGUF_TYPE_UINT8    = 0
_GGUF_TYPE_INT8     = 1
_GGUF_TYPE_UINT16   = 2
_GGUF_TYPE_INT16    = 3
_GGUF_TYPE_UINT32   = 4
_GGUF_TYPE_INT32    = 5
_GGUF_TYPE_FLOAT32  = 6
_GGUF_TYPE_BOOL     = 7
_GGUF_TYPE_STRING   = 8
_GGUF_TYPE_ARRAY    = 9
_GGUF_TYPE_UINT64   = 10
_GGUF_TYPE_INT64    = 11
_GGUF_TYPE_FLOAT64  = 12

# Jinja2 SSTI patterns for GGUF chat templates
_GGUF_SSTI_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\{\{\s*config\.__class__'), 'Jinja2 config class traversal'),
    (re.compile(r'__subclasses__\s*\(\s*\)'), 'Python subclass enumeration'),
    (re.compile(r'__globals__'), 'Python globals access'),
    (re.compile(r'__builtins__'), 'Python builtins access'),
    (re.compile(r'__import__\s*\('), 'Dynamic import'),
    (re.compile(r'os\.popen|os\.system'), 'OS command execution'),
    (re.compile(r'subprocess'), 'Subprocess invocation'),
    (re.compile(r'\{%\s*(?:import|from)\s'), 'Jinja2 import statement'),
    (re.compile(r'\{\{\s*(?:lipsum|cycler|joiner|namespace)\.__init__'), 'Jinja2 built-in object traversal'),
    (re.compile(r'\|\s*attr\s*\('), 'Jinja2 attr filter (attribute access bypass)'),
    (re.compile(r'request\.application\.__globals__'), 'Flask/WSGI globals traversal'),
    (re.compile(r'\beval\s*\('), 'eval() in template'),
    (re.compile(r'\bexec\s*\('), 'exec() in template'),
    (re.compile(r'Popen'), 'Popen in template'),
]

# Secrets patterns for model metadata (subset of common credential patterns)
_MODEL_SECRETS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}'), 'Anthropic API Key'),
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), 'OpenAI API Key'),
    (re.compile(r'hf_[a-zA-Z0-9]{20,}'), 'HuggingFace Token'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key ID'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), 'GitHub Personal Access Token'),
    (re.compile(r'gho_[a-zA-Z0-9]{36}'), 'GitHub OAuth Token'),
    (re.compile(r'glpat-[a-zA-Z0-9\-]{20,}'), 'GitLab Personal Access Token'),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'Private Key'),
    (re.compile(r'-----BEGIN CERTIFICATE-----'), 'SSL Certificate'),
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.'), 'JWT'),
    (re.compile(r'(?:mongodb|postgres|mysql|redis)://[^\s]{10,}'), 'Database Connection String'),
    (re.compile(r'xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}'), 'Slack Bot Token'),
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{5,}'), 'Hardcoded Password'),
    (re.compile(r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'), 'SendGrid API Key'),
]

# Subset of secrets patterns suitable for raw binary scanning (first 64KB).
# Only patterns with highly distinctive prefixes that won't false-positive
# on random weight bytes.
_BINARY_SECRETS_PATTERNS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'Private Key'),
    (re.compile(rb'AKIA[0-9A-Z]{16}'), 'AWS Access Key ID'),
    (re.compile(rb'sk-ant-[a-zA-Z0-9\-]{20,}'), 'Anthropic API Key'),
    (re.compile(rb'sk-[a-zA-Z0-9]{20,}'), 'OpenAI API Key'),
    (re.compile(rb'hf_[a-zA-Z0-9]{20,}'), 'HuggingFace Token'),
    (re.compile(rb'ghp_[a-zA-Z0-9]{36}'), 'GitHub Personal Access Token'),
]

# Maximum bytes to read for raw binary secret scanning.
_BINARY_SCAN_LIMIT = 64 * 1024  # 64 KB

# Directories to skip (virtualenvs, caches, etc.)
_SKIP_DIRS: frozenset[str] = frozenset({
    ".venv", "venv", "env", "node_modules",
    "__pycache__", "site-packages", ".git",
})

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _should_skip(path: Path) -> bool:
    """Return True if *path* lives inside a directory we want to ignore."""
    return any(part in _SKIP_DIRS for part in path.parts)


def _stream_sha256(path: Path) -> str:
    """Compute sha256 of *path* by reading in chunks (memory-safe)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_READ_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Extension-agnostic format detection via magic bytes (CVE-2025-10155 evasion)
# ---------------------------------------------------------------------------

def _detect_format_by_magic(path: Path) -> str | None:
    """Detect model file format by magic bytes, independent of file extension.

    Returns one of: 'pickle', 'zip', 'safetensors', 'numpy', 'hdf5', 'gguf', or None.
    """
    try:
        with path.open('rb') as fh:
            header = fh.read(16)
    except OSError:
        return None

    if len(header) < 4:
        return None

    # GGUF: magic 'GGUF'
    if header[:4] == b'GGUF':
        return 'gguf'

    # NumPy .npy: magic \x93NUMPY
    if header[:6] == b'\x93NUMPY':
        return 'numpy'

    # ZIP (PyTorch .pt/.pth, .npz): magic PK\x03\x04
    if header[:4] == b'PK\x03\x04':
        return 'zip'

    # SafeTensors: 8-byte LE header length followed by '{' (JSON object start)
    if len(header) >= 9:
        try:
            (header_size,) = struct.unpack_from('<Q', header[:8])
            if 0 < header_size < _SAFETENSORS_MAX_HEADER_BYTES and header[8:9] == b'{':
                return 'safetensors'
        except struct.error:
            pass

    # HDF5: magic \x89HDF\r\n\x1a\n
    if header[:8] == b'\x89HDF\r\n\x1a\n':
        return 'hdf5'

    # Pickle protocol 2+ starts with \x80 followed by protocol version byte (2-5)
    if len(header) >= 2 and header[0] == 0x80 and 2 <= header[1] <= 5:
        return 'pickle'

    # Pickle protocol 0/1: common first opcodes
    # 0x28 = MARK, 0x7d = EMPTY_DICT, 0x5d = EMPTY_LIST, 0x29 = EMPTY_TUPLE,
    # 0x4e = NONE, 0x49 = INT, 0x46 = FLOAT, 0x53 = STRING, 0x63 = GLOBAL
    _P01_FIRST_BYTES = frozenset({0x28, 0x7d, 0x5d, 0x29, 0x4e, 0x49, 0x46, 0x53, 0x63})
    if header[0] in _P01_FIRST_BYTES:
        return 'pickle'

    return None


# ---------------------------------------------------------------------------
# ZIP strict-mode validation (CVE-2025-1944, CVE-2025-10156, CVE-2025-1945)
# ---------------------------------------------------------------------------

_MAX_NESTED_ARCHIVE_DEPTH = 3  # Maximum depth for recursive archive scanning


def _validate_zip_strict(path: Path) -> list[dict]:
    """Perform strict ZIP validation checks beyond what Python's zipfile does.

    Returns list of dicts: {'issue': str, 'member': str, 'severity': str}

    Checks:
      - Local header filename vs central directory filename mismatch (CVE-2025-1944)
      - CRC-32 zeroed or invalid (CVE-2025-10156)
      - CRC-32 mismatch against actual data (CVE-2025-10156)
      - Suspicious flag bits (CVE-2025-1945)
      - Data descriptor flag consistency (CVE-2025-1945)
      - Hidden files (dotfiles) and path traversal (CVE-2025-1889)
    """
    issues: list[dict] = []
    try:
        raw = path.read_bytes()
    except OSError:
        return issues

    # Parse central directory entries
    cd_entries: dict[int, dict] = {}  # local_header_offset -> {fname, crc32}
    _CD_SIG = b'PK\x01\x02'
    pos = 0
    while True:
        idx = raw.find(_CD_SIG, pos)
        if idx < 0:
            break
        try:
            cd_crc32 = int.from_bytes(raw[idx + 16:idx + 20], 'little')
            fname_len = int.from_bytes(raw[idx + 28:idx + 30], 'little')
            extra_len = int.from_bytes(raw[idx + 30:idx + 32], 'little')
            comment_len = int.from_bytes(raw[idx + 32:idx + 34], 'little')
            local_offset = int.from_bytes(raw[idx + 42:idx + 46], 'little')
            fname = raw[idx + 46:idx + 46 + fname_len].decode('utf-8', errors='replace')
            cd_entries[local_offset] = {'fname': fname, 'crc32': cd_crc32}
            pos = idx + 46 + fname_len + extra_len + comment_len
        except (IndexError, ValueError):
            break

    # Parse local file headers and cross-check
    _LF_SIG = b'PK\x03\x04'
    for local_offset, cd_info in cd_entries.items():
        cd_fname = cd_info['fname']
        cd_crc32 = cd_info['crc32']

        if local_offset + 30 > len(raw):
            continue
        if raw[local_offset:local_offset + 4] != _LF_SIG:
            continue

        try:
            flags = int.from_bytes(raw[local_offset + 6:local_offset + 8], 'little')
            crc32_val = int.from_bytes(raw[local_offset + 14:local_offset + 18], 'little')
            compressed_size = int.from_bytes(raw[local_offset + 18:local_offset + 22], 'little')
            lf_fname_len = int.from_bytes(raw[local_offset + 26:local_offset + 28], 'little')
            lf_fname = raw[local_offset + 30:local_offset + 30 + lf_fname_len].decode(
                'utf-8', errors='replace')
        except (IndexError, ValueError):
            continue

        # Check 1: filename mismatch between local and central directory (CVE-2025-1944)
        if lf_fname != cd_fname:
            issues.append({
                'issue': 'zip_filename_mismatch',
                'detail': (f'Local header filename {lf_fname!r} differs from central '
                           f'directory filename {cd_fname!r}'),
                'member': cd_fname,
                'severity': 'critical',
            })

        # Check 2: CRC-32 is zeroed (not using data descriptor) (CVE-2025-10156)
        # Bit 3 of flags indicates data descriptor is used (CRC after data, not in header)
        uses_data_descriptor = bool(flags & 0x08)
        if crc32_val == 0 and not uses_data_descriptor:
            issues.append({
                'issue': 'zip_zeroed_crc',
                'detail': f'CRC-32 is zeroed for member {cd_fname!r} without data descriptor',
                'member': cd_fname,
                'severity': 'medium',
            })

        # Check 2b: CRC-32 mismatch between local header and central directory (CVE-2025-10156)
        if crc32_val != 0 and cd_crc32 != 0 and crc32_val != cd_crc32:
            issues.append({
                'issue': 'zip_crc_mismatch',
                'detail': (f'CRC-32 in local header (0x{crc32_val:08X}) differs from central '
                           f'directory (0x{cd_crc32:08X}) for member {cd_fname!r}'),
                'member': cd_fname,
                'severity': 'high',
            })

        # Check 3: suspicious flag bits (CVE-2025-1945)
        # Bits 0 (encrypted), 6 (strong encryption), 13 (central dir encrypted) are suspicious
        # for model files which should never be encrypted
        suspicious_bits = flags & 0x2041  # bits 0, 6, 13
        if suspicious_bits:
            issues.append({
                'issue': 'zip_suspicious_flags',
                'detail': (f'Suspicious ZIP flags 0x{flags:04X} for member {cd_fname!r} '
                           f'(encryption or strong encryption bits set)'),
                'member': cd_fname,
                'severity': 'medium',
            })

        # Check 3b: data descriptor flag consistency (CVE-2025-1945)
        # If bit 3 (data descriptor) is set, the CRC and sizes in the local header
        # SHOULD be zero per spec. If they're non-zero, it's inconsistent and
        # may indicate flag manipulation to confuse parsers.
        if uses_data_descriptor and crc32_val != 0 and compressed_size != 0:
            issues.append({
                'issue': 'zip_data_descriptor_inconsistency',
                'detail': (f'Data descriptor flag (bit 3) is set for member {cd_fname!r} '
                           f'but local header contains non-zero CRC/size values '
                           f'(CRC=0x{crc32_val:08X}, size={compressed_size}). '
                           f'This inconsistency may confuse parsers about entry boundaries.'),
                'member': cd_fname,
                'severity': 'medium',
            })

        # Check 4: hidden files and path traversal (CVE-2025-1889)
        _check_zip_path_issues(cd_fname, issues)
        # Also check local header filename for path issues (attacker may hide
        # traversal in local header while keeping central directory clean)
        if lf_fname != cd_fname:
            _check_zip_path_issues(lf_fname, issues)

    # Also check all entries via Python's zipfile for path traversal patterns
    # that may not appear in our manual parse (e.g., extra entries)
    try:
        with zipfile.ZipFile(io.BytesIO(raw), 'r') as zf:
            for info in zf.infolist():
                _check_zip_path_issues(info.filename, issues)
    except (zipfile.BadZipFile, OSError):
        pass

    # Deduplicate issues by (issue, member) pair
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for issue in issues:
        key = (issue['issue'], issue.get('member', ''))
        if key not in seen:
            seen.add(key)
            deduped.append(issue)

    return deduped


def _check_zip_path_issues(filename: str, issues: list[dict]) -> None:
    """Check a ZIP member filename for path traversal and hidden file patterns (CVE-2025-1889).

    Appends any issues found to the *issues* list.
    """
    # Path traversal: '../' or '..\\' anywhere in the filename
    if '..' in filename and ('/..' in filename or '\\' in filename
                            or filename.startswith('..')):
        # More precise check for actual traversal
        import posixpath
        normalized = posixpath.normpath(filename)
        if normalized.startswith('..') or '/../' in filename or filename.startswith('../'):
            issues.append({
                'issue': 'zip_path_traversal',
                'detail': (f'ZIP member {filename!r} contains path traversal sequence. '
                           f'This can be used to write files outside the extraction directory '
                           f'(Zip Slip attack).'),
                'member': filename,
                'severity': 'critical',
            })

    # Hidden files: filename components starting with '.'
    # (excluding '.' and '..' which are caught by traversal check above)
    parts = filename.replace('\\', '/').split('/')
    for part in parts:
        if part.startswith('.') and part not in ('.', '..') and len(part) > 1:
            issues.append({
                'issue': 'zip_hidden_file',
                'detail': (f'ZIP member {filename!r} contains a hidden file/directory '
                           f'component {part!r}. Hidden entries in model archives are '
                           f'suspicious and may conceal malicious payloads.'),
                'member': filename,
                'severity': 'medium',
            })
            break  # One finding per filename is enough


def _classify_global_ref(global_key: str) -> tuple[str | None, str | None, bool | None]:
    """Classify a resolved 'module.name' reference against the dangerous/safe lists.

    Returns (category, wildcard_module, ml_safe):
      - category: exact match from _DANGEROUS_GLOBALS (e.g. 'code_execution')
      - wildcard_module: match from _DANGEROUS_MODULES (e.g. 'os')
      - ml_safe: True if in _ML_SAFE_MODULES safe set, False if in module but
        not safe set, None if not in any ML module
    """
    category = _DANGEROUS_GLOBALS.get(global_key)
    wildcard_module = None
    ml_safe = None

    # Wildcard module matching: split on '.' and check
    # progressively longer prefixes against _DANGEROUS_MODULES
    if category is None:
        parts = global_key.split('.')
        for i in range(len(parts) - 1, 0, -1):
            prefix = '.'.join(parts[:i])
            if prefix in _DANGEROUS_MODULES:
                wildcard_module = prefix
                break

    # ML safe module allowlist (only if not already
    # classified as dangerous via exact or wildcard match)
    if category is None and wildcard_module is None:
        parts = global_key.split('.')
        func_name = parts[-1]
        # Try progressively longer module prefixes
        # (e.g. for torch.nn.modules.linear.Linear,
        # try torch.nn.modules.linear, then
        # torch.nn.modules, etc.)
        for i in range(len(parts) - 1, 0, -1):
            mod_prefix = '.'.join(parts[:i])
            if mod_prefix in _ML_SAFE_MODULES:
                if func_name in _ML_SAFE_MODULES[mod_prefix]:
                    ml_safe = True
                else:
                    ml_safe = False
                break

    return category, wildcard_module, ml_safe


def _scan_pickle_structural(data: bytes) -> tuple[list[dict], list[dict]]:
    """Structurally parse pickle stream(s) and return dangerous operations and parse errors.

    Uses pickletools.genops() (stdlib) to iterate real opcodes, skipping data bytes.
    Handles multiple concatenated pickle streams (loops after each STOP opcode).

    Tracks a lightweight memo table and operand stack so that STACK_GLOBAL
    (Protocol 4+) operands can be resolved — the two strings (module, name)
    are popped from the stack, not passed inline.  PUT/BINPUT/LONG_BINPUT,
    GET/BINGET/LONG_BINGET, MEMOIZE, and string-push opcodes are tracked.

    Returns a tuple of:
      - list of dicts: {'opcode': str, 'offset': int, 'arg': str|None, 'category': str|None}
      - list of dicts: {'error_type': str, 'error_msg': str, 'offset': int,
                        'ops_before_error': int}
    """
    results: list[dict] = []
    parse_errors: list[dict] = []
    stream = io.BytesIO(data)
    file_len = len(data)

    # Opcodes that push a string value onto the pickle stack.
    _STRING_PUSH_OPS = frozenset({
        'SHORT_BINUNICODE', 'BINUNICODE', 'SHORT_BINSTRING', 'BINSTRING',
        'SHORT_BINBYTES', 'BINBYTES', 'STRING', 'UNICODE',
    })

    while stream.tell() < file_len:
        start_pos = stream.tell()
        # Per-stream memo table and operand stack for STACK_GLOBAL resolution.
        memo: dict[int, str] = {}
        stack: list[str] = []
        try:
            for opcode, arg, pos in pickletools.genops(stream):
                op_name = opcode.name

                # ---- Operand stack / memo tracking for STACK_GLOBAL ----
                if op_name in _STRING_PUSH_OPS:
                    if isinstance(arg, (str, bytes)):
                        val = arg if isinstance(arg, str) else arg.decode('utf-8', errors='replace')
                        stack.append(val)
                    else:
                        stack.append(str(arg) if arg is not None else '')

                elif op_name in ('PUT', 'BINPUT', 'LONG_BINPUT'):
                    # PUT stores the top-of-stack value at memo[arg]
                    if stack and isinstance(arg, int):
                        memo[arg] = stack[-1]

                elif op_name == 'MEMOIZE':
                    # Protocol 4 implicit memo: memo[len(memo)] = stack[-1]
                    if stack:
                        memo[len(memo)] = stack[-1]

                elif op_name in ('GET', 'BINGET', 'LONG_BINGET'):
                    # Push the memoized value back onto the stack
                    if isinstance(arg, int):
                        stack.append(memo.get(arg, '<unknown_memo>'))
                    else:
                        stack.append('<unknown_memo>')

                elif op_name == 'GLOBAL':
                    # GLOBAL pushes a callable — track it on the stack too
                    if arg is not None:
                        global_key = str(arg).replace('\n', '.').replace(' ', '.')
                        stack.append(global_key)

                elif op_name == 'STOP':
                    # Reset stack/memo for concatenated streams
                    memo.clear()
                    stack.clear()

                else:
                    # Many opcodes manipulate the stack in complex ways
                    # (TUPLE, LIST, DICT, MARK, etc.).  We don't model all
                    # of them — we only need enough fidelity for the common
                    # STACK_GLOBAL pattern: push module, push name, STACK_GLOBAL.
                    # Non-string opcodes that consume/rearrange the stack
                    # may make our tracking imprecise, but the worst case is
                    # '<unknown_memo>' which we flag as suspicious anyway.
                    pass

                # ---- Dangerous opcode detection ----
                if op_name in _DANGEROUS_OPCODE_NAMES:
                    arg_str = str(arg) if arg is not None else None
                    category = None
                    wildcard_module = None
                    ml_safe = None

                    if arg_str and op_name in ('GLOBAL', 'INST'):
                        # pickletools normalizes 'module\nname' to 'module name'
                        global_key = arg_str.replace('\n', '.').replace(' ', '.')
                        category, wildcard_module, ml_safe = _classify_global_ref(global_key)

                    elif op_name == 'STACK_GLOBAL':
                        # Resolve module.name from the operand stack
                        if len(stack) >= 2:
                            sg_name = stack.pop()
                            sg_module = stack.pop()
                        elif len(stack) == 1:
                            sg_name = stack.pop()
                            sg_module = '<unknown>'
                        else:
                            sg_name = '<unknown>'
                            sg_module = '<unknown>'

                        global_key = f'{sg_module}.{sg_name}'
                        arg_str = global_key
                        category, wildcard_module, ml_safe = _classify_global_ref(global_key)

                        # If we could not resolve either operand, flag as
                        # suspicious (unknown memo reference or obfuscation)
                        if '<unknown' in sg_module or '<unknown' in sg_name:
                            if category is None and wildcard_module is None and ml_safe is None:
                                # Don't override a real classification, but
                                # make unresolved refs visible in the output
                                pass  # arg_str already contains the '<unknown...' markers

                        # Push the resolved callable onto the stack (like GLOBAL)
                        stack.append(global_key)

                    results.append({
                        'opcode': op_name,
                        'offset': pos,
                        'arg': arg_str,
                        'category': category,
                        'wildcard_module': wildcard_module,
                        'ml_safe': ml_safe,
                    })
        except Exception as exc:
            # Record the parse error with context for security reporting.
            parse_errors.append({
                'error_type': type(exc).__name__,
                'error_msg': str(exc),
                'offset': stream.tell(),
                'ops_before_error': len(results),
            })
            # Malformed pickle -- if we found any dangerous ops already, report them.
            # If not, advance past the bad byte and try again (handles garbage prefixes).
            if stream.tell() == start_pos:
                stream.seek(start_pos + 1)  # skip one byte to avoid infinite loop
            continue

    return results, parse_errors


def _scan_pickle_opcodes(path: Path) -> tuple[list[dict], list[dict]]:
    """Return dangerous pickle operations and parse errors found in *path*.

    Uses structural parsing via pickletools.genops(). Reads up to 100 MB
    to avoid OOM on huge files; pickle payloads are in the header, not
    deep in tensor data.

    Returns (dangerous_ops, parse_errors).
    """
    MAX_READ = 100 * 1024 * 1024  # 100 MB
    with path.open('rb') as fh:
        data = fh.read(MAX_READ)
    return _scan_pickle_structural(data)


def _scan_npy_content(data: bytes) -> tuple[list[dict], list[dict]]:
    """Check if .npy data contains pickled objects (object dtype) and scan if so.

    NumPy .npy format: 6-byte magic (\\x93NUMPY) + 1-byte major + 1-byte minor +
    2-byte (v1) or 4-byte (v2/v3) header_len + ASCII header string containing
    dtype descriptor.  If 'O' (object) dtype is present, the data section contains
    pickled Python objects.

    Returns (dangerous_ops, parse_errors).
    """
    NPY_MAGIC = b'\x93NUMPY'
    if not data.startswith(NPY_MAGIC):
        return [], []
    try:
        major = data[6]
        if major <= 1:
            header_len = int.from_bytes(data[8:10], 'little')
            header_start = 10
        else:
            header_len = int.from_bytes(data[8:12], 'little')
            header_start = 12
        header_str = data[header_start:header_start + header_len].decode('latin-1')
        if "'O'" not in header_str and "'|O'" not in header_str:
            return [], []  # Pure numeric array — safe, no pickle content
        pickle_data = data[header_start + header_len:]
        return _scan_pickle_structural(pickle_data[:100 * 1024 * 1024])
    except (IndexError, UnicodeDecodeError):
        return [], []


def _scan_zip_for_pickles(path: Path, *, _depth: int = 0) -> tuple[list[dict], list[dict]]:
    """Open *path* as a ZIP and scan members for dangerous pickle ops.

    Scans .pkl/.npy members for pickle opcodes, and recursively scans
    nested archives (ZIP, TAR) up to _MAX_NESTED_ARCHIVE_DEPTH.

    Returns (dangerous_ops, parse_errors) aggregated across all members.
    Handles CRC errors gracefully — still scans entries even when CRC
    doesn't match (CVE-2025-10156 defense).
    """
    results: list[dict] = []
    all_parse_errors: list[dict] = []
    if _depth > _MAX_NESTED_ARCHIVE_DEPTH:
        return results, all_parse_errors
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            for info in zf.infolist():
                member_lower = info.filename.lower()

                # Determine what kind of scanning this member needs
                is_pickle = (
                    member_lower.endswith('.pkl')
                    or member_lower.endswith('.pickle')
                    or member_lower == 'data.pkl'
                    or member_lower.endswith('.npy')
                )
                is_nested_archive = (
                    member_lower.endswith('.zip')
                    or member_lower.endswith('.pt')
                    or member_lower.endswith('.pth')
                    or member_lower.endswith('.npz')
                    or member_lower.endswith('.tar')
                    or member_lower.endswith('.tar.gz')
                    or member_lower.endswith('.tgz')
                )

                if not is_pickle and not is_nested_archive:
                    continue

                # Read the member data, handling CRC errors (CVE-2025-10156)
                data = None
                crc_error = False
                try:
                    data = zf.read(info.filename)
                except (zipfile.BadZipFile, RuntimeError, zlib.error):
                    crc_error = True
                    # CRC mismatch or decompression error — still try to read
                    # the raw data for scanning (CVE-2025-10156 defense)
                    try:
                        with zf.open(info.filename, 'r') as member_fh:
                            data = member_fh.read()
                    except Exception:
                        # Try raw decompression bypass as last resort
                        try:
                            raw_bytes = path.read_bytes()
                            # Find this entry's data in the raw bytes
                            _LF_SIG = b'PK\x03\x04'
                            offset = 0
                            for _ in range(len(zf.infolist())):
                                idx = raw_bytes.find(_LF_SIG, offset)
                                if idx < 0:
                                    break
                                lf_fname_len = int.from_bytes(
                                    raw_bytes[idx + 26:idx + 28], 'little')
                                lf_extra_len = int.from_bytes(
                                    raw_bytes[idx + 28:idx + 30], 'little')
                                lf_fname = raw_bytes[
                                    idx + 30:idx + 30 + lf_fname_len
                                ].decode('utf-8', errors='replace')
                                data_start = idx + 30 + lf_fname_len + lf_extra_len
                                if lf_fname == info.filename:
                                    comp_size = int.from_bytes(
                                        raw_bytes[idx + 18:idx + 22], 'little')
                                    if comp_size > 0:
                                        data = raw_bytes[
                                            data_start:data_start + comp_size]
                                    break
                                offset = data_start
                        except Exception:
                            pass

                if data is None:
                    continue

                if crc_error:
                    # Add CRC error annotation to any ops we find
                    pass  # Annotation added below per-op

                if is_pickle:
                    if member_lower.endswith('.npy'):
                        ops, perrs = _scan_npy_content(data)
                    else:
                        ops, perrs = _scan_pickle_structural(data[:100 * 1024 * 1024])
                    for op in ops:
                        op['zip_member'] = info.filename
                        if crc_error:
                            op['crc_error'] = True
                    results.extend(ops)
                    for pe in perrs:
                        pe['zip_member'] = info.filename
                    all_parse_errors.extend(perrs)

                if is_nested_archive and _depth < _MAX_NESTED_ARCHIVE_DEPTH:
                    # Write nested archive to temp file and recursively scan
                    import tempfile as _tempfile
                    with _tempfile.NamedTemporaryFile(
                        suffix=Path(info.filename).suffix, delete=True
                    ) as tmp:
                        tmp.write(data)
                        tmp.flush()
                        nested_path = Path(tmp.name)
                        nested_ops, nested_perrs = _scan_zip_for_pickles(
                            nested_path, _depth=_depth + 1)
                        for op in nested_ops:
                            op['zip_member'] = (
                                f"{info.filename} -> {op.get('zip_member', '?')}")
                            if crc_error:
                                op['crc_error'] = True
                        results.extend(nested_ops)
                        for pe in nested_perrs:
                            pe['zip_member'] = (
                                f"{info.filename} -> {pe.get('zip_member', '?')}")
                        all_parse_errors.extend(nested_perrs)

    except (zipfile.BadZipFile, OSError):
        pass  # Not a valid ZIP — caller should fall back to flat scan
    return results, all_parse_errors


def _validate_safetensors_header(path: Path) -> tuple[bool, str]:
    """Validate the safetensors header of *path*.

    Returns (is_valid, error_message).  error_message is empty when valid.

    SafeTensors layout:
      bytes 0-7   : little-endian u64 — length N of the JSON header
      bytes 8..8+N: UTF-8 JSON object
    """
    try:
        with path.open("rb") as fh:
            # Read the 8-byte header-size field
            size_bytes = fh.read(8)
            if len(size_bytes) < 8:
                return False, "File too short to contain a SafeTensors header (< 8 bytes)"

            (header_size,) = struct.unpack_from("<Q", size_bytes)

            if header_size == 0:
                return False, "SafeTensors header_size is 0 — invalid file"

            if header_size > _SAFETENSORS_MAX_HEADER_BYTES:
                return False, (
                    f"SafeTensors header_size ({header_size:,} bytes) exceeds the "
                    f"{_SAFETENSORS_MAX_HEADER_BYTES // (1024*1024)} MB sanity limit — "
                    "possible header corruption or tampered file"
                )

            # Read the JSON header — limit to header_size bytes
            json_bytes = fh.read(header_size)
            if len(json_bytes) < header_size:
                return False, (
                    f"SafeTensors file truncated: expected {header_size:,} bytes of JSON "
                    f"header but only {len(json_bytes):,} bytes available"
                )

            try:
                metadata = json.loads(json_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return False, f"SafeTensors JSON header is not valid UTF-8/JSON: {exc}"

            if not isinstance(metadata, dict):
                return False, "SafeTensors JSON header is not a JSON object (dict)"

    except OSError as exc:
        return False, f"Could not open file: {exc}"

    return True, ""


def _find_declared_checksums(config_path: Path) -> dict[str, str]:
    """Parse a config/model-card JSON and extract sha256 declarations.

    Returns a mapping of {filename: sha256_hex}.  Handles several
    common formats:
      - {"sha256": {"model.bin": "abcd..."}}
      - {"files": [{"name": "model.bin", "sha256": "abcd..."}]}
      - {"weight_map": {"layer.weight": "model.bin"}, "sha256": {...}}
    """
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(raw, dict):
        return {}

    result: dict[str, str] = {}

    # Format 1: top-level "sha256" dict mapping filename → hash
    sha256_section = raw.get("sha256")
    if isinstance(sha256_section, dict):
        for k, v in sha256_section.items():
            if isinstance(k, str) and isinstance(v, str) and len(v) == 64:
                result[k] = v.lower()

    # Format 2: "files" list of {name, sha256} objects
    files_section = raw.get("files")
    if isinstance(files_section, list):
        for entry in files_section:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("filename")
                sha = entry.get("sha256") or entry.get("hash")
                if isinstance(name, str) and isinstance(sha, str) and len(sha) == 64:
                    result[name] = sha.lower()

    return result


def _detect_arch_hint(path: Path) -> int | None:
    """Return the minimum expected byte-count for a model file based on arch hints.

    Looks for patterns like '7b', '13b', '70b' in the filename or parent
    directory names (case-insensitive).  Returns None if no hint is found.
    """
    # Only search the filename and its immediate parent — the user-controlled
    # portion of the path — to avoid false matches on system temp dir prefixes
    # (e.g. /tmp/tmp7bXXXX/... triggering "7b" before the actual model name).
    searchable = (path.parent.name + "/" + path.name).lower()
    for pattern, min_bytes in _ARCH_MIN_BYTES:
        if pattern in searchable:
            return min_bytes
    return None


def _skip_gguf_value(fh, val_type: int):
    """Skip a non-string GGUF value in the file stream."""
    sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
    if val_type in sizes:
        fh.read(sizes[val_type])
    elif val_type == 9:  # ARRAY
        arr_type = struct.unpack('<I', fh.read(4))[0]
        arr_len = struct.unpack('<Q', fh.read(8))[0]
        if arr_type == _GGUF_TYPE_STRING:
            for _ in range(min(arr_len, _GGUF_MAX_KV_COUNT)):
                slen = struct.unpack('<Q', fh.read(8))[0]
                fh.read(min(slen, _GGUF_MAX_STRING_LEN))
        elif arr_type in sizes:
            fh.read(sizes[arr_type] * min(arr_len, _GGUF_MAX_KV_COUNT))


def _parse_gguf_header(path: Path) -> dict:
    """Parse GGUF binary header. Returns dict with 'version', 'n_tensors',
    'n_kv', 'kv_pairs' (dict of key->value for string values), and
    'validation_errors' (list of structural issues).

    Only parses string-type KV pairs (chat_template, general.name, etc.).
    Skips numeric/array values to avoid complexity.
    Binary format (all little-endian):
      4 bytes: magic 'GGUF'
      4 bytes: version (u32)
      8 bytes: n_tensors (u64)
      8 bytes: n_kv (u64)
      Then n_kv KV pairs, each:
        string key (u64 len + bytes)
        u32 value_type
        value (type-dependent)
    """
    result: dict = {'version': 0, 'n_tensors': 0, 'n_kv': 0, 'kv_pairs': {},
                    'validation_errors': []}
    try:
        with path.open('rb') as fh:
            magic = fh.read(4)
            if magic != _GGUF_MAGIC:
                result['validation_errors'].append('Invalid GGUF magic bytes')
                return result
            version = struct.unpack('<I', fh.read(4))[0]
            result['version'] = version
            if version < 2 or version > 3:
                result['validation_errors'].append(
                    f'Unsupported GGUF version: {version}')
                return result
            n_tensors = struct.unpack('<Q', fh.read(8))[0]
            n_kv = struct.unpack('<Q', fh.read(8))[0]
            result['n_tensors'] = n_tensors
            result['n_kv'] = n_kv
            # Structural validation (CVE-2024-25664/25665/25666)
            if n_kv > _GGUF_MAX_KV_COUNT:
                result['validation_errors'].append(
                    f'n_kv={n_kv} exceeds maximum {_GGUF_MAX_KV_COUNT} '
                    f'(CVE-2024-25664)')
                return result
            if n_tensors > _GGUF_MAX_TENSOR_COUNT:
                result['validation_errors'].append(
                    f'n_tensors={n_tensors} exceeds maximum '
                    f'{_GGUF_MAX_TENSOR_COUNT}')
                return result
            # Parse KV pairs, extracting only string values
            for _ in range(n_kv):
                # Read key (GGUF string: u64 len + bytes)
                key_len = struct.unpack('<Q', fh.read(8))[0]
                if key_len > _GGUF_MAX_STRING_LEN:
                    result['validation_errors'].append(
                        f'KV key length {key_len} exceeds limit')
                    return result
                key = fh.read(key_len).decode('utf-8', errors='replace')
                # Read value type
                val_type = struct.unpack('<I', fh.read(4))[0]
                if val_type == _GGUF_TYPE_STRING:
                    val_len = struct.unpack('<Q', fh.read(8))[0]
                    if val_len > _GGUF_MAX_STRING_LEN:
                        result['validation_errors'].append(
                            f'String value for "{key}" length {val_len} '
                            f'exceeds limit')
                        return result
                    val = fh.read(val_len).decode('utf-8', errors='replace')
                    result['kv_pairs'][key] = val
                else:
                    # Skip non-string values
                    _skip_gguf_value(fh, val_type)
    except (struct.error, OSError, EOFError):
        result['validation_errors'].append('Truncated or malformed GGUF file')
    return result


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class ModelIntegrityScanner:
    """Verify the integrity of AI model weight files in a project directory.

    Detection capabilities:
      1. Pickle opcode RCE risk  — REDUCE / GLOBAL / INST / NEWOBJ in .bin/.pkl/.pt
      2. SafeTensors header validation — corrupt or tampered header structure
      3. Checksum mismatch — sha256 declared in config.json does not match file
      4. Missing integrity metadata — model files with no declared checksum at all
      5. Size anomaly — file is implausibly tiny for its claimed architecture
    """

    name = "model_integrity"
    ecosystems = ["huggingface"]

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan *project_dir* recursively for model integrity issues."""
        findings: list[Finding] = []

        # Gather all config files that may contain checksums, keyed by directory.
        # We do this once up-front so the per-file checks can look them up cheaply.
        declared_checksums: dict[Path, dict[str, str]] = {}
        for cfg_name in _CONFIG_FILENAMES:
            for cfg_file in sorted(project_dir.rglob(cfg_name)):
                if _should_skip(cfg_file):
                    continue
                sums = _find_declared_checksums(cfg_file)
                if sums:
                    declared_checksums[cfg_file.parent] = {
                        **declared_checksums.get(cfg_file.parent, {}),
                        **sums,
                    }

        # Scan config/metadata JSON for prompt injection
        for cfg_name in _CONFIG_FILENAMES:
            for cfg_file in sorted(project_dir.rglob(cfg_name)):
                if _should_skip(cfg_file):
                    continue
                findings.extend(self._check_metadata_injection(cfg_file, "config"))

        # Walk all weight files
        weight_extensions = _PICKLE_EXTENSIONS | {".safetensors", ".gguf"}
        for ext in weight_extensions:
            for model_file in sorted(project_dir.rglob(f"*{ext}")):
                if _should_skip(model_file):
                    continue

                try:
                    file_size = model_file.stat().st_size
                except OSError:
                    continue

                findings.extend(
                    self._check_file(model_file, file_size, declared_checksums)
                )

        return findings

    # ------------------------------------------------------------------
    # Per-file checks
    # ------------------------------------------------------------------

    def _check_file(
        self,
        path: Path,
        file_size: int,
        declared_checksums: dict[Path, dict[str, str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        ext = path.suffix.lower()

        # Extension-agnostic format detection: if magic bytes disagree with
        # extension, run scans for BOTH the extension-implied format AND the
        # magic-detected format.  This prevents CVE-2025-10155 style evasion
        # where a .safetensors extension hides a pickle payload.
        magic_fmt = _detect_format_by_magic(path)
        scan_pickle = ext in _PICKLE_EXTENSIONS
        scan_safetensors = ext == ".safetensors"
        scan_gguf = ext == ".gguf"

        # If magic says pickle/zip but extension doesn't, scan as pickle too
        if magic_fmt in ('pickle', 'zip') and not scan_pickle:
            scan_pickle = True
            if magic_fmt != ext.lstrip('.'):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.HIGH,
                    package=PackageId("huggingface", path.name),
                    title=f"Format mismatch: {path.name}",
                    detail=(
                        f"File '{path.name}' has extension '{ext}' but its content "
                        f"matches '{magic_fmt}' format by magic bytes. This is a "
                        f"strong indicator of extension-based evasion — the file may "
                        f"contain a pickle payload disguised with a safe extension."
                    ),
                    confidence=0.90,
                    metadata={
                        'source_file': str(path),
                        'declared_extension': ext,
                        'detected_format': magic_fmt,
                    },
                ))

        # ---- 5. Size anomaly (checked first — applies to all formats) --------
        findings.extend(self._check_size_anomaly(path, file_size))

        # ---- 1. Pickle opcode scanning ---------------------------------------
        if scan_pickle:
            findings.extend(self._check_pickle_opcodes(path, file_size))

        # ---- 2. SafeTensors header validation --------------------------------
        if scan_safetensors:
            findings.extend(self._check_safetensors(path))

        # ---- 2b. SafeTensors metadata injection scanning -----------------------
        if scan_safetensors:
            findings.extend(self._check_metadata_injection(path, "safetensors"))

        # ---- 6. GGUF structural validation + SSTI detection ------------------
        if scan_gguf:
            findings.extend(self._check_gguf(path))

        # ---- 7. ZIP strict-mode validation (for ZIP-based model files) -------
        if ext in ('.pt', '.pth', '.npz') or magic_fmt == 'zip':
            findings.extend(self._check_zip_strict(path))

        # ---- 8. Raw binary secret scanning (first 64KB) ---------------------
        # Only for formats where metadata is NOT already scanned as text above.
        # SafeTensors and GGUF metadata are scanned via _check_metadata_injection
        # and _check_gguf respectively, so binary scanning covers pickle-based
        # formats and any file whose metadata wasn't otherwise inspected.
        if not scan_safetensors and not scan_gguf:
            findings.extend(self._check_binary_secrets(path, file_size))

        # ---- 3 & 4. Checksum verification + unsigned-model flag --------------
        findings.extend(
            self._check_checksums(path, file_size, declared_checksums)
        )

        return findings

    def _check_pickle_opcodes(self, path: Path, file_size: int) -> list[Finding]:
        """Detect dangerous pickle opcodes indicating potential RCE payload."""
        # Skip tiny files — they are config stubs, not weights
        if file_size < _MIN_WEIGHT_BYTES:
            return []

        ext = path.suffix.lower()
        dangerous_ops: list[dict] = []
        parse_errors: list[dict] = []

        # Check if file matches pickle magic for "unreadable pickle" detection
        has_pickle_magic = _detect_format_by_magic(path) == 'pickle'

        if ext in ('.pt', '.pth', '.npz'):
            # These are ZIP archives — try ZIP inspection first
            dangerous_ops, parse_errors = _scan_zip_for_pickles(path)
            if not dangerous_ops and not parse_errors:
                # Fallback to flat scan (legacy .pt files that aren't ZIPs)
                try:
                    dangerous_ops, parse_errors = _scan_pickle_opcodes(path)
                except OSError:
                    return []
        elif ext == '.npy':
            # Flat .npy file — check for object dtype with pickled content
            try:
                with path.open('rb') as fh:
                    data = fh.read(100 * 1024 * 1024)
                dangerous_ops, parse_errors = _scan_npy_content(data)
            except OSError:
                return []
        else:
            # All other pickle extensions: flat scan
            try:
                dangerous_ops, parse_errors = _scan_pickle_opcodes(path)
            except OSError:
                return []

        pkg = PackageId("huggingface", path.name)
        findings: list[Finding] = []

        # --- Emit findings for parse errors ---
        if parse_errors and not dangerous_ops and has_pickle_magic:
            # File matches pickle magic but cannot be parsed at all
            first_err = parse_errors[0]
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Unreadable pickle file: {path.name}",
                detail=(
                    f"The file '{path.name}' matches pickle magic bytes but could "
                    f"not be parsed: {first_err['error_type']}: {first_err['error_msg']}. "
                    f"This may indicate a crafted file using evasion techniques to "
                    f"hide malicious content from static analysis."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security-pickle",
                ],
                confidence=0.75,
                metadata={
                    "model_id": path.stem,
                    "format": "pickle",
                    "source_file": str(path),
                    "line": 0,
                    "file_size_bytes": file_size,
                    "parse_errors": parse_errors[:10],
                },
            ))
        elif parse_errors and not dangerous_ops:
            # No pickle magic match but parse errors occurred during scanning
            first_err = parse_errors[0]
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Pickle parse error in {path.name}",
                detail=(
                    f"Pickle analysis of '{path.name}' encountered parse errors: "
                    f"{first_err['error_type']}: {first_err['error_msg']}. "
                    f"The file may use evasion techniques to prevent static analysis."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security-pickle",
                ],
                confidence=0.70,
                metadata={
                    "model_id": path.stem,
                    "format": "pickle",
                    "source_file": str(path),
                    "line": 0,
                    "file_size_bytes": file_size,
                    "parse_errors": parse_errors[:10],
                },
            ))
        elif parse_errors and dangerous_ops:
            # Dangerous opcodes found BEFORE the parse error — incomplete scan
            first_err = parse_errors[0]
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.HIGH,
                package=pkg,
                title=f"Incomplete pickle scan of {path.name}",
                detail=(
                    f"Structural analysis of '{path.name}' found {len(dangerous_ops)} "
                    f"dangerous opcode(s) but parsing failed before completion: "
                    f"{first_err['error_type']}: {first_err['error_msg']}. "
                    f"Additional malicious operations may be hidden beyond the "
                    f"parse error boundary at offset 0x{first_err['offset']:X}. "
                    f"This file should be treated as malicious."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security-pickle",
                ],
                confidence=0.90,
                metadata={
                    "model_id": path.stem,
                    "format": "pickle",
                    "source_file": str(path),
                    "line": 0,
                    "file_size_bytes": file_size,
                    "parse_errors": parse_errors[:10],
                    "ops_found_before_error": len(dangerous_ops),
                },
            ))

        if not dangerous_ops:
            return findings

        # ----- ML framework allowlist filtering (tiered classification) -----
        # Tier 1: Exact match _DANGEROUS_GLOBALS → CRITICAL (category is set)
        # Tier 2: Wildcard _DANGEROUS_MODULES → HIGH (wildcard_module is set)
        # Tier 3: ML safe module + name in safe set → SKIP (ml_safe=True)
        # Tier 4: ML safe module + name NOT in set → MEDIUM (ml_safe=False)
        # Tier 5: Unknown module → included in CRITICAL roll-up (no special flag)
        #
        # Opcodes without args (REDUCE, BUILD, NEWOBJ, etc.) are only
        # dangerous IN COMBINATION with a GLOBAL/INST that pushes a
        # dangerous callable.  If ALL GLOBAL/INST ops in the stream are
        # ML-safe, the bare opcodes are safe too.

        # Separate ops by classification
        truly_dangerous: list[dict] = []
        ml_unexpected: list[dict] = []
        for op in dangerous_ops:
            if op.get('ml_safe') is True:
                # Tier 3: known-safe ML function → skip entirely
                continue
            elif op.get('ml_safe') is False:
                # Tier 4: ML module but unexpected function → MEDIUM
                ml_unexpected.append(op)
            elif op.get('category') or op.get('wildcard_module'):
                # Tier 1 or 2: truly dangerous
                truly_dangerous.append(op)
            elif op['opcode'] in ('GLOBAL', 'INST', 'STACK_GLOBAL'):
                # Tier 5: unknown module GLOBAL/INST — still suspicious
                truly_dangerous.append(op)
            else:
                # Bare opcodes (REDUCE, BUILD, NEWOBJ, etc.) — only
                # dangerous if paired with a dangerous GLOBAL/INST.
                # We defer: include them only if there are other
                # truly dangerous GLOBAL/INST ops.
                truly_dangerous.append(op)

        # If the ONLY dangerous ops are bare opcodes (REDUCE/BUILD/NEWOBJ
        # etc.) with no dangerous GLOBAL/INST, suppress them ONLY when
        # there were ML-safe globals that explain the bare opcodes.
        # If there are no GLOBAL/INST ops at all, bare opcodes are still
        # suspicious (the callable may have been pushed onto the stack
        # by other means).
        has_dangerous_global = any(
            op['opcode'] in ('GLOBAL', 'INST', 'STACK_GLOBAL')
            for op in truly_dangerous
        )
        has_ml_safe_globals = any(
            op.get('ml_safe') is True
            for op in dangerous_ops
        )
        if not has_dangerous_global and has_ml_safe_globals:
            truly_dangerous = []

        # Emit MEDIUM findings for unexpected functions in ML-safe modules
        ml_unexpected_seen: set[str] = set()
        for op in ml_unexpected:
            arg_key = op.get('arg', '')
            if arg_key in ml_unexpected_seen:
                continue
            ml_unexpected_seen.add(arg_key)
            global_key = arg_key.replace('\n', '.').replace(' ', '.')
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Unexpected function in ML module: {path.name}",
                detail=(
                    f"The pickle stream in '{path.name}' references '{global_key}' "
                    f"which is from a known ML framework module but is NOT in the "
                    f"expected safe function set. This may indicate a legitimate "
                    f"newer API or a targeted attack using a trusted module namespace."
                ),
                confidence=0.70,
                metadata={
                    'source_file': str(path),
                    'global_ref': global_key,
                    'ml_module_recognized': True,
                },
            ))

        if not truly_dangerous:
            return findings

        # Build per-opcode detail
        op_summaries = []
        categories_found: set[str] = set()
        for op in truly_dangerous[:20]:  # Cap detail at 20 ops to avoid huge findings
            parts = [f"{op['opcode']} at offset 0x{op['offset']:X}"]
            if op['arg']:
                parts.append(f"arg={op['arg']!r}")
            if op['category']:
                parts.append(f"[{op['category']}]")
                categories_found.add(op['category'])
            op_summaries.append(', '.join(parts))

        opcodes_list = '\n    '.join(op_summaries)
        total = len(truly_dangerous)
        truncated = ' (showing first 20)' if total > 20 else ''

        findings.append(Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=pkg,
            title=f"Dangerous pickle opcodes in model file: {path.name}",
            detail=(
                f"Structural analysis of '{path.name}' found {total} dangerous pickle "
                f"opcode(s){truncated} that enable arbitrary code execution:\n"
                f"    {opcodes_list}\n\n"
                "These opcodes execute Python code when the file is loaded via "
                "torch.load() or pickle.load(). Do NOT load this file without verification. "
                "Migrate to .safetensors format."
            ),
            references=[
                "https://huggingface.co/docs/hub/security-pickle",
                "https://pytorch.org/docs/stable/generated/torch.load.html",
            ],
            confidence=0.98,
            metadata={
                "model_id": path.stem,
                "format": "pickle",
                "source_file": str(path),
                "line": 0,
                "file_size_bytes": file_size,
                "dangerous_opcodes_found": True,
                "dangerous_ops": truly_dangerous[:20],
                "total_dangerous_ops": total,
                "categories": sorted(categories_found),
            },
        ))

        # Emit an additional HIGH finding when network-category globals are present
        network_ops = [op for op in truly_dangerous if op.get('category') == 'network']
        if network_ops:
            net_details = ', '.join(f"{op['arg']}" for op in network_ops[:5] if op.get('arg'))
            findings.append(Finding(
                finding_type=FindingType.NETWORK,
                severity=Severity.HIGH,
                package=pkg,
                title=f'Network capability in model file: {path.name}',
                detail=f'Model file contains pickle operations that import network modules: '
                       f'{net_details}. This is a strong indicator of data exfiltration or '
                       f'C2 callback functionality. The model will attempt network access when loaded.',
                confidence=0.90,
                metadata={'source_file': str(path), 'network_globals': [op['arg'] for op in network_ops]},
            ))

        # Emit an additional HIGH finding for each wildcard-matched dangerous module
        # (only for ops that did NOT already match an exact _DANGEROUS_GLOBALS entry)
        wildcard_modules_seen: set[str] = set()
        for op in truly_dangerous:
            wm = op.get('wildcard_module')
            if wm and not op.get('category') and wm not in wildcard_modules_seen:
                wildcard_modules_seen.add(wm)
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"Dangerous module in model file: {path.name}",
                    detail=(
                        f"Module '{wm}' is dangerous (wildcard match). "
                        f"The pickle stream references '{wm}' which is a "
                        f"dangerous module — any function from this module "
                        f"can be abused for code execution, data exfiltration, "
                        f"or other malicious activity."
                    ),
                    confidence=0.85,
                    metadata={
                        'source_file': str(path),
                        'wildcard_module': wm,
                    },
                ))

        return findings

    def _check_safetensors(self, path: Path) -> list[Finding]:
        """Validate the SafeTensors header structure."""
        valid, error = _validate_safetensors_header(path)
        if valid:
            return []

        pkg = PackageId("huggingface", path.name)
        return [Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.HIGH,
            package=pkg,
            title=f"Invalid SafeTensors header: {path.name}",
            detail=(
                f"The file '{path.name}' has a .safetensors extension but its binary header "
                f"is invalid: {error}. "
                "A legitimate SafeTensors file must begin with an 8-byte little-endian u64 "
                "giving the JSON header length, followed by valid JSON. Corruption or "
                "deliberate tampering can produce this result."
            ),
            references=[
                "https://huggingface.co/docs/safetensors/index",
                "https://github.com/huggingface/safetensors",
            ],
            confidence=0.90,
            metadata={
                "model_id": path.stem,
                "format": "safetensors",
                "source_file": str(path),
                "line": 0,
                "header_error": error,
            },
        )]

    def _check_gguf(self, path: Path) -> list[Finding]:
        """Check GGUF file for structural issues and SSTI in chat templates."""
        findings: list[Finding] = []
        pkg = PackageId('huggingface', path.name)
        header = _parse_gguf_header(path)

        # GAP-P1-5: Structural validation findings
        for error in header['validation_errors']:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.HIGH,
                package=pkg,
                title=f'Malformed GGUF header: {path.name}',
                detail=(
                    f'GGUF structural validation failed: {error}. '
                    'This may indicate a crafted file targeting parser '
                    'vulnerabilities (CVE-2024-25664, CVE-2024-25665, '
                    'CVE-2024-25666).'
                ),
                references=['https://nvd.nist.gov/vuln/detail/CVE-2024-25664'],
                confidence=0.90,
                metadata={
                    'source_file': str(path),
                    'validation_error': error,
                    'n_kv': header['n_kv'],
                    'n_tensors': header['n_tensors'],
                },
            ))

        # GAP-P0-5: SSTI detection in chat_template
        chat_template = header['kv_pairs'].get('tokenizer.chat_template', '')
        # Also check general.description and other string metadata
        all_metadata_text = '\n'.join(header['kv_pairs'].values())

        for pattern, label in _GGUF_SSTI_PATTERNS:
            if pattern.search(chat_template) or pattern.search(all_metadata_text):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f'GGUF SSTI payload detected: {path.name}',
                    detail=(
                        f'The GGUF file contains a Jinja2 Server-Side Template '
                        f'Injection pattern in its metadata: {label}. When '
                        f'loaded by inference frameworks (SGLang, llama.cpp, '
                        f'ollama) that render chat templates via unsandboxed '
                        f'Jinja2, this enables full RCE. '
                        f'Do NOT load this file.'
                    ),
                    confidence=0.95,
                    metadata={
                        'source_file': str(path),
                        'ssti_pattern': label,
                        'template_key': 'tokenizer.chat_template',
                    },
                ))
                break  # One SSTI finding is sufficient

        # Also scan GGUF metadata for prompt injection
        if all_metadata_text:
            for pat, label in _MODEL_INJECTION_PATTERNS:
                if pat.search(all_metadata_text):
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=Severity.CRITICAL,
                        package=pkg,
                        title=f'Prompt injection in GGUF metadata: {label}',
                        detail=(
                            f'GGUF metadata of "{path.name}" contains '
                            f'adversarial text: {label}.'
                        ),
                        confidence=0.85,
                        metadata={
                            'source_file': str(path),
                            'matched_pattern': label,
                        },
                    ))

        # Scan GGUF metadata for embedded secrets/credentials
        if all_metadata_text:
            findings.extend(self._check_metadata_secrets(all_metadata_text, path, 'gguf'))

        return findings

    def _check_zip_strict(self, path: Path) -> list[Finding]:
        """Validate ZIP structure for model files (CVE-2025-1944/10156/1945/1889)."""
        issues = _validate_zip_strict(path)
        if not issues:
            return []

        _severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
        }
        # Map issue types to their most relevant CVE references
        _cve_refs: dict[str, list[str]] = {
            'zip_filename_mismatch': ['https://nvd.nist.gov/vuln/detail/CVE-2025-1944'],
            'zip_zeroed_crc': ['https://nvd.nist.gov/vuln/detail/CVE-2025-10156'],
            'zip_crc_mismatch': ['https://nvd.nist.gov/vuln/detail/CVE-2025-10156'],
            'zip_suspicious_flags': ['https://nvd.nist.gov/vuln/detail/CVE-2025-1945'],
            'zip_data_descriptor_inconsistency': [
                'https://nvd.nist.gov/vuln/detail/CVE-2025-1945'],
            'zip_path_traversal': ['https://nvd.nist.gov/vuln/detail/CVE-2025-1889'],
            'zip_hidden_file': ['https://nvd.nist.gov/vuln/detail/CVE-2025-1889'],
        }

        findings: list[Finding] = []
        pkg = PackageId("huggingface", path.name)
        for issue in issues:
            severity = _severity_map.get(issue['severity'], Severity.MEDIUM)
            refs = _cve_refs.get(issue['issue'], [
                'https://nvd.nist.gov/vuln/detail/CVE-2025-1944'])
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=severity,
                package=pkg,
                title=f"ZIP structural anomaly in {path.name}: {issue['issue']}",
                detail=issue['detail'],
                references=refs,
                confidence=0.85,
                metadata={
                    'source_file': str(path),
                    'zip_issue': issue['issue'],
                    'zip_member': issue['member'],
                },
            ))
        return findings

    def _check_metadata_injection(self, path: Path, fmt: str) -> list[Finding]:
        """Scan model metadata (safetensors headers, config JSON) for prompt injection."""
        findings: list[Finding] = []
        pkg = PackageId("huggingface", path.name)
        metadata_text = ""

        if fmt == "safetensors":
            try:
                with path.open("rb") as fh:
                    size_bytes = fh.read(8)
                    if len(size_bytes) < 8:
                        return findings
                    (header_size,) = struct.unpack_from("<Q", size_bytes)
                    if header_size == 0 or header_size > _SAFETENSORS_MAX_HEADER_BYTES:
                        return findings
                    json_bytes = fh.read(min(header_size, 1_000_000))
                    metadata_text = json_bytes.decode("utf-8", errors="ignore")
            except OSError:
                return findings
        elif fmt == "config":
            try:
                metadata_text = path.read_text(errors="ignore")[:500_000]
            except OSError:
                return findings

        if not metadata_text:
            return findings

        for pattern, label in _MODEL_INJECTION_PATTERNS:
            if pattern.search(metadata_text):
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"Prompt injection in model metadata: {label}",
                    detail=(
                        f"The {fmt} metadata of '{path.name}' contains adversarial "
                        f"text matching '{label}'. An AI assistant loading this model "
                        f"config may follow the injected instructions."
                    ),
                    cwe="CWE-77",
                    confidence=0.85,
                    metadata={
                        "model_id": path.stem,
                        "format": fmt,
                        "source_file": str(path),
                        "matched_pattern": label,
                    },
                ))

        # Also scan for embedded secrets/credentials in this metadata
        findings.extend(self._check_metadata_secrets(metadata_text, path, fmt))

        return findings

    def _check_metadata_secrets(self, metadata_text: str, path: Path, fmt: str) -> list[Finding]:
        """Scan model metadata text for embedded secrets/credentials."""
        findings = []
        pkg = PackageId('huggingface', path.name)
        for pattern, label in _MODEL_SECRETS_PATTERNS:
            match = pattern.search(metadata_text)
            if match:
                matched = match.group(0)
                redacted = matched[:8] + '...' + matched[-4:] if len(matched) > 16 else matched[:4] + '...'
                findings.append(Finding(
                    finding_type=FindingType.SECRET_EXPOSED,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f'Secret in model metadata: {label}',
                    detail=f'The {fmt} metadata of "{path.name}" contains what appears to be a '
                           f'{label} (value redacted: {redacted}). Leaked credentials in model '
                           f'artifacts can be harvested by anyone who downloads the model.',
                    confidence=0.85,
                    metadata={'source_file': str(path), 'secret_type': label, 'format': fmt},
                ))
        return findings

    def _check_binary_secrets(self, path: Path, file_size: int) -> list[Finding]:
        """Scan the first 64KB of a model file's raw bytes for secret patterns.

        Only uses the highly-distinctive binary patterns (SSH key headers,
        AWS key prefixes, etc.) to keep false-positive rate near zero even
        on arbitrary binary weight data.
        """
        if file_size < _MIN_WEIGHT_BYTES:
            return []

        findings: list[Finding] = []
        pkg = PackageId('huggingface', path.name)

        try:
            with path.open('rb') as fh:
                data = fh.read(_BINARY_SCAN_LIMIT)
        except OSError:
            return findings

        for pattern, label in _BINARY_SECRETS_PATTERNS:
            match = pattern.search(data)
            if match:
                try:
                    matched_str = match.group(0).decode('utf-8', errors='replace')
                except Exception:
                    matched_str = repr(match.group(0)[:40])
                if len(matched_str) > 16:
                    redacted = matched_str[:8] + '...' + matched_str[-4:]
                else:
                    redacted = matched_str[:4] + '...'
                findings.append(Finding(
                    finding_type=FindingType.SECRET_EXPOSED,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f'Secret in model file: {label}',
                    detail=(
                        f'The raw binary content of "{path.name}" contains what '
                        f'appears to be a {label} in the first 64KB '
                        f'(value redacted: {redacted}). Credentials embedded in '
                        f'model weight files can be harvested by anyone who '
                        f'downloads the model.'
                    ),
                    confidence=0.85,
                    metadata={
                        'source_file': str(path),
                        'secret_type': label,
                        'format': path.suffix.lstrip('.'),
                        'scan_type': 'binary',
                    },
                ))

        return findings

    def _check_checksums(
        self,
        path: Path,
        file_size: int,
        declared_checksums: dict[Path, dict[str, str]],
    ) -> list[Finding]:
        """Verify sha256 checksums and flag models with no integrity metadata."""
        # Skip tiny files
        if file_size < _MIN_WEIGHT_BYTES:
            return []

        findings: list[Finding] = []
        pkg = PackageId("huggingface", path.name)
        file_name = path.name

        # Look for a declared checksum in the same directory or any parent
        # config directory that covers this file.
        declared_hash: str | None = None
        for cfg_dir, sums in declared_checksums.items():
            # Only apply if the config is in the same dir or a parent
            try:
                path.relative_to(cfg_dir)
            except ValueError:
                if cfg_dir != path.parent:
                    continue
            if file_name in sums:
                declared_hash = sums[file_name]
                break

        if declared_hash is not None:
            # ---- 3. Checksum verification ------------------------------------
            try:
                actual_hash = _stream_sha256(path)
            except OSError:
                return findings

            if actual_hash != declared_hash:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"SHA-256 checksum mismatch: {file_name}",
                    detail=(
                        f"The model file '{file_name}' does not match its declared sha256 "
                        f"checksum.\n"
                        f"  Expected : {declared_hash}\n"
                        f"  Actual   : {actual_hash}\n"
                        "This is a strong indicator of tampering or a corrupted download. "
                        "Delete the file and re-download from the official source."
                    ),
                    references=[
                        "https://huggingface.co/docs/hub/security",
                    ],
                    confidence=1.0,
                    metadata={
                        "model_id": path.stem,
                        "format": path.suffix.lstrip("."),
                        "source_file": str(path),
                        "line": 0,
                        "expected_sha256": declared_hash,
                        "actual_sha256": actual_hash,
                        "file_size_bytes": file_size,
                    },
                ))
        else:
            # ---- 4. No integrity metadata ------------------------------------
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"No integrity metadata for model file: {file_name}",
                detail=(
                    f"The model file '{file_name}' has no sha256 checksum declared in any "
                    "config.json / model.json in its directory. Without a pinned hash, "
                    "there is no way to detect if the file has been silently swapped or "
                    "corrupted between download and use. "
                    "Add a sha256 entry to your config.json and verify it matches the "
                    "HuggingFace Hub's declared hash for this file."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security",
                    "https://huggingface.co/docs/hub/models-cards",
                ],
                confidence=0.85,
                metadata={
                    "model_id": path.stem,
                    "format": path.suffix.lstrip("."),
                    "source_file": str(path),
                    "line": 0,
                    "file_size_bytes": file_size,
                },
            ))

        return findings

    def _check_size_anomaly(self, path: Path, file_size: int) -> list[Finding]:
        """Flag model files that are implausibly small for their claimed architecture."""
        min_expected = _detect_arch_hint(path)
        if min_expected is None:
            return []

        if file_size >= min_expected:
            return []

        pkg = PackageId("huggingface", path.name)
        # Extract the arch hint that matched
        path_lower = str(path).lower()
        arch_label = next(
            (pat for pat, _ in _ARCH_MIN_BYTES if pat in path_lower), "unknown"
        )
        return [Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.HIGH,
            package=pkg,
            title=f"Suspicious size for {arch_label.upper()} model: {path.name}",
            detail=(
                f"The file '{path.name}' appears to be part of a {arch_label.upper()} "
                f"architecture model (based on its path), but is only "
                f"{file_size / (1024*1024):.1f} MB — far below the expected minimum of "
                f"{min_expected / (1024*1024*1024):.1f} GB per shard. "
                "Legitimate model shards for this architecture are orders of magnitude "
                "larger. This pattern is consistent with a trojan stub or shell payload "
                "replacing real weights."
            ),
            references=[
                "https://huggingface.co/docs/hub/security",
            ],
            confidence=0.80,
            metadata={
                "model_id": path.stem,
                "format": path.suffix.lstrip("."),
                "source_file": str(path),
                "line": 0,
                "file_size_bytes": file_size,
                "arch_hint": arch_label,
                "min_expected_bytes": min_expected,
            },
        )]
