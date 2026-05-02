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
import json
import struct
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pickle opcodes that allow arbitrary code execution.
# https://github.com/python/cpython/blob/main/Lib/pickletools.py
_DANGEROUS_PICKLE_OPCODES: frozenset[int] = frozenset({
    0x52,  # REDUCE  — calls a callable with args (the main RCE vector)
    0x63,  # GLOBAL  — imports an arbitrary module attribute
    0x69,  # INST    — instantiate a class from module (legacy REDUCE)
    0x81,  # NEWOBJ  — call cls.__new__(cls, *args)
})

# File extensions treated as potential pickle-based model weights.
_PICKLE_EXTENSIONS: frozenset[str] = frozenset({".bin", ".pkl", ".pickle", ".pt"})

# SafeTensors: the header is a little-endian u64 (8 bytes) giving JSON length,
# followed immediately by that many bytes of JSON.  There is no separate magic
# constant in the spec, but the header_size must be > 0 and < 100 MB for a
# valid file.  The JSON must contain at least an empty object.
_SAFETENSORS_MAX_HEADER_BYTES = 100 * 1024 * 1024  # 100 MB guard

# Chunk size for streaming reads — never load entire weight files into memory.
_READ_CHUNK_SIZE = 64 * 1024  # 64 KB

# Minimum plausible size for a real model weight file (anything smaller is
# either not weights or a red-flag trojan stub).
_MIN_WEIGHT_BYTES = 1 * 1024 * 1024  # 1 MB

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


def _scan_pickle_opcodes(path: Path) -> bool:
    """Return True if *path* contains any dangerous pickle opcodes.

    Reads the file in 64 KB chunks and checks each byte against the
    dangerous opcode set.  This is a heuristic — a determined attacker
    could obfuscate, but it catches the common RCE-via-pickle pattern.
    """
    with path.open("rb") as fh:
        while chunk := fh.read(_READ_CHUNK_SIZE):
            for byte in chunk:
                if byte in _DANGEROUS_PICKLE_OPCODES:
                    return True
    return False


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
    path_lower = str(path).lower()
    for pattern, min_bytes in _ARCH_MIN_BYTES:
        if pattern in path_lower:
            return min_bytes
    return None


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

        # Walk all weight files
        weight_extensions = _PICKLE_EXTENSIONS | {".safetensors"}
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

        # ---- 5. Size anomaly (checked first — applies to all formats) --------
        findings.extend(self._check_size_anomaly(path, file_size))

        # ---- 1. Pickle opcode scanning ---------------------------------------
        if ext in _PICKLE_EXTENSIONS:
            findings.extend(self._check_pickle_opcodes(path, file_size))

        # ---- 2. SafeTensors header validation --------------------------------
        if ext == ".safetensors":
            findings.extend(self._check_safetensors(path))

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

        try:
            has_dangerous = _scan_pickle_opcodes(path)
        except OSError:
            return []

        if not has_dangerous:
            return []

        pkg = PackageId("huggingface", path.name)
        return [Finding(
            finding_type=FindingType.MALICIOUS,
            severity=Severity.CRITICAL,
            package=pkg,
            title=f"Dangerous pickle opcode in model file: {path.name}",
            detail=(
                f"The model weight file '{path.name}' contains one or more pickle opcodes "
                "that allow arbitrary code execution (REDUCE=0x52, GLOBAL=0x63, INST=0x69, "
                "NEWOBJ=0x81). A malicious model can use these to run arbitrary Python when "
                "the file is loaded via torch.load() or pickle.load(). "
                "Do NOT load this file. Obtain the model from a trusted source and verify "
                "its sha256 checksum, or migrate to .safetensors format."
            ),
            references=[
                "https://huggingface.co/docs/hub/security-pickle",
                "https://pytorch.org/docs/stable/generated/torch.load.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-5480",
            ],
            confidence=0.95,
            metadata={
                "model_id": path.stem,
                "format": "pickle",
                "source_file": str(path),
                "line": 0,
                "file_size_bytes": file_size,
                "dangerous_opcodes_found": True,
            },
        )]

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
