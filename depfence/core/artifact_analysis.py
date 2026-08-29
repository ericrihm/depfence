"""Quarantine-first analysis for visual-versus-machine text deception.

The default path is deliberately non-rendering.  It uses bounded structural
parsing and never registers fonts, invokes office/PDF applications, or fetches
remote resources.  A separately configured OCI runner may provide rendered
comparison evidence; its JSON response is the only artifact allowed back.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import struct
import subprocess
import threading
import time
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import BinaryIO
from xml.etree import ElementTree

from depfence.core.local_state import PrivateState
from depfence.core.models import Finding, FindingType, ScanResult, ScanState, Severity
from depfence.core.scan_scope import InputLimitError, MalformedInputError, ScanIncompleteError

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_ARCHIVE_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_RATIO = 200
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_FONT_TABLES = 256
MAX_CMAP_ENTRIES = 100_000
MAX_SANDBOX_OUTPUT = 1024 * 1024
MAX_XML_NODES = 100_000
MAX_XML_DEPTH = 128
SANDBOX_SCHEMA_VERSION = "depfence.artifact-analysis/v1"
RENDER_SECCOMP_SHA256 = "b2b00be3c4924c217c4f9d151ae231cb95769462729ea9addb37fcccdfa2ef02"

FONT_SUFFIXES = frozenset({".ttf", ".otf", ".ttc", ".woff", ".woff2"})
WEB_SUFFIXES = frozenset({".html", ".htm", ".css"})
DOCUMENT_SUFFIXES = frozenset({".docx", ".pdf"})
SUPPORTED_SUFFIXES = FONT_SUFFIXES | WEB_SUFFIXES | DOCUMENT_SUFFIXES

_FONT_FACE = re.compile(r"@font-face\s*\{(.*?)\}", re.IGNORECASE | re.DOTALL)
_FONT_FAMILY = re.compile(
    r"font-family\s*:\s*([\"']?)([^;\"'}]+)\1", re.IGNORECASE
)
_UNICODE_RANGE = re.compile(r"unicode-range\s*:\s*([^;}]+)", re.IGNORECASE)
_SINGLE_CHAR_FONT_RUN = re.compile(
    r"<(?:span|div|p)\b[^>]*style\s*=\s*[\"'][^\"']*font-family\s*:[^\"']+[\"'][^>]*>\s*[^<\s]\s*</(?:span|div|p)>",
    re.IGNORECASE,
)
_PDF_INVISIBLE_TEXT = re.compile(rb"(?<!\d)3\s+Tr\b")
_PDF_TEXT_SHOW = re.compile(rb"(?:\)|>)[\s\r\n]*(?:Tj|TJ)\b")


@dataclass(frozen=True)
class FontSummary:
    family: str | None
    cmap_entries: int | None
    glyphs: int | None
    flavor: str
    complete: bool = True


@dataclass(frozen=True)
class FontSemanticSummary:
    member_count: int
    cmap_subtables: int
    cmap_conflicts: int
    mapped_codepoints: int
    unique_glyphs: int
    zero_width_glyphs: int
    missing_layout_tables: bool
    presentation_mechanisms: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class SandboxConfig:
    engine: str
    image: str
    runtime: str | None = None
    timeout_seconds: float = 120.0
    seccomp_profile: str = "containers/seccomp-render.json"
    seccomp_sha256: str = RENDER_SECCOMP_SHA256

    def validate(self) -> None:
        if self.engine not in {"docker", "podman"}:
            raise ValueError("sandbox engine must be docker or podman")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", self.image):
            raise ValueError("sandbox image must be pinned by an @sha256: digest")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 900:
            raise ValueError("sandbox timeout must be between 0 and 900 seconds")
        # Require explicit runtime attestation on all platforms.  "runsc"
        # and "kata"/"kata-runtime" are passed as --runtime to the engine.
        # "vm" is an operator attestation that the engine runs containers
        # inside a hardware-isolated VM (e.g. Docker Desktop, Podman Machine)
        # and is NOT passed as a --runtime flag.
        _VALID_RUNTIMES = {"runsc", "kata", "kata-runtime", "vm"}
        if self.runtime is None or self.runtime not in _VALID_RUNTIMES:
            raise ValueError(
                "sandbox runtime must be runsc, kata, kata-runtime, or vm "
                "(operator attestation of VM-mediated isolation)"
            )
        raw_profile = Path(self.seccomp_profile).expanduser()
        if raw_profile.is_symlink():
            raise ValueError("sandbox seccomp profile must not be a symlink")
        profile = raw_profile.resolve(strict=True)
        if not profile.is_file():
            raise ValueError("sandbox seccomp profile must be a regular file")
        raw = profile.read_bytes()
        if hashlib.sha256(raw).hexdigest() != self.seccomp_sha256:
            raise ValueError("sandbox seccomp profile hash does not match reviewed policy")
        try:
            policy = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("sandbox seccomp profile is malformed") from exc
        if not isinstance(policy, dict) or policy.get("defaultAction") != "SCMP_ACT_ERRNO":
            raise ValueError("sandbox seccomp profile must default deny")


def verify_image_signature(image: str, identity: str, issuer: str) -> None:
    """Verify a digest-pinned worker image against an expected Sigstore identity."""

    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", image):
        raise ValueError("worker image must be pinned by an @sha256: digest")
    if not identity or len(identity) > 512 or any(ord(value) < 32 for value in identity):
        raise ValueError("worker certificate identity is invalid")
    if not issuer.startswith("https://") or len(issuer) > 512 or any(ord(value) < 32 for value in issuer):
        raise ValueError("worker certificate issuer is invalid")
    executable = shutil.which("cosign")
    if not executable:
        raise ScanIncompleteError("cosign is required to verify the worker image signature")
    code, _stdout, _stderr = _run_bounded_subprocess(
        [
            executable,
            "verify",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            image,
        ],
        b"",
        {"PATH": os.environ.get("PATH", "")},
        60.0,
    )
    if code:
        raise ScanIncompleteError("worker image signature verification failed")


def detect_media_type(path: Path, data: bytes) -> str:
    """Return a MIME type for *data* using magic bytes and *path* suffix."""
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"wOFF"):
        return "font/woff"
    if data.startswith(b"wOF2"):
        return "font/woff2"
    if data[:4] in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1", b"ttcf"}:
        return "font/sfnt"
    if data.startswith(b"PK\x03\x04") and (
        path.suffix.lower() == ".docx"
        or (b"[Content_Types].xml" in data and b"word/document.xml" in data)
    ):
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if path.suffix.lower() in WEB_SUFFIXES:
        return "text/css" if path.suffix.lower() == ".css" else "text/html"
    return "application/octet-stream"


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise MalformedInputError("font table contains an out-of-bounds uint16")
    return int(struct.unpack_from(">H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise MalformedInputError("font table contains an out-of-bounds uint32")
    return int(struct.unpack_from(">I", data, offset)[0])


def _font_tables(data: bytes) -> tuple[str, dict[bytes, bytes]]:
    if len(data) < 12:
        raise MalformedInputError("font is shorter than its table directory")
    signature = data[:4]
    if signature == b"wOF2":
        return "woff2", {}
    if signature == b"wOFF":
        num_tables = _u16(data, 12)
        if num_tables > MAX_FONT_TABLES or 44 + num_tables * 20 > len(data):
            raise MalformedInputError("WOFF table directory is invalid")
        tables: dict[bytes, bytes] = {}
        expanded_total = 0
        import zlib

        for index in range(num_tables):
            base = 44 + index * 20
            tag = data[base : base + 4]
            offset = _u32(data, base + 4)
            compressed = _u32(data, base + 8)
            original = _u32(data, base + 12)
            if original > MAX_XML_BYTES or compressed > original or offset + compressed > len(data):
                raise MalformedInputError("WOFF table length is invalid")
            if tag in tables:
                raise MalformedInputError("WOFF contains duplicate table tags")
            expanded_total += original
            if expanded_total > MAX_ARCHIVE_EXPANDED_BYTES:
                raise InputLimitError("WOFF exceeds its expanded-byte budget")
            raw = data[offset : offset + compressed]
            if compressed != original:
                decompressor = zlib.decompressobj()
                value = decompressor.decompress(raw, original + 1)
                if (
                    len(value) != original
                    or not decompressor.eof
                    or decompressor.unconsumed_tail
                    or decompressor.unused_data
                ):
                    raise MalformedInputError("WOFF table expansion length is invalid")
            else:
                value = raw
            tables[tag] = value
        return "woff", tables
    if signature == b"ttcf":
        return "ttc", {}
    if signature not in {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}:
        raise MalformedInputError("unrecognized OpenType signature")
    num_tables = _u16(data, 4)
    if num_tables > MAX_FONT_TABLES or 12 + num_tables * 16 > len(data):
        raise MalformedInputError("OpenType table directory is invalid")
    tables = {}
    table_total = 0
    for index in range(num_tables):
        base = 12 + index * 16
        tag = data[base : base + 4]
        offset = _u32(data, base + 8)
        length = _u32(data, base + 12)
        if length > MAX_XML_BYTES or offset + length > len(data):
            raise MalformedInputError("OpenType table range is invalid")
        if tag in tables:
            raise MalformedInputError("OpenType contains duplicate table tags")
        table_total += length
        if table_total > MAX_ARCHIVE_EXPANDED_BYTES:
            raise InputLimitError("OpenType exceeds its table-byte budget")
        tables[tag] = data[offset : offset + length]
    return "otf" if signature == b"OTTO" else "ttf", tables


def _name_family(table: bytes) -> str | None:
    if len(table) < 6:
        raise MalformedInputError("font name table is truncated")
    count = _u16(table, 2)
    string_offset = _u16(table, 4)
    if count > 4096 or 6 + count * 12 > len(table) or string_offset > len(table):
        raise MalformedInputError("font name table directory is invalid")
    candidates: list[tuple[int, str]] = []
    for index in range(count):
        base = 6 + index * 12
        platform_id = _u16(table, base)
        name_id = _u16(table, base + 6)
        length = _u16(table, base + 8)
        offset = _u16(table, base + 10)
        start = string_offset + offset
        if name_id not in {1, 16} or start + length > len(table) or length > 4096:
            continue
        raw = table[start : start + length]
        try:
            decoded = raw.decode("utf-16-be" if platform_id in {0, 3} else "latin-1")
        except UnicodeError:
            continue
        cleaned = " ".join(decoded.replace("\x00", "").split())[:200]
        if cleaned:
            candidates.append((0 if name_id == 16 else 1, cleaned))
    return min(candidates, default=(9, ""))[1] or None


def _cmap_count(table: bytes) -> int:
    if len(table) < 4:
        raise MalformedInputError("font cmap table is truncated")
    count = _u16(table, 2)
    if count > 256 or 4 + count * 8 > len(table):
        raise MalformedInputError("font cmap directory is invalid")
    maximum = 0
    for index in range(count):
        offset = _u32(table, 4 + index * 8 + 4)
        if offset + 2 > len(table):
            raise MalformedInputError("font cmap subtable is out of bounds")
        fmt = _u16(table, offset)
        entries = 0
        if fmt == 0:
            if offset + 6 > len(table):
                raise MalformedInputError("format 0 cmap is truncated")
            length = _u16(table, offset + 2)
            if length < 262 or offset + length > len(table):
                raise MalformedInputError("format 0 cmap length is invalid")
            entries = sum(value != 0 for value in table[offset + 6 : offset + 262])
        elif fmt == 4:
            if offset + 14 > len(table):
                raise MalformedInputError("format 4 cmap is truncated")
            length = _u16(table, offset + 2)
            seg_count_x2 = _u16(table, offset + 6)
            if (
                length < 16
                or offset + length > len(table)
                or seg_count_x2 == 0
                or seg_count_x2 % 2
            ):
                raise MalformedInputError("format 4 cmap header is invalid")
            seg_count = seg_count_x2 // 2
            end_codes = offset + 14
            start_codes = end_codes + seg_count * 2 + 2
            deltas = start_codes + seg_count * 2
            range_offsets = deltas + seg_count * 2
            if range_offsets + seg_count * 2 > offset + length:
                raise MalformedInputError("format 4 cmap arrays are truncated")
            previous_end = -1
            for segment in range(seg_count):
                end = _u16(table, end_codes + segment * 2)
                start = _u16(table, start_codes + segment * 2)
                if start > end or start <= previous_end:
                    raise MalformedInputError("format 4 cmap segments are invalid")
                previous_end = end
                delta = _u16(table, deltas + segment * 2)
                range_offset_location = range_offsets + segment * 2
                range_offset = _u16(table, range_offset_location)
                for codepoint in range(start, end + 1):
                    if range_offset == 0:
                        glyph = (codepoint + delta) & 0xFFFF
                    else:
                        glyph_location = (
                            range_offset_location + range_offset + 2 * (codepoint - start)
                        )
                        if glyph_location + 2 > offset + length:
                            raise MalformedInputError(
                                "format 4 cmap glyph array is out of bounds"
                            )
                        glyph = _u16(table, glyph_location)
                        if glyph:
                            glyph = (glyph + delta) & 0xFFFF
                    entries += glyph != 0
                    if entries > MAX_CMAP_ENTRIES:
                        raise InputLimitError("font cmap exceeds its entry budget")
        elif fmt == 6:
            if offset + 10 > len(table):
                raise MalformedInputError("format 6 cmap is truncated")
            length = _u16(table, offset + 2)
            entry_count = _u16(table, offset + 8)
            if length < 10 + entry_count * 2 or offset + length > len(table):
                raise MalformedInputError("format 6 cmap length is invalid")
            entries = sum(
                _u16(table, offset + 10 + item * 2) != 0
                for item in range(entry_count)
            )
        elif fmt == 10:
            if offset + 20 > len(table):
                raise MalformedInputError("format 10 cmap is truncated")
            length = _u32(table, offset + 4)
            start = _u32(table, offset + 12)
            entry_count = _u32(table, offset + 16)
            if (
                entry_count > MAX_CMAP_ENTRIES
                or start > 0x10FFFF
                or (entry_count and start + entry_count - 1 > 0x10FFFF)
                or length < 20 + entry_count * 2
                or offset + length > len(table)
            ):
                raise MalformedInputError("format 10 cmap length is invalid")
            entries = sum(
                _u16(table, offset + 20 + item * 2) != 0
                for item in range(entry_count)
            )
        elif fmt in {12, 13}:
            if offset + 16 > len(table):
                raise MalformedInputError("grouped cmap is truncated")
            length = _u32(table, offset + 4)
            groups = _u32(table, offset + 12)
            if (
                groups > MAX_CMAP_ENTRIES
                or length < 16 + groups * 12
                or offset + length > len(table)
            ):
                raise MalformedInputError("grouped cmap has an invalid group count")
            total = 0
            previous_end = -1
            for group in range(groups):
                base = offset + 16 + group * 12
                start = _u32(table, base)
                end = _u32(table, base + 4)
                start_glyph = _u32(table, base + 8)
                if end < start or start <= previous_end or end > 0x10FFFF:
                    raise MalformedInputError("grouped cmap range is invalid")
                previous_end = end
                span = end - start + 1
                if fmt == 13:
                    mapped = span if start_glyph != 0 else 0
                else:
                    mapped = span - (1 if start_glyph == 0 else 0)
                total += mapped
                if total > MAX_CMAP_ENTRIES:
                    raise InputLimitError("font cmap exceeds its entry budget")
            entries = total
        else:
            raise ScanIncompleteError(f"unsupported cmap format {fmt}")
        maximum = max(maximum, entries)
    return maximum


def summarize_font(data: bytes) -> FontSummary:
    """Return a lightweight structural summary without FontTools dependency."""
    flavor, tables = _font_tables(data)
    if flavor in {"woff2", "ttc"}:
        return FontSummary(None, None, None, flavor, complete=False)
    family = _name_family(tables[b"name"]) if b"name" in tables else None
    cmap = _cmap_count(tables[b"cmap"]) if b"cmap" in tables else 0
    glyphs = _u16(tables[b"maxp"], 4) if len(tables.get(b"maxp", b"")) >= 6 else None
    return FontSummary(family, cmap, glyphs, flavor)


def inspect_font_semantics(data: bytes) -> FontSemanticSummary:
    """Decode every collection member and compare all Unicode cmap subtables."""
    try:
        from fontTools.ttLib import TTCollection, TTFont, TTLibError
    except ImportError as exc:
        raise ScanIncompleteError("fontTools is required for semantic font inspection") from exc
    if len(data) > MAX_ARTIFACT_BYTES:
        raise InputLimitError("font exceeds its byte budget")
    stream = BytesIO(data)
    fonts = []
    try:
        if data.startswith(b"ttcf"):
            # Pre-validate TTC header before passing to FontTools.
            # TTC header: tag(4) + majorVersion(2) + minorVersion(2) + numFonts(4)
            if len(data) < 12:
                raise MalformedInputError("TTC header is truncated")
            num_fonts = struct.unpack(">I", data[8:12])[0]
            if not 1 <= num_fonts <= 64:
                raise InputLimitError("font collection exceeds its member budget")
            collection = TTCollection(stream, lazy=True)
            fonts = list(collection.fonts)
        else:
            fonts = [TTFont(stream, lazy=True, recalcBBoxes=False, recalcTimestamp=False)]
    except (TTLibError, KeyError, ValueError, IndexError) as exc:
        raise MalformedInputError("font could not be decoded safely") from exc

    subtables = conflicts = 0
    codepoints: set[int] = set()
    all_glyph_ids: set[str] = set()
    zero_width_count = 0
    mechanisms: set[str] = set()
    limitations: set[str] = set()
    has_layout_tables = False
    try:
        for font in fonts:
            if "cmap" not in font:
                limitations.add("cmap_missing")
                continue
            mappings: dict[int, set[str]] = {}
            try:
                for subtable in font["cmap"].tables:
                    if not subtable.isUnicode():
                        continue
                    subtables += 1
                    cmap = subtable.cmap or {}
                    if len(cmap) > MAX_CMAP_ENTRIES:
                        raise InputLimitError("font cmap exceeds its entry budget")
                    for codepoint, glyph in cmap.items():
                        if not 0 <= int(codepoint) <= 0x10FFFF:
                            raise MalformedInputError("font cmap contains an invalid codepoint")
                        codepoints.add(int(codepoint))
                        all_glyph_ids.add(str(glyph))
                        mappings.setdefault(int(codepoint), set()).add(str(glyph))
            except (InputLimitError, MalformedInputError):
                raise
            except (TTLibError, struct.error, zlib.error, KeyError, IndexError, ValueError):
                # FontTools lazy-load can raise TTLibError, struct.error, zlib.error,
                # or other decoding failures during cmap traversal.
                limitations.add("cmap_decode_incomplete")
            conflicts += sum(len(values) > 1 for values in mappings.values())

            # Detect zero advance width glyphs (stealth font signal).
            # EvilFontTool creates a stealth variant where all glyphs
            # have advance width 0 so characters render as invisible.
            try:
                if "hmtx" in font:
                    hmtx = font["hmtx"].metrics
                    mapped_glyphs = set()
                    for glyph_sets in mappings.values():
                        mapped_glyphs.update(glyph_sets)
                    for glyph_name in mapped_glyphs:
                        if glyph_name in hmtx:
                            width, _ = hmtx[glyph_name]
                            if width == 0 and glyph_name != ".notdef":
                                zero_width_count += 1
            except (TTLibError, struct.error, KeyError, IndexError, ValueError):
                limitations.add("hmtx_decode_incomplete")

            # Check for layout table presence/absence.
            # EvilFontTool strips GSUB, GPOS, kern, and GDEF to prevent
            # substitution interference.  A font mapping 26+ ASCII
            # codepoints with none of these tables is unusual.
            for layout_table in ("GSUB", "GPOS", "kern", "GDEF"):
                if layout_table in font:
                    has_layout_tables = True

            for table, label in {
                "GSUB": "gsub", "fvar": "variations", "gvar": "variations",
                "CFF ": "cff", "CFF2": "cff2", "SVG ": "svg",
                "COLR": "color", "CBDT": "bitmap", "EBDT": "bitmap", "sbix": "bitmap",
            }.items():
                if table in font:
                    mechanisms.add(label)
            if "GSUB" in font:
                try:
                    scripts = font["GSUB"].table.ScriptList
                    if scripts is None:
                        limitations.add("gsub_script_list_missing")
                except (AttributeError, KeyError, TypeError):
                    limitations.add("gsub_parse_incomplete")
            if mechanisms.intersection({"svg", "color", "bitmap", "variations"}):
                limitations.add("rendered_glyph_reference_comparison_required")
    finally:
        for font in fonts:
            font.close()

    # Flag missing layout tables only when cmap has meaningful coverage.
    # A font mapping 26+ codepoints (full Latin alphabet) without any
    # of GSUB/GPOS/kern/GDEF is structurally unusual for production fonts.
    missing_layout = not has_layout_tables and len(codepoints) >= 26

    return FontSemanticSummary(
        member_count=len(fonts), cmap_subtables=subtables, cmap_conflicts=conflicts,
        mapped_codepoints=len(codepoints),
        unique_glyphs=len(all_glyph_ids),
        zero_width_glyphs=zero_width_count,
        missing_layout_tables=missing_layout,
        presentation_mechanisms=tuple(sorted(mechanisms)),
        limitations=tuple(sorted(limitations)),
    )


def _finding(
    path: Path,
    rule_id: str,
    title: str,
    detail: str,
    severity: Severity,
    confidence: float,
    **evidence: object,
) -> Finding:
    return Finding(
        finding_type=FindingType.VISUAL_TEXT_DECEPTION,
        severity=severity,
        package=f"artifact:{path.as_posix()}",
        title=title,
        detail=detail,
        confidence=confidence,
        metadata={
            "file": path.as_posix(),
            "rule_id": rule_id,
            "analysis_mode": "static",
            "content_redacted": True,
            **evidence,
        },
    )


def _scan_web(path: Path, data: bytes) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ScanIncompleteError(f"web artifact is not valid UTF-8: {path}") from exc
    faces = _FONT_FACE.findall(text)
    families = {
        match.group(2).strip().casefold()
        for match in _FONT_FAMILY.finditer(text)
        if match.group(2).strip()
    }
    ranges = _UNICODE_RANGE.findall(text)
    single_runs = len(_SINGLE_CHAR_FONT_RUN.findall(text))
    suspicious_faces = len(faces) >= 8 and len(families) >= 4
    suspicious_runs = single_runs >= 8 and len(families) >= 4
    if not (suspicious_faces and (suspicious_runs or len(ranges) >= 8)):
        return []
    return [_finding(
        path,
        "DF-WEB-001",
        "Suspicious per-character web-font construction",
        "The document combines many custom font faces with character-level or sparse-range font selection. No content was rendered.",
        Severity.MEDIUM,
        0.78,  # structural correlation only — no rendering to confirm
        font_face_count=len(faces),
        font_family_count=len(families),
        unicode_range_count=len(ranges),
        single_character_run_count=single_runs,
        evidence_class="structural_correlation",
    )]


def _bounded_zip_member(handle: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    if info.file_size > limit:
        raise InputLimitError(f"archive member exceeds {limit} bytes: {info.filename}")
    with handle.open(info, "r") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise InputLimitError(f"archive member expanded beyond {limit} bytes: {info.filename}")
    return value


def _parse_bounded_xml(data: bytes) -> ElementTree.Element:
    # Check raw bytes for UTF-8/ASCII DTD, then probe for UTF-16 variants
    # so <!DOCTYPE/<!ENTITY cannot slip past via alternate encodings.
    if re.search(br"<!DOCTYPE|<!ENTITY", data, re.IGNORECASE):
        raise MalformedInputError("DOCX XML declarations are unsafe")
    head = data[:4096]
    for encoding in ("utf-16-le", "utf-16-be"):
        try:
            decoded = head.decode(encoding, errors="ignore")
        except (UnicodeDecodeError, LookupError):
            continue
        if re.search(r"<!DOCTYPE|<!ENTITY", decoded, re.IGNORECASE):
            raise MalformedInputError("DOCX XML declarations are unsafe")
    depth = nodes = 0
    root: ElementTree.Element | None = None
    try:
        for event, node in ElementTree.iterparse(BytesIO(data), events=("start", "end")):
            if root is None:
                root = node
            if event == "start":
                depth += 1
                nodes += 1
                if depth > MAX_XML_DEPTH or nodes > MAX_XML_NODES:
                    raise InputLimitError("DOCX XML exceeds its structure budget")
            else:
                depth -= 1
    except ElementTree.ParseError as exc:
        raise MalformedInputError("DOCX document XML is malformed") from exc
    if root is None:
        raise MalformedInputError("DOCX document XML is empty")
    return root


def _scan_docx(path: Path, data: bytes) -> list[Finding]:
    try:
        archive = zipfile.ZipFile(BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise MalformedInputError(f"malformed DOCX package: {path}") from exc
    with archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise InputLimitError("DOCX exceeds the archive member budget")
        names: set[str] = set()
        expanded = 0
        for info in members:
            normalized = Path(info.filename.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts:
                raise MalformedInputError("DOCX contains a path-traversing member")
            if info.filename in names:
                raise MalformedInputError("DOCX contains duplicate member names")
            names.add(info.filename)
            member_mode = (info.external_attr >> 16) & 0xFFFF
            if member_mode and stat.S_ISLNK(member_mode):
                raise MalformedInputError("DOCX contains a symbolic-link member")
            expanded += info.file_size
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                raise InputLimitError("DOCX exceeds the expanded-byte budget")
            if info.compress_size == 0 and info.file_size:
                raise InputLimitError("DOCX member has an invalid compression size")
            if info.compress_size and info.file_size / info.compress_size > MAX_ARCHIVE_RATIO:
                raise InputLimitError("DOCX contains an excessive compression ratio")
            if info.flag_bits & 0x1:
                raise MalformedInputError("encrypted DOCX members are unsupported")
        by_name = {info.filename: info for info in members}
        document_info = by_name.get("word/document.xml")
        if document_info is None:
            raise MalformedInputError("DOCX is missing word/document.xml")
        story_pattern = re.compile(
            r"^word/(?:document|header\d+|footer\d+|footnotes|endnotes|comments|"
            r"commentsExtended|glossary/document)\.xml$"
        )
        story_infos = [info for name, info in by_name.items() if story_pattern.fullmatch(name)]
        if len(story_infos) > 256:
            raise InputLimitError("DOCX exceeds its story-part budget")
        embedded = [name for name in names if name.startswith("word/fonts/")]
        run_fonts: list[str] = []
        single_character_runs = 0
        hidden_runs = revision_nodes = field_nodes = text_box_nodes = 0
        font_classes: set[str] = set()
        hex_name_runs = 0
        rfonts_saturated_runs = 0
        _HEX_FONT_NAME = re.compile(r"\s+[0-9a-fA-F]+$")
        for story_info in story_infos:
            try:
                raw = _bounded_zip_member(archive, story_info, MAX_XML_BYTES)
            except (InputLimitError, MalformedInputError):
                raise
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
                raise MalformedInputError(f"DOCX member unreadable: {story_info.filename}") from exc
            root = _parse_bounded_xml(raw)
            for node in root.iter():
                local = node.tag.rsplit("}", 1)[-1]
                revision_nodes += local in {"ins", "del", "moveFrom", "moveTo"}
                field_nodes += local in {"fldChar", "instrText", "fldSimple"}
                text_box_nodes += local in {"txbxContent", "textbox"}
                if local != "r":
                    continue
                text_value = "".join(
                    child.text or "" for child in node.iter()
                    if child.tag.rsplit("}", 1)[-1] in {"t", "delText", "instrText"}
                )
                font = None
                for child in node.iter():
                    child_local = child.tag.rsplit("}", 1)[-1]
                    if child_local in {"vanish", "webHidden"}:
                        hidden_runs += 1
                    # White/near-white text color (augur ooxml.go)
                    if child_local == "color":
                        color_val = child.attrib.get(
                            "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val",
                            "",
                        ).upper()
                        if color_val in {"FFFFFF", "FEFEFE", "FDFDFD", "FCFCFC"}:
                            hidden_runs += 1
                    if child_local == "rFonts":
                        candidates = []
                        for key, value in child.attrib.items():
                            font_class = key.rsplit("}", 1)[-1]
                            if font_class in {"ascii", "hAnsi", "eastAsia", "cs"}:
                                font_classes.add(font_class)
                                candidates.append(str(value))
                        font = candidates[0] if candidates else None
                        # Detect EvilFontTool hex-encoded font names
                        # (e.g., "FontName 68" where 68 is the hex of the target char)
                        if font and _HEX_FONT_NAME.search(font):
                            hex_name_runs += 1
                        # Detect all four rFonts classes set to same non-default font
                        if len(candidates) == 4 and len(set(candidates)) == 1:
                            rfonts_saturated_runs += 1
                if font:
                    run_fonts.append(font.casefold())
                    if len(text_value.strip()) == 1:
                        single_character_runs += 1
        switches = sum(a != b for a, b in zip(run_fonts, run_fonts[1:]))
        switch_density = switches / max(1, len(run_fonts) - 1)
        findings: list[Finding] = []

        # DF-DOCX-002: Hidden document content (independent of font switching)
        if hidden_runs >= 3 or revision_nodes >= 5:
            detail_parts = []
            if hidden_runs >= 3:
                detail_parts.append(f"{hidden_runs} hidden text runs (vanish/webHidden)")
            if revision_nodes >= 5:
                detail_parts.append(f"{revision_nodes} tracked-change nodes")
            findings.append(_finding(
                path,
                "DF-DOCX-002",
                "DOCX contains hidden or revision-tracked content",
                "The document contains " + " and ".join(detail_parts) + ". "
                "Hidden text and excessive tracked changes can conceal modifications "
                "from visual inspection while remaining in the document's data.",
                Severity.MEDIUM,
                0.65,
                hidden_run_count=hidden_runs,
                revision_node_count=revision_nodes,
                story_count=len(story_infos),
                evidence_class="hidden_document_content",
            ))

        # DF-DOCX-001: Font-switching detection (existing logic)
        if len(embedded) >= 4 and single_character_runs >= 8 and switch_density >= 0.5:
            # Boost confidence when additional EvilFontTool signatures are present.
            # Hex-encoded font names and rFonts saturation are strong corroborating
            # signals that increase specificity beyond generic font switching.
            confidence = 0.84
            if hex_name_runs >= 4:
                confidence = min(confidence + 0.04, 0.98)
            if rfonts_saturated_runs >= 4:
                confidence = min(confidence + 0.02, 0.98)
            findings.append(_finding(
                path,
                "DF-DOCX-001",
                "Suspicious embedded-font run switching in DOCX",
                "The document embeds multiple fonts and changes font families across single-character runs, a structural pattern capable of making visible text differ from stored text.",
                Severity.MEDIUM,
                confidence,
                embedded_font_count=len(embedded),
                story_count=len(story_infos),
                font_classes=sorted(font_classes),
                hidden_run_count=hidden_runs,
                revision_node_count=revision_nodes,
                field_node_count=field_nodes,
                text_box_count=text_box_nodes,
                font_run_count=len(run_fonts),
                single_character_run_count=single_character_runs,
                font_switch_density=round(switch_density, 4),
                hex_encoded_font_name_runs=hex_name_runs,
                rfonts_saturated_runs=rfonts_saturated_runs,
                evidence_class="structural_correlation",
            ))

        return findings


def _scan_pdf(path: Path, data: bytes) -> list[Finding]:
    # DF-PDF-003 pre-parse: count %%EOF markers on raw bytes before parsing,
    # since incremental saves may produce PDFs that strict-mode readers reject.
    eof_count = data.count(b"%%EOF")

    # Import separately from the parse. Folded together, a missing pypdf raises
    # ImportError, and evaluating the handler tuple then raises NameError
    # because PdfReadError was never bound -- the error escapes scan_artifact_bytes
    # and the caller discards every finding from this scanner.
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
        from pypdf.generic import ContentStream, DictionaryObject
    except ImportError as exc:
        raise ScanIncompleteError("pypdf is required for PDF inspection") from exc

    try:
        reader = PdfReader(BytesIO(data), strict=True)
    except (PdfReadError, ValueError, TypeError, OSError) as exc:
        # If the PDF can't be parsed but has incremental saves, report that.
        if eof_count > 1:
            return [_finding(
                path,
                "DF-PDF-003",
                "PDF has multiple revision layers (incremental saves)",
                "The PDF contains multiple %%EOF markers indicating incremental updates. "
                "Later revisions can shadow or modify content from earlier revisions, "
                "a technique used to hide modifications from casual inspection. "
                "Additionally, the PDF object graph could not be fully decoded.",
                Severity.MEDIUM,
                0.70,
                eof_marker_count=eof_count,
                evidence_class="incremental_save",
            )]
        raise MalformedInputError(f"PDF object graph could not be decoded: {path}") from exc
    if len(reader.pages) > 250:
        raise InputLimitError("PDF exceeds its page budget")
    invisible = images = text_ops = actual_text = type3_fonts = missing_tounicode = 0
    clipping_ops = transform_ops = alpha_states = form_xobjects = white_text = 0
    operations_seen = 0

    MAX_FORM_DEPTH = 16       # form XObject nesting cap
    MAX_PDF_OBJECTS = 10_000  # distinct-object cap before bailout

    def inspect_resources(resources: object, seen: set[int], depth: int = 0) -> None:
        nonlocal images, type3_fonts, missing_tounicode, form_xobjects
        if resources is None:
            return
        if depth > MAX_FORM_DEPTH:
            raise InputLimitError("PDF form XObject nesting exceeds depth limit")
        if len(seen) > MAX_PDF_OBJECTS:
            raise InputLimitError("PDF exceeds its object budget")
        resources = resources.get_object() if hasattr(resources, "get_object") else resources
        if not isinstance(resources, DictionaryObject):
            return
        fonts = resources.get("/Font")
        if fonts is not None and hasattr(fonts, "get_object"):
            fonts = fonts.get_object()
        if isinstance(fonts, DictionaryObject):
            for reference in fonts.values():
                font = reference.get_object()
                if str(font.get("/Subtype")) == "/Type3":
                    type3_fonts += 1
                if "/ToUnicode" not in font:
                    missing_tounicode += 1
        xobjects = resources.get("/XObject")
        if xobjects is not None and hasattr(xobjects, "get_object"):
            xobjects = xobjects.get_object()
        if isinstance(xobjects, DictionaryObject):
            for reference in xobjects.values():
                obj = reference.get_object()
                identity = id(obj)
                if identity in seen:
                    continue
                seen.add(identity)
                subtype = str(obj.get("/Subtype"))
                if subtype == "/Image":
                    images += 1
                elif subtype == "/Form":
                    form_xobjects += 1
                    inspect_stream(obj, obj.get("/Resources") or resources, seen, depth + 1)

    def inspect_stream(stream: object, resources: object, seen: set[int], depth: int = 0) -> None:
        nonlocal invisible, white_text, text_ops, actual_text, clipping_ops, transform_ops
        nonlocal alpha_states, operations_seen
        try:
            content = ContentStream(stream, reader)
        except (PdfReadError, ValueError, TypeError, KeyError) as exc:
            raise MalformedInputError("PDF content stream could not be decoded") from exc
        for operands, operator in content.operations:
            operations_seen += 1
            if operations_seen > 500_000:
                raise InputLimitError("PDF exceeds its decoded-operation budget")
            if operator == b"Tr" and operands and int(operands[-1]) == 3:
                invisible += 1
            elif operator in {b"Tj", b"TJ", b"'", b'"'}:
                text_ops += 1
            elif operator in {b"W", b"W*"}:
                clipping_ops += 1
            elif operator == b"cm":
                transform_ops += 1
            elif operator in {b"BDC", b"DP"}:
                for operand in operands:
                    value = operand.get_object() if hasattr(operand, "get_object") else operand
                    if isinstance(value, DictionaryObject) and "/ActualText" in value:
                        actual_text += 1
            elif operator == b"gs":
                alpha_states += 1
            # White fill color — text drawn in white on white background
            elif operator == b"rg" and len(operands) == 3:
                try:
                    r, g_val, b_val = (float(o) for o in operands)
                    if r >= 0.98 and g_val >= 0.98 and b_val >= 0.98:
                        white_text += 1
                except (ValueError, TypeError):
                    pass
            elif operator == b"g" and len(operands) == 1:
                try:
                    if float(operands[0]) >= 0.98:
                        white_text += 1
                except (ValueError, TypeError):
                    pass
        inspect_resources(resources, seen, depth)

    seen: set[int] = set()
    for page in reader.pages:
        resources = page.get("/Resources")
        contents = page.get_contents()
        if contents is not None:
            inspect_stream(contents, resources, seen, 0)
        else:
            inspect_resources(resources, seen, 0)
    try:
        root_for_layers = reader.trailer.get("/Root", {})
        if hasattr(root_for_layers, "get_object"):
            root_for_layers = root_for_layers.get_object()
        optional_layers = int("/OCProperties" in root_for_layers)
    except (PdfReadError, ValueError, TypeError, KeyError):
        optional_layers = 0
    findings: list[Finding] = []

    # DF-PDF-001: invisible/substituted text (includes white-on-white)
    suspicious = bool(
        text_ops and (
            invisible or white_text or actual_text
            or (type3_fonts and missing_tounicode)
        )
    )
    if suspicious:
        findings.append(_finding(
            path,
            "DF-PDF-001",
            "PDF contains a structurally divergent text presentation",
            "Decoded PDF objects contain invisible, substituted, or semantically redirected text. Legitimate OCR and accessibility tagging are confounders; rendered regional comparison is required.",
            Severity.MEDIUM,
            0.62,
            invisible_text_mode_count=invisible,
            white_fill_color_count=white_text,
            image_object_count=images,
            text_show_operator_count=text_ops,
            actual_text_count=actual_text,
            type3_font_count=type3_fonts,
            missing_tounicode_count=missing_tounicode,
            recursive_form_xobject_count=form_xobjects,
            clipping_operator_count=clipping_ops,
            transform_operator_count=transform_ops,
            graphics_state_count=alpha_states,
            optional_layer_count=optional_layers,
            page_count=len(reader.pages),
            requires_render_comparison=True,
            evidence_class="hidden_text_topology",
        ))

    # DF-PDF-002: PDF active content (JavaScript / auto-actions)
    js_count = 0
    root_catalog_unreadable = False
    try:
        root = reader.trailer.get("/Root")
        if root is not None:
            root_obj = root.get_object() if hasattr(root, "get_object") else root
            if isinstance(root_obj, DictionaryObject):
                if "/OpenAction" in root_obj:
                    js_count += 1
                if "/AA" in root_obj:
                    js_count += 1
    except (PdfReadError, ValueError, TypeError, KeyError):
        # The root catalog couldn't be decoded; page-level /JS detection
        # below still runs, but any /OpenAction or /AA on a malformed
        # catalog is missed. Record that gap in the finding evidence.
        root_catalog_unreadable = True
    for page in reader.pages:
        for key in ("/JS", "/JavaScript", "/AA"):
            if key in page:
                js_count += 1
    if js_count:
        findings.append(_finding(
            path,
            "DF-PDF-002",
            "PDF contains active content (JavaScript or auto-actions)",
            "The PDF contains JavaScript, auto-action triggers, or open-actions "
            "that execute when the document is opened or interacted with. "
            "Active content in supply-chain artifacts is a deception vector.",
            Severity.HIGH,
            0.90,
            javascript_action_count=js_count,
            page_count=len(reader.pages),
            evidence_class="active_content",
            root_catalog_unreadable=root_catalog_unreadable,
        ))

    # DF-PDF-003: PDF incremental saves
    eof_count = data.count(b"%%EOF")
    # DF-PDF-004: the embedded font program disagrees with /ToUnicode.
    # Imported lazily: the module raises ScanIncompleteError at import time when
    # the [evilfont] extra is absent, and a module-scope import here would break
    # `depfence --help` for a bare install.
    try:
        from depfence.core.pdf_glyph_truth import glyph_truth_mismatches
    except ScanIncompleteError:
        mismatches = []
    else:
        mismatches = glyph_truth_mismatches(data)
    if mismatches:
        sample = "; ".join(
            f"a glyph draws {m.drawn!r} but the document claims {m.claimed!r}"
            for m in mismatches[:3]
        )
        findings.append(_finding(
            path,
            "DF-PDF-004",
            "PDF glyphs disagree with their declared Unicode",
            "The embedded font program states that a drawn glyph renders one "
            "character while the document's /ToUnicode map claims another, so "
            "extracted text differs from what a reader sees. "
            f"{sample}.",
            Severity.HIGH,
            0.95,
            mismatch_count=len(mismatches),
            evidence_class="glyph_unicode_mismatch",
        ))

    if eof_count > 1:
        findings.append(_finding(
            path,
            "DF-PDF-003",
            "PDF has multiple revision layers (incremental saves)",
            "The PDF contains multiple %%EOF markers indicating incremental updates. "
            "Later revisions can shadow or modify content from earlier revisions, "
            "a technique used to hide modifications from casual inspection.",
            Severity.MEDIUM,
            0.70,
            eof_marker_count=eof_count,
            page_count=len(reader.pages),
            evidence_class="incremental_save",
        ))

    return findings


def scan_artifact_bytes(path: Path, data: bytes) -> tuple[list[Finding], list[str]]:
    """Run host-side (Tier 1) deception analysis on in-memory artifact bytes."""
    if len(data) > MAX_ARTIFACT_BYTES:
        raise InputLimitError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    suffix = path.suffix.lower()
    media_type = detect_media_type(path, data)
    if suffix in FONT_SUFFIXES or media_type.startswith("font/"):
        semantic = inspect_font_semantics(data)
        findings = []
        if semantic.cmap_conflicts:
            findings.append(_finding(
                path, "DF-FONT-002", "Conflicting Unicode glyph mappings",
                "Unicode cmap subtables disagree about glyph identity. This is structural evidence and requires rendered reference comparison for confirmation.",
                Severity.MEDIUM, 0.82,  # structural; rendered reference comparison needed to confirm
                evidence_class="cmap_subtable_conflict",
                cmap_conflict_count=semantic.cmap_conflicts,
                cmap_subtable_count=semantic.cmap_subtables,
                member_count=semantic.member_count,
                presentation_mechanisms=list(semantic.presentation_mechanisms),
            ))
        # Glyph-to-codepoint ratio: many codepoints mapping to very few
        # unique glyphs is the core EvilFontTool technique.  A font where
        # 20+ codepoints all resolve to the same glyph ID is structurally
        # impossible in legitimate typography.
        if (
            semantic.unique_glyphs > 0
            and semantic.mapped_codepoints >= 20
            and semantic.mapped_codepoints / semantic.unique_glyphs > 20
        ):
            findings.append(_finding(
                path, "DF-FONT-003", "Degenerate glyph-to-codepoint mapping",
                "Many Unicode codepoints map to very few unique glyph IDs. "
                "This is the structural signature of a font engineered to "
                "display one character regardless of the codepoint used.",
                Severity.HIGH, 0.92,  # extremely high specificity for deception
                evidence_class="degenerate_cmap",
                mapped_codepoints=semantic.mapped_codepoints,
                unique_glyphs=semantic.unique_glyphs,
                ratio=round(semantic.mapped_codepoints / semantic.unique_glyphs, 2),
                member_count=semantic.member_count,
            ))
        # Zero advance width: a non-symbol font with many zero-width
        # mapped glyphs is used by EvilFontTool's "stealth font" variant
        # to render all characters as invisible.
        if semantic.zero_width_glyphs >= 8:
            findings.append(_finding(
                path, "DF-FONT-004", "Stealth font with zero-width mapped glyphs",
                "Multiple mapped codepoints have advance width zero. A font "
                "that renders all characters as invisible spaces is a "
                "mechanism for hiding machine-readable text from visual "
                "inspection.",
                Severity.HIGH, 0.90,
                evidence_class="zero_width_stealth",
                zero_width_glyphs=semantic.zero_width_glyphs,
                mapped_codepoints=semantic.mapped_codepoints,
                member_count=semantic.member_count,
            ))
        # Missing layout tables: a font mapping 26+ codepoints without
        # any of GSUB/GPOS/kern/GDEF is unusual for production fonts.
        # EvilFontTool strips these to prevent substitution interference.
        if semantic.missing_layout_tables:
            findings.append(_finding(
                path, "DF-FONT-005", "Font lacks expected layout tables",
                "A font mapping Latin characters contains none of "
                "GSUB, GPOS, kern, or GDEF. Production fonts include "
                "these for ligatures, kerning, and mark positioning. "
                "Stripped layout tables are a confounder for deception "
                "fonts that must prevent glyph substitution.",
                Severity.LOW, 0.55,  # legitimate fonts can lack these; lower confidence
                evidence_class="missing_layout_tables",
                mapped_codepoints=semantic.mapped_codepoints,
                member_count=semantic.member_count,
                presentation_mechanisms=list(semantic.presentation_mechanisms),
            ))
        return findings, list(semantic.limitations)
    if suffix in WEB_SUFFIXES:
        return _scan_web(path, data), []
    if suffix == ".docx" or media_type.startswith("application/vnd.openxmlformats"):
        return _scan_docx(path, data), []
    if suffix == ".pdf" or media_type == "application/pdf":
        if media_type != "application/pdf":
            raise MalformedInputError("PDF extension does not match its file signature")
        return _scan_pdf(path, data), []
    raise ScanIncompleteError(f"unsupported artifact type: {path}")


def scan_artifact_path(path: Path) -> tuple[list[Finding], list[str]]:
    """Read an on-disk artifact safely and delegate to :func:`scan_artifact_bytes`."""
    try:
        data = _read_regular_file(path)
    except ScanIncompleteError:
        raise
    except OSError as exc:
        raise ScanIncompleteError(f"artifact is unreadable: {path}") from exc
    return scan_artifact_bytes(Path(path.name), data)


def _read_regular_file(path: Path) -> bytes:
    """Read one stable regular file through a no-follow descriptor and a hard cap."""

    path_before = os.lstat(path)
    if stat.S_ISLNK(path_before.st_mode):
        raise ScanIncompleteError("artifact input must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        path_after = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(path_after.st_mode)
            or (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino)
            or (before.st_dev, before.st_ino) != (path_after.st_dev, path_after.st_ino)
        ):
            raise ScanIncompleteError("artifact input must be a regular non-symlink file")
        if before.st_size > MAX_ARTIFACT_BYTES:
            raise InputLimitError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise InputLimitError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
        if (
            len(data) != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ScanIncompleteError("artifact changed while it was being read")
        return data
    finally:
        os.close(descriptor)


def _sandbox_rate(metrics: dict[str, object], key: str) -> float:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScanIncompleteError(f"sandbox metric {key} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ScanIncompleteError(f"sandbox metric {key} is outside 0..1")
    return number


def _sandbox_count(metrics: dict[str, object], key: str, *, maximum: int) -> int:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ScanIncompleteError(f"sandbox metric {key} is outside its integer range")
    return value


def _sandbox_findings(document: object, artifact_name: str) -> list[Finding]:
    if not isinstance(document, dict):
        raise ScanIncompleteError("sandbox returned an invalid result envelope")
    expected_keys = {
        "schema_version", "input_sha256", "media_type", "complete", "limitations",
        "total_units", "processed_units", "findings",
    }
    if set(document) != expected_keys or document.get("schema_version") != SANDBOX_SCHEMA_VERSION:
        raise ScanIncompleteError("sandbox returned an unsupported result envelope")
    if not isinstance(document.get("findings"), list):
        raise ScanIncompleteError("sandbox findings must be an array")
    digest = document.get("input_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ScanIncompleteError("sandbox returned an invalid input digest")
    media_type = document.get("media_type")
    if media_type not in {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/html",
    }:
        raise ScanIncompleteError("sandbox returned an invalid media type")
    complete = document.get("complete")
    limitations = document.get("limitations")
    if not isinstance(complete, bool) or not isinstance(limitations, list) or any(
        not isinstance(item, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", item)
        for item in limitations
    ):
        raise ScanIncompleteError("sandbox returned invalid completeness metadata")
    total_units = document.get("total_units")
    processed_units = document.get("processed_units")
    if (
        isinstance(total_units, bool)
        or isinstance(processed_units, bool)
        or not isinstance(total_units, int)
        or not isinstance(processed_units, int)
        or total_units < 1
        or processed_units < 0
        or processed_units > total_units
    ):
        raise ScanIncompleteError("sandbox returned invalid coverage counts")
    if not complete or limitations or processed_units != total_units:
        codes = ",".join(limitations) if limitations else "partial_coverage"
        raise ScanIncompleteError(
            f"sandbox analysis incomplete ({processed_units}/{total_units}; {codes})"
        )
    findings: list[Finding] = []
    # Tier-1 IDs are listed deliberately. They are still rejected below -- Tier 2
    # confirms DF-VIS-001 only -- but recognising them here separates "a rule ID
    # we have never heard of" from "a real Tier-1 rule that a sandbox result
    # cannot establish", which is the more precise diagnostic.
    allowed_rules = {"DF-FONT-001", "DF-WEB-001", "DF-DOCX-001", "DF-PDF-001", "DF-VIS-001"}
    seen_regions: set[int] = set()
    for raw in document["findings"]:
        if not isinstance(raw, dict):
            raise ScanIncompleteError("sandbox returned an invalid finding")
        rule_id = str(raw.get("rule_id", ""))
        if rule_id not in allowed_rules:
            raise ScanIncompleteError("sandbox returned an unknown rule ID")
        if set(raw) != {"rule_id", "evidence_class", "metrics"}:
            raise ScanIncompleteError("sandbox finding contains unsupported fields")
        metrics = raw.get("metrics", {})
        required_metric_keys = {
            "character_error_rate", "ocr_confidence", "token_similarity",
            "compared_characters", "page_count",
            "visual_text_sha256", "machine_text_sha256", "hazardous_machine_text",
        }
        if (
            not isinstance(metrics, dict)
            or not required_metric_keys.issubset(metrics)
            or not set(metrics) <= required_metric_keys | {"region_index", "region_type"}
            or any(isinstance(value, (dict, list)) for value in metrics.values())
        ):
            raise ScanIncompleteError("sandbox metrics do not match the required contract")
        allowed_string_keys = {"region_type"}
        for key, value in metrics.items():
            if isinstance(value, str) and key not in allowed_string_keys and (
                not key.endswith("_sha256") or not re.fullmatch(r"[0-9a-f]{64}", value)
            ):
                raise ScanIncompleteError("sandbox metric strings must be SHA-256 digests")
            if not isinstance(value, (str, int, float, bool)):
                raise ScanIncompleteError("sandbox metric has an invalid scalar type")
        if rule_id != "DF-VIS-001":
            raise ScanIncompleteError("sandbox confirmation rule is not host-derivable")
        evidence_class = raw.get("evidence_class")
        if evidence_class != "rendered_text_comparison":
            raise ScanIncompleteError("sandbox evidence class is invalid")
        character_error_rate = _sandbox_rate(metrics, "character_error_rate")
        ocr_confidence = _sandbox_rate(metrics, "ocr_confidence")
        token_similarity = _sandbox_rate(metrics, "token_similarity")
        compared_characters = _sandbox_count(
            metrics, "compared_characters", maximum=MAX_ARTIFACT_BYTES
        )
        page_count = _sandbox_count(metrics, "page_count", maximum=10_000)
        if "region_index" in metrics:
            region_index = _sandbox_count(metrics, "region_index", maximum=10_000)
            if region_index < 1 or region_index in seen_regions or metrics.get("region_type") != "page":
                raise ScanIncompleteError("sandbox region metadata is invalid")
            seen_regions.add(region_index)
        hazardous = metrics.get("hazardous_machine_text")
        if not isinstance(hazardous, bool):
            raise ScanIncompleteError("sandbox hazard metric must be boolean")
        if not (
            compared_characters >= 20
            and character_error_rate >= 0.35
            and ocr_confidence >= 0.85
            and token_similarity <= 0.50
            and page_count == total_units
        ):
            raise ScanIncompleteError("sandbox finding does not meet host detection thresholds")
        severity = Severity.CRITICAL if hazardous else Severity.HIGH
        # Base 0.75 for any confirmed sandbox mismatch, scaled up by
        # divergence magnitude (CER) and OCR quality; capped at 0.99
        # because OCR is never fully deterministic.
        confidence = min(
            0.99, 0.75 + character_error_rate * 0.2 + ocr_confidence * 0.05
        )
        title = "Rendered text differs from machine-readable text"
        findings.append(Finding(
            finding_type=FindingType.VISUAL_TEXT_DECEPTION,
            severity=severity,
            package=f"artifact:{artifact_name}",
            title=title,
            detail="Sandboxed analysis confirmed conflicting visual and machine-readable text; content was withheld.",
            confidence=confidence,
            metadata={
                "file": artifact_name,
                "rule_id": rule_id,
                "analysis_mode": "sandboxed",
                "content_redacted": True,
                "evidence_class": "rendered_text_comparison",
                "metrics": metrics,
            },
        ))
    return findings


def run_sandbox_analysis(data: bytes, artifact_name: str, config: SandboxConfig) -> list[Finding]:
    """Run sandboxed (Tier 2) rendered-vs-text comparison in an OCI container."""
    if len(data) > MAX_ARTIFACT_BYTES:
        raise InputLimitError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    config.validate()
    container_name = "depfence-artifact-" + str(uuid.uuid4())
    command = [
        config.engine, "run", "--rm", "--interactive", "--pull", "never",
        "--name", container_name, "--label", "dev.depfence.purpose=artifact-analysis",
        "--network", "none",
        "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={Path(config.seccomp_profile).expanduser().resolve(strict=True)}",
        "--pids-limit", "64",
        "--memory", "512m", "--cpus", "1",
        "--ulimit", "nofile=256:256", "--ulimit", "core=0:0", "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=268435456",  # noqa: S108 - container tmpfs
    ]
    if config.runtime and config.runtime != "vm":
        # "vm" is an operator attestation, not a container engine runtime flag
        command.extend(["--runtime", config.runtime])
    command.extend([
        config.image,
        "depfence-artifact-analyzer",
        "--stdin",
        "--name",
        Path(artifact_name).name,
        "--format",
        "json",
    ])
    environment = {"PATH": os.environ.get("PATH", "")}
    try:
        return_code, stdout, _stderr = _run_bounded_subprocess(
            command,
            data,
            environment,
            config.timeout_seconds,
            discard_stderr=True,  # worker tracebacks must not cross the IPC boundary
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _force_remove_container(config.engine, container_name)
        raise ScanIncompleteError(f"sandbox analysis unavailable ({type(exc).__name__})") from exc
    except InputLimitError:
        _force_remove_container(config.engine, container_name)
        raise
    if return_code:
        raise ScanIncompleteError(f"sandbox analysis failed with exit {return_code}")
    def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(
            stdout,
            object_pairs_hook=strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScanIncompleteError("sandbox returned malformed JSON") from exc
    if not isinstance(document, dict) or document.get("input_sha256") != hashlib.sha256(data).hexdigest():
        raise ScanIncompleteError("sandbox input digest does not match the submitted artifact")
    expected_media_type = detect_media_type(Path(artifact_name), data)
    if document.get("media_type") != expected_media_type:
        raise ScanIncompleteError("sandbox media type does not match the submitted artifact")
    return _sandbox_findings(document, Path(artifact_name).name)


def _force_remove_container(engine: str, name: str) -> None:
    """Best-effort exact cleanup for a daemon-side worker after client failure."""

    try:
        subprocess.run(  # noqa: S603 - engine is restricted by SandboxConfig
            [engine, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_bounded_subprocess(
    command: list[str],
    stdin_value: bytes,
    environment: dict[str, str],
    timeout: float,
    *,
    discard_stderr: bool = False,
) -> tuple[int, bytes, bytes]:
    """Run a trusted pinned helper without allowing unbounded host output."""

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if discard_stderr else subprocess.PIPE,
        env=environment,
    )
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    deadline = time.monotonic() + timeout

    def read_bounded(stream: BinaryIO | None, destination: bytearray) -> None:
        assert stream is not None
        while chunk := stream.read(64 * 1024):
            if len(destination) + len(chunk) > MAX_SANDBOX_OUTPUT:
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                return
            destination.extend(chunk)

    def write_bounded(stream: BinaryIO | None) -> None:
        assert stream is not None
        try:
            view = memoryview(stdin_value)
            while view:
                written = stream.write(view[: 64 * 1024])
                if written is None:
                    raise BrokenPipeError
                view = view[written:]
            stream.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    output_thread = threading.Thread(
        target=read_bounded, args=(process.stdout, stdout), daemon=True
    )
    output_thread.start()
    if not discard_stderr:
        error_thread = threading.Thread(
            target=read_bounded, args=(process.stderr, stderr), daemon=True
        )
        error_thread.start()
    input_thread = threading.Thread(
        target=write_bounded, args=(process.stdin,), daemon=True
    )
    input_thread.start()
    try:
        while process.poll() is None:
            if overflow.is_set():
                raise InputLimitError("sandbox output exceeded its byte budget")
            if time.monotonic() >= deadline:
                process.kill()
                raise subprocess.TimeoutExpired(command, timeout)
            time.sleep(0.01)
        output_thread.join(timeout=1)
        if not discard_stderr:
            error_thread.join(timeout=1)
        input_thread.join(timeout=1)
        if overflow.is_set():
            raise InputLimitError("sandbox output exceeded its byte budget")
        return int(process.returncode or 0), bytes(stdout), bytes(stderr)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)


def inspect_artifact(
    path: Path,
    *,
    state: PrivateState,
    analysis_mode: str = "static",
    sandbox: SandboxConfig | None = None,
    retain_payload: bool = False,
) -> ScanResult:
    """Quarantine and inspect one artifact without exposing its original path."""

    if analysis_mode not in {"static", "sandboxed"}:
        raise ValueError("analysis_mode must be static or sandboxed")
    try:
        data = _read_regular_file(path)
    except ScanIncompleteError:
        raise
    except OSError as exc:
        raise ScanIncompleteError("artifact could not be quarantined") from exc

    digest = hashlib.sha256(data).hexdigest()
    artifact_id = state.opaque_id("artifact", digest)
    storage_id = artifact_id.split(":", 1)[-1]
    suffix = path.suffix.lower() if path.suffix.lower() in SUPPORTED_SUFFIXES else ".bin"
    # An extensionless opaque filename reduces accidental desktop preview or
    # indexing dispatch. It is still hostile data and remains mode 0600.
    if retain_payload:
        state.write_bytes(Path("artifacts") / ".metadata_never_index", b"")
        state.write_bytes(Path("artifacts") / storage_id / "payload", data)

    result = ScanResult(target=artifact_id, ecosystem="artifact", packages_scanned=1)
    try:
        findings, limitations = scan_artifact_bytes(Path(f"input{suffix}"), data)
        result.findings.extend(findings)
        if limitations:
            result.scanner_coverage["visual_text_deception_static"] = ScanState.UNPROVEN
            message = "; ".join(limitations)
            result.scanner_errors["visual_text_deception_static"] = message
            result.errors.append(message)
        else:
            result.scanner_coverage["visual_text_deception_static"] = ScanState.PASS
    except ScanIncompleteError as exc:
        result.scanner_coverage["visual_text_deception_static"] = ScanState.INDETERMINATE
        result.scanner_errors["visual_text_deception_static"] = str(exc)
        result.errors.append(str(exc))

    if analysis_mode == "sandboxed":
        if sandbox is None:
            raise ValueError("sandbox configuration is required for sandboxed analysis")
        try:
            result.findings.extend(run_sandbox_analysis(data, f"input{suffix}", sandbox))
            result.scanner_coverage["visual_text_deception_sandbox"] = ScanState.PASS
        except ScanIncompleteError as exc:
            result.scanner_coverage["visual_text_deception_sandbox"] = ScanState.INDETERMINATE
            result.scanner_errors["visual_text_deception_sandbox"] = str(exc)
            result.errors.append(str(exc))

    record = {
        "schema_version": "depfence.artifact-intake/v1",
        "artifact_id": artifact_id,
        "sha256": digest,
        "media_type": detect_media_type(path, data),
        "byte_count": len(data),
        "analysis_mode": analysis_mode,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "promoted": False,
        "payload_retained": retain_payload,
    }
    state.write_text(
        Path("artifacts") / storage_id / "record.json",
        json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    result.completed_at = datetime.now(timezone.utc)
    return result


__all__ = [
    "DOCUMENT_SUFFIXES",
    "FONT_SUFFIXES",
    "MAX_ARTIFACT_BYTES",
    "SUPPORTED_SUFFIXES",
    "SandboxConfig",
    "WEB_SUFFIXES",
    "detect_media_type",
    "inspect_artifact",
    "run_sandbox_analysis",
    "scan_artifact_bytes",
    "scan_artifact_path",
    "summarize_font",
    "inspect_font_semantics",
    "verify_image_signature",
]
