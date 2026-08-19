"""Tests for the bounded parsing primitives in artifact_analysis.

These test the security-critical XML parser, ZIP archive validator, and
web-font scanner without requiring real fonts or PDF binaries. They
verify bounds enforcement (depth, node count, size), XXE prevention
(DOCTYPE/ENTITY in UTF-8 and UTF-16), and archive-level protections
(path traversal, symlinks, compression bombs, encryption).
"""

from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from depfence.core.artifact_analysis import (
    _bounded_zip_member,
    _parse_bounded_xml,
    _scan_web,
    scan_artifact_bytes,
)
from depfence.core.scan_scope import InputLimitError, MalformedInputError, ScanIncompleteError

# ---------------------------------------------------------------------------
# _parse_bounded_xml — XXE prevention
# ---------------------------------------------------------------------------


class TestParseBoundedXml:
    def test_accepts_simple_xml(self) -> None:
        root = _parse_bounded_xml(b"<root><child/></root>")
        assert root.tag == "root"

    def test_rejects_doctype_declaration_utf8(self) -> None:
        data = b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x "y">]><root/>'
        with pytest.raises(MalformedInputError, match="unsafe"):
            _parse_bounded_xml(data)

    def test_rejects_doctype_case_insensitive(self) -> None:
        data = b"<!doctype root><root/>"
        with pytest.raises(MalformedInputError, match="unsafe"):
            _parse_bounded_xml(data)

    def test_rejects_entity_declaration(self) -> None:
        data = b"<!ENTITY foo SYSTEM 'file:///etc/passwd'><root/>"
        with pytest.raises(MalformedInputError, match="unsafe"):
            _parse_bounded_xml(data)

    def test_rejects_doctype_in_utf16_le(self) -> None:
        # Encode "<!DOCTYPE root>" in UTF-16-LE to bypass ASCII-only checks
        payload = "<!DOCTYPE root>".encode("utf-16-le")
        # Pad to 4096 bytes with nulls, then add valid UTF-8 XML
        data = payload + b"\x00" * (4096 - len(payload)) + b"<root/>"
        with pytest.raises(MalformedInputError, match="unsafe"):
            _parse_bounded_xml(data)

    def test_rejects_doctype_in_utf16_be(self) -> None:
        payload = "<!DOCTYPE root>".encode("utf-16-be")
        data = payload + b"\x00" * (4096 - len(payload)) + b"<root/>"
        with pytest.raises(MalformedInputError, match="unsafe"):
            _parse_bounded_xml(data)

    def test_rejects_empty_xml(self) -> None:
        # Empty input hits ParseError before the root-is-None check
        with pytest.raises(MalformedInputError, match="malformed"):
            _parse_bounded_xml(b"")

    def test_rejects_malformed_xml(self) -> None:
        with pytest.raises(MalformedInputError, match="malformed"):
            _parse_bounded_xml(b"not xml at all {{{")

    def test_rejects_deep_nesting(self) -> None:
        # MAX_XML_DEPTH is 128, build 130 levels
        nested = b"<a>" * 130 + b"x" + b"</a>" * 130
        with pytest.raises(InputLimitError, match="structure budget"):
            _parse_bounded_xml(nested)

    def test_accepts_xml_below_depth_limit(self) -> None:
        # 10 levels should be fine
        nested = b"<a>" * 10 + b"<leaf/>" + b"</a>" * 10
        root = _parse_bounded_xml(nested)
        assert root.tag == "a"


# ---------------------------------------------------------------------------
# _bounded_zip_member — size limits
# ---------------------------------------------------------------------------


class TestBoundedZipMember:
    def test_reads_small_member(self) -> None:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("test.txt", "hello")
        with zipfile.ZipFile(BytesIO(stream.getvalue())) as zf:
            info = zf.infolist()[0]
            result: bytes = _bounded_zip_member(zf, info, 1024)
        assert result == b"hello"

    def test_rejects_member_over_declared_size(self) -> None:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("big.txt", "x" * 100)
        with zipfile.ZipFile(BytesIO(stream.getvalue())) as zf:
            info = zf.infolist()[0]
            with pytest.raises(InputLimitError, match="exceeds"):
                _bounded_zip_member(zf, info, 50)


# ---------------------------------------------------------------------------
# _scan_docx — archive-level security
# ---------------------------------------------------------------------------


def _make_docx(members: dict[str, str | bytes]) -> bytes:
    """Build a minimal DOCX zip with the given members."""
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for name, content in members.items():
            if isinstance(content, str):
                content = content.encode()
            zf.writestr(name, content)
    return stream.getvalue()


_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_MINIMAL_DOCUMENT = f'<w:document xmlns:w="{_NS}"><w:body/></w:document>'


class TestScanDocx:
    def test_minimal_valid_docx_has_no_findings(self) -> None:
        data: bytes = _make_docx({
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": _MINIMAL_DOCUMENT,
        })
        findings, limitations = scan_artifact_bytes(Path("test.docx"), data)
        assert findings == []
        assert limitations == []

    def test_rejects_missing_document_xml(self) -> None:
        data: bytes = _make_docx({
            "[Content_Types].xml": "<Types/>",
        })
        with pytest.raises(MalformedInputError, match="missing word/document.xml"):
            scan_artifact_bytes(Path("test.docx"), data)

    def test_rejects_path_traversal(self) -> None:
        data: bytes = _make_docx({
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": _MINIMAL_DOCUMENT,
            "../../../etc/passwd": "root:x:0:0",
        })
        with pytest.raises(MalformedInputError, match="path-traversing"):
            scan_artifact_bytes(Path("test.docx"), data)

    def test_rejects_absolute_path_member(self) -> None:
        data: bytes = _make_docx({
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": _MINIMAL_DOCUMENT,
            "/etc/shadow": "bad",
        })
        with pytest.raises(MalformedInputError, match="path-traversing"):
            scan_artifact_bytes(Path("test.docx"), data)

    def test_rejects_duplicate_member_names(self) -> None:
        # zipfile.ZipFile allows writing duplicate entries
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", _MINIMAL_DOCUMENT)
            zf.writestr("word/document.xml", _MINIMAL_DOCUMENT)
        with pytest.raises(MalformedInputError, match="duplicate"):
            scan_artifact_bytes(Path("test.docx"), stream.getvalue())

    def test_rejects_encrypted_member(self) -> None:
        # Build a valid DOCX zip then patch the flag_bits in the raw bytes
        # to set bit 0 (encryption flag) on a member's local file header.
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", _MINIMAL_DOCUMENT)
        raw = bytearray(stream.getvalue())
        # Patch general purpose bit flag in the central directory entry
        # for "word/document.xml". The central directory flag is at offset
        # 8 from each central directory file header (sig 0x02014b50).
        sig = b"PK\x01\x02"
        idx = 0
        while True:
            pos = raw.find(sig, idx)
            if pos < 0:
                break
            # Filename starts at offset 46 of the central directory entry
            fname_len = int.from_bytes(raw[pos + 28 : pos + 30], "little")
            fname = raw[pos + 46 : pos + 46 + fname_len].decode()
            if fname == "word/document.xml":
                # Set bit 0 of the flag at offset 8
                raw[pos + 8] |= 0x01
                break
            idx = pos + 4
        # Also patch the local file header (sig 0x04034b50)
        local_sig = b"PK\x03\x04"
        idx = 0
        while True:
            pos = raw.find(local_sig, idx)
            if pos < 0:
                break
            fname_len = int.from_bytes(raw[pos + 26 : pos + 28], "little")
            fname = raw[pos + 30 : pos + 30 + fname_len].decode()
            if fname == "word/document.xml":
                raw[pos + 6] |= 0x01
                break
            idx = pos + 4
        with pytest.raises(MalformedInputError, match="encrypted"):
            scan_artifact_bytes(Path("test.docx"), bytes(raw))

    def test_rejects_non_zip_data(self) -> None:
        with pytest.raises(MalformedInputError, match="malformed DOCX"):
            scan_artifact_bytes(Path("test.docx"), b"not a zip file at all")

    def test_rejects_doctype_in_document_xml(self) -> None:
        doctype_doc = (
            '<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY x "y">]>'
            f'<w:document xmlns:w="{_NS}"><w:body/></w:document>'
        )
        data: bytes = _make_docx({
            "[Content_Types].xml": "<Types/>",
            "word/document.xml": doctype_doc,
        })
        with pytest.raises(MalformedInputError, match="unsafe"):
            scan_artifact_bytes(Path("test.docx"), data)

    def test_rejects_symlink_member(self) -> None:
        """DOCX with a symlink archive member is rejected."""
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", _MINIMAL_DOCUMENT)
            # Add a member with symlink external attributes
            info = zipfile.ZipInfo("word/evil_link")
            # Set symlink flag: S_IFLNK = 0o120000, shifted left 16
            info.external_attr = 0o120000 << 16
            zf.writestr(info, "/etc/passwd")
        with pytest.raises(MalformedInputError, match="symbolic-link"):
            scan_artifact_bytes(Path("test.docx"), stream.getvalue())


# ---------------------------------------------------------------------------
# _scan_web — per-character font detection
# ---------------------------------------------------------------------------


class TestScanWeb:
    def test_benign_html_has_no_findings(self) -> None:
        data = b"<html><body><p>Hello World</p></body></html>"
        findings: list = _scan_web(Path("test.html"), data)
        assert findings == []

    def test_non_utf8_html_raises(self) -> None:
        with pytest.raises(ScanIncompleteError, match="UTF-8"):
            _scan_web(Path("test.html"), b"\xff\xfe\x00\x00invalid")

    def test_suspicious_per_char_font_construction(self) -> None:
        """An HTML page with 10+ @font-face rules, 5 families, 10 unicode ranges,
        and single-character spans triggers DF-WEB-001."""
        faces = "\n".join(
            f"@font-face {{ font-family: 'Font{i}'; src: url(f{i}.woff); unicode-range: U+{0x41+i:04X}; }}"
            for i in range(12)
        )
        families = "\n".join(
            f".c{i} {{ font-family: 'Font{i}'; }}"
            for i in range(12)
        )
        spans = "\n".join(
            f"<span style=\"font-family: 'Font{i % 12}'\">{chr(0x41+i)}</span>"
            for i in range(20)
        )
        html = f"<html><head><style>{faces}\n{families}</style></head><body>{spans}</body></html>"
        findings: list = _scan_web(Path("test.html"), html.encode())
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DF-WEB-001"
        assert findings[0].metadata["font_face_count"] >= 8
        assert findings[0].metadata["single_character_run_count"] >= 8

    def test_css_file_below_threshold_no_findings(self) -> None:
        css = "@font-face { font-family: 'Roboto'; src: url(roboto.woff); }\nbody { font-family: Roboto; }"
        findings: list = _scan_web(Path("style.css"), css.encode())
        assert findings == []


# ---------------------------------------------------------------------------
# scan_artifact_bytes — routing and media type checks
# ---------------------------------------------------------------------------


class TestScanArtifactBytesRouting:
    def test_pdf_extension_with_wrong_signature_raises(self) -> None:
        with pytest.raises(MalformedInputError, match="file signature"):
            scan_artifact_bytes(Path("fake.pdf"), b"not a PDF at all")

    def test_html_extension_routes_to_web_scanner(self) -> None:
        # Simple HTML should not raise and should return no findings
        findings, limitations = scan_artifact_bytes(
            Path("page.html"), b"<html><body>Hello</body></html>"
        )
        assert findings == []
        assert limitations == []

    def test_htm_extension_routes_to_web_scanner(self) -> None:
        findings, limitations = scan_artifact_bytes(
            Path("page.htm"), b"<html><body>Hello</body></html>"
        )
        assert findings == []

    def test_css_extension_routes_to_web_scanner(self) -> None:
        findings, limitations = scan_artifact_bytes(
            Path("style.css"), b"body { color: red; }"
        )
        assert findings == []

    def test_unsupported_suffix_raises(self) -> None:
        with pytest.raises(ScanIncompleteError, match="unsupported"):
            scan_artifact_bytes(Path("readme.txt"), b"hello")

    def test_empty_font_raises_malformed(self) -> None:
        # Empty font data is too short for FontTools to decode
        with pytest.raises(MalformedInputError, match="font could not be decoded"):
            scan_artifact_bytes(Path("empty.ttf"), b"")
