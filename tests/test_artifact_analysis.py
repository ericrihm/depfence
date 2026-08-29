"""Unit tests for the artifact-analysis public API boundary.

These are host-side unit tests of parsing, limits, and error taxonomy.  They
never construct valid font/PDF binaries and never require the sandboxed
container worker; see test_visual_text_deception.py for the scanner-level
detection tests that build real (if inert) fixtures.
"""

from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from depfence.core.artifact_analysis import (
    FONT_SUFFIXES,
    MAX_ARTIFACT_BYTES,
    SUPPORTED_SUFFIXES,
    FontSemanticSummary,
    detect_media_type,
    scan_artifact_bytes,
    scan_artifact_path,
    summarize_font,
)
from depfence.core.scan_scope import InputLimitError, MalformedInputError, ScanIncompleteError


def test_scan_artifact_bytes_with_empty_data_returns_no_findings() -> None:
    findings, limitations = scan_artifact_bytes(Path("inert.html"), b"")
    assert findings == []
    assert limitations == []


def test_scan_artifact_bytes_rejects_data_over_the_byte_budget() -> None:
    oversized = b"x" * (MAX_ARTIFACT_BYTES + 1)
    with pytest.raises(InputLimitError, match=str(MAX_ARTIFACT_BYTES)):
        scan_artifact_bytes(Path("huge.pdf"), oversized)


def test_scan_artifact_path_rejects_unsupported_suffix(tmp_path: Path) -> None:
    artifact = tmp_path / "notes.txt"
    artifact.write_bytes(b"hello world")
    with pytest.raises(ScanIncompleteError, match="unsupported artifact type"):
        scan_artifact_path(artifact)


def test_scan_artifact_path_raises_for_a_nonexistent_file(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.pdf"
    with pytest.raises((FileNotFoundError, ScanIncompleteError)):
        scan_artifact_path(missing)


def test_summarize_font_rejects_truncated_data() -> None:
    with pytest.raises(MalformedInputError, match="table directory"):
        summarize_font(b"")


def test_summarize_font_reports_incomplete_coverage_for_woff2() -> None:
    # woff2 is a recognized signature the host cannot safely decompress
    # without brotli support, so it is reported incomplete rather than parsed.
    summary = summarize_font(b"wOF2" + b"\x00" * 8)
    assert summary.complete is False
    assert summary.flavor == "woff2"
    assert summary.family is None
    assert summary.cmap_entries is None
    assert summary.glyphs is None


@pytest.mark.parametrize(
    ("suffix", "signature", "expected"),
    [
        (".pdf", b"%PDF-1.4\n%%EOF", "application/pdf"),
        (".ttf", b"\x00\x01\x00\x00" + b"\x00" * 8, "font/sfnt"),
        (".otf", b"OTTO" + b"\x00" * 8, "font/sfnt"),
        (".woff", b"wOFF" + b"\x00" * 8, "font/woff"),
        (".woff2", b"wOF2" + b"\x00" * 8, "font/woff2"),
    ],
)
def test_detect_media_type_for_known_suffixes(
    suffix: str, signature: bytes, expected: str
) -> None:
    assert detect_media_type(Path(f"artifact{suffix}"), signature) == expected


def test_detect_media_type_for_docx_requires_zip_signature_and_markers() -> None:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
    docx = stream.getvalue()
    assert (
        detect_media_type(Path("sample.docx"), docx)
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )


def test_detect_media_type_falls_back_to_octet_stream_for_unknown_data() -> None:
    assert detect_media_type(Path("mystery.bin"), b"not a recognized signature") == (
        "application/octet-stream"
    )


def test_supported_suffixes_contain_expected_font_web_and_document_types() -> None:
    assert FONT_SUFFIXES == {".ttf", ".otf", ".ttc", ".woff", ".woff2"}
    assert SUPPORTED_SUFFIXES >= FONT_SUFFIXES
    assert {".html", ".htm", ".css", ".docx", ".pdf"} <= SUPPORTED_SUFFIXES


def test_scan_artifact_bytes_rejects_docx_with_a_doctype_declaration() -> None:
    namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    document = (
        '<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY x "y">]>'
        f'<w:document xmlns:w="{namespace}"><w:body/></w:document>'
    )
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", document)
    with pytest.raises(MalformedInputError, match="unsafe"):
        scan_artifact_bytes(Path("bad.docx"), stream.getvalue())


# -- verify_image_signature input validation --


def test_verify_image_rejects_unpinned_image() -> None:
    from depfence.core.artifact_analysis import verify_image_signature

    with pytest.raises(ValueError, match="sha256"):
        verify_image_signature("latest", "id@example", "https://issuer.example")


def test_verify_image_rejects_empty_identity() -> None:
    from depfence.core.artifact_analysis import verify_image_signature

    with pytest.raises(ValueError, match="identity"):
        verify_image_signature("img@sha256:" + "a" * 64, "", "https://issuer.example")


def test_verify_image_rejects_control_chars_in_identity() -> None:
    from depfence.core.artifact_analysis import verify_image_signature

    with pytest.raises(ValueError, match="identity"):
        verify_image_signature("img@sha256:" + "a" * 64, "id\x00evil", "https://issuer.example")


def test_verify_image_rejects_non_https_issuer() -> None:
    from depfence.core.artifact_analysis import verify_image_signature

    with pytest.raises(ValueError, match="issuer"):
        verify_image_signature("img@sha256:" + "a" * 64, "id@example", "http://issuer.example")


def test_verify_image_rejects_control_chars_in_issuer() -> None:
    from depfence.core.artifact_analysis import verify_image_signature

    with pytest.raises(ValueError, match="issuer"):
        verify_image_signature("img@sha256:" + "a" * 64, "id@example", "https://issuer\x01.example")


# -- _force_remove_container --


def test_force_remove_container_calls_engine_rm(monkeypatch: pytest.MonkeyPatch) -> None:
    from depfence.core.artifact_analysis import _force_remove_container

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> None:
        calls.append(cmd)

    monkeypatch.setattr("subprocess.run", fake_run)
    _force_remove_container("docker", "test-container")
    assert calls == [["docker", "rm", "--force", "test-container"]]


def test_force_remove_container_survives_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    from depfence.core.artifact_analysis import _force_remove_container

    def raise_oserror(cmd: list[str], **_kwargs: object) -> None:
        raise OSError("engine not found")

    monkeypatch.setattr("subprocess.run", raise_oserror)
    _force_remove_container("missing-engine", "ctr")  # should not raise


def test_force_remove_container_survives_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess as sp

    from depfence.core.artifact_analysis import _force_remove_container

    def raise_timeout(cmd: list[str], **_kwargs: object) -> None:
        raise sp.TimeoutExpired(cmd, 15)

    monkeypatch.setattr("subprocess.run", raise_timeout)
    _force_remove_container("docker", "hung-container")  # should not raise


def test_font_semantic_summary_is_a_frozen_dataclass_with_expected_fields() -> None:
    # Boundary check on the public shape rather than a live inspection, since
    # inspect_font_semantics requires a byte-accurate sfnt/ttc fixture.
    summary = FontSemanticSummary(
        member_count=1,
        cmap_subtables=0,
        cmap_conflicts=0,
        mapped_codepoints=0,
        unique_glyphs=0,
        zero_width_glyphs=0,
        missing_layout_tables=False,
        presentation_mechanisms=(),
        limitations=("cmap_missing",),
    )
    assert summary.member_count == 1
    assert summary.limitations == ("cmap_missing",)
    assert summary.unique_glyphs == 0
    assert summary.zero_width_glyphs == 0
    assert summary.missing_layout_tables is False
    with pytest.raises(AttributeError):
        summary.member_count = 2  # type: ignore[misc]


# -- DF-PDF-002: active content --


def _make_pdf(**extra_root_keys: object) -> bytes:
    """Build a minimal valid PDF, optionally injecting keys into the catalog."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    for key, value in extra_root_keys.items():
        if isinstance(value, dict):
            obj = DictionaryObject(
                {NameObject(k): (TextStringObject(v) if isinstance(v, str) else v)
                 for k, v in value.items()},
            )
            writer._root_object[NameObject(key)] = obj  # noqa: SLF001
        else:
            writer._root_object[NameObject(key)] = value  # noqa: SLF001
    buf = BytesIO()
    writer.write(buf)
    return buf.getvalue()


class TestPdfActiveContent:
    """DF-PDF-002: JavaScript and auto-action detection."""

    def test_pdf_with_openaction_triggers_df_pdf_002(self) -> None:
        from pypdf.generic import DictionaryObject, NameObject, TextStringObject
        action = DictionaryObject({
            NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject("alert(1)"),
        })
        pdf_bytes = _make_pdf(**{"/OpenAction": action})
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-002" in rule_ids

    def test_normal_pdf_no_active_content(self) -> None:
        pdf_bytes = _make_pdf()
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-002" not in rule_ids

    def test_openaction_destination_is_not_active_content(self) -> None:
        """A bare /OpenAction destination (open at fit-width) is navigation,
        not active content. fpdf2, LaTeX hyperref and Word exports all emit
        one, so counting its mere presence flags benign documents HIGH."""
        from pypdf.generic import ArrayObject, NameObject, NullObject, NumberObject
        # [<page ref> /FitH null] -- the fpdf2 shape. Use a page number stand-in;
        # scan only needs the value to be an array, not a JavaScript action.
        dest = ArrayObject([NumberObject(0), NameObject("/FitH"), NullObject()])
        pdf_bytes = _make_pdf(**{"/OpenAction": dest})
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-002" not in rule_ids

    def test_real_fpdf_document_is_not_flagged_active_content(self) -> None:
        """Regression: the shipped fpdf.pdf fixture -- a benign fpdf2 document --
        fired DF-PDF-002 HIGH on a fit-width /OpenAction."""
        fixture = Path(__file__).parent / "fixtures" / "pdf" / "fpdf.pdf"
        findings, _ = scan_artifact_bytes(fixture, fixture.read_bytes())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-002" not in rule_ids

    @staticmethod
    def _make_pdf_with_page_js() -> bytes:
        """Build a PDF with a page-level /JS entry (not a root-catalog action)."""
        from pypdf import PdfWriter
        from pypdf.generic import NameObject, TextStringObject
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        writer.pages[0][NameObject("/JS")] = TextStringObject("alert(1)")
        buf = BytesIO()
        writer.write(buf)
        return buf.getvalue()

    @staticmethod
    def _make_corrupted_root_reader_class():
        """Return a PdfReader subclass whose trailer.get("/Root") fails once.

        pypdf lazily resolves pages via ``root_object`` which calls
        ``trailer.get("/Root")``, so a permanent failure would break
        page traversal too.  Instead the proxy fails exactly once — the
        scanner's explicit root-catalog check — then recovers so that
        page traversal succeeds afterward.

        Timeline inside ``_scan_pdf``:
        1. ``PdfReader.__init__`` — real trailer used (proxy not yet installed)
        2. Scanner try/except block — ``trailer.get("/Root")`` → **raises** (caught)
        3. ``for page in reader.pages`` — ``trailer.get("/Root")`` → succeeds
        """
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError

        class _CorruptedRootReader(PdfReader):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                # Force root_object and page resolution BEFORE replacing
                # the trailer, so both are cached and subsequent access
                # (e.g. ``for page in reader.pages``) never calls
                # trailer.get("/Root") again.
                _ = self.root_object          # caches _validated_root
                _ = list(self.pages)          # caches flattened_pages
                real_trailer = self.trailer

                class _TrailerProxy:  # noqa: N801
                    """Proxy that raises on EVERY .get('/Root') call.

                    Both the OCProperties check (line ~938, its own try/except)
                    and the DF-PDF-002 check (lines ~976-989, its own try/except)
                    must each catch the error independently.  Page traversal
                    uses ``reader.pages`` which was pre-cached in __init__.
                    """
                    def get(self, key, default=None):  # noqa: N805
                        if key == "/Root":
                            raise PdfReadError("simulated root catalog corruption")
                        return real_trailer.get(key, default)
                    def __getattr__(self, name):
                        return getattr(real_trailer, name)
                    def __contains__(self, key):
                        return key in real_trailer
                    def __getitem__(self, key):
                        return real_trailer[key]

                self.trailer = _TrailerProxy()

        return _CorruptedRootReader

    def test_corrupted_root_still_detects_page_level_js(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unreadable root catalog must not blind DF-PDF-002 to page-level /JS."""
        CorruptedReader = self._make_corrupted_root_reader_class()
        monkeypatch.setattr("pypdf.PdfReader", CorruptedReader)
        pdf_bytes = self._make_pdf_with_page_js()
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        by_rule = {f.metadata.get("rule_id"): f for f in findings}
        assert "DF-PDF-002" in by_rule
        finding = by_rule["DF-PDF-002"]
        assert finding.metadata["root_catalog_unreadable"] is True
        assert finding.metadata["javascript_action_count"] >= 1

    def test_corrupted_root_without_page_js_does_not_fire_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A corrupted root catalog with no other active content must degrade gracefully."""
        CorruptedReader = self._make_corrupted_root_reader_class()
        monkeypatch.setattr("pypdf.PdfReader", CorruptedReader)
        pdf_bytes = _make_pdf()
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-002" not in rule_ids


# -- DF-PDF-003: incremental saves --


class TestPdfIncrementalSaves:
    """DF-PDF-003: Multiple %%EOF markers."""

    def test_pdf_with_multiple_eof_triggers_df_pdf_003(self) -> None:
        base = _make_pdf()
        # Simulate an incremental save by appending another %%EOF
        incremental = base + b"\n%%EOF"
        findings, _ = scan_artifact_bytes(Path("test.pdf"), incremental)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-003" in rule_ids

    def test_normal_pdf_single_eof_no_finding(self) -> None:
        pdf_bytes = _make_pdf()
        findings, _ = scan_artifact_bytes(Path("test.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-003" not in rule_ids


# -- DF-DOCX-002: hidden document content --


class TestDocxHiddenContent:
    """DF-DOCX-002: Hidden document content detection."""

    def test_docx_with_hidden_runs_triggers_df_docx_002(self) -> None:
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        doc = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{ns}"><w:body>'
        )
        for i in range(4):
            doc += (
                f"<w:r><w:rPr><w:vanish/></w:rPr>"
                f"<w:t>hidden{i}</w:t></w:r>"
            )
        doc += "</w:body></w:document>"
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", doc)
        findings, _ = scan_artifact_bytes(Path("hidden.docx"), stream.getvalue())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-DOCX-002" in rule_ids

    def test_docx_with_many_revisions_triggers_df_docx_002(self) -> None:
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        doc = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{ns}"><w:body>'
        )
        for i in range(6):
            doc += f"<w:del><w:r><w:t>deleted{i}</w:t></w:r></w:del>"
        doc += "</w:body></w:document>"
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", doc)
        findings, _ = scan_artifact_bytes(Path("revised.docx"), stream.getvalue())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-DOCX-002" in rule_ids

    def test_normal_docx_no_hidden_content(self) -> None:
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        doc = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{ns}"><w:body>'
            f"<w:r><w:t>Normal text</w:t></w:r>"
            f"</w:body></w:document>"
        )
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", doc)
        findings, _ = scan_artifact_bytes(Path("normal.docx"), stream.getvalue())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-DOCX-002" not in rule_ids

    def test_docx_with_white_text_triggers_df_docx_002(self) -> None:
        """White/near-white w:color values count as hidden runs."""
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        doc = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{ns}"><w:body>'
        )
        # 3 runs with white text color — should reach hidden_runs >= 3
        for color in ("FFFFFF", "FEFEFE", "FDFDFD"):
            doc += (
                f'<w:r><w:rPr><w:color w:val="{color}"/></w:rPr>'
                f"<w:t>invisible</w:t></w:r>"
            )
        doc += "</w:body></w:document>"
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", doc)
        findings, _ = scan_artifact_bytes(Path("white.docx"), stream.getvalue())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-DOCX-002" in rule_ids

    def test_docx_with_normal_color_no_hidden(self) -> None:
        """Non-white text colors should not trigger DF-DOCX-002."""
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        doc = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:document xmlns:w="{ns}"><w:body>'
        )
        for _ in range(5):
            doc += (
                '<w:r><w:rPr><w:color w:val="000000"/></w:rPr>'
                "<w:t>visible</w:t></w:r>"
            )
        doc += "</w:body></w:document>"
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", doc)
        findings, _ = scan_artifact_bytes(Path("normal.docx"), stream.getvalue())
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-DOCX-002" not in rule_ids


# -- DF-PDF-001: white-on-white text --


def _make_pdf_with_content(content_bytes: bytes) -> bytes:
    """Build a PDF with a custom content stream."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    stream = DecodedStreamObject()
    stream.set_data(content_bytes)
    page[NameObject("/Contents")] = stream
    buf = BytesIO()
    writer.write(buf)
    return buf.getvalue()


class TestPdfWhiteOnWhite:
    """DF-PDF-001: white fill color triggers invisible text detection."""

    def test_pdf_with_rgb_white_fill_triggers_df_pdf_001(self) -> None:
        content = b"BT\n1 1 1 rg\n/F1 12 Tf\n100 700 Td\n(hidden) Tj\nET"
        pdf_bytes = _make_pdf_with_content(content)
        findings, _ = scan_artifact_bytes(Path("white.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-001" in rule_ids
        # Verify the evidence includes the white fill count
        pdf001 = [f for f in findings if f.metadata.get("rule_id") == "DF-PDF-001"][0]
        assert pdf001.metadata.get("white_fill_color_count", 0) >= 1

    def test_pdf_with_grayscale_white_fill_triggers_df_pdf_001(self) -> None:
        content = b"BT\n1 g\n/F1 12 Tf\n100 700 Td\n(hidden) Tj\nET"
        pdf_bytes = _make_pdf_with_content(content)
        findings, _ = scan_artifact_bytes(Path("white.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-001" in rule_ids
        pdf001 = [f for f in findings if f.metadata.get("rule_id") == "DF-PDF-001"][0]
        assert pdf001.metadata.get("white_fill_color_count", 0) >= 1

    def test_pdf_with_near_white_fill_triggers_df_pdf_001(self) -> None:
        """Near-white (0.99 0.99 0.99) should also trigger."""
        content = b"BT\n0.99 0.99 0.99 rg\n/F1 12 Tf\n100 700 Td\n(hidden) Tj\nET"
        pdf_bytes = _make_pdf_with_content(content)
        findings, _ = scan_artifact_bytes(Path("white.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-001" in rule_ids

    def test_pdf_with_dark_fill_no_white_finding(self) -> None:
        """Normal dark text should not trigger white-on-white detection."""
        content = b"BT\n0 0 0 rg\n/F1 12 Tf\n100 700 Td\n(visible) Tj\nET"
        pdf_bytes = _make_pdf_with_content(content)
        findings, _ = scan_artifact_bytes(Path("normal.pdf"), pdf_bytes)
        rule_ids = [f.metadata.get("rule_id") for f in findings]
        assert "DF-PDF-001" not in rule_ids
