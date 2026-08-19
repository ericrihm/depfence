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
        presentation_mechanisms=(),
        limitations=("cmap_missing",),
    )
    assert summary.member_count == 1
    assert summary.limitations == ("cmap_missing",)
    with pytest.raises(AttributeError):
        summary.member_count = 2  # type: ignore[misc]
