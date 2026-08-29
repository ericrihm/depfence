"""Glyph-truth checks for PDF text.

A PDF can draw one character while its /ToUnicode map claims another, so the
text a reader sees differs from the text an extractor returns. The embedded
font program is the ground truth: it states what each glyph actually draws.

These fixtures are real files, not synthesised bytes. `evil.pdf` and
`stealth.pdf` render pixel-identically to benign originals, and pypdf, pdfium
and pdfminer are all fooled identically -- differential extraction cannot see
this class, only the glyph check can.
"""

from __future__ import annotations

from pathlib import Path

from depfence.core.pdf_glyph_truth import GlyphMismatch, glyph_truth_mismatches

FIXTURES = Path(__file__).parent / "fixtures" / "pdf"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_benign_pdf_has_no_mismatches() -> None:
    assert glyph_truth_mismatches(_read("orig.pdf")) == []


def test_non_identity_cid_to_gid_map_is_not_a_false_positive() -> None:
    """/Identity-H fixes code == CID, not code == GID.

    CID == GID additionally requires /CIDToGIDMap to be /Identity or absent
    (ISO 32000-1 9.7.4.2). fpdf2 emits a 131KB non-identity map on entirely
    benign output; ignoring it produced 9 false positives on this file.
    """
    assert glyph_truth_mismatches(_read("fpdf.pdf")) == []


def test_detects_tounicode_hijack() -> None:
    mismatches = glyph_truth_mismatches(_read("evil.pdf"))

    assert {(m.drawn, m.claimed) for m in mismatches} == {("A", "X"), ("B", "Y"), ("C", "Z")}


def test_detects_stealth_digit_substitution() -> None:
    """Renders 1000, extracts 9000 -- a financial substitution."""
    mismatches = glyph_truth_mismatches(_read("stealth.pdf"))

    assert len(mismatches) == 1
    assert (mismatches[0].drawn, mismatches[0].claimed) == ("1", "9")


def test_mismatch_carries_locating_detail() -> None:
    mismatch = glyph_truth_mismatches(_read("stealth.pdf"))[0]

    assert isinstance(mismatch, GlyphMismatch)
    assert mismatch.page == 0
    assert mismatch.font.startswith("/")
    assert isinstance(mismatch.code, int)


def test_malformed_pdf_returns_empty_rather_than_raising() -> None:
    """Callers catch ScanIncompleteError only; anything else discards findings."""
    assert glyph_truth_mismatches(b"%PDF-1.4\nnot a real pdf\n%%EOF\n") == []


def test_empty_input_returns_empty() -> None:
    assert glyph_truth_mismatches(b"") == []
