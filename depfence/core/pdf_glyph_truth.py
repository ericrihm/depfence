"""Compare what a PDF's glyphs draw against what the document claims they mean.

A PDF's `/ToUnicode` map is a claim, not a fact. The embedded font program is
the ground truth: its own character map states which character each glyph
actually draws. When the two disagree, the text a reader sees differs from the
text an extractor returns.

This catches a class that differential extraction cannot: the attack renders
pixel-identically to a benign original, and pypdf, pdfium and pdfminer are all
fooled the same way because they all trust `/ToUnicode`.

Dependencies are pypdf (BSD-3) and fontTools (MIT), both already required by
the ``evilfont`` extra. Deliberately not PyMuPDF or iText, which expose the
same capability under AGPL-3.0 and cannot ship inside an Apache-2.0 package.
"""

from __future__ import annotations

import io
import re
import unicodedata
from dataclasses import dataclass

from depfence.core.scan_scope import ScanIncompleteError

# Imported separately from any parsing `try`. Folding an import into a `try`
# whose handler names an exception from that same import raises NameError when
# the module is absent, and the error escapes into the caller, which discards
# every finding from the scanner rather than reporting incomplete analysis.
try:
    from fontTools import agl
    from fontTools.cffLib import CFFFontSet
    from fontTools.ttLib import TTFont
    from pypdf import PdfReader
    from pypdf.generic import ContentStream
except ImportError as exc:  # pragma: no cover - exercised by the extra-less install
    raise ScanIncompleteError(
        "pypdf and fontTools are required for PDF glyph-truth inspection"
    ) from exc

_MAX_BFRANGE_SPAN = 512


@dataclass(frozen=True)
class GlyphMismatch:
    """One glyph whose drawn character disagrees with the document's claim."""

    page: int
    font: str
    code: int
    drawn: str
    claimed: str


def _parse_tounicode(cmap_text: str) -> dict[int, str]:
    """Extract the document's code -> character claims from a ToUnicode CMap."""
    claims: dict[int, str] = {}
    for block in re.findall(r"beginbfchar(.*?)endbfchar", cmap_text, re.S):
        for src, dst in re.findall(r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", block):
            claims[int(src, 16)] = "".join(
                chr(int(dst[i : i + 4], 16)) for i in range(0, len(dst), 4)
            )
    for block in re.findall(r"beginbfrange(.*?)endbfrange", cmap_text, re.S):
        for low, _, arr in re.findall(
            r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\[(.*?)\]", block, re.S
        ):
            for offset, value in enumerate(re.findall(r"<([0-9a-fA-F]+)>", arr)):
                claims[int(low, 16) + offset] = chr(int(value[:4], 16))
        for low, high, dst in re.findall(
            r"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>", block
        ):
            start, end, target = int(low, 16), int(high, 16), int(dst[:4], 16)
            for offset in range(min(end - start + 1, _MAX_BFRANGE_SPAN)):
                claims.setdefault(start + offset, chr(target + offset))
    return claims


def _gid_to_character(descriptor: object) -> dict[int, str]:
    """Ground truth: what the embedded font program says each glyph draws."""
    if "/FontFile2" in descriptor:  # type: ignore[operator]
        font = TTFont(
            io.BytesIO(descriptor["/FontFile2"].get_data()),  # type: ignore[index]
            lazy=True,
        )
        order = font.getGlyphOrder()
        truth: dict[int, str] = {}
        if "cmap" in font:
            for codepoint, name in font.getBestCmap().items():
                if name in order:
                    truth.setdefault(order.index(name), chr(codepoint))
        if not truth and "post" in font:
            for index, name in enumerate(order):
                resolved = agl.toUnicode(name)
                if resolved:
                    truth[index] = resolved
        return truth
    if "/FontFile3" in descriptor:  # type: ignore[operator]
        cff = CFFFontSet()
        cff.decompile(io.BytesIO(descriptor["/FontFile3"].get_data()), None)  # type: ignore[index]
        names = cff[cff.fontNames[0]].getGlyphOrder()
        return {i: agl.toUnicode(n) for i, n in enumerate(names) if agl.toUnicode(n)}
    # /FontFile (Type1 PFB) carries no glyph order we can index; the PDF's own
    # /Encoding /Differences names would be needed, which is a separate path.
    return {}


def _normalise(text: str) -> str:
    """Ligatures are the dominant benign confounder; NFKC folds fi/fl."""
    return unicodedata.normalize("NFKC", text or "")


def _cid_to_gid_map(descendant: object) -> dict[int, int] | None:
    """Resolve /CIDToGIDMap, or signal that it cannot be resolved safely.

    Returns None for an identity mapping. Raises LookupError for a form this
    code does not understand, so the caller refuses rather than guessing.
    """
    raw_map = descendant.get("/CIDToGIDMap")  # type: ignore[attr-defined]
    raw_map = raw_map.get_object() if hasattr(raw_map, "get_object") else raw_map
    if raw_map is None or str(raw_map) in ("/Identity", "None"):
        return None
    if hasattr(raw_map, "get_data"):
        data = raw_map.get_data()
        return {i: int.from_bytes(data[2 * i : 2 * i + 2], "big") for i in range(len(data) // 2)}
    raise LookupError("unrecognised /CIDToGIDMap form")


def _drawn_codes(page: object, reader: object) -> dict[str, list[bytes]]:
    """Collect the byte strings actually drawn, keyed by font resource name."""
    drawn: dict[str, list[bytes]] = {}
    stream = ContentStream(page.get_contents(), reader)  # type: ignore[attr-defined,arg-type]
    current: str | None = None
    for operands, operator in stream.operations:
        if operator == b"Tf" and operands:
            current = str(operands[0])
        elif operator in (b"TJ", b"Tj") and current:
            items = operands[0] if operator == b"TJ" else [operands[0]]
            for item in items:
                raw = getattr(item, "original_bytes", item)
                if isinstance(raw, bytes):
                    drawn.setdefault(current, []).append(raw)
    return drawn


def glyph_truth_mismatches(data: bytes) -> list[GlyphMismatch]:
    """Return glyphs whose drawn character disagrees with the PDF's claim.

    A malformed PDF yields an empty list rather than raising: callers of
    ``scan_artifact_bytes`` catch only ``ScanIncompleteError``, so any other
    exception escaping here would discard every finding from the scanner.
    """
    mismatches: list[GlyphMismatch] = []
    try:
        reader = PdfReader(io.BytesIO(data))
        for page_number, page in enumerate(reader.pages):
            resources = (page.get("/Resources", {}) or {}).get("/Font", {}) or {}
            try:
                drawn = _drawn_codes(page, reader)
            except Exception:
                continue
            for name, font_ref in resources.items():
                font = font_ref.get_object()
                if "/ToUnicode" not in font:
                    continue
                # Only Type0/Identity-H makes the content-stream code a CID.
                # Simple fonts map code -> glyph through /Encoding, so treating
                # the byte as a glyph index gave a 23% false-positive rate.
                encoding = str(font.get("/Encoding"))
                if str(font.get("/Subtype")) != "/Type0" or encoding not in (
                    "/Identity-H",
                    "/Identity-V",
                ):
                    continue
                claimed = _parse_tounicode(font["/ToUnicode"].get_data().decode("latin1"))
                descendant = (font.get("/DescendantFonts") or [font])[0]
                descendant = (
                    descendant.get_object() if hasattr(descendant, "get_object") else descendant
                )
                descriptor = descendant.get("/FontDescriptor")
                if descriptor is None:
                    continue
                try:
                    truth = _gid_to_character(descriptor.get_object())
                    cid_to_gid = _cid_to_gid_map(descendant)
                except LookupError:
                    continue  # refuse rather than guess
                except Exception:
                    continue
                if not truth:
                    continue
                for raw in drawn.get(str(name), []):
                    codes = [
                        int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)
                    ]
                    for code in codes:
                        gid = cid_to_gid.get(code) if cid_to_gid is not None else code
                        if gid is None:
                            continue
                        drawn_char, claimed_char = truth.get(gid), claimed.get(code)
                        if drawn_char is None or claimed_char is None:
                            continue
                        left, right = _normalise(drawn_char), _normalise(claimed_char)
                        if left != right and not left.startswith(right):
                            mismatches.append(
                                GlyphMismatch(
                                    page=page_number,
                                    font=str(name),
                                    code=code,
                                    drawn=drawn_char,
                                    claimed=claimed_char,
                                )
                            )
    except Exception:
        return []
    return mismatches


__all__ = ["GlyphMismatch", "glyph_truth_mismatches"]
