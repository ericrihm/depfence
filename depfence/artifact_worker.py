"""Container-side rendered-versus-machine text comparison worker.

This executable is not used by normal DepFence scans. It is intended only for
the locked-down OCI contract enforced by ``artifact_analysis`` and emits no
document text, filenames, or rendered pages.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from depfence.core.artifact_analysis import (
    MAX_ARCHIVE_MEMBERS,
    MAX_ARTIFACT_BYTES,
    MAX_XML_BYTES,
    SANDBOX_SCHEMA_VERSION,
    _bounded_zip_member,
    _parse_bounded_xml,
    _run_bounded_subprocess,
    detect_media_type,
)

MAX_RENDER_PAGES = 10

_HAZARD = re.compile(
    r"(?:ignore\s+(?:previous|all)\s+instructions|curl\b.{0,200}\|\s*(?:ba)?sh|"
    r"invoke-expression|powershell\b|rm\s+-rf|exfiltrat|reveal\s+(?:secrets?|tokens?))",
    re.IGNORECASE | re.DOTALL,
)


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"required sandbox tool is unavailable: {name}")
    return resolved


def _run(command: list[str], timeout: float = 60.0) -> bytes:
    code, stdout, _stderr = _run_bounded_subprocess(
        command,
        b"",
        {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
        timeout,
    )
    if code:
        raise RuntimeError(f"sandbox tool failed with exit {code}")
    return stdout


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())


def _ocr_tsv(path: Path) -> tuple[str, float]:
    raw = _run([_tool("tesseract"), str(path), "stdout", "-l", "eng", "tsv"])
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")), delimiter="\t")
    words: list[str] = []
    confidences: list[float] = []
    for row in reader:
        word = (row.get("text") or "").strip()
        if not word:
            continue
        try:
            confidence = float(row.get("conf") or -1)
        except ValueError:
            continue
        words.append(word)
        if confidence >= 0:
            confidences.append(confidence / 100.0)
    return " ".join(words), sum(confidences) / len(confidences) if confidences else 0.0


def _pdf_page_count(pdf: Path) -> int:
    raw = _run([_tool("pdfinfo"), str(pdf)])
    match = re.search(rb"(?m)^Pages:\s*(\d+)\s*$", raw)
    if not match:
        raise RuntimeError("PDF page count could not be determined")
    count = int(match.group(1))
    if count < 1:
        raise RuntimeError("PDF page count is invalid")
    return count


def _render_pdf(
    pdf: Path, directory: Path
) -> tuple[str, str, float, int, int, list[str]]:
    total_pages = _pdf_page_count(pdf)
    if total_pages > MAX_RENDER_PAGES:
        return "", "", 0.0, 0, total_pages, ["page_limit_exceeded"]
    machine = _run([_tool("pdftotext"), str(pdf), "-"]).decode("utf-8", errors="replace")
    prefix = directory / "page"
    _run([
        _tool("pdftoppm"), "-png", "-r", "150", "-f", "1", "-l", str(total_pages),
        str(pdf), str(prefix),
    ], timeout=120.0)
    pages = sorted(directory.glob("page-*.png"))
    if len(pages) != total_pages:
        return "", "", 0.0, len(pages), total_pages, ["page_render_incomplete"]
    ocr_parts: list[str] = []
    confidences: list[float] = []
    for page in pages:
        text, confidence = _ocr_tsv(page)
        ocr_parts.append(text)
        confidences.append(confidence)
    return (
        machine,
        " ".join(ocr_parts),
        sum(confidences) / len(confidences),
        len(pages),
        total_pages,
        [],
    )


def _docx_to_pdf(docx: Path, directory: Path) -> Path:
    _run([
        _tool("soffice"),
        "--headless",
        "--nologo",
        "--nodefault",
        "--nolockcheck",
        "--norestore",
        "-env:UserInstallation=file:///tmp/depfence-lo-profile",
        "--convert-to",
        "pdf",
        "--outdir",
        str(directory),
        str(docx),
    ], timeout=120.0)
    output = directory / f"{docx.stem}.pdf"
    if not output.is_file():
        raise RuntimeError("LibreOffice did not produce the expected PDF")
    return output


def _docx_machine_text(docx: Path) -> str:
    try:
        with zipfile.ZipFile(docx) as archive:
            if len(archive.infolist()) > MAX_ARCHIVE_MEMBERS:
                raise RuntimeError("DOCX exceeds the sandbox archive budget")
            info = archive.getinfo("word/document.xml")
            root = _parse_bounded_xml(_bounded_zip_member(archive, info, MAX_XML_BYTES))
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError("DOCX machine text could not be extracted") from exc
    return " ".join(
        node.text or ""
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "t" and (node.text or "").strip()
    )


def compare(machine: str, visual: str, ocr_confidence: float, page_count: int) -> dict[str, object]:
    machine_norm = _normalize(machine)
    visual_norm = _normalize(visual)
    compared = min(len(machine_norm), len(visual_norm))
    similarity = difflib.SequenceMatcher(None, machine_norm, visual_norm, autojunk=False).ratio()
    machine_tokens = set(machine_norm.split())
    visual_tokens = set(visual_norm.split())
    union = machine_tokens | visual_tokens
    token_similarity = len(machine_tokens & visual_tokens) / len(union) if union else 1.0
    character_error_rate = 1.0 - similarity
    findings: list[dict[str, object]] = []
    if (
        compared >= 20
        and character_error_rate >= 0.35
        and ocr_confidence >= 0.85
        and token_similarity <= 0.50
    ):
        hazardous = bool(_HAZARD.search(machine_norm))
        findings.append({
            "rule_id": "DF-VIS-001",
            "evidence_class": "rendered_text_comparison",
            "metrics": {
                "character_error_rate": round(character_error_rate, 6),
                "ocr_confidence": round(ocr_confidence, 6),
                "token_similarity": round(token_similarity, 6),
                "compared_characters": compared,
                "page_count": page_count,
                "machine_text_sha256": hashlib.sha256(machine_norm.encode()).hexdigest(),
                "visual_text_sha256": hashlib.sha256(visual_norm.encode()).hexdigest(),
                "hazardous_machine_text": hazardous,
            },
        })
    return {"findings": findings}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin", action="store_true", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--format", choices=["json"], required=True)
    args = parser.parse_args()
    suffix = Path(args.name).suffix.lower()
    if suffix not in {".pdf", ".docx"}:
        raise SystemExit("rendered comparison currently supports PDF and DOCX")
    data = sys.stdin.buffer.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise SystemExit("artifact exceeds the sandbox byte budget")
    with tempfile.TemporaryDirectory(prefix="depfence-artifact-") as raw_directory:
        directory = Path(raw_directory)
        artifact = directory / f"input{suffix}"
        artifact.write_bytes(data)
        pdf = _docx_to_pdf(artifact, directory) if suffix == ".docx" else artifact
        machine, visual, confidence, pages, total_pages, limitations = _render_pdf(
            pdf, directory
        )
        if suffix == ".docx" and not limitations:
            machine = _docx_machine_text(artifact)
        result = compare(machine, visual, confidence, pages)
        result.update({
            "schema_version": SANDBOX_SCHEMA_VERSION,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "media_type": detect_media_type(Path(args.name), data),
            "complete": not limitations and pages == total_pages,
            "limitations": limitations,
            "total_units": total_pages,
            "processed_units": pages,
        })
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
