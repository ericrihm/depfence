"""Bounded poisoning checks for repository-hosted retrieval corpora."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity
from depfence.core.scan_scope import MalformedInputError, PartialScanError, ScanScope
from depfence.scanners.prompt_injection_scanner import _INJECTION_PATTERNS, _normalize_for_matching

_CORPUS_ROOTS = ("knowledge", "corpus", "rag", "embeddings", "vectorstore", "data/knowledge")
_TEXT_FORMATS = {".md", ".txt", ".rst", ".json", ".jsonl", ".csv"}
_UNSUPPORTED_MEDIA = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".parquet"}
_MAX_CORPUS_FILES = 10_000
_MAX_CORPUS_FILE_BYTES = 1_000_000


class RagPoisonScanner:
    """Detect instruction payloads in content intended for agent retrieval."""

    name = "rag_poison"
    ecosystems = ["rag"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        project_scope = ScanScope(project_dir)
        findings: list[Finding] = []
        unsupported: list[str] = []

        for relative_root in _CORPUS_ROOTS:
            candidate = project_scope.root / relative_root
            if candidate.is_symlink():
                project_scope.resolve(candidate)
            if not candidate.is_dir():
                continue
            scope = ScanScope(
                candidate,
                max_file_bytes=_MAX_CORPUS_FILE_BYTES,
                max_files=_MAX_CORPUS_FILES,
            )
            for path in scope.walk_files():
                suffix = path.suffix.lower()
                rel = path.relative_to(project_scope.root).as_posix()
                if suffix in _UNSUPPORTED_MEDIA:
                    unsupported.append(rel)
                    continue
                if suffix not in _TEXT_FORMATS:
                    continue
                text = scope.read_text(path)
                for record_number, record in _records(path, text):
                    findings.extend(_scan_record(rel, record_number, record))

        if unsupported:
            preview = ", ".join(unsupported[:5])
            raise PartialScanError(
                f"unsupported retrieval corpus media ({len(unsupported)}): {preview}",
                findings,
            )
        return findings


def _records(path: Path, text: str) -> list[tuple[int, str]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as bad:
            raise MalformedInputError(f"malformed RAG JSON {path}: {bad}") from bad
        return [(1, _flatten(value))]
    if suffix == ".jsonl":
        records: list[tuple[int, str]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append((line_number, _flatten(json.loads(line))))
            except json.JSONDecodeError as bad:
                raise MalformedInputError(
                    f"malformed RAG JSONL {path}:{line_number}: {bad}"
                ) from bad
        return records
    if suffix == ".csv":
        try:
            return [
                (number, " ".join(str(value) for value in row.values()))
                for number, row in enumerate(csv.DictReader(io.StringIO(text)), 2)
            ]
        except csv.Error as bad:
            raise MalformedInputError(f"malformed RAG CSV {path}: {bad}") from bad
    return [(1, text)]


def _flatten(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _scan_record(path: str, record_number: int, text: str) -> list[Finding]:
    findings: list[Finding] = []
    package = PackageId("rag", path)
    normalized = _normalize_for_matching(text)
    for pattern, label, severity in _INJECTION_PATTERNS:
        if pattern.search(normalized):
            findings.append(Finding(
                finding_type=FindingType.PROMPT_INJECTION,
                severity=Severity.CRITICAL if severity is Severity.CRITICAL else Severity.HIGH,
                package=package,
                title=f"RAG corpus instruction payload: {label}",
                detail=f"Record {record_number} contains instruction-like content; payload redacted.",
                cwe="CWE-77",
                confidence=0.85,
                metadata={
                    "file": path,
                    "record": record_number,
                    "matched_pattern": label,
                    "content_redacted": True,
                },
            ))
            break
    if re.search(r"(.)\1{4095,}", text, re.DOTALL):
        findings.append(Finding(
            finding_type=FindingType.ANSI_HIDING,
            severity=Severity.MEDIUM,
            package=package,
            title="RAG corpus contains extreme repeated padding",
            detail=f"Record {record_number} contains a repeated run over 4 KiB.",
            confidence=0.9,
            metadata={"file": path, "record": record_number, "content_redacted": True},
        ))
    return findings
