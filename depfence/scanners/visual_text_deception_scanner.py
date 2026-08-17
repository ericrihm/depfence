"""Static project scanner for font-driven visual text deception."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from depfence.core.artifact_analysis import (
    FONT_SUFFIXES,
    MAX_ARTIFACT_BYTES,
    SUPPORTED_SUFFIXES,
    scan_artifact_bytes,
    summarize_font,
)
from depfence.core.models import Finding, FindingType, PackageMeta, Severity
from depfence.core.scan_scope import PartialScanError, ScanIncompleteError, ScanScope

MAX_PROJECT_ARTIFACTS = 2_000
_RAG_ROOTS = frozenset({"knowledge", "corpus", "rag", "embeddings", "vectorstore"})


class VisualTextDeceptionScanner:
    """Find structural indicators without rendering hostile content."""

    name = "visual_text_deception"
    ecosystems = ["artifact"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        scope = project_dir if isinstance(project_dir, ScanScope) else ScanScope(project_dir)
        findings: list[Finding] = []
        errors: list[str] = []
        font_groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
        candidates = 0

        for path in scope.walk_files():
            suffix = path.suffix.lower()
            if suffix not in SUPPORTED_SUFFIXES:
                continue
            candidates += 1
            if candidates > MAX_PROJECT_ARTIFACTS:
                errors.append(
                    f"visual text artifact count exceeds {MAX_PROJECT_ARTIFACTS}"
                )
                break
            relative = path.relative_to(scope.root)
            try:
                data = scope.read_bytes(path, max_bytes=MAX_ARTIFACT_BYTES)
                artifact_findings, limitations = scan_artifact_bytes(relative, data)
                errors.extend(
                    f"{relative.as_posix()}: {limitation}"
                    for limitation in limitations
                )
                if _RAG_ROOTS.intersection(relative.parts):
                    for finding in artifact_findings:
                        finding.metadata["ingestion_context"] = "rag"
                findings.extend(artifact_findings)
                if suffix in FONT_SUFFIXES:
                    summary = summarize_font(data)
                    if (
                        summary.complete
                        and summary.family
                        and summary.cmap_entries is not None
                        and summary.cmap_entries <= 8
                    ):
                        font_groups[summary.family.casefold()].append(
                            (relative.as_posix(), summary.cmap_entries)
                        )
            except ScanIncompleteError as exc:
                errors.append(f"{relative.as_posix()}: {exc}")

        for family, members in sorted(font_groups.items()):
            if len(members) < 8:
                continue
            findings.append(Finding(
                finding_type=FindingType.VISUAL_TEXT_DECEPTION,
                severity=Severity.MEDIUM,
                package=f"artifact:{members[0][0]}",
                title="Suspicious sparse companion-font cluster",
                detail=(
                    "Multiple fonts in one family expose very small character maps. "
                    "Companion fonts like these can be selected per character to make "
                    "displayed text differ from stored Unicode text. No font was rendered."
                ),
                confidence=0.76,
                metadata={
                    "file": members[0][0],
                    "rule_id": "DF-FONT-001",
                    "analysis_mode": "static",
                    "content_redacted": True,
                    "evidence_class": "sparse_font_cluster",
                    "family_digest": hashlib.sha256(family.encode()).hexdigest(),
                    "font_count": len(members),
                    "max_cmap_entries": max(count for _path, count in members),
                    "sample_files": [path for path, _count in members[:5]],
                },
            ))

        if errors:
            preview = "; ".join(errors[:5])
            raise PartialScanError(
                f"visual text deception coverage incomplete ({len(errors)}): {preview}",
                findings,
            )
        return findings


__all__ = ["VisualTextDeceptionScanner"]
