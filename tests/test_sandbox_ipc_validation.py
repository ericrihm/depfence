"""Tests for the sandbox IPC validation boundary in artifact_analysis.

These tests exercise _sandbox_rate, _sandbox_count, and _sandbox_findings
without launching a container. They verify the host-side contract that
determines whether sandbox output is accepted or rejected — the point
where trust is established between the sandboxed OCI worker and the host.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from depfence.core.artifact_analysis import (
    SANDBOX_SCHEMA_VERSION,
    _sandbox_count,
    _sandbox_findings,
    _sandbox_rate,
)
from depfence.core.models import FindingType, Severity
from depfence.core.scan_scope import ScanIncompleteError

# ---------------------------------------------------------------------------
# _sandbox_rate
# ---------------------------------------------------------------------------


class TestSandboxRate:
    def test_accepts_zero(self) -> None:
        assert _sandbox_rate({"r": 0.0}, "r") == 0.0

    def test_accepts_one(self) -> None:
        assert _sandbox_rate({"r": 1.0}, "r") == 1.0

    def test_accepts_midpoint(self) -> None:
        assert _sandbox_rate({"r": 0.5}, "r") == 0.5

    def test_accepts_int_zero(self) -> None:
        # int 0 is a valid numeric value coerced to float
        assert _sandbox_rate({"r": 0}, "r") == 0.0

    def test_accepts_int_one(self) -> None:
        assert _sandbox_rate({"r": 1}, "r") == 1.0

    def test_rejects_missing_key(self) -> None:
        with pytest.raises(ScanIncompleteError, match="must be numeric"):
            _sandbox_rate({}, "missing")

    def test_rejects_none(self) -> None:
        with pytest.raises(ScanIncompleteError, match="must be numeric"):
            _sandbox_rate({"r": None}, "r")

    def test_rejects_string(self) -> None:
        with pytest.raises(ScanIncompleteError, match="must be numeric"):
            _sandbox_rate({"r": "0.5"}, "r")

    def test_rejects_boolean_true(self) -> None:
        # bool is a subclass of int in Python — the validator must explicitly
        # exclude it because True == 1 would silently pass.
        with pytest.raises(ScanIncompleteError, match="must be numeric"):
            _sandbox_rate({"r": True}, "r")

    def test_rejects_boolean_false(self) -> None:
        with pytest.raises(ScanIncompleteError, match="must be numeric"):
            _sandbox_rate({"r": False}, "r")

    def test_rejects_negative(self) -> None:
        with pytest.raises(ScanIncompleteError, match="outside 0..1"):
            _sandbox_rate({"r": -0.01}, "r")

    def test_rejects_above_one(self) -> None:
        with pytest.raises(ScanIncompleteError, match="outside 0..1"):
            _sandbox_rate({"r": 1.001}, "r")

    def test_rejects_nan(self) -> None:
        with pytest.raises(ScanIncompleteError, match="outside 0..1"):
            _sandbox_rate({"r": float("nan")}, "r")

    def test_rejects_inf(self) -> None:
        with pytest.raises(ScanIncompleteError, match="outside 0..1"):
            _sandbox_rate({"r": float("inf")}, "r")

    def test_rejects_negative_inf(self) -> None:
        with pytest.raises(ScanIncompleteError, match="outside 0..1"):
            _sandbox_rate({"r": float("-inf")}, "r")


# ---------------------------------------------------------------------------
# _sandbox_count
# ---------------------------------------------------------------------------


class TestSandboxCount:
    def test_accepts_zero(self) -> None:
        assert _sandbox_count({"c": 0}, "c", maximum=100) == 0

    def test_accepts_maximum(self) -> None:
        assert _sandbox_count({"c": 100}, "c", maximum=100) == 100

    def test_accepts_midpoint(self) -> None:
        assert _sandbox_count({"c": 50}, "c", maximum=100) == 50

    def test_rejects_negative(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": -1}, "c", maximum=100)

    def test_rejects_above_maximum(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": 101}, "c", maximum=100)

    def test_rejects_float(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": 50.0}, "c", maximum=100)

    def test_rejects_boolean_true(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": True}, "c", maximum=100)

    def test_rejects_boolean_false(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": False}, "c", maximum=100)

    def test_rejects_string(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({"c": "50"}, "c", maximum=100)

    def test_rejects_missing_key(self) -> None:
        with pytest.raises(ScanIncompleteError, match="integer range"):
            _sandbox_count({}, "missing", maximum=100)


# ---------------------------------------------------------------------------
# _sandbox_findings — valid document with one finding
# ---------------------------------------------------------------------------


def _valid_sandbox_document(
    *,
    total_units: int = 1,
    processed_units: int = 1,
    complete: bool = True,
    character_error_rate: float = 0.90,
    ocr_confidence: float = 0.95,
    token_similarity: float = 0.10,
    compared_characters: int = 200,
    hazardous: bool = True,
    region_index: int | None = None,
) -> dict:
    """Build a minimal valid sandbox result envelope with one finding."""
    machine_sha = hashlib.sha256(b"machine").hexdigest()
    visual_sha = hashlib.sha256(b"visual").hexdigest()
    metrics: dict = {
        "character_error_rate": character_error_rate,
        "ocr_confidence": ocr_confidence,
        "token_similarity": token_similarity,
        "compared_characters": compared_characters,
        "page_count": total_units,
        "visual_text_sha256": visual_sha,
        "machine_text_sha256": machine_sha,
        "hazardous_machine_text": hazardous,
    }
    if region_index is not None:
        metrics["region_index"] = region_index
        metrics["region_type"] = "page"
    return {
        "schema_version": SANDBOX_SCHEMA_VERSION,
        "input_sha256": hashlib.sha256(b"test-data").hexdigest(),
        "media_type": "application/pdf",
        "complete": complete,
        "limitations": [],
        "total_units": total_units,
        "processed_units": processed_units,
        "findings": [
            {
                "rule_id": "DF-VIS-001",
                "evidence_class": "rendered_text_comparison",
                "metrics": metrics,
            }
        ],
    }


class TestSandboxFindings:
    """Test _sandbox_findings document validation."""

    def test_valid_document_returns_one_finding(self) -> None:
        doc = _valid_sandbox_document()
        findings: list = _sandbox_findings(doc, "test.pdf")
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.VISUAL_TEXT_DECEPTION
        assert f.severity == Severity.CRITICAL  # hazardous=True → CRITICAL
        assert f.metadata["rule_id"] == "DF-VIS-001"
        assert f.metadata["analysis_mode"] == "sandboxed"
        assert f.metadata["content_redacted"] is True

    def test_non_hazardous_finding_is_high_not_critical(self) -> None:
        doc = _valid_sandbox_document(hazardous=False)
        findings: list = _sandbox_findings(doc, "test.pdf")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_rejects_non_dict_document(self) -> None:
        with pytest.raises(ScanIncompleteError, match="invalid result envelope"):
            _sandbox_findings("not a dict", "test.pdf")

    def test_rejects_wrong_schema_version(self) -> None:
        doc = _valid_sandbox_document()
        doc["schema_version"] = "wrong/v99"
        with pytest.raises(ScanIncompleteError, match="unsupported result envelope"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_extra_keys(self) -> None:
        doc = _valid_sandbox_document()
        doc["extra_key"] = "should not be here"
        with pytest.raises(ScanIncompleteError, match="unsupported result envelope"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_missing_keys(self) -> None:
        doc = _valid_sandbox_document()
        del doc["findings"]
        with pytest.raises(ScanIncompleteError, match="unsupported result envelope"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_list_findings(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"] = "not a list"
        with pytest.raises(ScanIncompleteError, match="findings must be an array"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_invalid_input_digest(self) -> None:
        doc = _valid_sandbox_document()
        doc["input_sha256"] = "not-a-hex-digest"
        with pytest.raises(ScanIncompleteError, match="invalid input digest"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_invalid_media_type(self) -> None:
        doc = _valid_sandbox_document()
        doc["media_type"] = "text/plain"
        with pytest.raises(ScanIncompleteError, match="invalid media type"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_bool_complete(self) -> None:
        doc = _valid_sandbox_document()
        doc["complete"] = 1
        with pytest.raises(ScanIncompleteError, match="invalid completeness"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_list_limitations(self) -> None:
        doc = _valid_sandbox_document()
        doc["limitations"] = "bad"
        with pytest.raises(ScanIncompleteError, match="invalid completeness"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_limitations_with_bad_pattern(self) -> None:
        doc = _valid_sandbox_document()
        doc["limitations"] = ["valid_code", "INVALID CODE!"]
        with pytest.raises(ScanIncompleteError, match="invalid completeness"):
            _sandbox_findings(doc, "test.pdf")

    def test_incomplete_analysis_raises(self) -> None:
        doc = _valid_sandbox_document(complete=False)
        with pytest.raises(ScanIncompleteError, match="sandbox analysis incomplete"):
            _sandbox_findings(doc, "test.pdf")

    def test_partial_coverage_raises(self) -> None:
        doc = _valid_sandbox_document(total_units=5, processed_units=3)
        with pytest.raises(ScanIncompleteError, match="sandbox analysis incomplete.*3/5"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_total_units_zero(self) -> None:
        doc = _valid_sandbox_document()
        doc["total_units"] = 0
        with pytest.raises(ScanIncompleteError, match="invalid coverage"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_processed_greater_than_total(self) -> None:
        doc = _valid_sandbox_document()
        doc["processed_units"] = 5
        doc["total_units"] = 3
        with pytest.raises(ScanIncompleteError, match="invalid coverage"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_bool_total_units(self) -> None:
        doc = _valid_sandbox_document()
        doc["total_units"] = True
        with pytest.raises(ScanIncompleteError, match="invalid coverage"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_dict_finding(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"] = ["not a dict"]
        with pytest.raises(ScanIncompleteError, match="invalid finding"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_unknown_rule_id(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["rule_id"] = "DF-UNKNOWN-001"
        with pytest.raises(ScanIncompleteError, match="unknown rule"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_finding_with_extra_fields(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["extra"] = "bad"
        with pytest.raises(ScanIncompleteError, match="unsupported fields"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_vis_001_rule(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["rule_id"] = "DF-FONT-001"
        with pytest.raises(ScanIncompleteError, match="not host-derivable"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_wrong_evidence_class(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["evidence_class"] = "wrong_class"
        with pytest.raises(ScanIncompleteError, match="evidence class is invalid"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_non_bool_hazardous(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["metrics"]["hazardous_machine_text"] = 1
        with pytest.raises(ScanIncompleteError, match="hazard metric must be boolean"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_low_character_error_rate(self) -> None:
        doc = _valid_sandbox_document(character_error_rate=0.10)
        with pytest.raises(ScanIncompleteError, match="host detection thresholds"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_low_ocr_confidence(self) -> None:
        doc = _valid_sandbox_document(ocr_confidence=0.50)
        with pytest.raises(ScanIncompleteError, match="host detection thresholds"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_high_token_similarity(self) -> None:
        doc = _valid_sandbox_document(token_similarity=0.80)
        with pytest.raises(ScanIncompleteError, match="host detection thresholds"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_short_compared_text(self) -> None:
        doc = _valid_sandbox_document(compared_characters=10)
        with pytest.raises(ScanIncompleteError, match="host detection thresholds"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_page_count_mismatch(self) -> None:
        # page_count in metrics must equal total_units
        doc = _valid_sandbox_document(total_units=3, processed_units=3)
        # metrics.page_count is set to total_units by _valid_sandbox_document,
        # but we override it
        doc["findings"][0]["metrics"]["page_count"] = 1
        with pytest.raises(ScanIncompleteError, match="host detection thresholds"):
            _sandbox_findings(doc, "test.pdf")

    def test_empty_findings_returns_empty(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"] = []
        findings: list = _sandbox_findings(doc, "test.pdf")
        assert findings == []

    def test_region_index_validation_accepts_valid(self) -> None:
        doc = _valid_sandbox_document(region_index=1)
        findings: list = _sandbox_findings(doc, "test.pdf")
        assert len(findings) == 1

    def test_region_index_zero_rejected(self) -> None:
        doc = _valid_sandbox_document(region_index=0)
        with pytest.raises(ScanIncompleteError, match="region metadata is invalid"):
            _sandbox_findings(doc, "test.pdf")

    def test_duplicate_region_index_rejected(self) -> None:
        # Build a document with two findings that have the same region_index
        doc = _valid_sandbox_document(region_index=1)
        second = dict(doc["findings"][0])
        second["metrics"] = dict(second["metrics"])
        doc["findings"].append(second)
        with pytest.raises(ScanIncompleteError, match="region metadata is invalid"):
            _sandbox_findings(doc, "test.pdf")

    def test_region_without_page_type_rejected(self) -> None:
        doc = _valid_sandbox_document(region_index=1)
        doc["findings"][0]["metrics"]["region_type"] = "section"
        with pytest.raises(ScanIncompleteError, match="region metadata is invalid"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_metric_string_that_is_not_sha256(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["metrics"]["machine_text_sha256"] = "not-a-hex-digest"
        with pytest.raises(ScanIncompleteError, match="SHA-256"):
            _sandbox_findings(doc, "test.pdf")

    def test_rejects_metric_with_nested_dict(self) -> None:
        doc = _valid_sandbox_document()
        doc["findings"][0]["metrics"]["nested"] = {"bad": True}
        # Extra key triggers "do not match the required contract"
        with pytest.raises(ScanIncompleteError, match="required contract"):
            _sandbox_findings(doc, "test.pdf")


# ---------------------------------------------------------------------------
# _read_regular_file edge cases
# ---------------------------------------------------------------------------


class TestReadRegularFile:
    """Test the TOCTOU-guarded file reader."""

    def test_reads_a_normal_file(self, tmp_path: Path) -> None:
        from depfence.core.artifact_analysis import _read_regular_file

        target = tmp_path / "normal.txt"
        target.write_bytes(b"hello world")
        assert _read_regular_file(target) == b"hello world"

    def test_rejects_symlink(self, tmp_path: Path) -> None:
        from depfence.core.artifact_analysis import _read_regular_file

        real = tmp_path / "real.txt"
        real.write_bytes(b"payload")
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        with pytest.raises(ScanIncompleteError, match="non-symlink"):
            _read_regular_file(link)

    def test_rejects_directory(self, tmp_path: Path) -> None:
        from depfence.core.artifact_analysis import _read_regular_file

        target = tmp_path / "subdir"
        target.mkdir()
        with pytest.raises((ScanIncompleteError, OSError)):
            _read_regular_file(target)

    def test_rejects_nonexistent_file(self, tmp_path: Path) -> None:
        from depfence.core.artifact_analysis import _read_regular_file

        with pytest.raises((FileNotFoundError, OSError)):
            _read_regular_file(tmp_path / "does-not-exist")


# ---------------------------------------------------------------------------
# SandboxConfig.validate
# ---------------------------------------------------------------------------


class TestSandboxConfigValidate:
    """Test the SandboxConfig validation without launching containers."""

    def test_rejects_unsupported_engine(self) -> None:
        from depfence.core.artifact_analysis import SandboxConfig

        cfg = SandboxConfig(engine="lxc", image="img@sha256:" + "a" * 64)
        with pytest.raises(ValueError, match="docker or podman"):
            cfg.validate()

    def test_rejects_unpinned_image(self) -> None:
        from depfence.core.artifact_analysis import SandboxConfig

        cfg = SandboxConfig(engine="docker", image="latest")
        with pytest.raises(ValueError, match="sha256"):
            cfg.validate()

    def test_rejects_invalid_timeout_zero(self) -> None:
        from depfence.core.artifact_analysis import SandboxConfig

        cfg = SandboxConfig(
            engine="docker",
            image="img@sha256:" + "a" * 64,
            timeout_seconds=0,
        )
        with pytest.raises(ValueError, match="timeout"):
            cfg.validate()

    def test_rejects_invalid_timeout_over_900(self) -> None:
        from depfence.core.artifact_analysis import SandboxConfig

        cfg = SandboxConfig(
            engine="docker",
            image="img@sha256:" + "a" * 64,
            timeout_seconds=901,
        )
        with pytest.raises(ValueError, match="timeout"):
            cfg.validate()

    def test_rejects_unsupported_runtime(self) -> None:
        from depfence.core.artifact_analysis import SandboxConfig

        cfg = SandboxConfig(
            engine="docker",
            image="img@sha256:" + "a" * 64,
            runtime="containerd",
        )
        with pytest.raises(ValueError, match="runtime"):
            cfg.validate()
