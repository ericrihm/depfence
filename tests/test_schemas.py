from __future__ import annotations

import pathlib
from typing import Any

import jsonschema
import pytest

from depfence.schemas import load_schema, validate_document

VALID_EVIDENCE: dict[str, Any] = {
    "schema_version": "depfence.evidence/v1",
    "evidence_id": "evidence-1",
    "created_at": "2026-08-18T00:00:00Z",
    "project_id": "project-hmac-sha256:" + "a" * 64,
    "classification": "redacted-private",
    "status": "PASS",
    "source_digest": "sha256:" + "b" * 64,
    "coverage": {
        "complete": True,
        "scanners": {"secrets": "PASS"},
        "errors": [],
        "scanner_errors": {},
    },
    "findings": [],
}


def test_load_schema_returns_dict_with_schema_key() -> None:
    schema: dict[str, Any] = load_schema("depfence.evidence/v1")

    assert isinstance(schema, dict)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_load_schema_rejects_unknown_contract() -> None:
    with pytest.raises(ValueError, match="unknown DepFence schema"):
        load_schema("depfence.does-not-exist/v1")


def test_validate_document_accepts_valid_document() -> None:
    validate_document(VALID_EVIDENCE)


def test_validate_document_rejects_invalid_document() -> None:
    invalid = dict(VALID_EVIDENCE)
    del invalid["status"]

    with pytest.raises(jsonschema.ValidationError):
        validate_document(invalid)


def test_validate_document_rejects_malformed_contract_name() -> None:
    with pytest.raises(ValueError, match="unknown DepFence schema"):
        validate_document(VALID_EVIDENCE, contract="not-a-real-contract")


# --- sealed-intake finding contract -----------------------------------------
#
# Regression guard for the drift found on 2026-08-29: the sealed-intake schema
# admitted 5 of the 11 emitted rule IDs, pinned severity to the constant
# "medium", and omitted `cmap_subtable_conflict` -- the exact evidence class
# DF-FONT-002 emits. Every finding below was rejected by the shipped schema even
# though the worker, the Python validator, and the methodology doc all claimed
# support for it. `fleet_commands._emit` validates against this schema outside a
# try/except, so each of these was an uncaught ValidationError in production.

_SEALED_FINDING_BASE: dict[str, Any] = {
    "artifact_id": "sealed-artifact-sha256:" + "a" * 64,
    "suffix": ".ttf",
    "rule_version": "2026-08-17",
    "artifact_type": "ttf",
    "carrier_type": "git_blob",
    "confidence": 0.92,
}

_SEALED_FINDING_CASES: list[dict[str, Any]] = [
    {"rule_id": "DF-FONT-001", "severity": "medium", "evidence_class": "sparse_font_cluster"},
    {"rule_id": "DF-FONT-002", "severity": "medium", "evidence_class": "cmap_subtable_conflict"},
    {"rule_id": "DF-FONT-003", "severity": "high", "evidence_class": "degenerate_cmap"},
    {"rule_id": "DF-FONT-004", "severity": "high", "evidence_class": "zero_width_stealth"},
    {"rule_id": "DF-FONT-005", "severity": "low", "evidence_class": "missing_layout_tables"},
    {"rule_id": "DF-WEB-001", "severity": "medium", "evidence_class": "structural_correlation"},
    {"rule_id": "DF-DOCX-001", "severity": "medium", "evidence_class": "structural_correlation"},
    {"rule_id": "DF-DOCX-002", "severity": "medium", "evidence_class": "hidden_document_content"},
    {"rule_id": "DF-PDF-001", "severity": "medium", "evidence_class": "hidden_text_topology"},
    {"rule_id": "DF-PDF-002", "severity": "high", "evidence_class": "active_content"},
    {"rule_id": "DF-PDF-003", "severity": "medium", "evidence_class": "incremental_save"},
]


def _sealed_finding_validator() -> jsonschema.Draft202012Validator:
    schema = load_schema("depfence.sealed-intake/v1")
    item_schema = schema["properties"]["analysis"]["properties"]["findings"]["items"]
    return jsonschema.Draft202012Validator(item_schema)


@pytest.mark.parametrize("case", _SEALED_FINDING_CASES, ids=lambda c: c["rule_id"] + "-" + c["severity"])
def test_sealed_intake_schema_accepts_every_emitted_rule(case: dict[str, Any]) -> None:
    finding: dict[str, Any] = {**_SEALED_FINDING_BASE, **case}
    errors = list(_sealed_finding_validator().iter_errors(finding))

    assert errors == [], f"schema rejected an emitted finding: {[e.message for e in errors]}"


def test_sealed_intake_schema_still_rejects_unknown_values() -> None:
    """The widened enums must not have become permissive."""
    validator = _sealed_finding_validator()
    bad: dict[str, Any] = {
        **_SEALED_FINDING_BASE,
        "rule_id": "DF-BOGUS-999",
        "severity": "critical",
        "evidence_class": "not_a_real_class",
    }

    assert list(validator.iter_errors(bad)), "schema accepted a finding it should reject"


def test_sealed_intake_schema_enums_match_the_python_validator() -> None:
    """The JSON Schema and sealed_intake.py must not drift apart again."""
    import ast

    item_schema = load_schema("depfence.sealed-intake/v1")[
        "properties"
    ]["analysis"]["properties"]["findings"]["items"]["properties"]

    source = pathlib.Path("depfence/core/sealed_intake.py").read_text()
    literals: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {
                "allowed_rules",
                "allowed_evidence_classes",
                "allowed_severities",
            }:
                literals[target.id] = set(ast.literal_eval(node.value))

    assert set(item_schema["rule_id"]["enum"]) == literals["allowed_rules"]
    assert set(item_schema["evidence_class"]["enum"]) == literals["allowed_evidence_classes"]
    assert set(item_schema["severity"]["enum"]) == literals["allowed_severities"]
