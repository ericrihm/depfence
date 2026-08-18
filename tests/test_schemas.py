from __future__ import annotations

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
