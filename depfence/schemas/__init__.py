"""Validation helpers for the sealed visual-deception worker contracts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from jsonschema.validators import validator_for

_SCHEMA_FILES = {
    "depfence.evidence/v1": "depfence.evidence.v1.schema.json",
    "depfence.sealed-intake/v1": "depfence.sealed-intake.v1.schema.json",
    "depfence.sealed-resolution/v1": "depfence.sealed-resolution.v1.schema.json",
    "depfence.artifact-intake/v1": "depfence.artifact-intake.v1.schema.json",
    "depfence.artifact-doctor/v1": "depfence.artifact-doctor.v1.schema.json",
    "depfence.intake-doctor/v1": "depfence.intake-doctor.v1.schema.json",
}


def load_schema(contract: str) -> dict[str, Any]:
    try:
        filename = _SCHEMA_FILES[contract]
    except KeyError as exc:
        raise ValueError(f"unknown DepFence schema: {contract!r}") from exc
    return cast(dict[str, Any], json.loads(
        files(__package__).joinpath(filename).read_text(encoding="utf-8")
    ))


def validate_document(document: Any, contract: str | None = None) -> None:
    if contract is None:
        if not isinstance(document, dict):
            raise ValueError("a DepFence document must be a JSON object")
        contract = str(document.get("schema_version"))
    schema = load_schema(contract)
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema).validate(document)


__all__ = ["load_schema", "validate_document"]

