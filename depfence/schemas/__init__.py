"""Packaged JSON Schemas for DepFence machine-readable contracts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from jsonschema.validators import validator_for

_SCHEMA_FILES = {
    "depfence.scan/v1": "depfence.scan.v1.schema.json",
    "depfence.snapshot/v1": "depfence.snapshot.v1.schema.json",
    "depfence.fleet/v1": "depfence.fleet.v1.schema.json",
    "depfence.fleet-evidence/v1": "depfence.fleet-evidence.v1.schema.json",
    "depfence.finding-evidence/v1": "depfence.finding-evidence.v1.schema.json",
    "depfence.fleet-checkpoint/v1": "depfence.fleet-checkpoint.v1.schema.json",
    "depfence.fleet-checkpoint-manifest/v1": "depfence.fleet-checkpoint-manifest.v1.schema.json",
    "depfence.evidence/v1": "depfence.evidence.v1.schema.json",
    "depfence.advisory-task/v1": "depfence.advisory-task.v1.schema.json",
    "depfence.advisory-result/v1": "depfence.advisory-result.v1.schema.json",
    "depfence.intake/v1": "depfence.intake.v1.schema.json",
    "depfence.intake-doctor/v1": "depfence.intake-doctor.v1.schema.json",
    "depfence.intake-readiness/v1": "depfence.intake-readiness.v1.schema.json",
    "depfence.sealed-intake/v1": "depfence.sealed-intake.v1.schema.json",
    "depfence.sealed-resolution/v1": "depfence.sealed-resolution.v1.schema.json",
    "depfence.artifact-intake/v1": "depfence.artifact-intake.v1.schema.json",
    "depfence.artifact-doctor/v1": "depfence.artifact-doctor.v1.schema.json",
    "depfence.kg/v1": "depfence.kg.v1.schema.json",
    "depfence.privacy/v1": "depfence.privacy.v1.schema.json",
    "depfence.triage/v1": "depfence.triage.v1.schema.json",
    "depfence.triage-plan/v1": "depfence.triage-plan.v1.schema.json",
    "depfence.triage-queue/v1": "depfence.triage-queue.v1.schema.json",
    "depfence.triage-review/v1": "depfence.triage-review.v1.schema.json",
}


def load_schema(contract: str) -> dict[str, Any]:
    """Load a shipped schema by its public contract identifier."""
    try:
        filename = _SCHEMA_FILES[contract]
    except KeyError as exc:
        raise ValueError(f"unknown DepFence schema: {contract!r}") from exc
    return cast(
        dict[str, Any],
        json.loads(files(__package__).joinpath(filename).read_text(encoding="utf-8")),
    )


def validate_document(document: Any, contract: str | None = None) -> None:
    """Validate a document with its declared (or explicitly selected) schema."""
    if contract is None:
        if not isinstance(document, dict):
            raise ValueError("a DepFence document must be a JSON object")
        contract = document.get("schema_version")
    schema = load_schema(str(contract))
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema).validate(document)


__all__ = ["load_schema", "validate_document"]
