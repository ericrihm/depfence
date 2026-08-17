"""Canonical, versioned identities for findings across every machine contract."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from depfence.core.models import Finding
from depfence.reporters.package_id import coerce_package_id

IDENTITY_VERSION = "depfence.finding-id/v1"


def _text(value: object | None) -> str:
    return "" if value is None else str(value).strip()


def _record_location(record: Mapping[str, Any]) -> str:
    direct = record.get("location")
    if direct:
        return _text(direct)
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping):
        return ""
    path = next(
        (
            metadata.get(key)
            for key in ("source_file", "file", "path", "relative_path", "lockfile_path")
            if metadata.get(key)
        ),
        "",
    )
    line = metadata.get("line") or metadata.get("line_number")
    return f"{_text(path)}:{line}" if path and line is not None else _text(path)


def canonical_finding_payload(value: Finding | Mapping[str, Any]) -> dict[str, str]:
    """Return the immutable fields defining one logical finding.

    Severity, confidence, detail, timestamps, and scan counters deliberately do
    not participate: they may change as intelligence improves without changing
    the identity of the underlying observation.
    """

    if isinstance(value, Finding):
        package_id = coerce_package_id(value.package)
        record: Mapping[str, Any] = value.metadata
        return {
            "schema": IDENTITY_VERSION,
            "type": value.finding_type.value,
            "ecosystem": package_id.ecosystem,
            "package": package_id.name,
            "version": package_id.version or "",
            "cve": value.cve or "",
            "cwe": value.cwe or "",
            "location": _record_location({"metadata": record}),
            "title": _text(value.title),
        }

    package_value = value.get("package")
    if isinstance(package_value, Mapping):
        ecosystem = _text(package_value.get("ecosystem"))
        package_name = _text(package_value.get("name"))
        version = _text(package_value.get("version"))
    elif package_value:
        coerced = coerce_package_id(str(package_value))
        ecosystem, package_name, version = (
            coerced.ecosystem,
            coerced.name,
            coerced.version or "",
        )
    else:
        ecosystem = package_name = version = ""
    finding_type = value.get("finding_type") or value.get("rule") or "unknown"
    if hasattr(finding_type, "value"):
        finding_type = finding_type.value
    return {
        "schema": IDENTITY_VERSION,
        "type": _text(finding_type),
        "ecosystem": ecosystem,
        "package": package_name,
        "version": version,
        "cve": _text(value.get("cve")),
        "cwe": _text(value.get("cwe")),
        "location": _record_location(value),
        "title": _text(value.get("title")),
    }


def finding_id(value: Finding | Mapping[str, Any]) -> str:
    """Return the public ``df-<20 hex>`` identity used by all v1 outputs."""

    payload = json.dumps(
        canonical_finding_payload(value), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "df-" + hashlib.sha256(payload).hexdigest()[:20]


__all__ = ["IDENTITY_VERSION", "canonical_finding_payload", "finding_id"]
