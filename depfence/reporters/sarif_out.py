"""Compatibility wrapper for the canonical SARIF generator."""

from __future__ import annotations

from depfence.core.models import FindingType, ScanResult
from depfence.reporters.sarif import (
    generate_sarif,
    make_partial_fingerprint,
    map_finding_type_to_rule_id,
    render_sarif,
)


def _rule_id(finding_type_value: str, package_str: str = "") -> str:
    """Return the stable rule ID; *package_str* is accepted for compatibility."""
    try:
        return map_finding_type_to_rule_id(FindingType(finding_type_value))
    except ValueError:
        return f"depfence/{finding_type_value}"


def _partial_fingerprint(package_str: str, cve: str | None, finding_type_value: str) -> str:
    return make_partial_fingerprint(package_str, cve, finding_type_value)


class SarifReporter:
    name = "sarif"
    format = "sarif"

    def render(self, result: ScanResult, run_id: str | None = None) -> str:
        return render_sarif(result, run_id=run_id)


__all__ = ["SarifReporter", "generate_sarif", "_partial_fingerprint", "_rule_id"]
