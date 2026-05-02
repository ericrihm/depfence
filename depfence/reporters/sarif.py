"""SARIF 2.1.0 output generator for depfence.

This module provides a standalone ``generate_sarif`` function that builds a
complete SARIF 2.1.0 document from a :class:`~depfence.core.models.ScanResult`.
It is the primary API for producing SARIF output (the :class:`SarifReporter`
class in ``sarif_out.py`` delegates its rendering here for the ``scan`` CLI
command path, while this module is also used directly by the GitHub Code
Scanning uploader in :mod:`depfence.reporters.github_sarif`).

SARIF 2.1.0 specification:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from depfence.core.models import FindingType, ScanResult, Severity

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Internal lookup tables
# ---------------------------------------------------------------------------

#: Maps depfence :class:`~depfence.core.models.Severity` → SARIF level string.
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: CVSS-proxy numeric string that GitHub uses to colour-code alerts.
#: GitHub thresholds: ≥9.0 critical, ≥7.0 high, ≥4.0 medium, else low.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}

#: Maps :class:`~depfence.core.models.FindingType` → short SARIF rule-ID prefix.
_RULE_ID_PREFIX: dict[str, str] = {
    FindingType.KNOWN_VULN.value: "depfence/vulnerability",
    FindingType.TYPOSQUAT.value: "depfence/typosquat",
    FindingType.DEP_CONFUSION.value: "depfence/dep-confusion",
    FindingType.MALICIOUS.value: "depfence/malicious",
    FindingType.BEHAVIORAL.value: "depfence/behavioral",
    FindingType.INSTALL_SCRIPT.value: "depfence/install-script",
    FindingType.MAINTAINER.value: "depfence/maintainer",
    FindingType.REPUTATION.value: "depfence/reputation",
    FindingType.LICENSE.value: "depfence/license",
    FindingType.PROVENANCE.value: "depfence/provenance",
    FindingType.DEPRECATED.value: "depfence/deprecated",
    FindingType.SLOPSQUAT.value: "depfence/slopsquat",
    FindingType.SECRET_EXPOSED.value: "depfence/secret",
    FindingType.UNPINNED.value: "depfence/unpinned",
    FindingType.DOCKERFILE.value: "depfence/dockerfile",
    FindingType.WORKFLOW.value: "depfence/workflow",
    FindingType.TERRAFORM.value: "depfence/terraform",
    FindingType.OBFUSCATION.value: "depfence/obfuscation",
    FindingType.NETWORK.value: "depfence/network",
    FindingType.PHANTOM_DEP.value: "depfence/phantom-dep",
    FindingType.SCOPE_SQUAT.value: "depfence/scope-squat",
}

_HELP_URI_BASE = "https://github.com/depfence/depfence/wiki/rules"

# ---------------------------------------------------------------------------
# Helper functions (exported for testing)
# ---------------------------------------------------------------------------


def map_severity_to_sarif_level(severity: Severity) -> str:
    """Return the SARIF level string for *severity*."""
    return _SARIF_LEVEL.get(severity, "warning")


def map_finding_type_to_rule_id(finding_type: FindingType) -> str:
    """Return the SARIF rule-ID prefix for *finding_type*."""
    return _RULE_ID_PREFIX.get(finding_type.value, f"depfence/{finding_type.value}")


def make_partial_fingerprint(package_str: str, cve: str | None, finding_type_value: str) -> str:
    """Return a stable SHA-256 fingerprint for cross-run deduplication."""
    raw = f"{package_str}|{cve or ''}|{finding_type_value}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _rule_entry(finding: Any) -> dict[str, Any]:
    """Build a SARIF ``rules[]`` descriptor from a :class:`Finding`."""
    ft_val = finding.finding_type.value
    rule_prefix = map_finding_type_to_rule_id(finding.finding_type)
    rid = f"{rule_prefix}/{str(finding.package)}"
    return {
        "id": rid,
        "name": ft_val.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail or finding.title},
        "helpUri": f"{_HELP_URI_BASE}/{ft_val}",
        "defaultConfiguration": {
            "level": map_severity_to_sarif_level(finding.severity),
        },
        "properties": {
            "tags": ["security", "supply-chain", ft_val],
            "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.5"),
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_sarif(
    result: ScanResult,
    tool_name: str = "depfence",
    tool_version: str = "0.4.0",
) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 document from a :class:`~depfence.core.models.ScanResult`.

    Args:
        result: Completed scan result containing findings, target path, and
                timing information.
        tool_name: Name to use in the SARIF ``tool.driver.name`` field.
        tool_version: Semantic version string for the ``tool.driver`` block.

    Returns:
        A Python ``dict`` ready for JSON serialisation (e.g.
        ``json.dumps(generate_sarif(result), indent=2)``).

    The document structure follows SARIF 2.1.0 §3:

    * ``$schema`` — canonical JSON Schema URI.
    * ``version`` — always ``"2.1.0"``.
    * ``runs[]`` — exactly one run containing:

      * ``tool`` — driver name, version, and the populated ``rules[]`` array.
      * ``results[]`` — one entry per :class:`~depfence.core.models.Finding`.
      * ``artifacts[]`` — one entry for each unique artifact URI seen in
        results and related-locations.
      * ``automationDetails`` — stable run-level ID for GitHub deduplication.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_key_to_index: dict[str, int] = {}
    artifact_uris: set[str] = set()

    scan_date = (
        result.started_at.strftime("%Y-%m-%d")
        if result.started_at
        else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    )
    automation_id = f"{tool_name}/{result.target}/{scan_date}/"

    for finding in result.findings:
        ft_val = finding.finding_type.value
        pkg_str = str(finding.package)

        rule_prefix = map_finding_type_to_rule_id(finding.finding_type)
        rule_key = f"{rule_prefix}/{pkg_str}"

        if rule_key not in rule_key_to_index:
            rule_key_to_index[rule_key] = len(rules)
            rules.append(_rule_entry(finding))

        # Primary location — the scan target (lockfile / project dir).
        target_uri = result.target
        artifact_uris.add(target_uri)

        locations: list[dict[str, Any]] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
        ]

        # codeFlows — present when a lockfile path is known in metadata.
        code_flows: list[dict[str, Any]] = []
        lockfile_path: str | None = finding.metadata.get("lockfile_path")  # type: ignore[assignment]
        if lockfile_path:
            artifact_uris.add(lockfile_path)
            code_flows.append(
                {
                    "message": {"text": f"Dependency path to {pkg_str}"},
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": lockfile_path,
                                                "uriBaseId": "%SRCROOT%",
                                            },
                                        },
                                        "message": {"text": f"{pkg_str} declared here"},
                                    }
                                }
                            ]
                        }
                    ],
                }
            )

        # relatedLocations — lockfile_paths list (multi-lockfile monorepos).
        related_locations: list[dict[str, Any]] = []
        lockfile_paths: list[str] = finding.metadata.get("lockfile_paths", [])  # type: ignore[assignment]
        for idx, lp in enumerate(lockfile_paths):
            artifact_uris.add(lp)
            related_locations.append(
                {
                    "id": idx + 1,
                    "message": {"text": f"{pkg_str} declared in {lp}"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": lp,
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                }
            )

        # fixes[] — present when fix_version is known.
        fixes: list[dict[str, Any]] = []
        if finding.fix_version:
            fixes.append(
                {
                    "description": {
                        "text": f"Upgrade {pkg_str} to {finding.fix_version}"
                    },
                    "artifactChanges": [],
                }
            )

        # Result properties.
        result_properties: dict[str, Any] = {
            "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.5"),
        }
        if finding.cve:
            result_properties["cve"] = finding.cve
        if finding.cwe:
            result_properties["cwe"] = finding.cwe
        if finding.references:
            result_properties["references"] = finding.references

        sarif_result: dict[str, Any] = {
            "ruleId": rule_key,
            "ruleIndex": rule_key_to_index[rule_key],
            "level": map_severity_to_sarif_level(finding.severity),
            "message": {"text": finding.detail or finding.title},
            "locations": locations,
            "partialFingerprints": {
                "primaryLocationLineHash/v1": make_partial_fingerprint(
                    pkg_str, finding.cve, ft_val
                ),
            },
            "properties": result_properties,
        }

        if related_locations:
            sarif_result["relatedLocations"] = related_locations
        if code_flows:
            sarif_result["codeFlows"] = code_flows
        if fixes:
            sarif_result["fixes"] = fixes

        results.append(sarif_result)

    # artifacts[] — collect all unique URIs referenced across all results.
    artifacts: list[dict[str, Any]] = [
        {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
        for uri in sorted(artifact_uris)
    ]

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "automationDetails": {"id": automation_id},
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "semanticVersion": tool_version,
                        "version": tool_version,
                        "informationUri": "https://github.com/depfence/depfence",
                        "rules": rules,
                    },
                },
                "results": results,
                "artifacts": artifacts,
            }
        ],
    }

    return sarif_doc


def render_sarif(result: ScanResult, tool_name: str = "depfence", tool_version: str = "0.4.0") -> str:
    """Convenience wrapper that returns ``generate_sarif`` output as indented JSON."""
    return json.dumps(generate_sarif(result, tool_name=tool_name, tool_version=tool_version), indent=2)
