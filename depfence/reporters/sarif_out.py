"""SARIF reporter for GitHub Code Scanning integration."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from depfence import __version__
from depfence.core.models import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# CVSS-style numeric severity for GitHub security badge colouring.
# GitHub maps: >= 9.0 -> critical, >= 7.0 -> high, >= 4.0 -> medium, else low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}

_HELP_URI_BASE = "https://github.com/depfence/depfence/wiki/rules"


def _rule_id(finding_type_value: str, package_str: str) -> str:
    """Stable, unique rule key scoped to finding type + package identity."""
    return f"{finding_type_value}/{package_str}"


def _partial_fingerprint(package_str: str, cve: str | None, finding_type_value: str) -> str:
    """SHA-256 fingerprint for stable cross-run deduplication in GitHub."""
    raw = f"{package_str}|{cve or ''}|{finding_type_value}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _rule_entry(finding) -> dict:
    """Build a SARIF rule descriptor from a Finding."""
    ft_val = finding.finding_type.value
    pkg_str = str(finding.package)
    rid = _rule_id(ft_val, pkg_str)
    return {
        "id": rid,
        "name": ft_val.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail or finding.title},
        "helpUri": f"{_HELP_URI_BASE}/{ft_val}",
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        },
        "properties": {
            "tags": ["security", "supply-chain", ft_val],
            "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.5"),
        },
    }


class SarifReporter:
    name = "sarif"
    format = "sarif"

    def render(self, result: ScanResult, run_id: str | None = None) -> str:
        rules: list[dict] = []
        results: list[dict] = []
        # Map rule_key -> index in rules list (for ruleIndex references)
        rule_ids: dict[str, int] = {}

        for finding in result.findings:
            ft_val = finding.finding_type.value
            pkg_str = str(finding.package)
            rule_key = _rule_id(ft_val, pkg_str)

            if rule_key not in rule_ids:
                rule_ids[rule_key] = len(rules)
                rules.append(_rule_entry(finding))

            # --- Primary location: the manifest/lockfile that was scanned ---
            locations = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target,
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                }
            ]

            # --- Related locations: lockfile paths stored in finding metadata ---
            related_locations: list[dict] = []
            lockfile_paths: list[str] = finding.metadata.get("lockfile_paths", [])
            for idx, lp in enumerate(lockfile_paths):
                related_locations.append(
                    {
                        "id": idx + 1,
                        "message": {
                            "text": f"{pkg_str} declared in {lp}",
                        },
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": lp,
                                "uriBaseId": "%SRCROOT%",
                            },
                        },
                    }
                )

            # --- Result properties (security-severity + optional CVE/refs) ---
            result_properties: dict[str, object] = {
                "security-severity": _SECURITY_SEVERITY.get(finding.severity, "5.5"),
            }
            if finding.cve:
                result_properties["cve"] = finding.cve
            if finding.cwe:
                result_properties["cwe"] = finding.cwe
            if finding.references:
                result_properties["references"] = finding.references

            sarif_result: dict[str, object] = {
                "ruleId": rule_key,
                "ruleIndex": rule_ids[rule_key],
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.detail or finding.title},
                "locations": locations,
                "partialFingerprints": {
                    "primaryLocationLineHash/v1": _partial_fingerprint(
                        pkg_str, finding.cve, ft_val
                    ),
                },
                "properties": result_properties,
            }

            if related_locations:
                sarif_result["relatedLocations"] = related_locations

            results.append(sarif_result)

        # --- Automation details: stable run-level ID for deduplication ---
        scan_date = (
            result.started_at.strftime("%Y-%m-%d")
            if result.started_at
            else datetime.now(timezone.utc).strftime("%Y-%m-%d")
        )
        automation_id = run_id or f"depfence/{result.target}/{scan_date}/"

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "automationDetails": {"id": automation_id},
                    "tool": {
                        "driver": {
                            "name": "depfence",
                            "semanticVersion": __version__,
                            "version": __version__,
                            "informationUri": "https://github.com/depfence/depfence",
                            "rules": rules,
                        },
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)
