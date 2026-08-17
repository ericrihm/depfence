"""Release-facing public contract regressions for DepFence 0.8."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

from click.testing import CliRunner

from depfence.cli.main import cli
from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity
from depfence.reporters.sarif import generate_sarif


def test_sarif_preserves_exact_depfence_severity() -> None:
    result = ScanResult(target=".", ecosystem="npm", packages_scanned=1)
    result.findings = [
        Finding(
            FindingType.KNOWN_VULN,
            severity,
            PackageId("npm", f"pkg-{severity.value}", "1.0.0"),
            severity.value,
            "detail",
        )
        for severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    results = generate_sarif(result)["runs"][0]["results"]
    assert [item["level"] for item in results] == ["error", "error"]
    assert [item["properties"]["depfence-severity"] for item in results] == [
        "critical",
        "high",
    ]


def test_action_counts_critical_by_exact_depfence_severity() -> None:
    action = Path("action.yml").read_text(encoding="utf-8")
    critical_lines = [line for line in action.splitlines() if "CRITICAL=$(" in line]
    assert len(critical_lines) == 2
    assert all("depfence-severity" in line for line in critical_lines)
    assert all("res.get('level')=='error'" not in line for line in critical_lines)


def test_report_renders_one_canonical_scan_result(tmp_path, monkeypatch) -> None:
    result = ScanResult(target=str(tmp_path), ecosystem="multi", packages_scanned=1)
    result.findings = [
        Finding(
            FindingType.TYPOSQUAT,
            Severity.HIGH,
            PackageId("pypi", "reqeusts", "1.0"),
            "Typosquat",
            "Looks like requests",
        )
    ]
    scan = AsyncMock(return_value=result)
    monkeypatch.setattr("depfence.core.engine.scan_directory", scan)
    destination = tmp_path / "report.json"

    invocation = CliRunner().invoke(
        cli,
        ["report", str(tmp_path), "--format", "json", "--output", str(destination)],
    )

    assert invocation.exit_code == 0, invocation.output
    scan.assert_awaited_once_with(tmp_path.resolve())
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["schema_version"] == "depfence.scan/v1"
    assert document["summary"]["findings"] == 1
    assert document["findings"][0]["severity"] == "high"
