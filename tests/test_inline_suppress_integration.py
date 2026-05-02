"""Integration tests: inline suppression wired into the scan engine.

Verifies that ``depfence:ignore`` comments in lockfiles are picked up by
``scan_directory`` and that suppressed findings are:
  * removed from ``ScanResult.findings``
  * recorded in ``ScanResult.suppressed_findings``
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.models import Finding, FindingType, PackageId, ScanResult, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    name: str,
    ecosystem: str = "pypi",
    version: str = "1.0.0",
    finding_type: FindingType = FindingType.KNOWN_VULN,
    severity: Severity = Severity.HIGH,
    cve: str | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        severity=severity,
        package=PackageId(ecosystem=ecosystem, name=name, version=version),
        title=f"Test finding for {name}",
        detail="Test detail",
        cve=cve,
    )


def _write(directory: Path, filename: str, content: str) -> Path:
    p = directory / filename
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_project(tmp_path: Path) -> Path:
    """Return a minimal project directory with a requirements.txt lockfile."""
    _write(
        tmp_path,
        "requirements.txt",
        # requests has a wildcard suppression; flask is not suppressed
        "requests==2.28.0  # depfence:ignore\n"
        "flask==2.3.0\n",
    )
    return tmp_path


@pytest.fixture()
def fake_project_cve(tmp_path: Path) -> Path:
    """Project where only a specific CVE is suppressed for requests."""
    _write(
        tmp_path,
        "requirements.txt",
        "requests==2.28.0  # depfence:ignore CVE-2024-1234\n"
        "flask==2.3.0\n",
    )
    return tmp_path


@pytest.fixture()
def fake_project_no_suppressions(tmp_path: Path) -> Path:
    """Project with no depfence:ignore comments at all."""
    _write(
        tmp_path,
        "requirements.txt",
        "requests==2.28.0\nflask==2.3.0\n",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Shared scan runner
# ---------------------------------------------------------------------------

REQUESTS_PKG = PackageId(ecosystem="pypi", name="requests", version="2.28.0")
FLASK_PKG = PackageId(ecosystem="pypi", name="flask", version="2.3.0")


def _run_scan(project_dir: Path, findings_to_return: list[Finding]) -> ScanResult:
    """Run scan_directory with all external I/O patched out.

    All scanners/analyzers/enrichers are bypassed; the only real logic exercised
    is the inline suppression wiring added to the engine.
    """
    from depfence.core import engine

    # Build a minimal mock registry that returns no scanner/analyzer findings.
    mock_scanner = MagicMock()
    mock_scanner.ecosystems = ["pypi"]
    mock_scanner.scan = AsyncMock(return_value=findings_to_return)

    mock_registry = MagicMock()
    mock_registry.scanners = {"mock_scanner": mock_scanner}
    mock_registry.analyzers = {}
    mock_registry.reporters = {}
    mock_registry.fire_hook = AsyncMock(return_value=None)

    with (
        patch.object(engine, "get_registry", return_value=mock_registry),
        patch.object(engine, "fetch_batch", new=AsyncMock(return_value=[])),
        # Disable enrichment and project scanners to keep tests fast and isolated.
        patch("depfence.core.engine.ThreatIntelDB", side_effect=ImportError, create=True),
    ):
        return asyncio.run(
            engine.scan_directory(
                project_dir,
                fetch_metadata=False,
                project_scanners=False,
                enrich=False,
            )
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInlineSuppressIntegration:
    """End-to-end tests for suppression wiring in engine.scan_directory."""

    def test_suppressed_finding_removed_from_findings(self, fake_project):
        """Wildcard-suppressed package findings must NOT appear in result.findings."""
        findings = [
            _make_finding("requests"),
            _make_finding("flask"),
        ]
        result = _run_scan(fake_project, findings)

        names_in_findings = {f.package.name for f in result.findings}
        assert "requests" not in names_in_findings, (
            "requests should be suppressed and absent from result.findings"
        )
        assert "flask" in names_in_findings, (
            "flask has no suppression and must remain in result.findings"
        )

    def test_suppressed_finding_tracked_in_suppressed_findings(self, fake_project):
        """Suppressed findings must be recorded in result.suppressed_findings."""
        findings = [
            _make_finding("requests"),
            _make_finding("flask"),
        ]
        result = _run_scan(fake_project, findings)

        suppressed_names = {f.package.name for f in result.suppressed_findings}
        assert "requests" in suppressed_names, (
            "requests should appear in result.suppressed_findings"
        )
        assert "flask" not in suppressed_names, (
            "flask must not appear in suppressed_findings"
        )

    def test_suppressed_count_correct(self, fake_project):
        """Count of suppressed findings must equal number of matched suppressions."""
        findings = [
            _make_finding("requests", finding_type=FindingType.KNOWN_VULN),
            _make_finding("requests", finding_type=FindingType.TYPOSQUAT),
            _make_finding("flask"),
        ]
        result = _run_scan(fake_project, findings)

        assert len(result.suppressed_findings) == 2, (
            "Both requests findings should be suppressed (wildcard)"
        )
        assert len(result.findings) == 1, (
            "Only flask should remain active"
        )

    def test_cve_specific_suppression_only_removes_matching_cve(self, fake_project_cve):
        """Only the explicitly named CVE is suppressed; other findings for the same package remain."""
        findings = [
            _make_finding("requests", cve="CVE-2024-1234"),   # should be suppressed
            _make_finding("requests", cve="CVE-2024-9999"),   # different CVE — NOT suppressed
            _make_finding("requests"),                         # no CVE — NOT suppressed
            _make_finding("flask"),
        ]
        result = _run_scan(fake_project_cve, findings)

        suppressed_cves = {f.cve for f in result.suppressed_findings}
        assert "CVE-2024-1234" in suppressed_cves
        assert "CVE-2024-9999" not in suppressed_cves

        active_names = [f.package.name for f in result.findings]
        flask_active = [f for f in result.findings if f.package.name == "flask"]
        assert len(flask_active) == 1

        # Two requests findings should still be active (non-matching CVE + no CVE)
        active_requests = [f for f in result.findings if f.package.name == "requests"]
        assert len(active_requests) == 2

    def test_no_suppressions_all_findings_active(self, fake_project_no_suppressions):
        """When no depfence:ignore comments exist, all findings pass through unchanged."""
        findings = [
            _make_finding("requests"),
            _make_finding("flask"),
        ]
        result = _run_scan(fake_project_no_suppressions, findings)

        assert len(result.findings) == 2
        assert result.suppressed_findings == []

    def test_suppressed_findings_field_exists_on_scan_result(self, fake_project_no_suppressions):
        """ScanResult must always expose a suppressed_findings attribute."""
        result = _run_scan(fake_project_no_suppressions, [])
        assert hasattr(result, "suppressed_findings")
        assert isinstance(result.suppressed_findings, list)

    def test_multiple_lockfiles_suppressions_merged(self, tmp_path):
        """When multiple lockfiles are present, suppressions from all are combined."""
        # requirements.txt suppresses requests; package.json would suppress lodash
        # (but we only produce pypi findings so only requests matters here)
        _write(tmp_path, "requirements.txt", "requests==2.28.0  # depfence:ignore\nflask==2.3.0\n")
        # A second lockfile that adds a suppression for flask
        _write(tmp_path, "requirements2.txt", "flask==2.3.0  # depfence:ignore\n")

        findings = [_make_finding("requests"), _make_finding("flask")]

        # Patch detect_ecosystem to return both files
        from depfence.core import engine
        from unittest.mock import patch as _patch

        mock_scanner = MagicMock()
        mock_scanner.ecosystems = ["pypi"]
        mock_scanner.scan = AsyncMock(return_value=findings)

        mock_registry = MagicMock()
        mock_registry.scanners = {"mock_scanner": mock_scanner}
        mock_registry.analyzers = {}
        mock_registry.reporters = {}
        mock_registry.fire_hook = AsyncMock(return_value=None)

        with (
            _patch.object(engine, "get_registry", return_value=mock_registry),
            _patch.object(engine, "fetch_batch", new=AsyncMock(return_value=[])),
            _patch(
                "depfence.core.engine.detect_ecosystem",
                return_value=[
                    ("pypi", tmp_path / "requirements.txt"),
                    ("pypi", tmp_path / "requirements2.txt"),
                ],
            ),
            _patch(
                "depfence.core.engine.parse_lockfile",
                return_value=[
                    PackageId("pypi", "requests", "2.28.0"),
                    PackageId("pypi", "flask", "2.3.0"),
                ],
            ),
        ):
            result = asyncio.run(
                engine.scan_directory(
                    tmp_path,
                    fetch_metadata=False,
                    project_scanners=False,
                    enrich=False,
                )
            )

        assert result.findings == [], "All findings should be suppressed"
        assert len(result.suppressed_findings) == 2
