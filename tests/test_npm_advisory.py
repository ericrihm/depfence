"""Tests for NpmAdvisoryScanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from depfence.scanners.npm_advisory import NpmAdvisoryScanner
from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def npm_meta(name: str, version: str | None = None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem="npm", name=name, version=version))


def pypi_meta(name: str, version: str | None = None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem="pypi", name=name, version=version))


def make_osv_vuln(
    vuln_id: str = "GHSA-1234-5678-abcd",
    summary: str = "Test vulnerability",
    details: str = "Details here",
    aliases: list[str] | None = None,
    severity: list[dict] | None = None,
    database_specific: dict | None = None,
    affected: list[dict] | None = None,
    references: list[dict] | None = None,
) -> dict:
    return {
        "id": vuln_id,
        "summary": summary,
        "details": details,
        "aliases": aliases or [],
        "severity": severity or [],
        "database_specific": database_specific or {},
        "affected": affected or [],
        "references": references or [],
    }


def stub_threat_db(
    is_malicious: bool = False,
    lookup_results: list[dict] | None = None,
) -> MagicMock:
    db = MagicMock()
    db.is_known_malicious.return_value = is_malicious
    db.lookup.return_value = lookup_results or []
    return db


# ---------------------------------------------------------------------------
# Ecosystem filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_skips_non_npm_packages():
    """PyPI packages should be ignored — only npm is handled."""
    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)
    findings = await scanner.scan([pypi_meta("requests", "2.28.0")])
    assert findings == []
    db.is_known_malicious.assert_not_called()


@pytest.mark.asyncio
async def test_scan_empty_list_returns_empty():
    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)
    findings = await scanner.scan([])
    assert findings == []


# ---------------------------------------------------------------------------
# OSV integration (mocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_osv_returns_known_vuln_finding():
    vuln = make_osv_vuln(
        summary="Prototype pollution in lodash",
        aliases=["CVE-2019-10744"],
        database_specific={"severity": "high"},
    )

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulns": [vuln]}

    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        findings = await scanner.scan([npm_meta("lodash", "4.17.15")])

    assert len(findings) >= 1
    osv_findings = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert osv_findings
    assert osv_findings[0].cve == "CVE-2019-10744"
    assert osv_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scan_osv_no_vulns_returns_empty():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulns": []}

    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        findings = await scanner.scan([npm_meta("safe-pkg", "1.0.0")])

    db_findings = [f for f in findings if f.metadata.get("source") == "local_threat_db"]
    osv_findings = [f for f in findings if f.metadata.get("source") != "local_threat_db"]
    assert osv_findings == []


@pytest.mark.asyncio
async def test_scan_osv_network_error_is_silenced():
    """A network failure should not raise — it should be logged and skipped."""
    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("timeout"))
        mock_client_cls.return_value = mock_client

        findings = await scanner.scan([npm_meta("some-pkg", "1.0.0")])

    # Should not raise; threat_db findings may still be present
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_scan_includes_fix_version_when_present():
    vuln = make_osv_vuln(
        summary="Critical RCE",
        affected=[{
            "package": {"name": "express", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.18.3"}]}],
        }],
    )

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulns": [vuln]}

    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        findings = await scanner.scan([npm_meta("express", "4.17.0")])

    osv_findings = [f for f in findings if f.fix_version is not None]
    assert osv_findings
    assert osv_findings[0].fix_version == "4.18.3"


@pytest.mark.asyncio
async def test_scan_references_capped_at_five():
    vuln = make_osv_vuln(
        references=[{"url": f"https://ref{i}.example.com"} for i in range(10)],
    )

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"vulns": [vuln]}

    db = stub_threat_db()
    scanner = NpmAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        findings = await scanner.scan([npm_meta("pkg", "1.0.0")])

    osv_findings = [f for f in findings if f.references]
    if osv_findings:
        assert len(osv_findings[0].references) <= 5


# ---------------------------------------------------------------------------
# _extract_severity
# ---------------------------------------------------------------------------

def test_extract_severity_cvss_critical():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert scanner._extract_severity(vuln) == Severity.CRITICAL


def test_extract_severity_cvss_high():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
    assert scanner._extract_severity(vuln) == Severity.HIGH


def test_extract_severity_cvss_medium():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "5.3/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}
    assert scanner._extract_severity(vuln) == Severity.MEDIUM


def test_extract_severity_cvss_low():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L"}]}
    assert scanner._extract_severity(vuln) == Severity.LOW


def test_extract_severity_falls_back_to_database_specific():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [], "database_specific": {"severity": "critical"}}
    assert scanner._extract_severity(vuln) == Severity.CRITICAL


def test_extract_severity_unknown_defaults_to_medium():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [], "database_specific": {}}
    assert scanner._extract_severity(vuln) == Severity.MEDIUM


def test_extract_severity_malformed_cvss_score_falls_back():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "severity": [{"type": "CVSS_V3", "score": "NOTANUMBER"}],
        "database_specific": {"severity": "high"},
    }
    assert scanner._extract_severity(vuln) == Severity.HIGH


# ---------------------------------------------------------------------------
# _extract_fix_version
# ---------------------------------------------------------------------------

def test_extract_fix_version_found():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "affected": [{
            "package": {"name": "mylib", "ecosystem": "npm"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
        }]
    }
    assert scanner._extract_fix_version(vuln, "mylib") == "2.0.1"


def test_extract_fix_version_wrong_package_name():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "affected": [{
            "package": {"name": "otherlib", "ecosystem": "npm"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
        }]
    }
    assert scanner._extract_fix_version(vuln, "mylib") is None


def test_extract_fix_version_no_affected():
    scanner = NpmAdvisoryScanner(threat_db=stub_threat_db())
    assert scanner._extract_fix_version({}, "mylib") is None


# ---------------------------------------------------------------------------
# _query_threat_db
# ---------------------------------------------------------------------------

def test_query_threat_db_known_malicious_emits_critical():
    db = stub_threat_db(is_malicious=True, lookup_results=[])
    scanner = NpmAdvisoryScanner(threat_db=db)
    pkg = npm_meta("evil-pkg", "1.0.0")
    findings = scanner._query_threat_db([pkg])
    malicious = [f for f in findings if f.finding_type == FindingType.MALICIOUS]
    assert malicious
    assert malicious[0].severity == Severity.CRITICAL


def test_query_threat_db_lookup_emits_known_vuln_for_non_malicious_type():
    threat = {
        "severity": "high",
        "threat_type": "vulnerability",
        "title": "XSS in template",
        "detail": "desc",
        "cve": "CVE-2023-1234",
        "source": "osv",
        "version_range": "<2.0",
        "first_seen": "2023-01-01",
        "last_updated": "2023-06-01",
    }
    db = stub_threat_db(is_malicious=False, lookup_results=[threat])
    scanner = NpmAdvisoryScanner(threat_db=db)
    pkg = npm_meta("vuln-pkg", "1.0.0")
    findings = scanner._query_threat_db([pkg])
    vuln_findings = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert vuln_findings
    assert vuln_findings[0].severity == Severity.HIGH


def test_query_threat_db_malware_type_emits_malicious_finding():
    threat = {
        "severity": "critical",
        "threat_type": "malware",
        "title": "Malware detected",
        "detail": "backdoor",
        "cve": None,
        "source": "internal",
        "version_range": None,
        "first_seen": None,
        "last_updated": None,
    }
    db = stub_threat_db(is_malicious=True, lookup_results=[threat])
    scanner = NpmAdvisoryScanner(threat_db=db)
    pkg = npm_meta("bad-pkg")
    findings = scanner._query_threat_db([pkg])
    assert any(f.finding_type == FindingType.MALICIOUS for f in findings)


def test_query_threat_db_no_db_hits_returns_empty():
    db = stub_threat_db(is_malicious=False, lookup_results=[])
    scanner = NpmAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([npm_meta("clean-pkg")])
    assert findings == []
