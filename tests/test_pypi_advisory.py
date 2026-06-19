"""Tests for PypiAdvisoryScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from depfence.scanners.pypi_advisory import PypiAdvisoryScanner
from depfence.core.models import FindingType, PackageId, PackageMeta, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def pypi_meta(name: str, version: str | None = None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem="pypi", name=name, version=version))


def npm_meta(name: str, version: str | None = None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem="npm", name=name, version=version))


def make_osv_vuln(
    vuln_id: str = "PYSEC-2023-1",
    summary: str = "Test vulnerability",
    details: str = "Details",
    aliases: list[str] | None = None,
    severity: list[dict] | None = None,
    affected: list[dict] | None = None,
    references: list[dict] | None = None,
) -> dict:
    return {
        "id": vuln_id,
        "summary": summary,
        "details": details,
        "aliases": aliases or [],
        "severity": severity or [],
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


def make_mock_client(response_data: dict):
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = response_data

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)
    return mock_client


# ---------------------------------------------------------------------------
# Ecosystem filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_skips_non_pypi_packages():
    """npm packages should be silently ignored."""
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = await scanner.scan([npm_meta("lodash", "4.17.21")])
    assert findings == []
    db.is_known_malicious.assert_not_called()


@pytest.mark.asyncio
async def test_scan_empty_list_returns_empty():
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = await scanner.scan([])
    assert findings == []


# ---------------------------------------------------------------------------
# OSV integration (mocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_osv_returns_known_vuln_finding():
    vuln = make_osv_vuln(
        summary="SQL injection in Django ORM",
        aliases=["CVE-2023-9999"],
        severity=[{"type": "CVSS_V3", "score": "8.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    )
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("Django", "3.2.0")])

    osv = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert osv
    assert osv[0].cve == "CVE-2023-9999"
    assert osv[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scan_osv_no_vulns_clean_package():
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": []})
        findings = await scanner.scan([pypi_meta("requests", "2.31.0")])

    osv = [f for f in findings if f.metadata.get("source") != "local_threat_db"]
    assert osv == []


@pytest.mark.asyncio
async def test_scan_osv_network_error_is_silenced():
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("unreachable"))

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = mock_client
        findings = await scanner.scan([pypi_meta("requests", "2.31.0")])

    # Must not raise; threat_db portion may still run
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_scan_osv_sends_pypi_ecosystem_in_payload():
    """OSV payload must use 'PyPI' (capital P) — the canonical ecosystem name."""
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = make_mock_client({"vulns": []})
        mock_cls.return_value = mock_client
        await scanner.scan([pypi_meta("numpy", "1.24.0")])

    call_kwargs = mock_client.post.call_args
    payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
    assert payload["package"]["ecosystem"] == "PyPI"


@pytest.mark.asyncio
async def test_scan_osv_sends_version_when_present():
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = make_mock_client({"vulns": []})
        mock_cls.return_value = mock_client
        await scanner.scan([pypi_meta("numpy", "1.24.0")])

    payload = mock_client.post.call_args[1]["json"]
    assert payload.get("version") == "1.24.0"


@pytest.mark.asyncio
async def test_scan_osv_omits_version_when_absent():
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_client = make_mock_client({"vulns": []})
        mock_cls.return_value = mock_client
        await scanner.scan([pypi_meta("numpy")])  # no version

    payload = mock_client.post.call_args[1]["json"]
    assert "version" not in payload


@pytest.mark.asyncio
async def test_scan_references_capped_at_five():
    vuln = make_osv_vuln(
        references=[{"url": f"https://ref{i}.example.com"} for i in range(10)],
    )
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("pkg", "1.0.0")])

    osv = [f for f in findings if f.references]
    if osv:
        assert len(osv[0].references) <= 5


@pytest.mark.asyncio
async def test_scan_fix_version_extracted():
    vuln = make_osv_vuln(
        summary="RCE in Pillow",
        affected=[{
            "package": {"name": "Pillow", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.3.0"}]}],
        }],
    )
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("Pillow", "9.0.0")])

    with_fix = [f for f in findings if f.fix_version]
    assert with_fix
    assert with_fix[0].fix_version == "9.3.0"


@pytest.mark.asyncio
async def test_scan_cve_picked_from_aliases():
    vuln = make_osv_vuln(
        aliases=["GHSA-aaaa-bbbb-cccc", "CVE-2022-12345"],
    )
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("pkg", "1.0.0")])

    osv = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert osv
    assert osv[0].cve == "CVE-2022-12345"


@pytest.mark.asyncio
async def test_scan_no_cve_alias_leaves_cve_none():
    vuln = make_osv_vuln(aliases=["GHSA-aaaa-bbbb-cccc"])
    db = stub_threat_db()
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("pkg", "1.0.0")])

    osv = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert osv
    assert osv[0].cve is None


# ---------------------------------------------------------------------------
# _parse_severity
# ---------------------------------------------------------------------------

def test_parse_severity_cvss_critical():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert scanner._parse_severity(vuln) == Severity.CRITICAL


def test_parse_severity_cvss_high():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
    assert scanner._parse_severity(vuln) == Severity.HIGH


def test_parse_severity_cvss_medium():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}
    assert scanner._parse_severity(vuln) == Severity.MEDIUM


def test_parse_severity_cvss_low():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"}]}
    assert scanner._parse_severity(vuln) == Severity.LOW


def test_parse_severity_no_cvss_defaults_to_medium():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": []}
    assert scanner._parse_severity(vuln) == Severity.MEDIUM


def test_parse_severity_malformed_score_defaults_to_medium():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {"severity": [{"type": "CVSS_V3", "score": "BADVALUE"}]}
    assert scanner._parse_severity(vuln) == Severity.MEDIUM


def test_parse_severity_empty_vuln_defaults_to_medium():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    assert scanner._parse_severity({}) == Severity.MEDIUM


# ---------------------------------------------------------------------------
# _find_fix
# ---------------------------------------------------------------------------

def test_find_fix_returns_version():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "affected": [{
            "package": {"name": "cryptography", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "41.0.0"}]}],
        }]
    }
    assert scanner._find_fix(vuln, "cryptography") == "41.0.0"


def test_find_fix_wrong_package_name_returns_none():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "affected": [{
            "package": {"name": "other-pkg", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"fixed": "1.0.0"}]}],
        }]
    }
    assert scanner._find_fix(vuln, "cryptography") is None


def test_find_fix_no_fixed_event_returns_none():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    vuln = {
        "affected": [{
            "package": {"name": "mypkg", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"}]}],
        }]
    }
    assert scanner._find_fix(vuln, "mypkg") is None


def test_find_fix_empty_vuln_returns_none():
    scanner = PypiAdvisoryScanner(threat_db=stub_threat_db())
    assert scanner._find_fix({}, "mypkg") is None


# ---------------------------------------------------------------------------
# _query_threat_db
# ---------------------------------------------------------------------------

def test_query_threat_db_known_malicious_emits_critical():
    db = stub_threat_db(is_malicious=True, lookup_results=[])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("evil-lib")])
    malicious = [f for f in findings if f.finding_type == FindingType.MALICIOUS]
    assert malicious
    assert malicious[0].severity == Severity.CRITICAL
    assert "evil-lib" in malicious[0].title


def test_query_threat_db_malware_threat_type_is_malicious_finding():
    threat = {
        "severity": "critical",
        "threat_type": "malware",
        "title": "Malware in package",
        "detail": "backdoor found",
        "cve": None,
        "source": "internal",
        "version_range": None,
        "first_seen": None,
        "last_updated": None,
    }
    db = stub_threat_db(is_malicious=True, lookup_results=[threat])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("bad-lib")])
    assert any(f.finding_type == FindingType.MALICIOUS for f in findings)


def test_query_threat_db_vuln_threat_type_is_known_vuln():
    threat = {
        "severity": "high",
        "threat_type": "vulnerability",
        "title": "XSS in Jinja2",
        "detail": "template injection",
        "cve": "CVE-2023-5678",
        "source": "osv",
        "version_range": "<3.1.3",
        "first_seen": "2023-01-01",
        "last_updated": "2023-06-01",
    }
    db = stub_threat_db(is_malicious=False, lookup_results=[threat])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("Jinja2")])
    vuln = [f for f in findings if f.finding_type == FindingType.KNOWN_VULN]
    assert vuln
    assert vuln[0].severity == Severity.HIGH
    assert vuln[0].cve == "CVE-2023-5678"


def test_query_threat_db_no_hits_returns_empty():
    db = stub_threat_db(is_malicious=False, lookup_results=[])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("numpy")])
    assert findings == []


def test_query_threat_db_missing_title_uses_default():
    threat = {
        "severity": "medium",
        "threat_type": "vulnerability",
        "title": None,
        "detail": "some detail",
        "cve": None,
        "source": "osv",
        "version_range": None,
        "first_seen": None,
        "last_updated": None,
    }
    db = stub_threat_db(is_malicious=False, lookup_results=[threat])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("mypkg")])
    assert findings
    assert "mypkg" in findings[0].title


def test_query_threat_db_unknown_severity_defaults_to_medium():
    threat = {
        "severity": "bogus",
        "threat_type": "vulnerability",
        "title": "Some issue",
        "detail": "",
        "cve": None,
        "source": "osv",
        "version_range": None,
        "first_seen": None,
        "last_updated": None,
    }
    db = stub_threat_db(is_malicious=False, lookup_results=[threat])
    scanner = PypiAdvisoryScanner(threat_db=db)
    findings = scanner._query_threat_db([pypi_meta("mypkg")])
    assert findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Integration: scan() chains OSV + threat_db
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_combines_osv_and_threat_db_findings():
    """Both OSV findings and threat_db findings should appear in the result."""
    vuln = make_osv_vuln(summary="Known CVE")
    threat = {
        "severity": "critical",
        "threat_type": "malware",
        "title": "Backdoor detected",
        "detail": "",
        "cve": None,
        "source": "internal",
        "version_range": None,
        "first_seen": None,
        "last_updated": None,
    }
    db = stub_threat_db(is_malicious=True, lookup_results=[threat])
    scanner = PypiAdvisoryScanner(threat_db=db)

    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = make_mock_client({"vulns": [vuln]})
        findings = await scanner.scan([pypi_meta("evil-lib", "1.0.0")])

    types = {f.finding_type for f in findings}
    assert FindingType.KNOWN_VULN in types
    assert FindingType.MALICIOUS in types
