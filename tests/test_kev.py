"""Tests for the CISA KEV client and enricher (unit tests with mocked HTTP)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.kev_client import KevClient, KevEntry, _parse_entry, _catalog_from_payload
from depfence.core.kev_enricher import enrich_with_kev
from depfence.core.models import Finding, FindingType, PackageId, Severity


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_SAMPLE_PAYLOAD: dict = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.01.15",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2022-30190",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Microsoft Windows Support Diagnostic Tool (MSDT) RCE",
            "dateAdded": "2022-05-31",
            "shortDescription": "Microsoft MSDT contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2022-06-14",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def _make_finding(
    cve: str | None = None,
    severity: Severity = Severity.HIGH,
    title: str = "Test vulnerability",
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem="pypi", name="log4j", version="2.14.0"),
        title=title,
        detail="Detail text.",
        cve=cve,
    )


def _mock_http_response(payload: dict) -> MagicMock:
    """Build a mock httpx response returning *payload* as JSON."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = payload
    return mock_resp


# ---------------------------------------------------------------------------
# KevEntry dataclass & parsing helpers
# ---------------------------------------------------------------------------

class TestKevEntryParsing:
    def test_parse_entry_known_ransomware(self):
        raw = _SAMPLE_PAYLOAD["vulnerabilities"][0]
        entry = _parse_entry(raw)
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.vendor == "Apache"
        assert entry.product == "Log4j"
        assert entry.name == "Apache Log4j2 Remote Code Execution Vulnerability"
        assert entry.date_added == "2021-12-10"
        assert entry.due_date == "2021-12-24"
        assert entry.ransomware is True

    def test_parse_entry_unknown_ransomware(self):
        raw = _SAMPLE_PAYLOAD["vulnerabilities"][1]
        entry = _parse_entry(raw)
        assert entry.cve_id == "CVE-2022-30190"
        assert entry.ransomware is False

    def test_parse_entry_ransomware_case_insensitive(self):
        raw = {**_SAMPLE_PAYLOAD["vulnerabilities"][0], "knownRansomwareCampaignUse": "KNOWN"}
        entry = _parse_entry(raw)
        assert entry.ransomware is True

    def test_parse_entry_missing_ransomware_field(self):
        raw = {k: v for k, v in _SAMPLE_PAYLOAD["vulnerabilities"][0].items()
               if k != "knownRansomwareCampaignUse"}
        entry = _parse_entry(raw)
        assert entry.ransomware is False

    def test_catalog_from_payload_keyed_by_cve(self):
        catalog = _catalog_from_payload(_SAMPLE_PAYLOAD)
        assert "CVE-2021-44228" in catalog
        assert "CVE-2022-30190" in catalog
        assert len(catalog) == 2

    def test_catalog_from_payload_empty_vulnerabilities(self):
        catalog = _catalog_from_payload({"vulnerabilities": []})
        assert catalog == {}

    def test_catalog_from_payload_missing_vulnerabilities_key(self):
        catalog = _catalog_from_payload({})
        assert catalog == {}

    def test_entry_with_empty_cve_id_skipped(self):
        payload = {
            "vulnerabilities": [
                {"cveID": "", "vendorProject": "Test", "product": "X",
                 "vulnerabilityName": "X", "dateAdded": "2024-01-01",
                 "shortDescription": "X", "requiredAction": "X",
                 "dueDate": "2024-01-15", "knownRansomwareCampaignUse": "Unknown"},
            ]
        }
        catalog = _catalog_from_payload(payload)
        assert catalog == {}


# ---------------------------------------------------------------------------
# KevClient — fetch from network
# ---------------------------------------------------------------------------

class TestKevClientFetch:
    @pytest.mark.asyncio
    async def test_fetch_catalog_returns_keyed_dict(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        assert "CVE-2021-44228" in catalog
        assert isinstance(catalog["CVE-2021-44228"], KevEntry)
        assert catalog["CVE-2021-44228"].vendor == "Apache"

    @pytest.mark.asyncio
    async def test_fetch_catalog_saves_to_cache(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()

        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert "vulnerabilities" in data

    @pytest.mark.asyncio
    async def test_fetch_catalog_uses_in_memory_cache_on_second_call(self, tmp_path):
        """Second call should not hit the network at all."""
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()
            await client.fetch_catalog()

        assert mock_http.get.call_count == 1

    @pytest.mark.asyncio
    async def test_fresh_disk_cache_skips_network(self, tmp_path):
        """When a fresh cache exists on disk, no HTTP request should be made."""
        cache_file = tmp_path / "kev_catalog.json"
        cache_file.write_text(json.dumps(_SAMPLE_PAYLOAD), encoding="utf-8")

        mock_http = AsyncMock()
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        mock_http.get.assert_not_called()
        assert "CVE-2021-44228" in catalog


# ---------------------------------------------------------------------------
# KevClient — cache fallback on network error
# ---------------------------------------------------------------------------

class TestKevClientCacheFallback:
    @pytest.mark.asyncio
    async def test_network_error_falls_back_to_stale_cache(self, tmp_path):
        """When the network fails but a stale cache exists, return cached data."""
        cache_file = tmp_path / "kev_catalog.json"
        cache_file.write_text(json.dumps(_SAMPLE_PAYLOAD), encoding="utf-8")
        # Make cache appear older than TTL (26 hours ago)
        old_mtime = time.time() - (26 * 3600)
        import os
        os.utime(cache_file, (old_mtime, old_mtime))

        mock_http = AsyncMock()
        mock_http.get.side_effect = Exception("Network unreachable")
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        assert "CVE-2021-44228" in catalog

    @pytest.mark.asyncio
    async def test_network_error_no_cache_returns_empty(self, tmp_path):
        """When network fails and no cache exists, return empty dict."""
        cache_file = tmp_path / "kev_catalog.json"

        mock_http = AsyncMock()
        mock_http.get.side_effect = Exception("Network unreachable")
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        assert catalog == {}

    @pytest.mark.asyncio
    async def test_timeout_falls_back_to_cache(self, tmp_path):
        import httpx

        cache_file = tmp_path / "kev_catalog.json"
        cache_file.write_text(json.dumps(_SAMPLE_PAYLOAD), encoding="utf-8")

        mock_http = AsyncMock()
        mock_http.get.side_effect = httpx.TimeoutException("timed out")
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        # Should still have data from cache
        assert "CVE-2021-44228" in catalog

    @pytest.mark.asyncio
    async def test_http_error_falls_back_to_cache(self, tmp_path):
        import httpx

        cache_file = tmp_path / "kev_catalog.json"
        cache_file.write_text(json.dumps(_SAMPLE_PAYLOAD), encoding="utf-8")

        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_http = AsyncMock()
        mock_http.get.side_effect = httpx.HTTPStatusError(
            "Service Unavailable", request=MagicMock(), response=mock_response
        )
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            catalog = await client.fetch_catalog()

        assert "CVE-2021-44228" in catalog


# ---------------------------------------------------------------------------
# KevClient — is_exploited / get_entry
# ---------------------------------------------------------------------------

class TestKevClientLookups:
    @pytest.mark.asyncio
    async def test_is_exploited_returns_true_for_kev_cve(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()

        assert client.is_exploited("CVE-2021-44228") is True

    @pytest.mark.asyncio
    async def test_is_exploited_returns_false_for_unknown_cve(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()

        assert client.is_exploited("CVE-9999-9999") is False

    @pytest.mark.asyncio
    async def test_get_entry_returns_entry_for_known_cve(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()

        entry = client.get_entry("CVE-2021-44228")
        assert entry is not None
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.product == "Log4j"
        assert entry.ransomware is True

    @pytest.mark.asyncio
    async def test_get_entry_returns_none_for_unknown_cve(self, tmp_path):
        cache_file = tmp_path / "kev_catalog.json"
        mock_http = AsyncMock()
        mock_http.get.return_value = _mock_http_response(_SAMPLE_PAYLOAD)
        mock_http.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_http):
            client = KevClient(cache_path=cache_file)
            await client.fetch_catalog()

        assert client.get_entry("CVE-9999-9999") is None


# ---------------------------------------------------------------------------
# enrich_with_kev — metadata addition
# ---------------------------------------------------------------------------

class TestEnrichWithKevMetadata:
    @pytest.mark.asyncio
    async def test_kev_cve_populates_metadata(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.CRITICAL)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].metadata["kev_exploited"] is True
        assert result[0].metadata["kev_date_added"] == "2021-12-10"
        assert result[0].metadata["kev_due_date"] == "2021-12-24"
        assert result[0].metadata["kev_ransomware"] is True

    @pytest.mark.asyncio
    async def test_non_ransomware_kev_cve_metadata(self):
        finding = _make_finding(cve="CVE-2022-30190", severity=Severity.CRITICAL)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].metadata["kev_exploited"] is True
        assert result[0].metadata["kev_ransomware"] is False


# ---------------------------------------------------------------------------
# enrich_with_kev — severity upgrade
# ---------------------------------------------------------------------------

class TestEnrichWithKevSeverityUpgrade:
    @pytest.mark.asyncio
    async def test_medium_severity_elevated_to_high(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.MEDIUM)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_low_severity_elevated_to_high(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.LOW)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_high_severity_not_changed(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.HIGH)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_critical_severity_not_changed(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.CRITICAL)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# enrich_with_kev — title prefix
# ---------------------------------------------------------------------------

class TestEnrichWithKevTitlePrefix:
    @pytest.mark.asyncio
    async def test_title_prefixed_with_cisa_kev(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.HIGH)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].title.startswith("[CISA KEV] ")

    @pytest.mark.asyncio
    async def test_title_prefix_is_idempotent(self):
        """Re-enriching the same finding should not double-prefix the title."""
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.HIGH)

        catalog = _catalog_from_payload(_SAMPLE_PAYLOAD)

        for _ in range(3):
            with patch("depfence.core.kev_enricher.KevClient") as MockClient:
                mock_instance = AsyncMock()
                mock_instance.fetch_catalog.return_value = catalog
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
                await enrich_with_kev([finding])

        assert finding.title.count("[CISA KEV]") == 1

    @pytest.mark.asyncio
    async def test_non_kev_cve_title_unchanged(self):
        finding = _make_finding(cve="CVE-9999-9999", severity=Severity.MEDIUM, title="Some vuln")

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].title == "Some vuln"


# ---------------------------------------------------------------------------
# enrich_with_kev — pass-through cases
# ---------------------------------------------------------------------------

class TestEnrichWithKevPassThrough:
    @pytest.mark.asyncio
    async def test_findings_without_cve_pass_through_unchanged(self):
        finding = _make_finding(cve=None, severity=Severity.HIGH, title="No CVE finding")

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].metadata == {}
        assert result[0].title == "No CVE finding"
        assert result[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_empty_findings_list_returns_empty(self):
        result = await enrich_with_kev([])
        assert result == []

    @pytest.mark.asyncio
    async def test_mixed_kev_and_non_kev_findings(self):
        kev_finding = _make_finding(cve="CVE-2021-44228", severity=Severity.MEDIUM)
        non_kev_finding = _make_finding(cve="CVE-9999-9999", severity=Severity.MEDIUM, title="Not in KEV")
        no_cve_finding = _make_finding(cve=None, severity=Severity.LOW, title="No CVE")

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([kev_finding, non_kev_finding, no_cve_finding])

        # KEV finding: elevated severity, metadata set, prefixed title
        assert result[0].severity == Severity.HIGH
        assert result[0].metadata.get("kev_exploited") is True
        assert result[0].title.startswith("[CISA KEV] ")

        # Non-KEV CVE finding: unchanged
        assert result[1].severity == Severity.MEDIUM
        assert result[1].metadata == {}
        assert result[1].title == "Not in KEV"

        # No-CVE finding: completely unchanged
        assert result[2].severity == Severity.LOW
        assert result[2].metadata == {}
        assert result[2].title == "No CVE"

    @pytest.mark.asyncio
    async def test_findings_without_cve_skip_kev_fetch_entirely(self):
        """When no findings have a CVE, KevClient should never be instantiated."""
        finding = _make_finding(cve=None)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            result = await enrich_with_kev([finding])

        MockClient.assert_not_called()
        assert result[0].metadata == {}


# ---------------------------------------------------------------------------
# enrich_with_kev — ransomware flag
# ---------------------------------------------------------------------------

class TestEnrichWithKevRansomware:
    @pytest.mark.asyncio
    async def test_ransomware_flag_set_true_for_known(self):
        finding = _make_finding(cve="CVE-2021-44228", severity=Severity.CRITICAL)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].metadata["kev_ransomware"] is True

    @pytest.mark.asyncio
    async def test_ransomware_flag_set_false_for_unknown(self):
        finding = _make_finding(cve="CVE-2022-30190", severity=Severity.CRITICAL)

        with patch("depfence.core.kev_enricher.KevClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.fetch_catalog.return_value = _catalog_from_payload(_SAMPLE_PAYLOAD)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_with_kev([finding])

        assert result[0].metadata["kev_ransomware"] is False
