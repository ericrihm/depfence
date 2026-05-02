"""Tests for EPSS client and enricher (unit tests with mocked HTTP)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.epss_client import EpssClient, EpssScore
from depfence.core.epss_enricher import enrich_findings, _epss_priority
from depfence.core.models import Finding, FindingType, PackageId, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    cve: str | None = None,
    severity: Severity = Severity.HIGH,
    title: str = "Test vulnerability",
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem="pypi", name="requests", version="2.28.0"),
        title=title,
        detail="Detail text.",
        cve=cve,
    )


def _mock_epss_response(entries: list[dict]) -> MagicMock:
    """Build a mock httpx response returning the given EPSS data entries."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"status": "OK", "data": entries}
    return mock_resp


# ---------------------------------------------------------------------------
# EpssScore dataclass
# ---------------------------------------------------------------------------

class TestEpssScore:
    def test_fields(self):
        s = EpssScore(cve="CVE-2024-1234", score=0.234, percentile=0.567)
        assert s.cve == "CVE-2024-1234"
        assert s.score == pytest.approx(0.234)
        assert s.percentile == pytest.approx(0.567)


# ---------------------------------------------------------------------------
# EpssClient — basic fetching
# ---------------------------------------------------------------------------

class TestEpssClientGetScores:
    @pytest.mark.asyncio
    async def test_single_cve_parsed_correctly(self):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response(
            [{"cve": "CVE-2024-1234", "epss": "0.00234", "percentile": "0.567"}]
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(["CVE-2024-1234"])

        assert "CVE-2024-1234" in result
        score = result["CVE-2024-1234"]
        assert score.score == pytest.approx(0.00234)
        assert score.percentile == pytest.approx(0.567)

    @pytest.mark.asyncio
    async def test_empty_list_returns_empty_dict(self):
        client = EpssClient()
        result = await client.get_scores([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_cve_not_in_response_omitted(self):
        """CVEs absent from the API response should not appear in the result."""
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response([])
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(["CVE-2099-9999"])

        assert result == {}

    @pytest.mark.asyncio
    async def test_duplicate_cves_deduplicated(self):
        """Duplicate CVE IDs should result in only one API call entry."""
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response(
            [{"cve": "CVE-2024-1234", "epss": "0.1", "percentile": "0.8"}]
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(
                ["CVE-2024-1234", "CVE-2024-1234", "CVE-2024-1234"]
            )

        # Only one GET call should have been made
        assert mock_client_instance.get.call_count == 1
        assert "CVE-2024-1234" in result


# ---------------------------------------------------------------------------
# EpssClient — batch splitting
# ---------------------------------------------------------------------------

class TestEpssClientBatching:
    @pytest.mark.asyncio
    async def test_more_than_30_cves_split_into_multiple_requests(self):
        """31 CVEs should produce 2 GET requests (30 + 1)."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(31)]

        mock_client_instance = AsyncMock()
        # Return one matching score per batch call
        mock_client_instance.get.return_value = _mock_epss_response(
            [{"cve": cve_ids[0], "epss": "0.05", "percentile": "0.6"}]
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            await client.get_scores(cve_ids)

        assert mock_client_instance.get.call_count == 2

    @pytest.mark.asyncio
    async def test_exactly_30_cves_makes_one_request(self):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(30)]

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response([])
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            await client.get_scores(cve_ids)

        assert mock_client_instance.get.call_count == 1

    @pytest.mark.asyncio
    async def test_60_cves_split_into_two_batches(self):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(60)]

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response([])
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            await client.get_scores(cve_ids)

        assert mock_client_instance.get.call_count == 2


# ---------------------------------------------------------------------------
# EpssClient — in-memory cache
# ---------------------------------------------------------------------------

class TestEpssClientCache:
    @pytest.mark.asyncio
    async def test_cached_results_not_refetched(self):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_epss_response(
            [{"cve": "CVE-2024-1234", "epss": "0.1", "percentile": "0.8"}]
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result1 = await client.get_scores(["CVE-2024-1234"])
            result2 = await client.get_scores(["CVE-2024-1234"])

        # Second call should have served from cache — only 1 GET
        assert mock_client_instance.get.call_count == 1
        assert result1 == result2


# ---------------------------------------------------------------------------
# EpssClient — graceful degradation
# ---------------------------------------------------------------------------

class TestEpssClientGracefulDegradation:
    @pytest.mark.asyncio
    async def test_timeout_returns_empty_dict(self):
        import httpx

        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("timed out")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(["CVE-2024-1234"])

        assert result == {}

    @pytest.mark.asyncio
    async def test_http_error_returns_empty_dict(self):
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 503

        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.HTTPStatusError(
            "Service Unavailable", request=MagicMock(), response=mock_response
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(["CVE-2024-1234"])

        assert result == {}

    @pytest.mark.asyncio
    async def test_generic_exception_returns_empty_dict(self):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = RuntimeError("unexpected")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(["CVE-2024-1234"])

        assert result == {}

    @pytest.mark.asyncio
    async def test_partial_batch_failure_returns_successful_batches(self):
        """When one batch fails, others should still succeed."""
        import httpx

        cve_ids = [f"CVE-2024-{i:04d}" for i in range(31)]
        # First batch (30 CVEs) succeeds, second batch (1 CVE) times out
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = [
            _mock_epss_response(
                [{"cve": cve_ids[0], "epss": "0.05", "percentile": "0.6"}]
            ),
            httpx.TimeoutException("timed out"),
        ]
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = EpssClient()
            result = await client.get_scores(cve_ids)

        # At least the first batch result should be present
        assert cve_ids[0] in result


# ---------------------------------------------------------------------------
# Priority mapping
# ---------------------------------------------------------------------------

class TestEpssPriorityMapping:
    def test_above_90_is_critical(self):
        assert _epss_priority(0.91) == "critical"

    def test_exactly_90_is_not_critical(self):
        # strictly greater-than 0.9
        assert _epss_priority(0.9) == "high"

    def test_above_70_is_high(self):
        assert _epss_priority(0.75) == "high"

    def test_above_40_is_medium(self):
        assert _epss_priority(0.55) == "medium"

    def test_at_or_below_40_is_low(self):
        assert _epss_priority(0.4) == "low"
        assert _epss_priority(0.1) == "low"
        assert _epss_priority(0.0) == "low"


# ---------------------------------------------------------------------------
# enrich_findings
# ---------------------------------------------------------------------------

class TestEnrichFindings:
    @pytest.mark.asyncio
    async def test_finding_metadata_populated(self):
        finding = _make_finding(cve="CVE-2024-1234", severity=Severity.HIGH)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {
                "CVE-2024-1234": EpssScore(
                    cve="CVE-2024-1234", score=0.8, percentile=0.95
                )
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert result[0].metadata["epss_score"] == pytest.approx(0.8)
        assert result[0].metadata["epss_percentile"] == pytest.approx(0.95)
        assert result[0].metadata["epss_priority"] == "critical"

    @pytest.mark.asyncio
    async def test_medium_severity_high_score_annotates_title(self):
        finding = _make_finding(cve="CVE-2024-5678", severity=Severity.MEDIUM)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {
                "CVE-2024-5678": EpssScore(
                    cve="CVE-2024-5678", score=0.75, percentile=0.85
                )
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert result[0].title.startswith("[Active Exploitation Risk]")

    @pytest.mark.asyncio
    async def test_medium_severity_low_score_no_annotation(self):
        finding = _make_finding(cve="CVE-2024-5678", severity=Severity.MEDIUM)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {
                "CVE-2024-5678": EpssScore(
                    cve="CVE-2024-5678", score=0.3, percentile=0.5
                )
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert not result[0].title.startswith("[Active Exploitation Risk]")

    @pytest.mark.asyncio
    async def test_high_severity_high_score_no_annotation(self):
        """Annotation only applies when severity is exactly MEDIUM."""
        finding = _make_finding(cve="CVE-2024-1111", severity=Severity.HIGH)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {
                "CVE-2024-1111": EpssScore(
                    cve="CVE-2024-1111", score=0.99, percentile=0.99
                )
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert not result[0].title.startswith("[Active Exploitation Risk]")

    @pytest.mark.asyncio
    async def test_annotation_not_duplicated_on_reenrichment(self):
        """Re-running enrich_findings should not double-prefix the title."""
        finding = _make_finding(cve="CVE-2024-5678", severity=Severity.MEDIUM)

        epss_score = EpssScore(cve="CVE-2024-5678", score=0.75, percentile=0.85)

        for _ in range(2):
            with patch(
                "depfence.core.epss_enricher.EpssClient"
            ) as MockClient:
                mock_instance = AsyncMock()
                mock_instance.get_scores.return_value = {"CVE-2024-5678": epss_score}
                MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
                MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
                await enrich_findings([finding])

        assert finding.title.count("[Active Exploitation Risk]") == 1

    @pytest.mark.asyncio
    async def test_findings_without_cve_pass_through_unchanged(self):
        no_cve = _make_finding(cve=None, severity=Severity.HIGH)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([no_cve])

        assert result[0].metadata == {}
        assert result[0].title == "Test vulnerability"

    @pytest.mark.asyncio
    async def test_empty_findings_list_returns_empty(self):
        result = await enrich_findings([])
        assert result == []

    @pytest.mark.asyncio
    async def test_mixed_cve_and_no_cve_findings(self):
        with_cve = _make_finding(cve="CVE-2024-1234", severity=Severity.HIGH)
        without_cve = _make_finding(cve=None, severity=Severity.LOW)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {
                "CVE-2024-1234": EpssScore(
                    cve="CVE-2024-1234", score=0.1, percentile=0.3
                )
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([with_cve, without_cve])

        assert "epss_score" in result[0].metadata
        assert result[1].metadata == {}

    @pytest.mark.asyncio
    async def test_cve_not_in_epss_response_leaves_metadata_empty(self):
        """A CVE absent from the EPSS API (unknown CVE) should not touch metadata."""
        finding = _make_finding(cve="CVE-9999-9999", severity=Severity.HIGH)

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert result[0].metadata == {}

    @pytest.mark.asyncio
    async def test_epss_api_failure_leaves_findings_unchanged(self):
        """If the EPSS client returns empty (due to error), findings pass through."""
        finding = _make_finding(cve="CVE-2024-1234", severity=Severity.MEDIUM)
        original_title = finding.title

        with patch(
            "depfence.core.epss_enricher.EpssClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get_scores.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await enrich_findings([finding])

        assert result[0].title == original_title
        assert result[0].metadata == {}
