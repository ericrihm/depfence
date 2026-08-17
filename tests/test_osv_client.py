"""Tests for OSV.dev client (unit tests with mocked HTTP)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.osv_client import OsvClient, OsvVulnerability, _parse_vuln


@pytest.fixture
def client():
    return OsvClient(timeout=5.0)


class TestOsvVulnerability:
    def test_dataclass_creation(self):
        vuln = OsvVulnerability(
            id="GHSA-xxxx-yyyy-zzzz",
            summary="Test vulnerability",
            severity="HIGH",
            affected_versions=["1.0.0", "1.1.0"],
            fixed_version="1.2.0",
            references=["https://example.com"],
            published="2024-01-01",
        )
        assert vuln.id == "GHSA-xxxx-yyyy-zzzz"
        assert vuln.severity == "HIGH"
        assert vuln.fixed_version == "1.2.0"


class TestEcosystemMapping:
    def test_known_ecosystems(self):
        from depfence.core.osv_client import _ECOSYSTEM_MAP
        assert _ECOSYSTEM_MAP["pypi"] == "PyPI"
        assert _ECOSYSTEM_MAP["npm"] == "npm"
        assert _ECOSYSTEM_MAP["maven"] == "Maven"


class TestParseVuln:
    def test_basic_parsing(self):
        raw = {
            "id": "GHSA-test-1234",
            "summary": "Prototype pollution in lodash",
            "severity": [],
            "affected": [
                {
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                    "versions": ["4.17.20"],
                }
            ],
            "references": [{"url": "https://github.com/lodash/lodash/issues/1234"}],
            "published": "2024-01-15T00:00:00Z",
        }
        vuln = _parse_vuln(raw)
        assert vuln.id == "GHSA-test-1234"
        assert vuln.fixed_version == "4.17.21"
        assert "https://github.com/lodash/lodash/issues/1234" in vuln.references

    def test_severity_from_database_specific(self):
        raw = {
            "id": "TEST-001",
            "summary": "Test",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [],
            "references": [],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        assert vuln.severity == "CRITICAL"

    def test_no_fixed_version(self):
        raw = {
            "id": "TEST-002",
            "summary": "No fix",
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
            "references": [],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        assert vuln.fixed_version is None


class TestQueryPackage:
    @pytest.mark.asyncio
    async def test_returns_empty_on_network_error(self, client):
        """Network errors should not propagate — return empty list."""
        # The client creates its own httpx.AsyncClient; mock the whole class
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = Exception("Network error")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.query_package("npm", "lodash", "4.17.20")
            assert result == []


class TestQueryBatchTruth:
    @staticmethod
    def _response(body):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = body
        response.raise_for_status.return_value = None
        return response

    @pytest.mark.asyncio
    async def test_hydrates_ids_paginates_and_preserves_schema_fields(self):
        batch = self._response(
            {
                "results": [
                    {
                        "vulns": [{"id": "OSV-ONE", "modified": "2026-01-01T00:00:00Z"}],
                        "next_page_token": "page-2",
                    }
                ]
            }
        )
        page = self._response({"results": [{"vulns": [{"id": "OSV-TWO"}]}]})
        full_one = self._response(
            {
                "id": "OSV-ONE",
                "summary": "Complete advisory",
                "published": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "aliases": ["CVE-2026-0001"],
                "withdrawn": "2026-02-01T00:00:00Z",
                "severity": [
                    {
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "base_score": 9.3,
                        "source": "security@example.test",
                    }
                ],
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "Exact_Name"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                            }
                        ],
                    }
                ],
            }
        )
        full_two = self._response(
            {
                "id": "OSV-TWO",
                "modified": "2026-01-03T00:00:00Z",
                "summary": "Second advisory",
                "affected": [],
                "severity": [],
            }
        )

        transport = AsyncMock()
        transport.post = AsyncMock(side_effect=[batch, page])
        transport.get = AsyncMock(side_effect=[full_one, full_two])
        transport.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=transport):
            result = await OsvClient(max_concurrency=2).query_batch(
                [{"ecosystem": "pypi", "name": "Exact_Name", "version": "1.0.0"}]
            )

        vulns = result["pypi:Exact_Name@1.0.0"]
        assert [vuln.id for vuln in vulns] == ["OSV-ONE", "OSV-TWO"]
        assert vulns[0].aliases == ["CVE-2026-0001"]
        assert vulns[0].withdrawn == "2026-02-01T00:00:00Z"
        assert vulns[0].fixed_versions == ["2.0.0"]
        assert vulns[0].affected[0]["package"] == {
            "ecosystem": "PyPI",
            "name": "Exact_Name",
        }
        assert vulns[0].cvss == [
            {
                "version": "CVSS_V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "source": "security@example.test",
                "base_score": 9.3,
            }
        ]
        assert (
            transport.post.await_args_list[1].kwargs["json"]["queries"][0]["page_token"]
            == "page-2"
        )

    @pytest.mark.asyncio
    async def test_malformed_batch_is_incomplete_not_clean(self):
        transport = AsyncMock()
        transport.post.return_value = self._response({"results": []})
        transport.aclose = AsyncMock()
        client = OsvClient()

        with patch("httpx.AsyncClient", return_value=transport):
            result = await client.query_batch([{"ecosystem": "npm", "name": "lodash"}])

        assert result == {"npm:lodash": []}
        assert client.last_error is not None
        assert "one result per query" in client.last_error


class TestGetVulnerability:
    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, client):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = Exception("404")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_vulnerability("NONEXISTENT")
            assert result is None
