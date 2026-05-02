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


class TestGetVulnerability:
    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, client):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = Exception("404")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_vulnerability("NONEXISTENT")
            assert result is None
