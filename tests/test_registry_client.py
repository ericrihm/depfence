"""Tests for multi-registry package intelligence client."""

from unittest.mock import AsyncMock, patch

import pytest

from depfence.core.registry_client import PackageMetadata, RegistryClient


@pytest.fixture
def client():
    return RegistryClient(timeout=5.0)


class TestPackageMetadata:
    def test_creation(self):
        meta = PackageMetadata(
            name="express",
            ecosystem="npm",
            version="4.18.2",
            maintainers=["dougwilson"],
            weekly_downloads=25000000,
        )
        assert meta.name == "express"
        assert meta.weekly_downloads == 25000000


class TestNpmMetadata:
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, client):
        mock_resp = AsyncMock()
        mock_resp.status_code = 404

        mock_http_client = AsyncMock()
        mock_http_client.get = AsyncMock(return_value=mock_resp)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_http_client):
            result = await client.get_npm_metadata("nonexistent-pkg-xyz")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, client):
        mock_http_client = AsyncMock()
        mock_http_client.get = AsyncMock(side_effect=Exception("timeout"))
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_http_client):
            result = await client.get_npm_metadata("express")
            assert result is None


class TestPyPIMetadata:
    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, client):
        mock_resp = AsyncMock()
        mock_resp.status_code = 404

        mock_http_client = AsyncMock()
        mock_http_client.get = AsyncMock(return_value=mock_resp)
        mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_http_client.__aexit__ = AsyncMock(return_value=None)

        with patch("httpx.AsyncClient", return_value=mock_http_client):
            result = await client.get_pypi_metadata("nonexistent-pkg")
            assert result is None


class TestGetMetadata:
    @pytest.mark.asyncio
    async def test_routes_to_npm(self, client):
        with patch.object(client, "get_npm_metadata", new_callable=AsyncMock, return_value=None) as mock:
            await client.get_metadata("npm", "express")
            mock.assert_called_once_with("express")

    @pytest.mark.asyncio
    async def test_routes_to_pypi(self, client):
        with patch.object(client, "get_pypi_metadata", new_callable=AsyncMock, return_value=None) as mock:
            await client.get_metadata("pypi", "requests")
            mock.assert_called_once_with("requests")

    @pytest.mark.asyncio
    async def test_unknown_ecosystem_returns_none(self, client):
        result = await client.get_metadata("unknown", "pkg")
        assert result is None
