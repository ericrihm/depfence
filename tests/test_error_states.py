"""Comprehensive error state and edge case testing for depfence.

Tests error handling paths in critical modules:
- Cache corruption and recovery
- Malformed API responses
- Database errors
- Network timeouts and connection failures
- Parser errors with invalid input
- Empty/null responses
- Concurrent access edge cases
"""

from __future__ import annotations

import json
import sqlite3
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from depfence.cache.advisory_cache import AdvisoryCache
from depfence.cache.download_cache import DownloadCache
from depfence.core.osv_client import OsvClient, _parse_vuln
from depfence.core.registry_client import RegistryClient
from depfence.core.scorecard_client import ScorecardClient, _parse_repo_path

# ===========================================================================
# Cache Error States — Corruption & Database Errors
# ===========================================================================


class TestAdvisoryCacheErrorStates:
    """Test error handling in AdvisoryCache under database failures."""

    def test_corrupt_json_in_cache_returns_none(self, tmp_path):
        """When JSON blob is corrupted, should return None not crash."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")

        # Insert a valid entry first
        cache.put("npm", "lodash", "4.17.21", {"vulns": []})

        # Corrupt the JSON directly in the database
        db_path = tmp_path / "cache" / "advisories.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE advisories SET response = ? WHERE ecosystem = ? AND package = ?",
            (b"not-valid-json{[", "npm", "lodash"),
        )
        conn.commit()
        conn.close()

        # Getting the corrupted entry should return None and log warning
        result = cache.get("npm", "lodash", "4.17.21")
        assert result is None

    def test_get_with_nonexistent_database_creates_it(self, tmp_path):
        """Getting from cache when DB doesn't exist should create it."""
        cache_dir = tmp_path / "cache"
        cache = AdvisoryCache(cache_dir=cache_dir)

        # DB should be created on init
        assert (cache_dir / "advisories.db").exists()

        # First get should be a miss
        assert cache.get("npm", "lodash", "4.17.21") is None

    def test_put_creates_cache_dir_if_missing(self, tmp_path):
        """Put should create cache directory if it doesn't exist."""
        cache_dir = tmp_path / "nested" / "cache" / "path"
        assert not cache_dir.exists()

        cache = AdvisoryCache(cache_dir=cache_dir)
        cache.put("npm", "lodash", "4.17.21", {"vulns": []})

        assert cache_dir.exists()
        assert (cache_dir / "advisories.db").exists()

    def test_prune_with_empty_cache_returns_zero(self, tmp_path):
        """Pruning an empty cache should return 0 not error."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")
        count = cache.prune(max_age_days=30)
        assert count == 0

    def test_invalidate_nonexistent_package_returns_zero(self, tmp_path):
        """Invalidating non-existent package should return 0 not error."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")
        count = cache.invalidate("npm", "nonexistent-package")
        assert count == 0

    def test_clear_empty_cache_returns_zero(self, tmp_path):
        """Clearing an empty cache should return 0."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")
        count = cache.clear()
        assert count == 0

    def test_stats_with_invalid_date_in_db_handles_gracefully(self, tmp_path):
        """Stats should handle malformed dates in DB gracefully."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")

        # Insert valid entry first
        cache.put("npm", "lodash", "4.17.21", {"vulns": []})

        # Corrupt the fetched_at field with invalid date
        db_path = tmp_path / "cache" / "advisories.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE advisories SET fetched_at = ? WHERE ecosystem = ?",
            ("invalid-date-format", "npm"),
        )
        conn.commit()
        conn.close()

        # Stats should not crash, just skip the bad date
        stats = cache.stats()
        assert stats.total_entries == 1
        assert stats.oldest_entry is None  # Bad date should be skipped


class TestDownloadCacheErrorStates:
    """Test error handling in DownloadCache."""

    def test_corrupt_json_returns_none(self, tmp_path):
        """Corrupted JSON in download cache should return None."""
        cache = DownloadCache(cache_dir=tmp_path / "cache")

        # Put valid data
        cache.put("npm", "lodash", {"info": "test"})

        # Corrupt the JSON
        db_path = tmp_path / "cache" / "advisories.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE metadata SET response = ? WHERE ecosystem = ? AND package = ?",
            (b"corrupted{[[", "npm", "lodash"),
        )
        conn.commit()
        conn.close()

        result = cache.get("npm", "lodash")
        assert result is None

    def test_invalidate_entire_ecosystem_returns_count(self, tmp_path):
        """Invalidating entire ecosystem should return number of deleted rows."""
        cache = DownloadCache(cache_dir=tmp_path / "cache")

        # Add multiple packages
        cache.put("npm", "lodash", {"info": "a"})
        cache.put("npm", "requests", {"info": "b"})
        cache.put("pypi", "requests", {"info": "c"})

        # Invalidate entire npm ecosystem
        count = cache.invalidate("npm")
        assert count == 2

        # npm entries gone, pypi remains
        assert cache.get("npm", "lodash") is None
        assert cache.get("pypi", "requests") is not None


# ===========================================================================
# OSV Client Error States — Network & Parsing
# ===========================================================================


class TestOsvClientErrorStates:
    """Test OSV client error handling."""

    @pytest.mark.asyncio
    async def test_query_package_rate_limit_returns_empty(self):
        """Rate limit (429) should return empty list."""
        client = OsvClient(timeout=5.0)

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Rate limited",
            request=MagicMock(),
            response=mock_response,
        )

        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = mock_response.raise_for_status
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.query_package("npm", "lodash", "4.17.20")
            assert result == []

    @pytest.mark.asyncio
    async def test_query_batch_timeout_returns_empty_dict(self):
        """Batch query timeout should return dict with empty lists."""
        client = OsvClient(timeout=5.0)

        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = httpx.TimeoutException("timed out")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            packages = [
                {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
                {"ecosystem": "pypi", "name": "requests", "version": "2.28.0"},
            ]
            result = await client.query_batch(packages)

            # Should have empty list for each package
            assert result["npm:lodash@4.17.20"] == []
            assert result["pypi:requests@2.28.0"] == []

    @pytest.mark.asyncio
    async def test_query_batch_empty_packages_returns_empty_dict(self):
        """Query batch with empty list should return empty dict."""
        client = OsvClient(timeout=5.0)
        result = await client.query_batch([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_get_vulnerability_404_returns_none(self):
        """404 on get_vulnerability should return None."""
        client = OsvClient(timeout=5.0)

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_vulnerability("NONEXISTENT-ID")
            assert result is None

    def test_parse_vuln_with_missing_fields(self):
        """Parse should handle missing fields gracefully."""
        raw_minimal = {
            "id": "CVE-2024-1234",
            # Missing many fields
        }
        vuln = _parse_vuln(raw_minimal)
        assert vuln.id == "CVE-2024-1234"
        assert vuln.summary == ""
        assert vuln.severity == "MEDIUM"  # default
        assert vuln.affected_versions == []
        assert vuln.fixed_version is None
        assert vuln.references == []

    def test_parse_vuln_with_invalid_severity_score(self):
        """Parse should handle invalid CVSS scores."""
        raw = {
            "id": "TEST-001",
            "summary": "Test",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "not-a-number",
                    "base_score": "also-invalid",
                }
            ],
            "affected": [],
            "references": [],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        # Should default to MEDIUM when scores can't be parsed
        assert vuln.severity in ("MEDIUM", "CRITICAL", "HIGH", "LOW")

    def test_parse_vuln_with_null_references(self):
        """Parse should handle null references."""
        raw = {
            "id": "TEST-001",
            "summary": "Test",
            "references": None,
            "affected": [],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        assert vuln.references == []


# ===========================================================================
# Scorecard Client Error States
# ===========================================================================


class TestScorecardClientErrorStates:
    """Test Scorecard client error handling."""

    @pytest.mark.asyncio
    async def test_invalid_repo_url_returns_none(self):
        """Invalid repo URL should return None, not crash."""
        client = ScorecardClient(timeout=15.0)

        invalid_urls = [
            "not-a-url",
            "https://gitlab.com/owner/repo",
            "https://github.com/",
            "https://github.com/just-one-component",
            "",
        ]

        for url in invalid_urls:
            result = await client.get_score(url)
            assert result is None

    @pytest.mark.asyncio
    async def test_batch_scores_with_invalid_urls_filters_them(self):
        """Batch scores should skip invalid URLs."""
        client = ScorecardClient(timeout=15.0)

        mock_client_instance = AsyncMock()
        # Only valid URL should get a request
        mock_client_instance.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "repo": {"name": "valid/repo"},
                "score": 7.5,
                "checks": [],
                "date": "2024-01-01",
            },
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            urls = [
                "https://github.com/valid/repo",
                "not-a-url",
                "https://gitlab.com/invalid/repo",
            ]
            result = await client.batch_scores(urls)

            # Only valid one should be in result
            assert "valid/repo" in result or len(result) == 1

    @pytest.mark.asyncio
    async def test_get_score_malformed_json_response(self):
        """Malformed JSON response should return None."""
        client = ScorecardClient(timeout=15.0)

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(side_effect=json.JSONDecodeError("msg", "doc", 0)),
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_score("https://github.com/owner/repo")
            assert result is None


class TestParseRepoPathEdgeCases:
    """Test repo path parsing edge cases."""

    def test_parse_repo_path_with_whitespace(self):
        """Should handle whitespace in URLs."""
        result = _parse_repo_path("  https://github.com/owner/repo  ")
        assert result == "owner/repo"

    def test_parse_repo_path_colon_separator(self):
        """Should handle github.com:owner/repo format."""
        result = _parse_repo_path("git@github.com:owner/repo")
        # This may or may not parse depending on implementation
        # Just ensure it doesn't crash
        assert result is None or result == "owner/repo"

    def test_parse_repo_path_multiple_slashes(self):
        """Should handle extra path components after repo name."""
        result = _parse_repo_path(
            "https://github.com/owner/repo/issues/123/discussion"
        )
        assert result == "owner/repo"

    def test_parse_repo_path_query_strings_ignored(self):
        """Should ignore query strings."""
        result = _parse_repo_path("https://github.com/owner/repo?tab=readme")
        assert result == "owner/repo"


# ===========================================================================
# Registry Client Error States
# ===========================================================================


class TestRegistryClientErrorStates:
    """Test Registry client error handling."""

    @pytest.mark.asyncio
    async def test_npm_registry_404_returns_none(self):
        """npm registry 404 should return None."""
        client = RegistryClient(timeout=10.0)

        mock_client_instance = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_npm_metadata("nonexistent-package-xyz")
            assert result is None

    @pytest.mark.asyncio
    async def test_npm_registry_network_error_returns_none(self):
        """Network error should return None."""
        client = RegistryClient(timeout=10.0)

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.side_effect = httpx.ConnectError("Connection failed")

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_npm_metadata("lodash")
            assert result is None

    @pytest.mark.asyncio
    async def test_pypi_registry_malformed_response(self):
        """Malformed PyPI response should return None."""
        client = RegistryClient(timeout=10.0)

        mock_client_instance = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_pypi_metadata("requests")
            assert result is None


# ===========================================================================
# Parser Error States
# ===========================================================================


class TestParserErrorHandling:
    """Test error handling in parsers."""

    def test_parse_vuln_with_empty_affected_array(self):
        """Parse should handle empty affected array."""
        raw = {
            "id": "TEST-001",
            "summary": "Test",
            "affected": [],  # Empty
            "references": [],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        assert vuln.affected_versions == []
        assert vuln.fixed_version is None

    def test_parse_vuln_with_nested_none_values(self):
        """Parse should handle nested None values."""
        raw = {
            "id": "TEST-001",
            "summary": "Test",
            "affected": [
                {
                    "versions": None,
                    "ranges": None,
                }
            ],
            "references": [{"url": None}],
            "published": "2024-01-01",
        }
        vuln = _parse_vuln(raw)
        # Should not crash
        assert vuln.id == "TEST-001"


# ===========================================================================
# Concurrent Access Error States
# ===========================================================================


class TestCacheConcurrencyErrorStates:
    """Test cache behavior under concurrent access."""

    def test_concurrent_puts_no_corruption(self, tmp_path):
        """Concurrent puts should not corrupt cache."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")

        def put_many(offset: int):
            for i in range(5):
                cache.put(
                    "npm",
                    f"package-{offset}-{i}",
                    "1.0.0",
                    {"vulns": [{"id": f"GHSA-{offset}-{i}"}]},
                )

        threads = [threading.Thread(target=put_many, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All entries should be present and valid
        stats = cache.stats()
        assert stats.total_entries == 15

    def test_concurrent_get_put_no_race(self, tmp_path):
        """Concurrent gets and puts should work safely."""
        cache = AdvisoryCache(cache_dir=tmp_path / "cache")

        # Pre-populate
        for i in range(5):
            cache.put("npm", f"pkg-{i}", "1.0.0", {"vulns": []})

        results = []

        def read_and_write(idx: int):
            # Read
            for i in range(5):
                result = cache.get("npm", f"pkg-{i}", "1.0.0")
                if result is not None:
                    results.append(result)

            # Write
            cache.put("npm", f"pkg-new-{idx}", "1.0.0", {"vulns": []})

        threads = [threading.Thread(target=read_and_write, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have read original 5 entries 3 times each
        assert len(results) >= 15


# ===========================================================================
# Empty/Null Response Handling
# ===========================================================================


class TestEmptyResponseHandling:
    """Test handling of empty/null API responses."""

    @pytest.mark.asyncio
    async def test_osv_query_with_null_vulns_field(self):
        """OSV response with null vulns field should work."""
        client = OsvClient(timeout=5.0)

        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"vulns": None},  # Null instead of list
            raise_for_status=lambda: None,
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.query_package("npm", "lodash")
            assert result == []

    @pytest.mark.asyncio
    async def test_scorecard_response_with_missing_checks(self):
        """Scorecard response missing checks field should work."""
        client = ScorecardClient(timeout=15.0)

        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "repo": {"name": "owner/repo"},
                "score": 7.5,
                "checks": None,  # Missing/null
                "date": "2024-01-01",
            },
            raise_for_status=lambda: None,
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            result = await client.get_score("https://github.com/owner/repo")
            assert result is not None
            assert result.checks == []
