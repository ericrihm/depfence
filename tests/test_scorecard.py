"""Tests for OpenSSF Scorecard client and enricher (unit tests with mocked HTTP)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity
from depfence.core.scorecard_client import (
    ScorecardCheck,
    ScorecardClient,
    ScorecardResult,
    _parse_repo_path,
)
from depfence.core.scorecard_enricher import enrich_with_scorecard, scorecard_findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_response(
    score: float = 7.5,
    repo_name: str = "owner/repo",
    date: str = "2024-01-01",
    checks: list[dict] | None = None,
) -> dict:
    """Build a minimal Scorecard API response dict."""
    if checks is None:
        checks = [
            {"name": "Code-Review", "score": 8, "reason": "Found 8/10 code-reviewed changesets", "details": []},
            {"name": "Maintained", "score": 9, "reason": "30 commits in the last 90 days", "details": []},
            {"name": "Vulnerabilities", "score": 10, "reason": "0 existing vulnerabilities detected", "details": []},
        ]
    return {
        "date": date,
        "repo": {"name": repo_name, "commit": "abc123"},
        "scorecard": {"version": "v4.13.1", "commit": "def456"},
        "score": score,
        "checks": checks,
    }


def _mock_http_response(data: dict, status_code: int = 200) -> MagicMock:
    """Build a mock httpx response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = data
    return mock_resp


def _mock_404_response() -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.raise_for_status = MagicMock(side_effect=Exception("404"))
    return mock_resp


def _make_package_meta(
    name: str = "requests",
    ecosystem: str = "pypi",
    version: str = "2.28.0",
    repository: str = "https://github.com/psf/requests",
) -> PackageMeta:
    return PackageMeta(
        pkg=PackageId(ecosystem=ecosystem, name=name, version=version),
        repository=repository,
    )


# ---------------------------------------------------------------------------
# _parse_repo_path — URL parsing
# ---------------------------------------------------------------------------

class TestParseRepoPath:
    def test_full_https_url(self):
        assert _parse_repo_path("https://github.com/psf/requests") == "psf/requests"

    def test_http_url(self):
        assert _parse_repo_path("http://github.com/psf/requests") == "psf/requests"

    def test_shorthand_no_scheme(self):
        assert _parse_repo_path("github.com/psf/requests") == "psf/requests"

    def test_git_suffix_stripped(self):
        assert _parse_repo_path("https://github.com/psf/requests.git") == "psf/requests"

    def test_shorthand_with_git_suffix(self):
        assert _parse_repo_path("github.com/psf/requests.git") == "psf/requests"

    def test_extra_path_segments_ignored(self):
        assert _parse_repo_path("https://github.com/psf/requests/tree/main") == "psf/requests"

    def test_non_github_url_returns_none(self):
        assert _parse_repo_path("https://gitlab.com/owner/repo") is None

    def test_empty_string_returns_none(self):
        assert _parse_repo_path("") is None

    def test_random_string_returns_none(self):
        assert _parse_repo_path("not-a-url") is None

    def test_preserves_case(self):
        assert _parse_repo_path("https://github.com/PyCQA/flake8") == "PyCQA/flake8"


# ---------------------------------------------------------------------------
# ScorecardCheck and ScorecardResult dataclasses
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_scorecard_check_fields(self):
        check = ScorecardCheck(name="Code-Review", score=8, reason="looks good")
        assert check.name == "Code-Review"
        assert check.score == 8
        assert check.reason == "looks good"

    def test_scorecard_result_fields(self):
        checks = [ScorecardCheck(name="Maintained", score=9, reason="active")]
        result = ScorecardResult(
            repo="owner/repo",
            overall_score=7.5,
            checks=checks,
            date="2024-01-01",
        )
        assert result.repo == "owner/repo"
        assert result.overall_score == pytest.approx(7.5)
        assert len(result.checks) == 1
        assert result.date == "2024-01-01"


# ---------------------------------------------------------------------------
# ScorecardClient.get_score — successful fetch
# ---------------------------------------------------------------------------

class TestScorecardClientGetScore:
    @pytest.mark.asyncio
    async def test_successful_fetch_returns_result(self):
        api_data = _make_api_response(score=7.5, repo_name="psf/requests")
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_http_response(api_data)
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/psf/requests")

        assert result is not None
        assert result.overall_score == pytest.approx(7.5)
        assert result.repo == "psf/requests"
        assert result.date == "2024-01-01"

    @pytest.mark.asyncio
    async def test_checks_are_parsed(self):
        checks_data = [
            {"name": "Code-Review", "score": 8, "reason": "good", "details": []},
            {"name": "Maintained", "score": -1, "reason": "not applicable", "details": []},
            {"name": "Vulnerabilities", "score": 3, "reason": "has vulns", "details": []},
        ]
        api_data = _make_api_response(score=5.0, checks=checks_data)
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_http_response(api_data)
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("github.com/owner/repo")

        assert result is not None
        assert len(result.checks) == 3
        code_review = next(c for c in result.checks if c.name == "Code-Review")
        assert code_review.score == 8
        maintained = next(c for c in result.checks if c.name == "Maintained")
        assert maintained.score == -1  # not applicable
        vulns = next(c for c in result.checks if c.name == "Vulnerabilities")
        assert vulns.score == 3

    @pytest.mark.asyncio
    async def test_url_with_git_suffix_accepted(self):
        api_data = _make_api_response(score=6.0, repo_name="owner/repo")
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_http_response(api_data)
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/owner/repo.git")

        assert result is not None
        assert result.overall_score == pytest.approx(6.0)

    @pytest.mark.asyncio
    async def test_correct_api_url_constructed(self):
        """Verify the client calls the correct Scorecard API endpoint."""
        api_data = _make_api_response()
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_http_response(api_data)
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            await client.get_score("https://github.com/psf/requests")

        call_args = mock_client_instance.get.call_args
        called_url = call_args[0][0]
        assert "api.securityscorecards.dev" in called_url
        assert "github.com/psf/requests" in called_url


# ---------------------------------------------------------------------------
# ScorecardClient.get_score — 404 and error handling
# ---------------------------------------------------------------------------

class TestScorecardClientErrors:
    @pytest.mark.asyncio
    async def test_404_returns_none(self):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_404_response()
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/owner/nonexistent-repo")

        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        import httpx

        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("timed out")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/owner/repo")

        assert result is None

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response
        )
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/owner/repo")

        assert result is None

    @pytest.mark.asyncio
    async def test_generic_exception_returns_none(self):
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = RuntimeError("connection refused")
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://github.com/owner/repo")

        assert result is None

    @pytest.mark.asyncio
    async def test_unparseable_url_returns_none(self):
        """A non-GitHub URL should return None without making any HTTP call."""
        mock_client_instance = AsyncMock()
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            client = ScorecardClient()
            result = await client.get_score("https://gitlab.com/owner/repo")

        assert result is None
        mock_client_instance.get.assert_not_called()


# ---------------------------------------------------------------------------
# ScorecardClient — async context manager
# ---------------------------------------------------------------------------

class TestScorecardClientContextManager:
    @pytest.mark.asyncio
    async def test_context_manager_uses_shared_client(self):
        api_data = _make_api_response(score=8.0)
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = _mock_http_response(api_data)
        mock_client_instance.aclose = AsyncMock()

        with patch("httpx.AsyncClient", return_value=mock_client_instance):
            async with ScorecardClient() as client:
                r1 = await client.get_score("https://github.com/owner/repo-a")
                r2 = await client.get_score("https://github.com/owner/repo-b")

        assert r1 is not None
        assert r2 is not None
        # aclose called once on exit, not per-request
        assert mock_client_instance.aclose.call_count == 1


# ---------------------------------------------------------------------------
# ScorecardClient.batch_scores — concurrent fetching
# ---------------------------------------------------------------------------

class TestBatchScores:
    @pytest.mark.asyncio
    async def test_batch_returns_dict_keyed_by_url(self):
        api_data = _make_api_response(score=6.5)

        with patch(
            "depfence.core.scorecard_client.ScorecardClient.get_score",
            new_callable=AsyncMock,
        ) as mock_get:
            mock_get.return_value = ScorecardResult(
                repo="owner/repo", overall_score=6.5, checks=[], date="2024-01-01"
            )
            async with ScorecardClient() as client:
                results = await client.batch_scores(
                    [
                        "https://github.com/owner/repo-a",
                        "https://github.com/owner/repo-b",
                    ]
                )

        assert len(results) == 2
        assert "https://github.com/owner/repo-a" in results
        assert "https://github.com/owner/repo-b" in results

    @pytest.mark.asyncio
    async def test_batch_omits_none_results(self):
        """Repos that return None (404 / error) are omitted from the result dict."""
        async def _side_effect(url: str) -> ScorecardResult | None:
            if "good-repo" in url:
                return ScorecardResult(
                    repo="owner/good-repo",
                    overall_score=8.0,
                    checks=[],
                    date="2024-01-01",
                )
            return None

        with patch(
            "depfence.core.scorecard_client.ScorecardClient.get_score",
            new_callable=AsyncMock,
            side_effect=_side_effect,
        ):
            async with ScorecardClient() as client:
                results = await client.batch_scores(
                    [
                        "https://github.com/owner/good-repo",
                        "https://github.com/owner/bad-repo",
                    ]
                )

        assert "https://github.com/owner/good-repo" in results
        assert "https://github.com/owner/bad-repo" not in results

    @pytest.mark.asyncio
    async def test_empty_batch_returns_empty_dict(self):
        async with ScorecardClient() as client:
            results = await client.batch_scores([])
        assert results == {}

    @pytest.mark.asyncio
    async def test_batch_issues_concurrent_requests(self):
        """All URLs in the batch should be fetched (calls == len(urls))."""
        urls = [f"https://github.com/owner/repo-{i}" for i in range(5)]

        call_count = 0

        async def _side_effect(url: str) -> ScorecardResult:
            nonlocal call_count
            call_count += 1
            return ScorecardResult(
                repo=f"owner/repo-{call_count}",
                overall_score=7.0,
                checks=[],
                date="2024-01-01",
            )

        with patch(
            "depfence.core.scorecard_client.ScorecardClient.get_score",
            new_callable=AsyncMock,
            side_effect=_side_effect,
        ):
            async with ScorecardClient() as client:
                results = await client.batch_scores(urls)

        assert len(results) == 5
        assert call_count == 5


# ---------------------------------------------------------------------------
# Score interpretation helpers
# ---------------------------------------------------------------------------

class TestScoreInterpretation:
    def test_score_below_3_is_critical_risk(self):
        """Scores < 3 map to 'critical' risk level."""
        from depfence.core.scorecard_enricher import _risk_level
        assert _risk_level(0.0) == "critical"
        assert _risk_level(2.9) == "critical"

    def test_score_3_to_5_is_high_risk(self):
        from depfence.core.scorecard_enricher import _risk_level
        assert _risk_level(3.0) == "high"
        assert _risk_level(4.9) == "high"

    def test_score_5_to_7_is_medium_risk(self):
        from depfence.core.scorecard_enricher import _risk_level
        assert _risk_level(5.0) == "medium"
        assert _risk_level(6.9) == "medium"

    def test_score_7_or_above_is_good(self):
        from depfence.core.scorecard_enricher import _risk_level
        assert _risk_level(7.0) == "good"
        assert _risk_level(10.0) == "good"


# ---------------------------------------------------------------------------
# enrich_with_scorecard
# ---------------------------------------------------------------------------

class TestEnrichWithScorecard:
    @pytest.mark.asyncio
    async def test_packages_without_repo_are_skipped(self):
        packages = [
            PackageMeta(pkg=PackageId("pypi", "no-repo-pkg", "1.0.0"), repository=""),
            PackageMeta(pkg=PackageId("npm", "another-pkg", "2.0.0"), repository=""),
        ]

        with patch(
            "depfence.core.scorecard_enricher.ScorecardClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.batch_scores.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await enrich_with_scorecard(packages)

        assert results == []
        mock_instance.batch_scores.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_github_repo_urls_skipped(self):
        packages = [
            PackageMeta(
                pkg=PackageId("cargo", "serde", "1.0.0"),
                repository="https://gitlab.com/owner/serde",
            ),
        ]

        with patch(
            "depfence.core.scorecard_enricher.ScorecardClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.batch_scores.return_value = {}
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await enrich_with_scorecard(packages)

        assert results == []

    @pytest.mark.asyncio
    async def test_enriched_result_has_expected_fields(self):
        pkg_meta = _make_package_meta(
            name="requests", ecosystem="pypi", repository="https://github.com/psf/requests"
        )

        scorecard_result = ScorecardResult(
            repo="psf/requests",
            overall_score=7.5,
            checks=[
                ScorecardCheck(name="Code-Review", score=8, reason="good"),
                ScorecardCheck(name="Maintained", score=9, reason="active"),
                ScorecardCheck(name="Vulnerabilities", score=3, reason="has vulns"),
            ],
            date="2024-01-01",
        )

        with patch(
            "depfence.core.scorecard_enricher.ScorecardClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.batch_scores.return_value = {
                "https://github.com/psf/requests": scorecard_result
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await enrich_with_scorecard([pkg_meta])

        assert len(results) == 1
        entry = results[0]
        assert entry["package"] == pkg_meta.pkg
        assert entry["repo"] == "psf/requests"
        assert entry["score"] == pytest.approx(7.5)
        assert entry["risk_level"] == "good"
        # Vulnerabilities check has score 3, which is < 5 → weak
        assert any(c.name == "Vulnerabilities" for c in entry["weak_checks"])
        # Code-Review (8) and Maintained (9) are not weak
        weak_names = [c.name for c in entry["weak_checks"]]
        assert "Code-Review" not in weak_names
        assert "Maintained" not in weak_names

    @pytest.mark.asyncio
    async def test_not_applicable_checks_excluded_from_weak(self):
        """Checks with score -1 (N/A) should not be counted as weak."""
        pkg_meta = _make_package_meta(repository="https://github.com/owner/repo")
        scorecard_result = ScorecardResult(
            repo="owner/repo",
            overall_score=6.0,
            checks=[
                ScorecardCheck(name="Fuzzing", score=-1, reason="not applicable"),
                ScorecardCheck(name="SAST", score=0, reason="no SAST tooling"),
            ],
            date="2024-01-01",
        )

        with patch(
            "depfence.core.scorecard_enricher.ScorecardClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.batch_scores.return_value = {
                "https://github.com/owner/repo": scorecard_result
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await enrich_with_scorecard([pkg_meta])

        weak_names = [c.name for c in results[0]["weak_checks"]]
        assert "Fuzzing" not in weak_names  # -1 is excluded
        assert "SAST" in weak_names          # 0 is a genuine weak score

    @pytest.mark.asyncio
    async def test_risk_level_critical_for_low_score(self):
        pkg_meta = _make_package_meta(repository="https://github.com/owner/repo")
        scorecard_result = ScorecardResult(
            repo="owner/repo", overall_score=1.5, checks=[], date="2024-01-01"
        )

        with patch(
            "depfence.core.scorecard_enricher.ScorecardClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.batch_scores.return_value = {
                "https://github.com/owner/repo": scorecard_result
            }
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await enrich_with_scorecard([pkg_meta])

        assert results[0]["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# scorecard_findings
# ---------------------------------------------------------------------------

class TestScorecardFindings:
    def _make_entry(
        self,
        score: float,
        repo: str = "owner/repo",
        pkg_name: str = "my-pkg",
        weak_checks: list[ScorecardCheck] | None = None,
    ) -> dict:
        return {
            "package": PackageId("pypi", pkg_name, "1.0.0"),
            "repo": repo,
            "score": score,
            "risk_level": "high" if score < 5 else "good",
            "weak_checks": weak_checks or [],
        }

    def test_low_score_generates_finding(self):
        entry = self._make_entry(score=2.5)
        findings = scorecard_findings([entry])
        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == FindingType.PROVENANCE
        assert f.severity == Severity.CRITICAL  # 2.5 < 3.0

    def test_high_score_below_5_generates_finding(self):
        entry = self._make_entry(score=4.5)
        findings = scorecard_findings([entry])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_score_at_5_generates_no_finding(self):
        entry = self._make_entry(score=5.0)
        findings = scorecard_findings([entry])
        assert findings == []

    def test_score_above_5_generates_no_finding(self):
        entry = self._make_entry(score=7.5)
        findings = scorecard_findings([entry])
        assert findings == []

    def test_finding_severity_critical_for_score_below_3(self):
        entry = self._make_entry(score=1.0)
        findings = scorecard_findings([entry])
        assert findings[0].severity == Severity.CRITICAL

    def test_finding_severity_high_for_score_3_to_5(self):
        entry = self._make_entry(score=3.5)
        findings = scorecard_findings([entry])
        assert findings[0].severity == Severity.HIGH

    def test_finding_contains_repo_in_title(self):
        entry = self._make_entry(score=2.0, repo="acme/dangerous-lib")
        findings = scorecard_findings([entry])
        assert "acme/dangerous-lib" in findings[0].title

    def test_finding_detail_mentions_weak_checks(self):
        weak = [
            ScorecardCheck(name="Signed-Releases", score=0, reason="no signed releases"),
            ScorecardCheck(name="Branch-Protection", score=2, reason="weak branch protection"),
        ]
        entry = self._make_entry(score=3.0, weak_checks=weak)
        findings = scorecard_findings([entry])
        assert "Signed-Releases" in findings[0].detail
        assert "Branch-Protection" in findings[0].detail

    def test_finding_metadata_contains_score(self):
        entry = self._make_entry(score=2.0)
        findings = scorecard_findings([entry])
        assert findings[0].metadata["scorecard_score"] == pytest.approx(2.0)

    def test_finding_metadata_contains_weak_check_names(self):
        weak = [ScorecardCheck(name="Dangerous-Workflow", score=0, reason="dangerous")]
        entry = self._make_entry(score=1.5, weak_checks=weak)
        findings = scorecard_findings([entry])
        assert "Dangerous-Workflow" in findings[0].metadata["weak_checks"]

    def test_finding_references_scorecard_viewer(self):
        entry = self._make_entry(score=2.0, repo="owner/repo")
        findings = scorecard_findings([entry])
        assert any("scorecard.dev" in ref for ref in findings[0].references)

    def test_empty_results_produces_no_findings(self):
        assert scorecard_findings([]) == []

    def test_mixed_scores_only_low_ones_flagged(self):
        entries = [
            self._make_entry(score=1.5, pkg_name="bad-pkg"),
            self._make_entry(score=8.0, pkg_name="good-pkg"),
            self._make_entry(score=4.0, pkg_name="risky-pkg"),
        ]
        findings = scorecard_findings(entries)
        assert len(findings) == 2
        flagged_pkgs = {f.package.name for f in findings}
        assert "bad-pkg" in flagged_pkgs
        assert "risky-pkg" in flagged_pkgs
        assert "good-pkg" not in flagged_pkgs

    def test_finding_package_id_matches_input(self):
        pkg_id = PackageId("npm", "left-pad", "1.3.0")
        entry = {
            "package": pkg_id,
            "repo": "stevemao/left-pad",
            "score": 2.0,
            "risk_level": "critical",
            "weak_checks": [],
        }
        findings = scorecard_findings([entry])
        assert findings[0].package == pkg_id
