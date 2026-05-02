"""Tests for the package trust scoring system."""

from __future__ import annotations

import pytest

from depfence.core.models import PackageId
from depfence.core.trust_scorer import (
    TrustScore,
    TrustSignals,
    batch_trust_scores,
    compute_trust,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(name: str = "test-pkg", ecosystem: str = "npm", version: str = "1.0.0") -> PackageId:
    return PackageId(ecosystem=ecosystem, name=name, version=version)


def _well_known_signals() -> TrustSignals:
    """Signals representative of a mature, well-maintained package."""
    return TrustSignals(
        weekly_downloads=5_000_000,
        age_days=2000,
        maintainer_count=5,
        has_repository=True,
        has_readme=True,
        has_license=True,
        has_types=True,
        version_count=80,
        last_publish_days=10,
        has_ci=True,
        has_provenance=True,
        open_issues=50,
        dependents_count=10_000,
    )


def _brand_new_signals() -> TrustSignals:
    """Signals for a freshly published, unknown package."""
    return TrustSignals(
        weekly_downloads=5,
        age_days=1,
        maintainer_count=1,
        has_repository=False,
        has_readme=False,
        has_license=False,
        has_types=False,
        version_count=1,
        last_publish_days=1,
        has_ci=False,
        has_provenance=False,
        open_issues=None,
        dependents_count=0,
    )


# ---------------------------------------------------------------------------
# Core scoring tests
# ---------------------------------------------------------------------------

class TestWellKnownPackage:
    def test_high_score(self):
        ts = compute_trust(_pkg("lodash"), _well_known_signals())
        assert ts.score >= 80, f"Expected high score, got {ts.score}"

    def test_grade_a(self):
        ts = compute_trust(_pkg("lodash"), _well_known_signals())
        assert ts.grade == "A"

    def test_no_critical_risk_factors(self):
        ts = compute_trust(_pkg("lodash"), _well_known_signals())
        # Well-known package should have no or very few risk factors
        assert len(ts.risk_factors) == 0, f"Unexpected risk factors: {ts.risk_factors}"

    def test_package_identity_preserved(self):
        pkg = _pkg("lodash", "npm", "4.17.21")
        ts = compute_trust(pkg, _well_known_signals())
        assert ts.package == pkg


class TestBrandNewPackage:
    def test_low_score(self):
        ts = compute_trust(_pkg("brand-new-pkg"), _brand_new_signals())
        assert ts.score < 35, f"Expected low score, got {ts.score}"

    def test_grade_f(self):
        ts = compute_trust(_pkg("brand-new-pkg"), _brand_new_signals())
        assert ts.grade == "F"

    def test_has_risk_factors(self):
        ts = compute_trust(_pkg("brand-new-pkg"), _brand_new_signals())
        assert len(ts.risk_factors) > 0

    def test_new_package_risk_factor_mentioned(self):
        ts = compute_trust(_pkg("brand-new-pkg"), _brand_new_signals())
        risk_text = " ".join(ts.risk_factors).lower()
        # Should mention age / publish recency
        assert any(
            word in risk_text for word in ["day", "published", "ago"]
        ), f"Risk factors: {ts.risk_factors}"


# ---------------------------------------------------------------------------
# Graceful degradation with None / missing signals
# ---------------------------------------------------------------------------

class TestMissingSignals:
    def test_all_none_signals(self):
        signals = TrustSignals()  # all defaults: None/False/0
        ts = compute_trust(_pkg(), signals)
        # Should not raise and should give a low score
        assert isinstance(ts.score, float)
        assert 0.0 <= ts.score <= 100.0

    def test_all_none_grade_is_f(self):
        ts = compute_trust(_pkg(), TrustSignals())
        assert ts.grade == "F"

    def test_none_downloads_conservative(self):
        signals = TrustSignals(
            weekly_downloads=None,
            age_days=500,
            maintainer_count=3,
            has_repository=True,
            has_ci=True,
            has_readme=True,
            has_license=True,
            last_publish_days=30,
            has_provenance=True,
            dependents_count=500,
        )
        ts_none = compute_trust(_pkg(), signals)
        signals_known = TrustSignals(
            weekly_downloads=1_000_000,
            age_days=500,
            maintainer_count=3,
            has_repository=True,
            has_ci=True,
            has_readme=True,
            has_license=True,
            last_publish_days=30,
            has_provenance=True,
            dependents_count=500,
        )
        ts_known = compute_trust(_pkg(), signals_known)
        # Known downloads should yield higher score than unknown (treated as 0)
        assert ts_none.score < ts_known.score

    def test_none_age_counts_as_zero_not_error(self):
        signals = TrustSignals(age_days=None)
        ts = compute_trust(_pkg(), signals)
        assert "age unknown" in " ".join(ts.risk_factors).lower()

    def test_none_maintainers_counts_as_unknown(self):
        signals = TrustSignals(maintainer_count=None)
        ts = compute_trust(_pkg(), signals)
        assert "maintainer" in " ".join(ts.risk_factors).lower()

    def test_partial_signals_no_exception(self):
        """Partial signals should score without raising."""
        signals = TrustSignals(
            weekly_downloads=50_000,
            age_days=200,
        )
        ts = compute_trust(_pkg(), signals)
        assert isinstance(ts.score, float)


# ---------------------------------------------------------------------------
# Grade boundary tests
# ---------------------------------------------------------------------------

class TestGradeBoundaries:
    def _score_for(self, score_override: float) -> str:
        """Helper: find grade by constructing signals that yield approximately
        the desired score, using the known grading thresholds directly."""
        from depfence.core.trust_scorer import _score_to_grade
        return _score_to_grade(score_override)

    def test_grade_a_at_80(self):
        assert self._score_for(80.0) == "A"

    def test_grade_a_at_100(self):
        assert self._score_for(100.0) == "A"

    def test_grade_b_at_65(self):
        assert self._score_for(65.0) == "B"

    def test_grade_b_at_79(self):
        assert self._score_for(79.9) == "B"

    def test_grade_c_at_50(self):
        assert self._score_for(50.0) == "C"

    def test_grade_c_at_64(self):
        assert self._score_for(64.9) == "C"

    def test_grade_d_at_35(self):
        assert self._score_for(35.0) == "D"

    def test_grade_d_at_49(self):
        assert self._score_for(49.9) == "D"

    def test_grade_f_at_34(self):
        assert self._score_for(34.9) == "F"

    def test_grade_f_at_zero(self):
        assert self._score_for(0.0) == "F"

    def test_actual_high_score_package_gets_a(self):
        ts = compute_trust(_pkg(), _well_known_signals())
        assert ts.grade == "A"

    def test_actual_new_package_gets_f(self):
        ts = compute_trust(_pkg(), _brand_new_signals())
        assert ts.grade == "F"


# ---------------------------------------------------------------------------
# Risk factors tests
# ---------------------------------------------------------------------------

class TestRiskFactors:
    def test_no_repository_risk_factor(self):
        signals = TrustSignals(has_repository=False)
        ts = compute_trust(_pkg(), signals)
        assert any("repository" in r.lower() for r in ts.risk_factors)

    def test_single_maintainer_risk_factor(self):
        signals = TrustSignals(maintainer_count=1)
        ts = compute_trust(_pkg(), signals)
        assert any("single maintainer" in r.lower() for r in ts.risk_factors)

    def test_no_provenance_risk_factor(self):
        signals = TrustSignals(has_provenance=False)
        ts = compute_trust(_pkg(), signals)
        assert any("provenance" in r.lower() for r in ts.risk_factors)

    def test_no_readme_risk_factor(self):
        signals = TrustSignals(has_readme=False, has_license=True)
        ts = compute_trust(_pkg(), signals)
        assert any("readme" in r.lower() for r in ts.risk_factors)

    def test_no_license_risk_factor(self):
        signals = TrustSignals(has_readme=True, has_license=False)
        ts = compute_trust(_pkg(), signals)
        assert any("license" in r.lower() for r in ts.risk_factors)

    def test_stale_package_risk_factor(self):
        signals = TrustSignals(last_publish_days=800)
        ts = compute_trust(_pkg(), signals)
        assert any("updated" in r.lower() or "days" in r.lower() for r in ts.risk_factors)

    def test_very_low_downloads_risk_factor(self):
        signals = TrustSignals(weekly_downloads=10)
        ts = compute_trust(_pkg(), signals)
        assert any("download" in r.lower() for r in ts.risk_factors)

    def test_no_dependents_risk_factor(self):
        signals = TrustSignals(dependents_count=0)
        ts = compute_trust(_pkg(), signals)
        assert any("dependent" in r.lower() for r in ts.risk_factors)

    def test_clean_package_no_risk_factors(self):
        ts = compute_trust(_pkg(), _well_known_signals())
        assert ts.risk_factors == []


# ---------------------------------------------------------------------------
# Batch scoring tests
# ---------------------------------------------------------------------------

class TestBatchScoring:
    def test_sorted_riskiest_first(self):
        pairs = [
            (_pkg("safe"), _well_known_signals()),
            (_pkg("risky"), _brand_new_signals()),
            (_pkg("medium"), TrustSignals(
                weekly_downloads=10_000,
                age_days=180,
                maintainer_count=2,
                has_repository=True,
                has_readme=True,
                has_license=True,
                last_publish_days=60,
                has_provenance=False,
                dependents_count=100,
            )),
        ]
        scores = batch_trust_scores(pairs)
        assert scores[0].package.name == "risky"
        assert scores[-1].package.name == "safe"

    def test_sorted_ascending(self):
        pairs = [
            (_pkg("p1"), _well_known_signals()),
            (_pkg("p2"), _brand_new_signals()),
        ]
        scores = batch_trust_scores(pairs)
        assert scores[0].score <= scores[1].score

    def test_empty_list(self):
        assert batch_trust_scores([]) == []

    def test_single_package(self):
        pairs = [(_pkg("solo"), _well_known_signals())]
        scores = batch_trust_scores(pairs)
        assert len(scores) == 1
        assert scores[0].package.name == "solo"

    def test_all_packages_scored(self):
        pairs = [(_pkg(f"pkg-{i}"), _well_known_signals()) for i in range(5)]
        scores = batch_trust_scores(pairs)
        assert len(scores) == 5

    def test_returns_trust_score_objects(self):
        pairs = [(_pkg("x"), _well_known_signals())]
        scores = batch_trust_scores(pairs)
        assert isinstance(scores[0], TrustScore)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_zero_downloads(self):
        signals = TrustSignals(weekly_downloads=0)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["downloads"] == 0.0

    def test_exactly_100_downloads(self):
        """100 downloads/week is the minimum non-zero threshold."""
        signals = TrustSignals(weekly_downloads=100)
        ts = compute_trust(_pkg(), signals)
        # Should be 0: at log10(100)=2, which maps to 0 on the [2,6] scale
        assert ts.breakdown["downloads"] == 0.0

    def test_one_million_downloads_maxes_out(self):
        signals = TrustSignals(weekly_downloads=1_000_000)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["downloads"] == pytest.approx(20.0, abs=0.1)

    def test_negative_age_handled(self):
        """Negative age shouldn't raise; treat as zero."""
        signals = TrustSignals(age_days=-5)
        ts = compute_trust(_pkg(), signals)
        assert isinstance(ts.score, float)
        assert ts.breakdown["age"] == 0.0

    def test_zero_maintainers(self):
        signals = TrustSignals(maintainer_count=0)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["maintainers"] == 0.0
        assert any("maintainer" in r.lower() for r in ts.risk_factors)

    def test_score_bounded_0_to_100(self):
        """Score should never exceed 100 or fall below 0."""
        for signals in [_well_known_signals(), _brand_new_signals(), TrustSignals()]:
            ts = compute_trust(_pkg(), signals)
            assert 0.0 <= ts.score <= 100.0

    def test_three_maintainers_max(self):
        """3+ maintainers should score the same as 3."""
        sig3 = TrustSignals(maintainer_count=3)
        sig10 = TrustSignals(maintainer_count=10)
        ts3 = compute_trust(_pkg(), sig3)
        ts10 = compute_trust(_pkg(), sig10)
        assert ts3.breakdown["maintainers"] == ts10.breakdown["maintainers"]

    def test_large_dependents_capped(self):
        """1M dependents should not exceed the max contribution."""
        signals = TrustSignals(dependents_count=1_000_000)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["dependents"] <= 10.0  # max is weight * 100

    def test_has_ci_without_repo_gets_zero(self):
        """CI flag has no effect if no repository is listed."""
        sig_no_repo_ci = TrustSignals(has_repository=False, has_ci=True)
        sig_no_repo = TrustSignals(has_repository=False, has_ci=False)
        ts_ci = compute_trust(_pkg(), sig_no_repo_ci)
        ts_no = compute_trust(_pkg(), sig_no_repo)
        assert ts_ci.breakdown["repository"] == ts_no.breakdown["repository"] == 0.0

    def test_freshness_730_days_is_zero(self):
        signals = TrustSignals(last_publish_days=730)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["freshness"] == 0.0

    def test_freshness_under_90_days_is_max(self):
        signals = TrustSignals(last_publish_days=89)
        ts = compute_trust(_pkg(), signals)
        assert ts.breakdown["freshness"] == pytest.approx(10.0, abs=0.01)


# ---------------------------------------------------------------------------
# Breakdown integrity tests
# ---------------------------------------------------------------------------

class TestBreakdownIntegrity:
    def test_breakdown_keys_present(self):
        ts = compute_trust(_pkg(), _well_known_signals())
        expected_keys = {
            "downloads", "age", "maintainers", "repository",
            "documentation", "freshness", "provenance", "dependents",
        }
        assert set(ts.breakdown.keys()) == expected_keys

    def test_breakdown_sums_to_score(self):
        for signals in [_well_known_signals(), _brand_new_signals()]:
            ts = compute_trust(_pkg(), signals)
            assert sum(ts.breakdown.values()) == pytest.approx(ts.score, abs=0.1)

    def test_breakdown_non_negative(self):
        ts = compute_trust(_pkg(), _brand_new_signals())
        for key, val in ts.breakdown.items():
            assert val >= 0.0, f"Negative breakdown for {key}: {val}"

    def test_perfect_signals_breakdown_near_100(self):
        ts = compute_trust(_pkg(), _well_known_signals())
        total = sum(ts.breakdown.values())
        assert total >= 80.0  # perfect signals should yield high score

    def test_breakdown_each_contribution_bounded(self):
        """Each signal's contribution should not exceed its max weight * 100."""
        weight_max = {
            "downloads": 20.0,
            "age": 15.0,
            "maintainers": 10.0,
            "repository": 15.0,
            "documentation": 10.0,
            "freshness": 10.0,
            "provenance": 10.0,
            "dependents": 10.0,
        }
        ts = compute_trust(_pkg(), _well_known_signals())
        for key, max_val in weight_max.items():
            assert ts.breakdown[key] <= max_val + 0.01, (
                f"{key} contribution {ts.breakdown[key]} exceeds max {max_val}"
            )
