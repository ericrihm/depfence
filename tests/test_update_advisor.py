"""Tests for dependency update safety advisor."""

import pytest

from depfence.core.update_advisor import (
    UpdateRecommendation,
    UpdateRisk,
    analyze_update,
    batch_analyze,
    generate_update_plan,
)


class TestAnalyzeUpdate:
    def test_patch_bump_is_safe(self):
        rec = analyze_update("lodash", "npm", "4.17.20", "4.17.21")
        assert rec.risk == UpdateRisk.SAFE
        assert rec.auto_merge is True

    def test_minor_bump_is_low(self):
        rec = analyze_update("express", "npm", "4.17.0", "4.18.0")
        assert rec.risk == UpdateRisk.LOW
        assert rec.auto_merge is False

    def test_major_bump_is_breaking(self):
        rec = analyze_update("react", "npm", "17.0.2", "18.0.0")
        assert rec.risk == UpdateRisk.BREAKING
        assert rec.auto_merge is False
        assert any("breaking" in r.lower() for r in rec.reasons)

    def test_dev_dep_discount(self):
        rec = analyze_update("jest", "npm", "28.0.0", "29.0.0", is_dev_dep=True)
        assert rec.risk == UpdateRisk.BREAKING  # Major is still breaking even for dev

        rec = analyze_update("eslint", "npm", "8.0.0", "8.1.0", is_dev_dep=True)
        assert rec.risk == UpdateRisk.SAFE  # Minor dev dep -> safe

    def test_no_lockfile_increases_risk(self):
        rec = analyze_update("pkg", "npm", "1.0.0", "1.0.1", has_lockfile=False)
        assert rec.risk == UpdateRisk.LOW  # Patch without lockfile -> low

    def test_low_test_coverage_increases_risk(self):
        rec = analyze_update("pkg", "npm", "1.0.0", "1.1.0", test_coverage=0.1)
        assert rec.risk == UpdateRisk.MEDIUM

    def test_high_test_coverage_noted(self):
        rec = analyze_update("pkg", "npm", "1.0.0", "1.1.0", test_coverage=0.9)
        assert rec.risk == UpdateRisk.LOW
        assert any("coverage" in r.lower() for r in rec.reasons)

    def test_multiple_minor_skipped(self):
        rec = analyze_update("pkg", "npm", "1.0.0", "1.5.0")
        assert rec.risk == UpdateRisk.MEDIUM

    def test_unparseable_version(self):
        rec = analyze_update("pkg", "npm", "latest", "1.0.0")
        assert rec.risk == UpdateRisk.MEDIUM


class TestBatchAnalyze:
    def test_sorted_by_risk(self):
        updates = [
            {"package": "safe", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "1.0.1"},
            {"package": "risky", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "2.0.0"},
            {"package": "medium", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "1.5.0"},
        ]
        results = batch_analyze(updates)
        assert results[0].package == "risky"
        assert results[-1].package == "safe"


class TestUpdatePlan:
    def test_plan_structure(self):
        updates = [
            {"package": "a", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "1.0.1"},
            {"package": "b", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "2.0.0"},
            {"package": "c", "ecosystem": "npm", "current_version": "1.0.0", "target_version": "1.2.0"},
        ]
        results = batch_analyze(updates)
        plan = generate_update_plan(results)
        assert plan["stats"]["total"] == 3
        assert plan["stats"]["auto_mergeable"] == 1
        assert plan["stats"]["breaking"] == 1
        assert len(plan["auto_merge"]) == 1
        assert len(plan["breaking_changes"]) == 1
