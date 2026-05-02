"""Tests for the typosquat detector."""

from __future__ import annotations

import pytest

from depfence.analyzers.typosquat_detector import (
    TyposquatMatch,
    batch_check,
    check_against_popular,
    common_substitutions,
    keyboard_distance,
    levenshtein_distance,
)


# ---------------------------------------------------------------------------
# levenshtein_distance
# ---------------------------------------------------------------------------

class TestLevenshteinDistance:
    def test_identical_strings(self):
        assert levenshtein_distance("hello", "hello") == 0

    def test_empty_strings(self):
        assert levenshtein_distance("", "") == 0

    def test_one_empty(self):
        assert levenshtein_distance("abc", "") == 3
        assert levenshtein_distance("", "abc") == 3

    def test_single_insertion(self):
        assert levenshtein_distance("flask", "flaask") == 1

    def test_single_deletion(self):
        assert levenshtein_distance("reqests", "requests") == 1

    def test_single_substitution(self):
        assert levenshtein_distance("react", "reect") == 1

    def test_transposition_two_edits(self):
        # "lodahs" requires 2 edits from "lodash" (swap h and s)
        assert levenshtein_distance("lodash", "lodahs") == 2

    def test_completely_different(self):
        d = levenshtein_distance("abc", "xyz")
        assert d == 3

    def test_reqeusts_vs_requests(self):
        # "reqeusts" → "requests": distance should be ≤ 2
        assert levenshtein_distance("reqeusts", "requests") <= 2

    def test_known_values(self):
        assert levenshtein_distance("kitten", "sitting") == 3
        assert levenshtein_distance("saturday", "sunday") == 3

    def test_symmetry(self):
        a, b = "express", "expres"
        assert levenshtein_distance(a, b) == levenshtein_distance(b, a)


# ---------------------------------------------------------------------------
# keyboard_distance
# ---------------------------------------------------------------------------

class TestKeyboardDistance:
    def test_identical(self):
        assert keyboard_distance("hello", "hello") == 0.0

    def test_adjacent_keys_cheaper_than_far_keys(self):
        # 'q' and 'w' are adjacent; 'q' and 'p' are far apart
        near = keyboard_distance("q", "w")
        far = keyboard_distance("q", "p")
        assert near < far

    def test_empty(self):
        assert keyboard_distance("", "abc") == 3.0
        assert keyboard_distance("abc", "") == 3.0

    def test_non_negative(self):
        assert keyboard_distance("react", "reect") >= 0.0

    def test_returns_float(self):
        result = keyboard_distance("flask", "flaask")
        assert isinstance(result, float)

    def test_same_length_substitution(self):
        # Substitution of adjacent key should be less than 1.0
        d = keyboard_distance("a", "s")  # adjacent
        assert 0.0 < d < 1.0

    def test_symmetry(self):
        assert keyboard_distance("foo", "bar") == pytest.approx(
            keyboard_distance("bar", "foo"), abs=1e-6
        )


# ---------------------------------------------------------------------------
# common_substitutions
# ---------------------------------------------------------------------------

class TestCommonSubstitutions:
    def test_transposition_generated(self):
        variants = common_substitutions("lodash")
        # Adjacent swap of 'a' and 's' positions etc.
        # "ldoash" is swap of l/d; "lоdash" has many; let's check a specific one
        # swap index 4,5: "lodahs"
        assert "lodahs" in variants

    def test_omission_generated(self):
        variants = common_substitutions("requests")
        # Drop 'u' → "reqests"
        assert "reqests" in variants

    def test_insertion_generated(self):
        variants = common_substitutions("flask")
        # Duplicate 'a' → "flaask"
        assert "flaask" in variants

    def test_homoglyph_l_to_1(self):
        variants = common_substitutions("flask")
        # 'l' → '1': "f1ask"
        assert "f1ask" in variants

    def test_homoglyph_o_to_0(self):
        variants = common_substitutions("torch")
        # 't', 'o' → '0': "t0rch"
        assert "t0rch" in variants

    def test_homoglyph_rn_to_m(self):
        variants = common_substitutions("cornmeal")
        # "cornmeal" contains 'rn'; "rn"→"m" gives "commeal"
        assert "commeal" in variants

    def test_separator_confusion_dash_to_none(self):
        variants = common_substitutions("my-package")
        assert "mypackage" in variants

    def test_separator_confusion_dash_to_underscore(self):
        variants = common_substitutions("my-package")
        assert "my_package" in variants

    def test_separator_confusion_dash_to_dot(self):
        variants = common_substitutions("my-package")
        assert "my.package" in variants

    def test_scope_squatting(self):
        variants = common_substitutions("react")
        # Should include scoped variants
        scoped = [v for v in variants if v.startswith("@") and "react" in v]
        assert len(scoped) >= 1

    def test_returns_list(self):
        assert isinstance(common_substitutions("django"), list)

    def test_no_self_in_variants(self):
        name = "flask"
        variants = common_substitutions(name)
        assert name not in variants

    def test_variants_are_strings(self):
        variants = common_substitutions("numpy")
        assert all(isinstance(v, str) for v in variants)


# ---------------------------------------------------------------------------
# check_against_popular – detection cases
# ---------------------------------------------------------------------------

class TestCheckAgainstPopular:
    # --- Positive detections ---

    def test_reqeusts_detects_requests(self):
        """'reqeusts' should match 'requests' (distance ≤ 2)."""
        match = check_against_popular("reqeusts", "pypi")
        assert match is not None
        assert match.target == "requests"
        assert match.distance <= 2
        assert match.confidence > 0.7

    def test_reqests_detects_requests(self):
        """'reqests' (one char omitted) should match 'requests'."""
        match = check_against_popular("reqests", "pypi")
        assert match is not None
        assert match.target == "requests"
        assert match.distance <= 2

    def test_flaask_detects_flask(self):
        """'flaask' (extra 'a') should match 'flask'."""
        match = check_against_popular("flaask", "pypi")
        assert match is not None
        assert match.target == "flask"
        assert match.attack_type == "insertion"

    def test_lodahs_detects_lodash(self):
        """'lodahs' (transposition) should match 'lodash'."""
        match = check_against_popular("lodahs", "npm")
        assert match is not None
        assert match.target == "lodash"

    def test_lo_dash_separator_detected(self):
        """'lo-dash' should be detected as separator confusion of 'lodash'."""
        match = check_against_popular("lo-dash", "npm")
        assert match is not None
        assert match.target == "lodash"
        assert match.attack_type == "separator"

    def test_lodash_with_underscore_detected(self):
        """'lo_dash' should be detected as separator confusion of 'lodash'."""
        match = check_against_popular("lo_dash", "npm")
        assert match is not None
        assert match.target == "lodash"
        assert match.attack_type == "separator"

    def test_djang0_homoglyph_detected(self):
        """'djang0' (o→0) should match 'django'."""
        match = check_against_popular("djang0", "pypi")
        assert match is not None
        assert match.target == "django"
        assert match.attack_type == "homoglyph"

    def test_reakt_npm_detected(self):
        """'reakt' (c→k substitution) should match 'react'."""
        match = check_against_popular("reakt", "npm")
        assert match is not None
        assert match.target == "react"

    def test_nump_detects_numpy(self):
        """'nump' (omitting 'y') should match 'numpy'."""
        match = check_against_popular("nump", "pypi")
        assert match is not None
        assert match.target == "numpy"
        assert match.attack_type == "omission"

    # --- Negative cases: legitimate packages ---

    def test_react_native_not_typosquat_of_react(self):
        """'react-native' is a legitimate package, not a typosquat of 'react'."""
        match = check_against_popular("react-native", "npm")
        # react-native is much longer than react, should not be flagged
        if match is not None:
            assert match.target != "react"

    def test_express_validator_not_typosquat(self):
        """'express-validator' should not be flagged as a typosquat of 'express'."""
        match = check_against_popular("express-validator", "npm")
        if match is not None:
            assert match.target != "express"

    def test_popular_package_itself_not_flagged(self):
        """'requests' itself should not be flagged."""
        match = check_against_popular("requests", "pypi")
        assert match is None

    def test_flask_itself_not_flagged(self):
        """'flask' itself should not be flagged."""
        match = check_against_popular("flask", "pypi")
        assert match is None

    def test_completely_different_name_not_flagged(self):
        """An unrelated package name should not be flagged."""
        match = check_against_popular("zzzunrelated", "pypi")
        assert match is None

    def test_long_unique_name_not_flagged(self):
        """A unique long name should not be flagged as a typosquat."""
        match = check_against_popular("mycompany-internal-toolkit", "npm")
        assert match is None


# ---------------------------------------------------------------------------
# TyposquatMatch dataclass
# ---------------------------------------------------------------------------

class TestTyposquatMatch:
    def test_fields_present(self):
        m = TyposquatMatch(
            suspect="reqests",
            target="requests",
            distance=1,
            confidence=0.85,
            attack_type="omission",
        )
        assert m.suspect == "reqests"
        assert m.target == "requests"
        assert m.distance == 1
        assert m.confidence == 0.85
        assert m.attack_type == "omission"

    def test_confidence_in_range(self):
        match = check_against_popular("reqests", "pypi")
        assert match is not None
        assert 0.0 <= match.confidence <= 1.0

    def test_attack_type_is_string(self):
        match = check_against_popular("flaask", "pypi")
        assert match is not None
        assert isinstance(match.attack_type, str)

    def test_distance_non_negative(self):
        match = check_against_popular("reqests", "pypi")
        assert match is not None
        assert match.distance >= 0


# ---------------------------------------------------------------------------
# batch_check
# ---------------------------------------------------------------------------

class TestBatchCheck:
    def test_empty_input(self):
        results = batch_check([], "pypi")
        assert results == []

    def test_detects_multiple_typosquats(self):
        names = ["reqests", "flaask", "lodahs", "totally-legit-unique-xqzk"]
        results = batch_check(names, "pypi")
        suspects = {m.suspect for m in results}
        assert "reqests" in suspects
        assert "flaask" in suspects
        assert "totally-legit-unique-xqzk" not in suspects

    def test_returns_list_of_matches(self):
        results = batch_check(["reqests", "flaask"], "pypi")
        assert isinstance(results, list)
        assert all(isinstance(m, TyposquatMatch) for m in results)

    def test_legitimate_packages_excluded(self):
        """Known legitimate packages should not appear in batch results."""
        names = ["requests", "flask", "django", "numpy"]
        results = batch_check(names, "pypi")
        assert results == []

    def test_mixed_ecosystems_npm(self):
        names = ["reakt", "exprss", "lodahs"]
        results = batch_check(names, "npm")
        suspects = {m.suspect for m in results}
        # At least some of these should be detected
        assert len(suspects) >= 1

    def test_each_name_at_most_one_match(self):
        """batch_check should return at most one match per input name."""
        names = ["reqests", "flaask", "lodahs"]
        results = batch_check(names, "pypi")
        suspect_counts: dict[str, int] = {}
        for m in results:
            suspect_counts[m.suspect] = suspect_counts.get(m.suspect, 0) + 1
        for name, count in suspect_counts.items():
            assert count == 1, f"{name!r} appeared {count} times in batch results"

    def test_confidence_above_threshold(self):
        """All returned matches should have confidence > 0.7."""
        names = ["reqests", "flaask", "nump", "djang0"]
        results = batch_check(names, "pypi")
        for m in results:
            assert m.confidence > 0.7, (
                f"{m.suspect!r} → {m.target!r} has confidence {m.confidence}"
            )
