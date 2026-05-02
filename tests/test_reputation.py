"""Tests for reputation scanner."""

from datetime import datetime, timezone, timedelta

import pytest

from depfence.core.models import MaintainerInfo, PackageId, PackageMeta
from depfence.scanners.reputation import ReputationScanner


@pytest.fixture
def scorer():
    return ReputationScanner()


def test_established_package(scorer):
    meta = PackageMeta(
        pkg=PackageId("npm", "lodash", "4.17.21"),
        description="Lodash modular utilities.",
        repository="https://github.com/lodash/lodash",
        license="MIT",
        maintainers=[
            MaintainerInfo("jdalton"),
            MaintainerInfo("mathias"),
            MaintainerInfo("contributor3"),
        ],
        first_published=datetime(2012, 1, 1, tzinfo=timezone.utc),
        has_provenance=True,
    )
    score = scorer.compute_score(meta)
    assert score >= 70


def test_brand_new_package(scorer):
    meta = PackageMeta(
        pkg=PackageId("npm", "xyzzy-test-1234", "0.0.1"),
        first_published=datetime.now(timezone.utc) - timedelta(days=2),
        maintainers=[MaintainerInfo("newuser123")],
    )
    score = scorer.compute_score(meta)
    assert score < 40


def test_ownership_change_penalty(scorer):
    meta = PackageMeta(
        pkg=PackageId("npm", "some-pkg", "2.0.0"),
        description="A package",
        repository="https://github.com/a/b",
        license="MIT",
        maintainers=[
            MaintainerInfo("original", recent_ownership_change=True),
        ],
        first_published=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    score = scorer.compute_score(meta)
    assert score < 60


def test_no_repo_penalty(scorer):
    meta = PackageMeta(
        pkg=PackageId("npm", "no-repo", "1.0.0"),
        description="A package without a repo",
        license="MIT",
    )
    score = scorer.compute_score(meta)
    meta_with_repo = PackageMeta(
        pkg=PackageId("npm", "with-repo", "1.0.0"),
        description="A package with a repo",
        repository="https://github.com/a/b",
        license="MIT",
    )
    score_with = scorer.compute_score(meta_with_repo)
    assert score < score_with
