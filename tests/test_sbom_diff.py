"""Tests for SBOM diffing."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.models import PackageId
from depfence.core.sbom_diff import SbomDiff, diff_sbom_files, diff_sboms


def test_no_changes():
    pkgs = [PackageId("npm", "lodash", "4.17.21"), PackageId("npm", "express", "4.18.0")]
    diff = diff_sboms(pkgs, pkgs)
    assert diff.total_changes == 0
    assert diff.risk_score == 0


def test_added_packages():
    before = [PackageId("npm", "lodash", "4.17.21")]
    after = [PackageId("npm", "lodash", "4.17.21"), PackageId("npm", "malicious-pkg", "1.0.0")]
    diff = diff_sboms(before, after)
    assert len(diff.added) == 1
    assert diff.added[0].name == "malicious-pkg"
    assert diff.risk_score > 0


def test_removed_packages():
    before = [PackageId("npm", "lodash", "4.17.21"), PackageId("npm", "old-dep", "2.0.0")]
    after = [PackageId("npm", "lodash", "4.17.21")]
    diff = diff_sboms(before, after)
    assert len(diff.removed) == 1
    assert diff.removed[0].name == "old-dep"


def test_upgraded_packages():
    before = [PackageId("npm", "lodash", "4.17.20")]
    after = [PackageId("npm", "lodash", "4.17.21")]
    diff = diff_sboms(before, after)
    assert len(diff.upgraded) == 1
    assert diff.upgraded[0][0].version == "4.17.20"
    assert diff.upgraded[0][1].version == "4.17.21"


def test_downgraded_packages():
    before = [PackageId("npm", "lodash", "4.17.21")]
    after = [PackageId("npm", "lodash", "4.17.20")]
    diff = diff_sboms(before, after)
    assert len(diff.downgraded) == 1
    assert diff.risk_score >= 5


def test_mixed_changes():
    before = [
        PackageId("npm", "lodash", "4.17.20"),
        PackageId("npm", "removed-pkg", "1.0.0"),
        PackageId("pypi", "requests", "2.28.0"),
    ]
    after = [
        PackageId("npm", "lodash", "4.17.21"),
        PackageId("npm", "new-pkg", "1.0.0"),
        PackageId("pypi", "requests", "2.31.0"),
    ]
    diff = diff_sboms(before, after)
    assert len(diff.added) == 1
    assert len(diff.removed) == 1
    assert len(diff.upgraded) == 2


def test_diff_sbom_files():
    before_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
            {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
        ],
    }
    after_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
            {"name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
            {"name": "axios", "version": "1.6.0", "purl": "pkg:npm/axios@1.6.0"},
        ],
    }
    with tempfile.TemporaryDirectory() as d:
        before_path = Path(d) / "before.json"
        after_path = Path(d) / "after.json"
        before_path.write_text(json.dumps(before_doc))
        after_path.write_text(json.dumps(after_doc))

        diff = diff_sbom_files(before_path, after_path)
        assert len(diff.added) == 1
        assert diff.added[0].name == "axios"
        assert len(diff.upgraded) == 1


def test_render_table():
    before = [PackageId("npm", "lodash", "4.17.20")]
    after = [PackageId("npm", "lodash", "4.17.21"), PackageId("npm", "axios", "1.0.0")]
    diff = diff_sboms(before, after)
    table = diff.render_table()
    assert "axios" in table
    assert "lodash" in table
    assert "4.17.21" in table


def test_to_dict():
    before = [PackageId("npm", "lodash", "4.17.20")]
    after = [PackageId("npm", "lodash", "4.17.21")]
    diff = diff_sboms(before, after)
    d = diff.to_dict()
    assert "upgraded" in d
    assert d["total_changes"] == 1


def test_scoped_npm_purl():
    before_doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "@babel/core", "version": "7.23.0", "purl": "pkg:npm/%40babel/core@7.23.0"},
        ],
    }
    after_doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "@babel/core", "version": "7.24.0", "purl": "pkg:npm/%40babel/core@7.24.0"},
        ],
    }
    with tempfile.TemporaryDirectory() as d:
        before_path = Path(d) / "before.json"
        after_path = Path(d) / "after.json"
        before_path.write_text(json.dumps(before_doc))
        after_path.write_text(json.dumps(after_doc))

        diff = diff_sbom_files(before_path, after_path)
        assert len(diff.upgraded) == 1
