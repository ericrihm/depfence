"""Tests for baseline/suppression management."""

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from depfence.core.baseline import Baseline, finding_fingerprint
from depfence.core.models import Finding, FindingType, Severity


def _make_finding(pkg="npm:lodash@4.17.20", title="Test vuln"):
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=Severity.HIGH,
        package=pkg,
        title=title,
        detail="Test detail",
    )


def test_fingerprint_stability():
    f1 = _make_finding()
    f2 = _make_finding()
    assert finding_fingerprint(f1) == finding_fingerprint(f2)


def test_fingerprint_differs_for_different_findings():
    f1 = _make_finding(pkg="npm:lodash@4.17.20")
    f2 = _make_finding(pkg="npm:express@4.18.0")
    assert finding_fingerprint(f1) != finding_fingerprint(f2)


def test_suppress_and_check():
    baseline = Baseline()
    finding = _make_finding()
    assert not baseline.is_suppressed(finding)
    baseline.suppress(finding, reason="Accepted risk")
    assert baseline.is_suppressed(finding)
    assert baseline.count == 1


def test_remove_suppression():
    baseline = Baseline()
    finding = _make_finding()
    baseline.suppress(finding)
    assert baseline.is_suppressed(finding)
    assert baseline.remove(finding)
    assert not baseline.is_suppressed(finding)


def test_filter_findings():
    baseline = Baseline()
    f1 = _make_finding(pkg="npm:a@1.0.0", title="Vuln A")
    f2 = _make_finding(pkg="npm:b@1.0.0", title="Vuln B")
    f3 = _make_finding(pkg="npm:c@1.0.0", title="Vuln C")

    baseline.suppress(f1)
    baseline.suppress(f2)

    active, suppressed = baseline.filter_findings([f1, f2, f3])
    assert len(active) == 1
    assert len(suppressed) == 2
    assert f3 in active


def test_expiry_honored():
    baseline = Baseline()
    finding = _make_finding()

    # Expired yesterday
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    baseline.suppress(finding, expires=yesterday)
    assert not baseline.is_suppressed(finding)


def test_future_expiry_still_suppressed():
    baseline = Baseline()
    finding = _make_finding()

    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    baseline.suppress(finding, expires=tomorrow)
    assert baseline.is_suppressed(finding)


def test_save_and_load():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / ".depfence-baseline.json"
        baseline = Baseline(path)
        finding = _make_finding()
        baseline.suppress(finding, reason="Known issue")
        baseline.save()

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["version"] == 1
        assert len(data["entries"]) == 1

        # Load in new instance
        baseline2 = Baseline(path)
        assert baseline2.is_suppressed(finding)
        assert baseline2.count == 1


def test_from_project():
    with tempfile.TemporaryDirectory() as d:
        project = Path(d)
        baseline = Baseline.from_project(project)
        assert baseline.count == 0

        finding = _make_finding()
        baseline.suppress(finding)
        baseline._path = project / ".depfence-baseline.json"
        baseline.save()

        baseline2 = Baseline.from_project(project)
        assert baseline2.is_suppressed(finding)


def test_no_path_save_is_noop():
    baseline = Baseline()
    baseline.suppress(_make_finding())
    baseline.save()  # should not crash
