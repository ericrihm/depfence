"""Tests for the findings->regression-gate flywheel (depfence/flywheel/regression_gate.py).

The load-bearing property: a finding that was seen, then RESOLVED, then comes back must trip the
gate (a regression), while a finding that simply persists must not. That is the compounding
discipline — a fix becomes a permanent tripwire. Runnable under pytest or standalone.
"""

from __future__ import annotations

import os
import tempfile

from depfence.flywheel import regression_gate as rg


def _rec(rule, name):
    return {"rule": rule, "severity": "high", "title": name,
            "package": {"ecosystem": "npm", "name": name, "version": "1.0"}}


def _tmp():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.unlink(path)  # start with no ledger (a first run)
    return path


def test_resolved_finding_that_recurs_is_a_regression():
    path = _tmp()
    try:
        f = _rec("known_vulnerability", "lodash")
        clock = lambda: "T0"  # noqa: E731
        # scan A: finding present -> open
        entries, _ = rg.update([f], path, clock=clock)
        rg.save_ledger(entries, path)
        assert entries[rg.finding_id(f)]["status"] == "open"
        # scan B: finding gone -> fixed
        entries, _ = rg.update([], path, clock=clock)
        rg.save_ledger(entries, path)
        assert entries[rg.finding_id(f)]["status"] == "fixed"
        # scan C: finding is BACK -> regression
        regressed, _ = rg.gate([f], path)
        assert regressed == [rg.finding_id(f)], regressed
    finally:
        os.path.exists(path) and os.unlink(path)


def test_persisting_finding_is_not_a_regression():
    path = _tmp()
    try:
        f = _rec("known_vulnerability", "lodash")
        clock = lambda: "T0"  # noqa: E731
        entries, _ = rg.update([f], path, clock=clock)
        rg.save_ledger(entries, path)
        entries, _ = rg.update([f], path, clock=clock)  # still present
        rg.save_ledger(entries, path)
        assert rg.gate([f], path)[0] == []  # open, never fixed -> no regression
    finally:
        os.path.exists(path) and os.unlink(path)


def test_accepted_finding_stays_accepted_across_scans():
    path = _tmp()
    try:
        f = _rec("license_risk", "gpl-thing")
        fid = rg.finding_id(f)
        entries, _ = rg.update([f], path)
        entries[fid]["status"] = "accepted"      # operator risk-acceptance
        rg.save_ledger(entries, path)
        entries2, _ = rg.update([f], path)        # a later scan must not silently reopen it
        assert entries2[fid]["status"] == "accepted"
    finally:
        os.path.exists(path) and os.unlink(path)


def test_ledger_and_graph_share_finding_identity():
    from depfence.reporters import kg_out
    f = _rec("known_vulnerability", "lodash")
    assert rg.finding_id(f) == kg_out._finding_name(f)


def _standalone():
    checks = []

    def run(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as e:  # noqa: BLE001
            checks.append((name, False, "%s: %s" % (type(e).__name__, e)))

    run("resolved-then-recurs is a regression", test_resolved_finding_that_recurs_is_a_regression)
    run("persisting finding is not a regression", test_persisting_finding_is_not_a_regression)
    run("accepted stays accepted", test_accepted_finding_stays_accepted_across_scans)
    run("ledger & graph share identity", test_ledger_and_graph_share_finding_identity)
    for name, ok, detail in checks:
        print("  %-4s %-38s %s" % ("ok" if ok else "FAIL", name, detail))
    return all(ok for _, ok, _ in checks)


if __name__ == "__main__":
    import sys
    sys.exit(0 if _standalone() else 1)
