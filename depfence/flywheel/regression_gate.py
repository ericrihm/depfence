"""regression_gate.py — turn a security finding into a permanent regression gate.

A finding that is logged and forgotten is a log, not a flywheel. This module is the compounding
half of the ``wheels/patterns/production-failure-to-regression-dataset`` discipline, re-implemented
natively for depfence (the dynamo flywheels that inspired it are QUARANTINED — pattern only, never
imported): once a finding has been seen and then RESOLVED, its reappearance is a **regression** and
must fail the gate. "The same failure class cannot ship twice, and the acceptance bar rises with
each incident."

The ledger keys every finding on the SAME stable id the knowledge graph uses
(``kg_out._finding_name`` — a content digest, no timestamp/scan-counter), so the flywheel and the
graph agree on identity and a re-scan never re-opens a finding under a new id. Statuses:

    open      seen in the latest scan, not yet resolved
    fixed     was in the ledger, absent from the latest scan (resolved) — now a regression tripwire
    accepted  an operator decision to tolerate it (a risk acceptance, recorded, not a silent skip)

``update`` folds a scan into the ledger; ``regressions`` returns every ``fixed`` finding that came
back. The gate exits non-zero on any regression. Nothing here reads secret material or a network —
it is pure set arithmetic over finding ids, safe to run in CI on the public repo.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from depfence.reporters import kg_out

DEFAULT_LEDGER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findings_ledger.jsonl")


def _now(clock=None):
    return (clock or (lambda: datetime.now(tz=timezone.utc).isoformat()))()


def finding_id(record):
    """The stable finding id — the SAME digest the KG mints, so ledger and graph share identity."""
    return kg_out._finding_name(record)


def load_ledger(path=DEFAULT_LEDGER):
    """Read the ledger as {finding_id: entry}. A missing ledger is an empty history (a first run),
    a malformed LINE is skipped-and-counted (never crashes the gate), returned in `notes`."""
    entries, notes = {}, []
    if not os.path.exists(path):
        return entries, notes
    with open(path) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                entries[e["finding_id"]] = e
            except (ValueError, KeyError):
                notes.append("ledger line %d unreadable" % i)
    return entries, notes


def save_ledger(entries, path=DEFAULT_LEDGER):
    """Write the ledger deterministically (sorted by id), so a diff is reviewable and a re-run is
    byte-stable."""
    with open(path, "w") as fh:
        for fid in sorted(entries):
            fh.write(json.dumps(entries[fid], sort_keys=True) + "\n")


def update(records, path=DEFAULT_LEDGER, clock=None):
    """Fold a scan's finding records into the ledger. Returns (entries, notes).

    - a finding present now: upsert status `open` (unless `accepted` — an accepted finding stays
      accepted), refresh `last_seen`.
    - a finding in the ledger, ABSENT now, currently `open`: it was resolved -> mark `fixed` (this
      is what arms the regression tripwire). An already-`fixed`/`accepted` entry is left as-is.
    """
    entries, notes = load_ledger(path)
    now = _now(clock)
    current = {finding_id(r): r for r in records}
    for fid, rec in current.items():
        e = entries.get(fid)
        if e is None:
            entries[fid] = {"finding_id": fid, "rule": rec.get("rule", ""),
                            "severity": rec.get("severity", "info"), "status": "open",
                            "first_seen": now, "last_seen": now}
        else:
            if e.get("status") != "accepted":
                e["status"] = "open"
            e["last_seen"] = now
    for fid, e in entries.items():
        if fid not in current and e.get("status") == "open":
            e["status"] = "fixed"
            e["fixed_at"] = now
    return entries, notes


def regressions(records, path=DEFAULT_LEDGER):
    """Every finding that is `fixed` in the ledger but present in the current scan — a resolved
    finding that came back. This is the gate's whole job."""
    entries, _notes = load_ledger(path)
    current = {finding_id(r) for r in records}
    return sorted(fid for fid, e in entries.items()
                  if e.get("status") == "fixed" and fid in current)


def gate(records, path=DEFAULT_LEDGER):
    """Return (regressed_ids, notes). A non-empty regressed_ids is a CI failure."""
    regressed = regressions(records, path)
    _entries, notes = load_ledger(path)
    return regressed, notes


def main(argv=None):
    """CLI: `regression_gate.py --update <records.json>` folds a scan in; `--check <records.json>`
    fails (exit 4) if any resolved finding regressed. records.json is a list of finding records
    (as depfence.reporters.kg_out consumes, e.g. from normalize_depfence / sarif_in)."""
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in ("--update", "--check"):
        sys.stderr.write("usage: regression_gate.py [--update|--check] <records.json>\n")
        return 2
    mode, src = argv[0], argv[1]
    try:
        with open(src) as fh:
            data = json.load(fh)
        records = data.get("records", data) if isinstance(data, dict) else data
    except (OSError, ValueError) as e:
        sys.stderr.write("could not read records: %s\n" % e)
        return 2
    if mode == "--update":
        entries, notes = update(records)
        save_ledger(entries)
        for n in notes:
            sys.stderr.write("note: %s\n" % n)
        print("ledger updated (%d finding(s) tracked)" % len(entries))
        return 0
    regressed, notes = gate(records)
    for n in notes:
        sys.stderr.write("note: %s\n" % n)
    if regressed:
        sys.stderr.write("REGRESSION: %d resolved finding(s) came back:\n" % len(regressed))
        for fid in regressed:
            sys.stderr.write("  %s\n" % fid)
        return 4
    print("no regressions (%d finding(s) checked against the ledger)" % len(records))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
