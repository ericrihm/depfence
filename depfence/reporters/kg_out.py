"""kg_out.py — emit a scan as a federation-conformant knowledge graph (JSON-LD).

depfence already speaks SARIF, JSON, CycloneDX and SPDX. This reporter adds the one output nothing
in the estate produces yet: a knowledge graph conforming to the atlas **KG-CONTRACT**
(``~/dev/atlas/hub/KG-CONTRACT.md``), so a scan's findings become nodes and edges that federate
with every other repo's graph under one id scheme. The emitter pattern is ported verbatim from the
proven, single-repo reference implementation ``macmon/kbgraph.py``: a single ``RELATION_RANGE`` dict
as the sole source of edge truth, byte-exact deterministic serialization, the four integrity gates,
and build-stamped provenance.

WHY A KNOWLEDGE GRAPH AND NOT JUST SARIF. SARIF is a flat list of results. A graph makes the
*relationships* first-class and queryable across tools and repos: which **package** a **finding**
affects, which **rule** detected it, which **CVE**/**CWE** it maps to, which **ecosystem** the
package lives in. Two producers — depfence (SCA, dependency findings) and the semgrep CLI (SAST,
code findings) — normalize into ONE finding-record shape (:func:`normalize_depfence`,
``parsers/sarif_in.normalize_sarif``) and feed this one emitter, so a single graph spans both.

THE CONTRACT, enforced here (KG-CONTRACT §§1-8):
  * **Identity** — ``https://kg.local/depfence/<kind>/<name>``, ``<name>`` percent-escaped, never
    space-substituted.
  * **Serialization** — stdlib JSON-LD, byte-exact
    ``json.dumps(..., indent=2, sort_keys=True, allow_nan=False) + "\\n"``; ``--check`` is a byte
    comparison, so any nondeterminism is a red gate.
  * **Edges** — ``RELATION_RANGE`` is the only edge register; ``@context`` derives the @id-typed
    property set from it, so declaring a relation auto-widens the referential-integrity gate.
  * **Provenance** — every node is ``origin: "derived"``, ``derivedBy: "kg_out.py"`` (a producer
    that self-set ``derivedBy`` would be refused upstream; here the build owns it).
  * **Four integrity gates** — dangling / wrong_kind / undeclared_edge / (unchecked_relations empty
    by construction). A non-empty gate is NOT PROVEN, exit 3.

The ``--write``/``--check`` commands operate on a committed FIXTURE scan
(``kg_fixture.json`` -> ``kg_fixture.jsonld``), so the *emitter's* determinism and conformance are
gated in CI without needing a live scan. Runtime use is :func:`emit` (scan -> validated JSON-LD).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_JSON = os.path.join(HERE, "kg_fixture.json")
FIXTURE_GRAPH = os.path.join(HERE, "kg_fixture.jsonld")

REPO = "depfence"
BASE = "https://kg.local"
VOCAB = "%s/%s/vocab#" % (BASE, REPO)
DERIVED_BY = "kg_out.py"

# The single source of truth for what is an edge: relation -> target node kind. `@context` derives
# the @id-typed property set from this (build_context), so DECLARING a relation here auto-widens the
# referential-integrity gate. A second edge register beside this would be forbidden drift.
RELATION_RANGE = {
    "detected_by": "rule",        # finding  -> the rule/scanner class that flagged it
    "affects": "package",         # finding  -> the dependency it concerns (absent for SAST)
    "references_cve": "cve",      # finding  -> a CVE id
    "classified_as": "cwe",       # finding  -> a CWE id
    "in_ecosystem": "ecosystem",  # package  -> npm / pypi / cargo / ...
}
KINDS = ("finding", "package", "rule", "cve", "cwe", "ecosystem")

# Node keys the build owns (structural, not authored edges). The undeclared-edge gate skips these;
# every OTHER non-relation property is checked, but only flags a value that is itself an internal
# IRI, so literal attributes (severity, title, ...) pass naturally.
RESERVED_KEYS = ("id", "type", "repo", "origin", "derivedBy")


class KGError(Exception):
    """A refusal, not a crash. Carries an exit code per KG-CONTRACT §8."""

    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- id minting

def iri(kind, name):
    """Mint a node IRI. `name` is percent-escaped whole (never space-substituted), so a package
    like `@scope/pkg` or a title with spaces yields one stable, unambiguous id (KG-CONTRACT §1)."""
    if kind not in KINDS:
        raise KGError("unknown node kind %r" % kind, 3)
    return "%s/%s/%s/%s" % (BASE, REPO, kind, quote(str(name), safe=""))


def _is_internal_iri(v):
    return isinstance(v, str) and v.startswith("%s/%s/" % (BASE, REPO))


def _finding_name(rec):
    """A stable, ephemeral-free finding id: a digest of the fields that define the finding's
    identity (rule, package, cve/cwe, title, location) - not a timestamp or a scan-run counter, so
    the same finding keeps the same node id across re-scans (the baseline-stability discipline)."""
    pkg = rec.get("package") or {}
    key = "|".join(str(x) for x in (
        rec.get("rule", ""), pkg.get("ecosystem", ""), pkg.get("name", ""),
        pkg.get("version", ""), rec.get("cve", ""), rec.get("cwe", ""),
        rec.get("location", ""), rec.get("title", "")))
    return "%s-%s" % (rec.get("rule", "finding"), hashlib.sha256(key.encode()).hexdigest()[:16])


# ---------------------------------------------------------------- normalization

def normalize_depfence(scan_result):
    """A depfence ScanResult -> the unified finding-record list this emitter consumes.

    The record shape (also produced by parsers.sarif_in from semgrep/any SARIF) is:
        {rule, severity, title, detail, confidence, package{ecosystem,name,version}|None,
         cve|None, cwe|None, location|None}
    Keeping ONE shape is what lets a single graph span both the SCA (depfence) and SAST (semgrep)
    producers. Only real findings are emitted; suppressed_findings are left out by design.
    """
    records = []
    for f in getattr(scan_result, "findings", []) or []:
        ft = getattr(f, "finding_type", None)
        sev = getattr(f, "severity", None)
        pkg = getattr(f, "package", None)
        records.append({
            "rule": getattr(ft, "value", str(ft)) if ft is not None else "unknown",
            "severity": getattr(sev, "value", str(sev)) if sev is not None else "info",
            "title": getattr(f, "title", "") or "",
            "detail": (getattr(f, "detail", "") or "")[:500],
            "confidence": float(getattr(f, "confidence", 1.0) or 1.0),
            "package": ({"ecosystem": getattr(pkg, "ecosystem", "") or "",
                         "name": getattr(pkg, "name", "") or "",
                         "version": getattr(pkg, "version", None) or ""} if pkg else None),
            "cve": getattr(f, "cve", None) or None,
            "cwe": getattr(f, "cwe", None) or None,
            "location": None,
        })
    return records


# ---------------------------------------------------------------- graph build

def build_nodes(records):
    """Unified finding-records -> a de-duplicated node list. Never raises on record shape; a record
    missing its rule is still a finding (rule 'unknown'), never dropped silently."""
    by_id = {}

    def _put(node):
        by_id.setdefault(node["id"], node)  # first writer wins; ids are content-stable

    for rec in records:
        rule = rec.get("rule") or "unknown"
        _put({"id": iri("rule", rule), "type": "rule", "repo": REPO,
              "origin": "derived", "derivedBy": DERIVED_BY, "name": rule})

        pkg_iri = None
        pkg = rec.get("package")
        if pkg and (pkg.get("name") or pkg.get("ecosystem")):
            eco = pkg.get("ecosystem") or "unknown"
            pkg_name = "%s:%s@%s" % (eco, pkg.get("name") or "?", pkg.get("version") or "")
            pkg_iri = iri("package", pkg_name)
            _put({"id": iri("ecosystem", eco), "type": "ecosystem", "repo": REPO,
                  "origin": "derived", "derivedBy": DERIVED_BY, "name": eco})
            _put({"id": pkg_iri, "type": "package", "repo": REPO, "origin": "derived",
                  "derivedBy": DERIVED_BY, "name": pkg_name,
                  "in_ecosystem": [iri("ecosystem", eco)]})

        cve_iri = cwe_iri = None
        if rec.get("cve"):
            cve_iri = iri("cve", rec["cve"])
            _put({"id": cve_iri, "type": "cve", "repo": REPO, "origin": "derived",
                  "derivedBy": DERIVED_BY, "name": rec["cve"]})
        if rec.get("cwe"):
            cwe_iri = iri("cwe", rec["cwe"])
            _put({"id": cwe_iri, "type": "cwe", "repo": REPO, "origin": "derived",
                  "derivedBy": DERIVED_BY, "name": rec["cwe"]})

        node = {"id": iri("finding", _finding_name(rec)), "type": "finding", "repo": REPO,
                "origin": "derived", "derivedBy": DERIVED_BY,
                "severity": rec.get("severity") or "info", "title": rec.get("title") or "",
                "confidence": rec.get("confidence", 1.0),
                "detected_by": [iri("rule", rule)]}
        if rec.get("location"):
            node["location"] = rec["location"]
        if pkg_iri:
            node["affects"] = [pkg_iri]
        if cve_iri:
            node["references_cve"] = [cve_iri]
        if cwe_iri:
            node["classified_as"] = [cwe_iri]
        _put(node)

    return sorted(by_id.values(), key=lambda n: n["id"])


def gate(nodes):
    """The four integrity gates (KG-CONTRACT §7). Non-empty list => NOT PROVEN (exit 3)."""
    ids = {n["id"]: n["type"] for n in nodes}
    fails = []
    for n in nodes:
        for rel, val in n.items():
            if rel in RELATION_RANGE:
                want = RELATION_RANGE[rel]
                for t in (val if isinstance(val, list) else [val]):
                    if t not in ids:
                        fails.append("dangling: %s --%s--> %s (no such node)" % (n["id"], rel, t))
                    elif ids[t] != want:
                        fails.append("wrong_kind: %s --%s--> %s (is %s, want %s)"
                                     % (n["id"], rel, t, ids[t], want))
            elif rel in RESERVED_KEYS:
                continue
            else:
                for v in (val if isinstance(val, list) else [val]):
                    if _is_internal_iri(v):
                        fails.append("undeclared_edge: %s.%s -> %s (IRI value on a non-relation "
                                     "property)" % (n["id"], rel, v))
    return sorted(fails)


def build_context():
    ctx = {"@vocab": VOCAB, "id": "@id", "type": "@type"}
    for rel in RELATION_RANGE:
        ctx[rel] = {"@type": "@id"}
    return ctx


def render(nodes):
    graph = {"@context": build_context(), "@graph": nodes}
    return json.dumps(graph, indent=2, sort_keys=True, allow_nan=False) + "\n"


def emit(scan_result):
    """Runtime path: a ScanResult -> validated JSON-LD string. Raises KGError if a gate fails, so a
    non-conformant graph is never emitted as output."""
    nodes = build_nodes(normalize_depfence(scan_result))
    fails = gate(nodes)
    if fails:
        raise KGError("KG NOT PROVEN (%d gate failure(s)): %s" % (len(fails), "; ".join(fails[:3])))
    return render(nodes)


# ---------------------------------------------------------------- fixture gate

def _records_from_fixture(path=FIXTURE_JSON):
    """Load the committed fixture as unified finding-records (a JSON list). Kept as plain records,
    not a live ScanResult, so the emitter gate needs no scanner or network."""
    with open(path) as fh:
        data = json.load(fh)
    return data.get("records", data) if isinstance(data, dict) else data


def _built(path=FIXTURE_JSON):
    nodes = build_nodes(_records_from_fixture(path))
    return nodes, gate(nodes)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = argv[0] if argv else "--check"
    try:
        nodes, fails = _built()
        if fails:
            for f in fails:
                sys.stderr.write("GATE: %s\n" % f)
            return 3
        out = render(nodes)
        if mode == "--write":
            with open(FIXTURE_GRAPH, "w") as fh:
                fh.write(out)
            print("wrote %s (%d nodes)" % (FIXTURE_GRAPH, len(nodes)))
            return 0
        if mode == "--check":
            if not os.path.exists(FIXTURE_GRAPH):
                sys.stderr.write("missing %s (run --write)\n" % FIXTURE_GRAPH)
                return 1
            with open(FIXTURE_GRAPH) as fh:
                if fh.read() != out:
                    sys.stderr.write("STALE: %s does not match the emitter (run --write)\n"
                                     % FIXTURE_GRAPH)
                    return 1
            print("current: %s matches source (%d nodes)" % (FIXTURE_GRAPH, len(nodes)))
            return 0
        sys.stderr.write("usage: kg_out.py [--write|--check]\n")
        return 2
    except KGError as e:
        sys.stderr.write("kg_out: %s\n" % e)
        return e.code


if __name__ == "__main__":
    sys.exit(main())
