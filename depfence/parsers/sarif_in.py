"""sarif_in.py — normalize any SARIF 2.1.0 log into depfence's unified finding-record shape.

This is the piece that lets a SECOND producer — the semgrep CLI (SAST), or any tool that emits
SARIF — feed the same knowledge graph as depfence's own scans (:mod:`depfence.reporters.kg_out`).
Both converge on SARIF; nothing consumed it before. Each SARIF ``result`` becomes one finding
record ``{rule, severity, title, detail, confidence, package, cve, cwe, location}`` — the exact
shape ``kg_out.build_nodes`` ingests, so ``semgrep scan --sarif ... | kg_out`` and
``depfence scan --format kg`` land in one graph.

Doctrine: a malformed SARIF is a **failure**, never a silent empty. :func:`normalize_sarif` returns
``(records, failures)``; a caller that gets a non-empty ``failures`` must treat the graph as NOT
PROVEN (KG-CONTRACT §6 three-value returns), exactly as a scanner that "found nothing" must be
distinguished from one that "couldn't look".

SAST findings have no dependency, so ``package`` is ``None`` (``kg_out`` simply omits the ``affects``
edge). CWE is lifted from ``properties.cwe`` or a ``CWE-\\d+`` tag when the producer supplies it
(semgrep does); CVE likewise from ``properties.cve``/tags. Line/file becomes ``location`` evidence.
"""

from __future__ import annotations

import json
import re

# SARIF result.level -> depfence Severity value. `error` is the strongest SARIF has; map to `high`
# (not `critical` - SARIF cannot express critical, and inventing it would overstate).
_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_CWE = re.compile(r"CWE-\d+", re.I)
_CVE = re.compile(r"CVE-\d{4}-\d+", re.I)


def _first_location(result):
    """`<uri>:<startLine>` from the first physicalLocation, or None. Never raises."""
    for loc in (result.get("locations") or []):
        phys = (loc or {}).get("physicalLocation") or {}
        uri = ((phys.get("artifactLocation") or {}).get("uri"))
        if uri:
            line = ((phys.get("region") or {}).get("startLine"))
            return "%s:%s" % (uri, line) if line is not None else uri
    return None


def _tag_hits(result, pattern):
    """Scan result.properties (cwe/cve fields + tags) for a pattern. SAST tools stash CWE/CVE in
    properties rather than dedicated SARIF fields, so this is where they live."""
    props = result.get("properties") or {}
    blob = " ".join(str(props.get(k, "")) for k in ("cwe", "cve", "tags")) + " " + json.dumps(
        props.get("tags") or [])
    m = pattern.search(blob)
    return m.group(0).upper() if m else None


def normalize_sarif(sarif):
    """A parsed SARIF 2.1.0 dict -> (records, failures). Every `result` across every `run` becomes
    one unified finding record. `failures` names anything that could not be parsed."""
    records, failures = [], []
    if not isinstance(sarif, dict):
        return [], ["sarif root is not an object (%s)" % type(sarif).__name__]
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return [], ["sarif has no `runs` array"]
    for ri, run in enumerate(runs):
        tool = (((run or {}).get("tool") or {}).get("driver") or {}).get("name") or "sarif"
        results = (run or {}).get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            failures.append("run[%d].results is not a list" % ri)
            continue
        for result in results:
            if not isinstance(result, dict):
                failures.append("run[%d] has a non-object result" % ri)
                continue
            rule = result.get("ruleId") or ("%s-unruled" % tool)
            msg = ((result.get("message") or {}).get("text")) or rule
            records.append({
                "rule": str(rule),
                "severity": _LEVEL.get(str(result.get("level") or "warning").lower(), "medium"),
                "title": str(msg).splitlines()[0][:160] if msg else str(rule),
                "detail": str(msg)[:500],
                "confidence": 0.9,
                "package": None,                 # SAST: no dependency; kg_out omits `affects`
                "cve": _tag_hits(result, _CVE),
                "cwe": _tag_hits(result, _CWE),
                "location": _first_location(result),
            })
    return records, failures


def load_sarif(path_or_text):
    """Parse SARIF from a file path or a raw JSON string. Returns (records, failures); a JSON
    parse error is a named failure, not an exception."""
    try:
        if "\n" in path_or_text or path_or_text.lstrip().startswith("{"):
            data = json.loads(path_or_text)
        else:
            with open(path_or_text) as fh:
                data = json.load(fh)
    except (OSError, ValueError) as e:
        return [], ["could not read SARIF: %s" % e]
    return normalize_sarif(data)


if __name__ == "__main__":  # `semgrep scan --sarif ... | python -m depfence.parsers.sarif_in`
    import sys
    from depfence.reporters import kg_out
    raw = sys.stdin.read()
    recs, fails = load_sarif(raw)
    if fails:
        sys.stderr.write("SARIF NOT PROVEN: %s\n" % "; ".join(fails[:3]))
        sys.exit(3)
    nodes = kg_out.build_nodes(recs)
    gate_fails = kg_out.gate(nodes)
    if gate_fails:
        sys.stderr.write("KG NOT PROVEN: %s\n" % "; ".join(gate_fails[:3]))
        sys.exit(3)
    sys.stdout.write(kg_out.render(nodes))
