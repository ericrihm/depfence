"""Tests for the knowledge-graph reporter (depfence/reporters/kg_out.py) and the SARIF normalizer
(depfence/parsers/sarif_in.py).

Mirrors the red-then-green discipline of the macmon reference emitter's gate: the committed graph
must be byte-identical to what the emitter produces (a drift makes CI red), each of the integrity
gates must actually fire on a planted violation (so the gate is not decorative), and the SARIF
path must turn a semgrep-shaped result into a graph node (proving the second producer unifies).

Runnable two ways: `pytest tests/test_kg_out.py`, or standalone `python tests/test_kg_out.py`
(stdlib only) so the emitter can be verified without the dev-deps installed.
"""

from __future__ import annotations

from depfence.parsers import sarif_in
from depfence.reporters import kg_out


def test_fixture_graph_matches_emitter():
    """The committed kg_fixture.jsonld is byte-identical to the emitter's output. A source drift
    (edit the fixture without re-running --write) makes this red."""
    nodes, fails = kg_out._built()
    assert fails == [], fails
    import os

    with open(kg_out.FIXTURE_GRAPH) as fh:
        assert fh.read() == kg_out.render(nodes)
    assert os.path.exists(kg_out.FIXTURE_GRAPH)
    assert nodes and {node["lineage"] for node in nodes} == {"synthetic"}


def test_runtime_graph_is_observed_not_synthetic():
    class _Result:
        findings = []
        packages_scanned = 1
        errors = []
        scanner_errors = {}
        scanner_coverage = {}

    # An empty graph has no nodes to label, so exercise the record boundary directly too.
    emitted = kg_out.emit(_Result())
    assert '"@graph": []' in emitted
    assert '"schema_version": "depfence.kg/v1"' in emitted
    nodes = kg_out.build_nodes([{"rule": "observed-rule", "title": "observed"}])
    assert {node["lineage"] for node in nodes} == {"observed"}


def test_private_overlay_is_a_digest_only_non_authoritative_observation(tmp_path):
    import hashlib
    import json

    from depfence.core.local_state import PrivateState
    from depfence.core.models import Finding, FindingType, ScanResult, Severity

    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")
    result = ScanResult(target=str(project), ecosystem="project", packages_scanned=1)
    result.findings.append(
        Finding(
            FindingType.PROMPT_INJECTION,
            Severity.HIGH,
            "project:secret-document",
            "private title must not be federated",
            "private detail must not be federated",
        )
    )

    destination = kg_out.write_private_overlay(result, state=state)
    encoded = destination.read_text()
    document = json.loads(encoded)
    node = document["@graph"][0]
    assert node["id"].startswith("https://kg.local/local-observation/depfence/")
    assert node["observedSubject"] == kg_out.iri("product", "depfence")
    assert node["evidenceDigest"] == "sha256:" + hashlib.sha256(
        kg_out.emit(result).encode()
    ).hexdigest()
    assert node["findingCount"] == 1
    assert "private title" not in encoded
    assert "private detail" not in encoded
    assert "secret-document" not in encoded


def test_incomplete_scan_is_not_emitted_as_an_empty_clean_graph():
    import pytest

    class _Failed:
        findings = []
        packages_scanned = 0
        errors = ["all scanners crashed"]
        scanner_errors = {"secrets": "worker exited"}
        scanner_coverage = {"secrets": "INDETERMINATE"}

    with pytest.raises(kg_out.KGError, match="KG NOT PROVEN"):
        kg_out.emit(_Failed())


def test_string_resource_keeps_subject_edge():
    from depfence.core.models import Finding, FindingType, ScanResult, Severity

    result = ScanResult(target=".", ecosystem="project", packages_scanned=1)
    result.findings.append(
        Finding(
            FindingType.PROMPT_INJECTION,
            Severity.HIGH,
            "docker:Dockerfile",
            "Injected instructions",
            "redacted",
        )
    )
    nodes = kg_out.build_nodes(kg_out.normalize_depfence(result))
    finding = next(node for node in nodes if node["type"] == "finding")
    package = next(node for node in nodes if node["type"] == "package")
    assert finding["affects"] == [package["id"]]


def test_gate_catches_foreign_nested_undeclared_edge():
    nodes = kg_out.build_nodes([{"rule": "r", "severity": "low", "title": "t"}])
    finding = next(node for node in nodes if node["type"] == "finding")
    finding["mystery"] = {"@id": "https://kg.local/atlas/decision/secret"}
    assert any(failure.startswith("undeclared_edge:") for failure in kg_out.gate(nodes))


def test_nonfinite_graph_is_a_named_refusal():
    import pytest

    nodes = kg_out.build_nodes(
        [{"rule": "r", "severity": "low", "title": "t", "confidence": float("nan")}]
    )
    with pytest.raises(kg_out.KGError, match="not finite"):
        kg_out.render(nodes)


def test_duplicate_identity_refuses_divergent_claims():
    import pytest

    records = [
        {"rule": "same", "title": "same", "severity": "low"},
        {"rule": "same", "title": "same", "severity": "critical"},
    ]
    with pytest.raises(kg_out.KGError, match="divergent duplicate node identity"):
        kg_out.build_nodes(records)


def test_duplicate_identity_accepts_identical_claims():
    record = {"rule": "same", "title": "same", "severity": "low"}
    once = kg_out.build_nodes([record])
    twice = kg_out.build_nodes([record, dict(record)])
    assert twice == once


def test_gate_catches_dangling_edge():
    """A finding pointing at a rule node that was never emitted is a `dangling` gate failure. If
    this did not fire, the referential-integrity gate would be decorative."""
    good = kg_out.build_nodes([{"rule": "r", "severity": "low", "title": "t"}])
    assert kg_out.gate(good) == []
    # plant a dangling edge: a finding detected_by a rule id that is not a node
    broken = [n for n in good if n["type"] != "rule"]  # drop the rule node
    fails = kg_out.gate(broken)
    assert any(f.startswith("dangling:") for f in fails), fails


def test_gate_catches_wrong_kind():
    """An edge whose target exists but is the wrong node kind is `wrong_kind`."""
    nodes = kg_out.build_nodes([{"rule": "r", "severity": "low", "title": "t"}])
    # retype the rule node as an ecosystem -> detected_by now points at the wrong kind
    for n in nodes:
        if n["type"] == "rule":
            n["type"] = "ecosystem"
    fails = kg_out.gate(nodes)
    assert any(f.startswith("wrong_kind:") for f in fails), fails


def test_emit_refuses_nonconformant_graph():
    """emit() raises rather than returning a graph that fails a gate - a non-conformant graph is
    never handed out as output."""
    import pytest  # only needed for this one assertion under pytest

    class _Bad:
        findings = None
        packages_scanned = 1
        errors = []
        scanner_errors = {}
        scanner_coverage = {}

    # monkeypatch build_nodes to yield a dangling edge, then emit must raise
    orig = kg_out.build_nodes
    try:
        kg_out.build_nodes = lambda recs, **kwargs: [
            {
                "id": kg_out.iri("finding", "x"),
                "type": "finding",
                "repo": kg_out.REPO,
                "origin": "derived",
                "derivedBy": kg_out.DERIVED_BY,
                "detected_by": [kg_out.iri("rule", "missing")],
            }
        ]
        with pytest.raises(kg_out.KGError):
            kg_out.emit(_Bad())
    finally:
        kg_out.build_nodes = orig


def test_sarif_normalizes_to_a_finding_node():
    """A semgrep-shaped SARIF result becomes a finding record -> a finding node with a
    detected_by->rule edge and a location; SAST findings carry no `affects` (no package)."""
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep"}},
                "results": [
                    {
                        "ruleId": "python.exec",
                        "level": "error",
                        "message": {"text": "use of exec()"},
                        "properties": {"cwe": "CWE-95"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    recs, fails = sarif_in.normalize_sarif(sarif)
    assert fails == []
    assert len(recs) == 1 and recs[0]["rule"] == "python.exec"
    assert recs[0]["location"] == "app.py:42" and recs[0]["cwe"] == "CWE-95"
    assert recs[0]["package"] is None
    nodes = kg_out.build_nodes(recs)
    assert kg_out.gate(nodes) == []
    kinds = sorted(n["type"] for n in nodes)
    assert "finding" in kinds and "rule" in kinds and "cwe" in kinds
    finding = next(n for n in nodes if n["type"] == "finding")
    assert "affects" not in finding and finding["detected_by"]


def test_sarif_malformed_is_a_named_failure_not_a_silent_zero():
    """A SARIF that is not an object / has no runs returns a named failure - never (silently) an
    empty finding set that would read as 'nothing wrong'."""
    recs, fails = sarif_in.normalize_sarif([])
    assert recs == [] and fails, "malformed SARIF must name a failure"
    recs, fails = sarif_in.normalize_sarif({"version": "2.1.0"})  # no runs
    assert fails


def test_render_is_deterministic():
    recs = [
        {
            "rule": "r",
            "severity": "high",
            "title": "t",
            "package": {"ecosystem": "npm", "name": "x", "version": "1"},
        }
    ]
    n = kg_out.build_nodes(recs)
    assert kg_out.render(n) == kg_out.render(kg_out.build_nodes(recs))


# ---- standalone runner (no pytest needed) ---------------------------------


def _standalone():
    checks = []

    def run(name, fn):
        try:
            fn()
            checks.append((name, True, ""))
        except Exception as e:  # noqa: BLE001 - a test runner reports, does not raise
            checks.append((name, False, f"{type(e).__name__}: {e}"))

    run("fixture matches emitter", test_fixture_graph_matches_emitter)
    run("gate catches dangling", test_gate_catches_dangling_edge)
    run("gate catches wrong_kind", test_gate_catches_wrong_kind)
    run("sarif -> finding node", test_sarif_normalizes_to_a_finding_node)
    run("sarif malformed -> failure", test_sarif_malformed_is_a_named_failure_not_a_silent_zero)
    run("render deterministic", test_render_is_deterministic)
    for name, ok, detail in checks:
        print(f"  {'ok' if ok else 'FAIL':<4} {name:<32} {detail}")
    return all(ok for _, ok, _ in checks)


if __name__ == "__main__":
    import sys

    sys.exit(0 if _standalone() else 1)
