"""Tests for the PreToolUse author-gate hook."""

from __future__ import annotations

from depfence.integrations import pretooluse_hook as hook

REAL = "1" * 40
FAB = "f" * 40
WF = ".github/workflows/ci.yml"


def _wf_line(repo: str, sha: str) -> str:
    return f"jobs:\n  b:\n    steps:\n      - uses: {repo}@{sha} # v4\n"


def _fake_resolve(mapping):
    return lambda repo, sha: mapping.get(sha, "exists")


def _patch(monkeypatch, mapping):
    monkeypatch.setattr(hook, "_resolve", _fake_resolve(mapping))
    monkeypatch.delenv("DEPFENCE_PRETOOLUSE", raising=False)
    monkeypatch.delenv("DEPFENCE_PRETOOLUSE_BLOCK", raising=False)


def test_non_file_tool_is_noop(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    assert hook.main({"tool_name": "Bash", "tool_input": {"command": "ls"}}) == {}


def test_non_workflow_path_is_noop(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": "src/app.py", "content": _wf_line("a/b", FAB)}})
    assert out == {}


def test_write_fabricated_warns_by_default(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("actions/checkout", FAB)}})
    assert "systemMessage" in out
    assert "hookSpecificOutput" not in out  # warn never auto-approves / never denies
    assert "fabricated" in out["systemMessage"].lower()


def test_write_fabricated_blocks_when_enabled(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    monkeypatch.setenv("DEPFENCE_PRETOOLUSE_BLOCK", "1")
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("actions/checkout", FAB)}})
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert FAB[:10] in hso["permissionDecisionReason"]


def test_real_sha_is_noop(monkeypatch):
    _patch(monkeypatch, {REAL: "exists"})
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("actions/checkout", REAL)}})
    assert out == {}


def test_edit_uses_new_string_not_content(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    # Edit has new_string, NOT content — content must be ignored.
    out = hook.main({"tool_name": "Edit", "tool_input": {
        "file_path": WF,
        "old_string": "x",
        "new_string": _wf_line("actions/checkout", FAB),
        "content": "irrelevant",
    }})
    assert "systemMessage" in out


def test_multiedit_joins_edits(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    out = hook.main({"tool_name": "MultiEdit", "tool_input": {
        "file_path": WF,
        "edits": [{"old_string": "a", "new_string": "noop"},
                  {"old_string": "b", "new_string": _wf_line("actions/checkout", FAB)}],
    }})
    assert "systemMessage" in out


def test_kill_switch_disables(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_commit"})
    monkeypatch.setenv("DEPFENCE_PRETOOLUSE", "0")
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("actions/checkout", FAB)}})
    assert out == {}


def test_fabricated_repo_message(monkeypatch):
    _patch(monkeypatch, {FAB: "fabricated_repo"})
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("nope/ghost", FAB)}})
    assert "repository does not exist" in out["systemMessage"]


def test_unverified_is_advisory_not_block(monkeypatch):
    _patch(monkeypatch, {FAB: "unverified"})
    monkeypatch.setenv("DEPFENCE_PRETOOLUSE_BLOCK", "1")  # even in block mode, unverified never denies
    out = hook.main({"tool_name": "Write",
                     "tool_input": {"file_path": WF, "content": _wf_line("actions/checkout", FAB)}})
    assert "hookSpecificOutput" not in out
    assert "could not verify" in out["systemMessage"].lower()


def test_gh_api_ladder_parses_status(monkeypatch):
    # Exercise _resolve -> _gh_api with a fake gh returning structured statuses.
    def fake_gh(path):
        if path == f"repos/x/y/commits/{FAB}":
            return (1, "422")
        return (0, "200")
    monkeypatch.setattr(hook, "_gh_api", fake_gh)
    assert hook._resolve("x/y", FAB) == "fabricated_commit"
    assert hook._resolve("x/y", REAL) == "exists"
