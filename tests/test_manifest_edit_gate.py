"""Tests for the manifest edit gate PreToolUse hook."""

from __future__ import annotations

import pytest

from depfence.integrations import manifest_edit_gate as gate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(file_path: str, content: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": file_path, "content": content}}


def _edit(file_path: str, new_string: str) -> dict:
    return {"tool_name": "Edit", "tool_input": {
        "file_path": file_path, "old_string": "x", "new_string": new_string,
    }}


def _multiedit(file_path: str, *new_strings: str) -> dict:
    return {"tool_name": "MultiEdit", "tool_input": {
        "file_path": file_path,
        "edits": [{"old_string": "x", "new_string": s} for s in new_strings],
    }}


def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEPFENCE_MANIFEST_GATE", raising=False)
    monkeypatch.delenv("DEPFENCE_MANIFEST_GATE_BLOCK", raising=False)


# ---------------------------------------------------------------------------
# Basic plumbing
# ---------------------------------------------------------------------------

def test_non_file_tool_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tools other than Write/Edit/MultiEdit are always ignored."""
    _clean(monkeypatch)
    out = gate.main({"tool_name": "Bash", "tool_input": {"command": "npm install loadsh"}})
    assert out == {}


def test_non_manifest_file_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A file that is not a recognised manifest basename is ignored instantly."""
    _clean(monkeypatch)
    # Even if the content looks like a package.json dependency, the path wins.
    out = gate.main(_edit("src/app.py", '"loadsh": "^4.0.0"'))
    assert out == {}


def test_disable_mode_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEPFENCE_MANIFEST_GATE=0 suppresses all output including typosquats."""
    monkeypatch.setenv("DEPFENCE_MANIFEST_GATE", "0")
    monkeypatch.delenv("DEPFENCE_MANIFEST_GATE_BLOCK", raising=False)
    out = gate.main(_edit("package.json", '"loadsh": "^4.0.0"'))
    assert out == {}


# ---------------------------------------------------------------------------
# npm / package.json
# ---------------------------------------------------------------------------

def test_package_json_safe_lodash_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """lodash is in the popular list — exact match → no flag."""
    _clean(monkeypatch)
    out = gate.main(_edit("package.json", '"lodash": "^4.17.21"'))
    assert out == {}


def test_package_json_loadsh_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    """loadsh is a transposition of lodash (distance=2, confidence≈0.75)."""
    _clean(monkeypatch)
    out = gate.main(_edit("package.json", '"loadsh": "^4.0.0"'))
    assert "systemMessage" in out, "expected a warn-only systemMessage"
    assert "hookSpecificOutput" not in out, "warn mode must not emit a permission decision"
    msg = out["systemMessage"]
    assert "loadsh" in msg
    assert "lodash" in msg


def test_package_json_loadsh_blocks_when_gate_block_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEPFENCE_MANIFEST_GATE_BLOCK=1 escalates to permissionDecision: deny."""
    monkeypatch.delenv("DEPFENCE_MANIFEST_GATE", raising=False)
    monkeypatch.setenv("DEPFENCE_MANIFEST_GATE_BLOCK", "1")
    out = gate.main(_edit("package.json", '"loadsh": "^4.0.0"'))
    hso = out.get("hookSpecificOutput", {})
    assert hso.get("hookEventName") == "PreToolUse"
    assert hso.get("permissionDecision") == "deny"
    reason = hso.get("permissionDecisionReason", "")
    assert "loadsh" in reason


def test_package_json_safe_package_not_blocked_in_block_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """A legitimate package produces no output even in BLOCK mode."""
    monkeypatch.delenv("DEPFENCE_MANIFEST_GATE", raising=False)
    monkeypatch.setenv("DEPFENCE_MANIFEST_GATE_BLOCK", "1")
    out = gate.main(_edit("package.json", '"lodash": "^4.17.21"'))
    assert out == {}


# ---------------------------------------------------------------------------
# pypi / requirements.txt
# ---------------------------------------------------------------------------

def test_requirements_txt_reqeusts_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    """reqeusts is a transposition of requests (distance=2, confidence≈0.75)."""
    _clean(monkeypatch)
    content = "flask>=2.0.0\nreqeusts>=2.28.0\nnumpy>=1.24.0\n"
    out = gate.main(_edit("requirements.txt", content))
    assert "systemMessage" in out
    msg = out["systemMessage"]
    assert "reqeusts" in msg
    assert "requests" in msg


def test_requirements_txt_comments_and_flags_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    """Comment lines, -r flags, and blank lines are not extracted as packages."""
    _clean(monkeypatch)
    content = "# a comment\n-r base.txt\n--index-url https://pypi.org/simple\n\n"
    out = gate.main(_edit("requirements.txt", content))
    assert out == {}


# ---------------------------------------------------------------------------
# Cargo.toml
# ---------------------------------------------------------------------------

def test_cargo_toml_write_checks_dependencies_section(monkeypatch: pytest.MonkeyPatch) -> None:
    """Write to Cargo.toml scans [dependencies] for typosquats.

    'flaks' is a transposition of 'flask' (in POPULAR_PYPI; Cargo ecosystem
    falls back to the combined npm+pypi list).
    """
    _clean(monkeypatch)
    content = (
        "[package]\n"
        'name = "my-crate"\n'
        'version = "0.1.0"\n\n'
        "[dependencies]\n"
        'serde = "1.0"\n'
        'flaks = "0.11"\n'
    )
    out = gate.main(_write("Cargo.toml", content))
    assert "systemMessage" in out
    assert "flaks" in out["systemMessage"]


def test_cargo_toml_clean_dependencies_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Cargo.toml with no suspicious crate names produces no output."""
    _clean(monkeypatch)
    content = (
        "[dependencies]\n"
        'serde = { version = "1.0", features = ["derive"] }\n'
        'tokio = { version = "1", features = ["full"] }\n'
    )
    out = gate.main(_write("Cargo.toml", content))
    assert out == {}


# ---------------------------------------------------------------------------
# MultiEdit
# ---------------------------------------------------------------------------

def test_multiedit_checks_all_new_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    """MultiEdit scans every new_string, not just the first."""
    _clean(monkeypatch)
    out = gate.main(_multiedit(
        "package.json",
        '"lodash": "^4.17.21"',   # safe — no flag
        '"loadsh": "^4.0.0"',     # typosquat — should flag
    ))
    assert "systemMessage" in out
    assert "loadsh" in out["systemMessage"]
