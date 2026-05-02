"""Enhanced tests for auto-fix engine — Poetry, Cargo, Go, and mixed projects."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.core.fixer import (
    apply_fixes,
    apply_fixes_cargo_toml,
    apply_fixes_pyproject_toml,
    suggest_go_mod_commands,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fix(ecosystem: str, package: str, fix_version: str, severity: str = "HIGH") -> dict:
    return {
        "package": package,
        "ecosystem": ecosystem,
        "current_version": None,
        "fix_version": fix_version,
        "severity": severity,
        "title": "Test vulnerability",
    }


# ---------------------------------------------------------------------------
# Poetry / pyproject.toml tests
# ---------------------------------------------------------------------------

PYPROJECT_POETRY = """\
[tool.poetry]
name = "myapp"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28"
flask = "~2.3.0"
cryptography = "41.0.0"
boto3 = ">=1.26"

[tool.poetry.dev-dependencies]
pytest = "^7.4"
"""


def test_pyproject_caret_version_updated():
    """Caret constraint: requests = "^2.28" -> "^2.31"."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "pyproject.toml"
        p.write_text(PYPROJECT_POETRY)
        fixes = [_make_fix("pypi", "requests", "2.31.0")]
        changes = apply_fixes_pyproject_toml(p, fixes)

        assert len(changes) == 1
        assert '"^2.31"' in p.read_text()
        assert '"^2.28"' not in p.read_text()
        assert "requests" in changes[0]


def test_pyproject_tilde_version_updated():
    """Tilde constraint: flask = "~2.3.0" -> "^2.4" (caret of fix major.minor)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "pyproject.toml"
        p.write_text(PYPROJECT_POETRY)
        fixes = [_make_fix("pypi", "flask", "2.4.0")]
        changes = apply_fixes_pyproject_toml(p, fixes)

        assert len(changes) == 1
        content = p.read_text()
        assert '"^2.4"' in content
        assert "flask" in changes[0]


def test_pyproject_plain_version_updated():
    """Plain version: cryptography = "41.0.0" -> "42.0.1"."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "pyproject.toml"
        p.write_text(PYPROJECT_POETRY)
        fixes = [_make_fix("pypi", "cryptography", "42.0.1")]
        changes = apply_fixes_pyproject_toml(p, fixes)

        assert len(changes) == 1
        assert '"42.0.1"' in p.read_text()
        assert '"41.0.0"' not in p.read_text()


def test_pyproject_non_pypi_ecosystem_ignored():
    """npm fixes must not touch pyproject.toml entries."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "pyproject.toml"
        p.write_text(PYPROJECT_POETRY)
        fixes = [_make_fix("npm", "requests", "99.0.0")]
        changes = apply_fixes_pyproject_toml(p, fixes)

        assert changes == []
        assert '"^2.28"' in p.read_text()


def test_pyproject_unrelated_packages_untouched():
    """boto3 should remain unchanged when not in fixes list."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "pyproject.toml"
        p.write_text(PYPROJECT_POETRY)
        fixes = [_make_fix("pypi", "requests", "2.31.0")]
        apply_fixes_pyproject_toml(p, fixes)

        content = p.read_text()
        assert '">=1.26"' in content  # boto3 untouched


def test_pyproject_missing_file_returns_empty():
    changes = apply_fixes_pyproject_toml(Path("/tmp/nonexistent_pyproject.toml"), [])
    assert changes == []


# ---------------------------------------------------------------------------
# Cargo.toml tests
# ---------------------------------------------------------------------------

CARGO_TOML = """\
[package]
name = "myapp"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.100"
tokio = { version = "1.20.0", features = ["full"] }
reqwest = "^0.11.0"
log = "=0.4.17"

[dev-dependencies]
criterion = "0.5.0"
"""


def test_cargo_plain_version_updated():
    """serde = "1.0.100" -> "1.0.200"."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("cargo", "serde", "1.0.200")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert len(changes) == 1
        assert '"1.0.200"' in p.read_text()
        assert '"1.0.100"' not in p.read_text()
        assert "serde" in changes[0]


def test_cargo_caret_version_preserved():
    """reqwest = "^0.11.0" -> "^0.12.0" (caret preserved)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("cargo", "reqwest", "0.12.0")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert len(changes) == 1
        assert '"^0.12.0"' in p.read_text()


def test_cargo_pinned_version_preserved():
    """log = "=0.4.17" -> "=0.4.20" (= sigil preserved)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("cargo", "log", "0.4.20")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert len(changes) == 1
        assert '"=0.4.20"' in p.read_text()


def test_cargo_table_dependency_updated():
    """tokio = { version = "1.20.0", ... } -> version updated to "1.35.0"."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("cargo", "tokio", "1.35.0")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert len(changes) == 1
        content = p.read_text()
        assert '"1.35.0"' in content
        assert "tokio" in changes[0]


def test_cargo_dev_dependencies_updated():
    """criterion in [dev-dependencies] should be updated."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("cargo", "criterion", "0.6.0")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert len(changes) == 1
        assert '"0.6.0"' in p.read_text()


def test_cargo_non_cargo_ecosystem_ignored():
    """pypi fixes must not touch Cargo.toml."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "Cargo.toml"
        p.write_text(CARGO_TOML)
        fixes = [_make_fix("pypi", "serde", "9.9.9")]
        changes = apply_fixes_cargo_toml(p, fixes)

        assert changes == []


def test_cargo_missing_file_returns_empty():
    changes = apply_fixes_cargo_toml(Path("/tmp/nonexistent_Cargo.toml"), [])
    assert changes == []


# ---------------------------------------------------------------------------
# go.mod suggestion tests
# ---------------------------------------------------------------------------

GO_MOD = """\
module github.com/example/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.0
\tgolang.org/x/crypto v0.12.0
)
"""


def test_go_mod_returns_shell_commands():
    """Go mod produces 'go get' commands, not file edits."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "go.mod"
        p.write_text(GO_MOD)
        fixes = [_make_fix("go", "golang.org/x/crypto", "0.17.0")]
        cmds = suggest_go_mod_commands(p, fixes)

        assert len(cmds) == 2  # one go get + go mod tidy
        assert "go get golang.org/x/crypto@v0.17.0" in cmds
        assert "go mod tidy" in cmds[1]


def test_go_mod_multiple_packages():
    """Multiple go fixes produce multiple 'go get' commands."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "go.mod"
        p.write_text(GO_MOD)
        fixes = [
            _make_fix("go", "golang.org/x/crypto", "0.17.0"),
            _make_fix("go", "github.com/gin-gonic/gin", "1.9.1"),
        ]
        cmds = suggest_go_mod_commands(p, fixes)

        assert len(cmds) == 3  # 2 go get + go mod tidy
        assert any("golang.org/x/crypto@v0.17.0" in c for c in cmds)
        assert any("github.com/gin-gonic/gin@v1.9.1" in c for c in cmds)
        assert cmds[-1] == "go mod tidy"


def test_go_mod_file_not_edited():
    """The go.mod file content must remain unchanged (we only suggest commands)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "go.mod"
        p.write_text(GO_MOD)
        original = p.read_text()
        fixes = [_make_fix("go", "golang.org/x/crypto", "0.17.0")]
        suggest_go_mod_commands(p, fixes)

        assert p.read_text() == original


def test_go_mod_non_go_fixes_ignored():
    """Non-go fixes produce no commands."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "go.mod"
        p.write_text(GO_MOD)
        fixes = [_make_fix("cargo", "serde", "1.0.200")]
        cmds = suggest_go_mod_commands(p, fixes)

        assert cmds == []


def test_go_mod_missing_file_returns_empty():
    cmds = suggest_go_mod_commands(Path("/tmp/nonexistent_go.mod"), [])
    assert cmds == []


# ---------------------------------------------------------------------------
# apply_fixes (orchestrator) — mixed project tests
# ---------------------------------------------------------------------------

def test_apply_fixes_mixed_project():
    """Project with requirements.txt + pyproject.toml + Cargo.toml + go.mod."""
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)

        (proj / "requirements.txt").write_text("requests==2.28.0\nflask>=2.0\n")
        (proj / "pyproject.toml").write_text(
            "[tool.poetry.dependencies]\nrequests = \"^2.28\"\ncryptography = \"41.0.0\"\n"
        )
        (proj / "Cargo.toml").write_text(
            "[dependencies]\nserde = \"1.0.100\"\n"
        )
        (proj / "go.mod").write_text(
            "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.12.0\n"
        )

        fixes = [
            _make_fix("pypi", "requests", "2.31.0"),
            _make_fix("cargo", "serde", "1.0.200"),
            _make_fix("go", "golang.org/x/crypto", "0.17.0"),
        ]
        descriptions = apply_fixes(proj, fixes)

        # Should have changes from requirements.txt
        assert any("[requirements.txt]" in d for d in descriptions)
        # Should have changes from pyproject.toml
        assert any("[pyproject.toml]" in d for d in descriptions)
        # Should have changes from Cargo.toml
        assert any("[Cargo.toml]" in d for d in descriptions)
        # Should have go mod suggestions
        assert any("[go.mod]" in d for d in descriptions)
        assert any("go get golang.org/x/crypto@v0.17.0" in d for d in descriptions)


def test_apply_fixes_only_present_manifests():
    """apply_fixes skips manifests that don't exist."""
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)
        (proj / "Cargo.toml").write_text("[dependencies]\nserde = \"1.0.100\"\n")

        fixes = [
            _make_fix("cargo", "serde", "1.0.200"),
            _make_fix("pypi", "requests", "2.31.0"),   # no requirements.txt
            _make_fix("npm", "lodash", "4.17.21"),      # no package.json
        ]
        descriptions = apply_fixes(proj, fixes)

        assert any("[Cargo.toml]" in d for d in descriptions)
        assert not any("[requirements.txt]" in d for d in descriptions)
        assert not any("[package.json]" in d for d in descriptions)


def test_apply_fixes_empty_fixes_list():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "go.mod").write_text("module example.com/app\ngo 1.21\n")
        descriptions = apply_fixes(Path(d), [])
        assert descriptions == []


def test_apply_fixes_returns_strings():
    """Return type is list[str]."""
    with tempfile.TemporaryDirectory() as d:
        proj = Path(d)
        (proj / "requirements.txt").write_text("requests==2.28.0\n")
        fixes = [_make_fix("pypi", "requests", "2.31.0")]
        result = apply_fixes(proj, fixes)
        assert isinstance(result, list)
        assert all(isinstance(s, str) for s in result)
