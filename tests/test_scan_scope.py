"""Tests for bounded scan scope and partial-scan error primitives."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from depfence.core.scan_scope import (
    InputLimitError,
    MalformedInputError,
    PartialScanError,
    ScanIncompleteError,
    ScanScope,
    ScopeEscapeError,
)


# -- Exception hierarchy --


def test_exception_hierarchy() -> None:
    """All scan errors derive from ScanIncompleteError → RuntimeError."""
    assert issubclass(ScopeEscapeError, ScanIncompleteError)
    assert issubclass(InputLimitError, ScanIncompleteError)
    assert issubclass(MalformedInputError, ScanIncompleteError)
    assert issubclass(PartialScanError, ScanIncompleteError)
    assert issubclass(ScanIncompleteError, RuntimeError)


def test_partial_scan_error_preserves_findings() -> None:
    findings = [{"rule": "DF-FONT-001"}, {"rule": "DF-PDF-001"}]
    err = PartialScanError("incomplete coverage", findings)
    assert str(err) == "incomplete coverage"
    assert err.findings == findings
    assert err.findings is not findings  # defensive copy


# -- ScanScope construction --


def test_scope_valid_directory() -> None:
    with tempfile.TemporaryDirectory() as d:
        scope = ScanScope(root=Path(d))
        assert scope.root == Path(d).resolve()


def test_scope_non_directory_raises() -> None:
    with tempfile.NamedTemporaryFile() as f:
        with pytest.raises(ScanIncompleteError, match="not a directory"):
            ScanScope(root=Path(f.name))


def test_scope_negative_limits_raise() -> None:
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="positive"):
            ScanScope(root=Path(d), max_file_bytes=0)
        with pytest.raises(ValueError, match="positive"):
            ScanScope(root=Path(d), max_files=-1)


# -- Path protocol --


def test_fspath_returns_root_string() -> None:
    with tempfile.TemporaryDirectory() as d:
        scope = ScanScope(root=Path(d))
        assert os.fspath(scope) == os.fspath(scope.root)


def test_truediv_joins_path() -> None:
    with tempfile.TemporaryDirectory() as d:
        scope = ScanScope(root=Path(d))
        result: Path = scope / "subdir" / "file.txt"
        assert result == scope.root / "subdir" / "file.txt"


# -- resolve() --


def test_resolve_relative_path() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "test.txt").write_text("content")
        scope = ScanScope(root=Path(d))
        resolved = scope.resolve("test.txt")
        assert resolved == Path(d).resolve() / "test.txt"


def test_resolve_rejects_escape() -> None:
    """An escape attempt raises ScopeEscapeError (non-strict) or ScanIncompleteError (strict)."""
    with tempfile.TemporaryDirectory() as d:
        scope = ScanScope(root=Path(d))
        # With must_exist=False, resolve normalizes and checks containment
        with pytest.raises(ScopeEscapeError, match="escapes project root"):
            scope.resolve("../../etc/passwd", must_exist=False)


def test_resolve_rejects_symlink() -> None:
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "real.txt"
        target.write_text("real")
        link = Path(d) / "link.txt"
        link.symlink_to(target)
        scope = ScanScope(root=Path(d))
        with pytest.raises(ScopeEscapeError, match="symlink"):
            scope.resolve("link.txt")


def test_resolve_none_returns_root() -> None:
    with tempfile.TemporaryDirectory() as d:
        scope = ScanScope(root=Path(d))
        assert scope.resolve() == scope.root


# -- read_text() / read_bytes() --


def test_read_text_within_limits() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "small.txt").write_text("hello")
        scope = ScanScope(root=Path(d))
        assert scope.read_text("small.txt") == "hello"


def test_read_text_exceeds_limit() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "big.txt").write_text("x" * 100)
        scope = ScanScope(root=Path(d), max_file_bytes=50)
        with pytest.raises(InputLimitError, match="exceeds.*50 byte limit"):
            scope.read_text("big.txt")


def test_read_bytes_within_limits() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "data.bin").write_bytes(b"\x00\x01\x02")
        scope = ScanScope(root=Path(d))
        assert scope.read_bytes("data.bin") == b"\x00\x01\x02"


def test_read_bytes_custom_limit() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "data.bin").write_bytes(b"x" * 200)
        scope = ScanScope(root=Path(d))
        with pytest.raises(InputLimitError):
            scope.read_bytes("data.bin", max_bytes=100)


# -- parse_json() / parse_yaml() --


def test_parse_json_valid() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "config.json").write_text(json.dumps({"key": "value"}))
        scope = ScanScope(root=Path(d))
        result: dict = scope.parse_json("config.json")
        assert result == {"key": "value"}


def test_parse_json_malformed() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "bad.json").write_text("{not json")
        scope = ScanScope(root=Path(d))
        with pytest.raises(MalformedInputError, match="malformed JSON"):
            scope.parse_json("bad.json")


def test_parse_json_non_dict() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "list.json").write_text("[1, 2, 3]")
        scope = ScanScope(root=Path(d))
        with pytest.raises(MalformedInputError, match="expected a JSON object"):
            scope.parse_json("list.json")


# -- walk_files() --


def test_walk_files_yields_regular_files() -> None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "a.txt").write_text("a")
        sub = Path(d) / "sub"
        sub.mkdir()
        (sub / "b.txt").write_text("b")
        scope = ScanScope(root=Path(d))
        files = list(scope.walk_files())
        names = {f.name for f in files}
        assert "a.txt" in names
        assert "b.txt" in names


def test_walk_files_rejects_symlinked_dir() -> None:
    with tempfile.TemporaryDirectory() as d:
        real = Path(d) / "real"
        real.mkdir()
        (real / "secret.txt").write_text("secret")
        (Path(d) / "link").symlink_to(real)
        scope = ScanScope(root=Path(d))
        with pytest.raises(ScopeEscapeError, match="symlinked scanner directory"):
            list(scope.walk_files())


def test_walk_files_enforces_max_files() -> None:
    with tempfile.TemporaryDirectory() as d:
        for i in range(10):
            (Path(d) / f"file_{i}.txt").write_text(str(i))
        scope = ScanScope(root=Path(d), max_files=5)
        with pytest.raises(InputLimitError, match="file limit"):
            list(scope.walk_files())
