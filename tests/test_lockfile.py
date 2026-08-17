"""Tests for lockfile parsing."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.core.lockfile import UnsupportedLockfileError, detect_ecosystem, parse_lockfile
from depfence.core.models import PackageId


def test_detect_npm_lockfile():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text("{}")
        result = detect_ecosystem(Path(d))
        assert len(result) == 1
        assert result[0][0] == "npm"


def test_detect_pypi_requirements():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "requirements.txt").write_text("requests==2.31.0")
        result = detect_ecosystem(Path(d))
        assert len(result) == 1
        assert result[0][0] == "pypi"


def test_detect_multiple():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text("{}")
        (Path(d) / "requirements.txt").write_text("")
        result = detect_ecosystem(Path(d))
        assert len(result) == 2


def test_parse_package_lock_v3():
    lock_data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "myapp", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/express": {"version": "4.18.2"},
        },
    }
    with tempfile.TemporaryDirectory() as d:
        lock_path = Path(d) / "package-lock.json"
        lock_path.write_text(json.dumps(lock_data))
        packages = parse_lockfile("npm", lock_path)
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert "lodash" in names
        assert "express" in names


def test_parse_requirements_txt():
    content = "requests==2.31.0\nflask>=2.0\n# comment\nnumpy~=1.26.0"
    with tempfile.TemporaryDirectory() as d:
        req_path = Path(d) / "requirements.txt"
        req_path.write_text(content)
        packages = parse_lockfile("pypi", req_path)
        assert len(packages) == 3
        names = {p.name for p in packages}
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names


def test_parse_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        result = detect_ecosystem(Path(d))
        assert result == []


def test_parse_standard_pylock_and_named_variant(tmp_path: Path):
    lock = tmp_path / "pylock.dev.toml"
    lock.write_text('lock-version = "1.0"\n[[packages]]\nname = "requests"\nversion = "2.32.0"\n')

    assert ("pypi", lock) in detect_ecosystem(tmp_path)
    assert parse_lockfile("pypi", lock)[0].version == "2.32.0"


def test_parse_bun_text_lock(tmp_path: Path):
    lock = tmp_path / "bun.lock"
    lock.write_text('''{"packages":{"is-even":["is-even@1.0.0","",{},""]}}''')

    assert parse_lockfile("npm", lock) == [
        PackageId("npm", "is-even", "1.0.0")
    ]


def test_binary_bun_lock_is_unproven_not_heuristically_parsed(tmp_path: Path):
    lock = tmp_path / "bun.lockb"
    lock.write_bytes(b"BUN\x00plausible-package\x00")
    with pytest.raises(UnsupportedLockfileError, match="binary format"):
        parse_lockfile("npm", lock)


def test_pylock_requires_supported_lock_version(tmp_path: Path):
    lock = tmp_path / "pylock.toml"
    lock.write_text('[[packages]]\nname = "requests"\nversion = "2.32.0"\n')
    with pytest.raises(UnsupportedLockfileError, match="missing"):
        parse_lockfile("pypi", lock)


def test_parse_npm_shrinkwrap_and_deno_npm_packages(tmp_path: Path):
    shrinkwrap = tmp_path / "npm-shrinkwrap.json"
    shrinkwrap.write_text(json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}}))
    deno = tmp_path / "deno.lock"
    deno.write_text(json.dumps({"packages": {"npm": {"lodash@4.17.21": {}}}}))

    assert parse_lockfile("npm", shrinkwrap)[0].name == "lodash"
    assert parse_lockfile("npm", deno)[0].version == "4.17.21"
