"""Tests for Terraform/IaC scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.scanners.terraform_scanner import TerraformScanner


@pytest.fixture
def scanner():
    return TerraformScanner()


def _write_tf(tmpdir: Path, content: str, name: str = "main.tf") -> Path:
    f = tmpdir / name
    f.write_text(content)
    return f


class TestUnpinnedModules:
    @pytest.mark.asyncio
    async def test_github_no_ref(self, scanner):
        tf = '''
module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc"
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert any("npin" in f.title.lower() or "pin" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_git_ref_branch(self, scanner):
        tf = '''
module "vpc" {
  source = "git::https://example.com/module.git?ref=main"
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert any("ref" in f.detail.lower() or "pin" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_pinned_commit_ok(self, scanner):
        tf = '''
module "vpc" {
  source = "git::https://example.com/module.git?ref=abc123def456789012345678901234567890abcd"
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert not any("npin" in f.title.lower() for f in findings)


class TestHttpSources:
    @pytest.mark.asyncio
    async def test_http_source_flagged(self, scanner):
        tf = '''
module "unsafe" {
  source = "http://example.com/module.zip"
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert any("http" in f.title.lower() or "HTTP" in f.title for f in findings)


class TestProviderVersions:
    @pytest.mark.asyncio
    async def test_unpinned_provider(self, scanner):
        tf = '''
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert any("provider" in f.title.lower() or "version" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_pinned_provider_ok(self, scanner):
        tf = '''
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
'''
        with tempfile.TemporaryDirectory() as d:
            _write_tf(Path(d), tf)
            findings = await scanner.scan_project(Path(d))
            assert not any("provider" in f.title.lower() and "npin" in f.title.lower() for f in findings)


class TestScanInterface:
    @pytest.mark.asyncio
    async def test_scan_returns_empty(self, scanner):
        result = await scanner.scan([])
        assert result == []

    @pytest.mark.asyncio
    async def test_no_tf_files_no_findings(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            findings = await scanner.scan_project(Path(d))
            assert findings == []
