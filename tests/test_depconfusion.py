"""Tests for dependency confusion scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.depconfusion import DepConfusionScanner


@pytest.fixture
def scanner():
    return DepConfusionScanner()


@pytest.mark.asyncio
async def test_extra_index_url_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        pyproject = Path(d) / "pyproject.toml"
        pyproject.write_text("""
[tool.uv]
extra-index-url = "https://private.corp/simple"
""")
        findings = await scanner.scan_project_configs(Path(d))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "dependency confusion" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_npmrc_no_always_auth(scanner):
    with tempfile.TemporaryDirectory() as d:
        npmrc = Path(d) / ".npmrc"
        npmrc.write_text("registry=https://private.corp/npm/\n")
        findings = await scanner.scan_project_configs(Path(d))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_npmrc_with_always_auth_clean(scanner):
    with tempfile.TemporaryDirectory() as d:
        npmrc = Path(d) / ".npmrc"
        npmrc.write_text("registry=https://private.corp/npm/\nalways-auth=true\n")
        findings = await scanner.scan_project_configs(Path(d))
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_no_config_clean(scanner):
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project_configs(Path(d))
        assert len(findings) == 0
