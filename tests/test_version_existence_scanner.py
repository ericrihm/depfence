"""Tests for the package-version existence scanner."""

from __future__ import annotations

import re

import httpx

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.scanners import version_existence_scanner as mod
from depfence.scanners.version_existence_scanner import VersionExistenceScanner


def _meta(eco: str, name: str, version: str | None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(eco, name, version))


def _client(npm_versions=None, pypi_releases=None, pypi_perversion=None,
            npm_status=200, pypi_status=200) -> httpx.AsyncClient:
    npm_versions = npm_versions or {}
    pypi_releases = pypi_releases or {}
    pypi_perversion = pypi_perversion or {}

    def handler(req: httpx.Request) -> httpx.Response:
        host, path = req.url.host, req.url.path
        if host == "registry.npmjs.org":
            if npm_status != 200:
                return httpx.Response(npm_status, json={})
            return httpx.Response(200, json={"versions": {v: {} for v in npm_versions}})
        if host == "pypi.org":
            m = re.match(r"/pypi/([^/]+)/([^/]+)/json$", path)  # per-version
            if m:
                ver = m.group(2)
                return httpx.Response(200 if ver in pypi_perversion else 404, json={})
            if re.match(r"/pypi/([^/]+)/json$", path):
                if pypi_status != 200:
                    return httpx.Response(pypi_status, json={})
                return httpx.Response(200, json={"releases": {v: [] for v in pypi_releases}})
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _patch(monkeypatch, client, enabled=True):
    monkeypatch.setattr(mod, "_get_client", lambda: client)
    monkeypatch.setattr(mod, "fetch_enabled", lambda: enabled)
    monkeypatch.delenv("DEPFENCE_VERSION_EXISTENCE", raising=False)


async def _scan(metas, client, monkeypatch, enabled=True):
    _patch(monkeypatch, client, enabled)
    return await VersionExistenceScanner().scan(metas)


async def test_npm_existing_version_ok(monkeypatch):
    c = _client(npm_versions={"1.2.3", "1.2.4"})
    out = await _scan([_meta("npm", "left-pad", "1.2.3")], c, monkeypatch)
    assert out == []


async def test_npm_missing_version_critical(monkeypatch):
    c = _client(npm_versions={"1.2.3"})
    out = await _scan([_meta("npm", "left-pad", "9.9.9")], c, monkeypatch)
    fab = [f for f in out if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1 and fab[0].severity == Severity.CRITICAL
    assert fab[0].metadata["fault"] == "version_never_published"


async def test_npm_package_missing(monkeypatch):
    c = _client(npm_status=404)
    out = await _scan([_meta("npm", "totally-not-real-pkg", "1.0.0")], c, monkeypatch)
    fab = [f for f in out if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1 and fab[0].metadata["fault"] == "package_missing"


async def test_pypi_existing_in_releases_ok(monkeypatch):
    c = _client(pypi_releases={"2.31.0"})
    out = await _scan([_meta("pypi", "requests", "2.31.0")], c, monkeypatch)
    assert out == []


async def test_pypi_yanked_is_real(monkeypatch):
    # Present in releases (even if yanked) => exists, never flagged.
    c = _client(pypi_releases={"2.31.0", "0.0.1"})
    out = await _scan([_meta("pypi", "requests", "0.0.1")], c, monkeypatch)
    assert out == []


async def test_pypi_canonical_equivalence(monkeypatch):
    # Pin "1.0" exists as "1.0.0" in releases => canonical match, no finding.
    c = _client(pypi_releases={"1.0.0"})
    out = await _scan([_meta("pypi", "foo", "1.0")], c, monkeypatch)
    assert out == []


async def test_pypi_missing_requires_both_signals(monkeypatch):
    # Absent from releases AND per-version 404 => fabricated.
    c = _client(pypi_releases={"1.0.0"}, pypi_perversion=set())
    out = await _scan([_meta("pypi", "foo", "9.9.9")], c, monkeypatch)
    fab = [f for f in out if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1 and fab[0].metadata["fault"] == "version_never_published"


async def test_pypi_stale_release_map_not_flagged(monkeypatch):
    # Not in releases map, but per-version endpoint 200 => real (map was stale).
    c = _client(pypi_releases={"1.0.0"}, pypi_perversion={"1.1.0"})
    out = await _scan([_meta("pypi", "foo", "1.1.0")], c, monkeypatch)
    assert out == []


async def test_non_exact_pins_skipped_no_network(monkeypatch):
    # Ranges/wildcards/urls/git/None must be skipped with NO network call.
    # Use a client whose handler raises if hit, to prove no request is made.
    def boom(req):
        raise AssertionError(f"unexpected network call: {req.url}")
    c = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    metas = [
        _meta("pypi", "a", ">=1.0"), _meta("pypi", "b", None), _meta("npm", "c", "^1.2.3"),
        _meta("npm", "d", "~1.0.0"), _meta("npm", "e", "latest"), _meta("npm", "f", "1.x"),
        _meta("npm", "g", "npm:other@1.0.0"), _meta("pypi", "h", "git+https://x/y"),
        _meta("npm", "i", "1.* "), _meta("pypi", "j", "1 || 2"),
    ]
    out = await _scan(metas, c, monkeypatch)
    assert out == []


async def test_kill_switch(monkeypatch):
    c = _client(npm_status=404)
    _patch(monkeypatch, c)
    monkeypatch.setenv("DEPFENCE_VERSION_EXISTENCE", "0")
    out = await VersionExistenceScanner().scan([_meta("npm", "x", "9.9.9")])
    assert out == []


async def test_offline_no_fetch_returns_empty(monkeypatch):
    def boom(req):
        raise AssertionError("network under --no-fetch")
    c = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    out = await _scan([_meta("npm", "x", "9.9.9")], c, monkeypatch, enabled=False)
    assert out == []


async def test_network_error_is_unverified(monkeypatch):
    def boom(req):
        raise httpx.ConnectError("down")
    c = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    out = await _scan([_meta("npm", "x", "1.0.0")], c, monkeypatch)
    assert any(f.finding_type == FindingType.UNVERIFIED_REF for f in out)
    assert not any(f.finding_type == FindingType.FABRICATED_REF for f in out)


async def test_dedup_same_pin(monkeypatch):
    c = _client(npm_versions={"1.0.0"})
    out = await _scan([_meta("npm", "x", "9.9.9"), _meta("npm", "x", "9.9.9")], c, monkeypatch)
    fab = [f for f in out if f.finding_type == FindingType.FABRICATED_REF]
    assert len(fab) == 1
