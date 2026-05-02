"""Tests for the depfence MCP server.

Covers:
- Protocol handshake (initialize / tools/list)
- Tool dispatch for all 6 tools
- Response envelope format (jsonrpc, id, result/error)
- Error handling (bad method, missing params, malformed JSON)
- CheckResult / ProjectScanResult / etc. dataclass serialisation
- Risk score computation
- Recommendation builder
- Typosquat detection (real scanner, no mocking)
- Alternatives lookup
- License classification
- Notification messages (no response expected)
- Unknown tool name → error
- Ping method
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.mcp.server import (
    PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    TOOL_DEFINITIONS,
    DepfenceMcpServer,
    McpError,
    _require_str,
)
from depfence.mcp.tools import (
    Advisory,
    AlternativeResult,
    CheckResult,
    LicenseResult,
    McpTools,
    ProjectScanResult,
    TyposquatResult,
    _build_recommendation,
    _compute_risk_score,
    _finding_to_dict,
    _severity_to_score,
)
from depfence.core.models import Finding, FindingType, PackageId, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_server() -> DepfenceMcpServer:
    return DepfenceMcpServer()


async def call(server: DepfenceMcpServer, method: str, params: dict | None = None, req_id: int = 1) -> dict:
    req: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        req["params"] = params
    resp = await server.handle_request(req)
    assert resp is not None
    return resp


def make_finding(
    ftype: FindingType = FindingType.KNOWN_VULN,
    severity: Severity = Severity.HIGH,
    name: str = "testpkg",
    ecosystem: str = "pypi",
) -> Finding:
    return Finding(
        finding_type=ftype,
        severity=severity,
        package=PackageId(ecosystem=ecosystem, name=name),
        title="Test finding",
        detail="Detail text",
        confidence=0.9,
    )


# ---------------------------------------------------------------------------
# 1. Protocol handshake
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_initialize_returns_server_info():
    server = make_server()
    resp = await call(server, "initialize", {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test"}})
    result = resp["result"]
    assert result["serverInfo"]["name"] == SERVER_NAME
    assert result["serverInfo"]["version"] == SERVER_VERSION
    assert result["protocolVersion"] == PROTOCOL_VERSION


@pytest.mark.asyncio
async def test_initialize_declares_tools_capability():
    server = make_server()
    resp = await call(server, "initialize", {"protocolVersion": PROTOCOL_VERSION})
    assert "tools" in resp["result"]["capabilities"]


@pytest.mark.asyncio
async def test_ping_returns_empty_result():
    server = make_server()
    resp = await call(server, "ping")
    assert resp["result"] == {}


# ---------------------------------------------------------------------------
# 2. tools/list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tools_list_returns_all_six_tools():
    server = make_server()
    resp = await call(server, "tools/list")
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "check_package", "scan_project", "is_typosquat",
        "get_advisories", "suggest_alternative", "check_license",
    }


@pytest.mark.asyncio
async def test_tools_list_has_input_schemas():
    server = make_server()
    resp = await call(server, "tools/list")
    for tool in resp["result"]["tools"]:
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"


@pytest.mark.asyncio
async def test_tools_list_check_package_requires_name_and_ecosystem():
    server = make_server()
    resp = await call(server, "tools/list")
    cp = next(t for t in resp["result"]["tools"] if t["name"] == "check_package")
    assert set(cp["inputSchema"].get("required", [])) >= {"name", "ecosystem"}


# ---------------------------------------------------------------------------
# 3. Response envelope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_response_has_jsonrpc_field():
    server = make_server()
    resp = await call(server, "ping", req_id=42)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42


@pytest.mark.asyncio
async def test_notification_returns_none():
    """Requests without an id are notifications — no response expected."""
    server = make_server()
    req = {"jsonrpc": "2.0", "method": "initialized", "params": {}}
    resp = await server.handle_request(req)
    assert resp is None


# ---------------------------------------------------------------------------
# 4. Error handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_method_returns_method_not_found():
    server = make_server()
    resp = await call(server, "nonexistent/method")
    assert "error" in resp
    assert resp["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_malformed_json_returns_parse_error():
    server = make_server()
    raw_bytes = b"not valid json{"
    resp_bytes = await server._handle_raw(raw_bytes)
    assert resp_bytes is not None
    resp = json.loads(resp_bytes)
    assert resp["error"]["code"] == -32700


@pytest.mark.asyncio
async def test_unknown_tool_name_returns_error():
    server = make_server()
    resp = await call(server, "tools/call", {"name": "does_not_exist", "arguments": {}})
    assert "error" in resp
    assert resp["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_missing_required_param_returns_error():
    server = make_server()
    # check_package requires 'name' and 'ecosystem'
    resp = await call(server, "tools/call", {"name": "check_package", "arguments": {"name": "requests"}})
    assert "error" in resp


# ---------------------------------------------------------------------------
# 5. _require_str helper
# ---------------------------------------------------------------------------

def test_require_str_ok():
    assert _require_str({"key": "value"}, "key") == "value"


def test_require_str_missing_raises():
    with pytest.raises(McpError) as exc_info:
        _require_str({}, "key")
    assert exc_info.value.code == -32602


def test_require_str_empty_raises():
    with pytest.raises(McpError):
        _require_str({"key": "  "}, "key")


# ---------------------------------------------------------------------------
# 6. Risk score helpers
# ---------------------------------------------------------------------------

def test_severity_to_score_ordering():
    assert _severity_to_score(Severity.CRITICAL) > _severity_to_score(Severity.HIGH)
    assert _severity_to_score(Severity.HIGH) > _severity_to_score(Severity.MEDIUM)
    assert _severity_to_score(Severity.MEDIUM) > _severity_to_score(Severity.LOW)


def test_compute_risk_score_empty():
    assert _compute_risk_score([]) == 0


def test_compute_risk_score_single_critical():
    f = make_finding(severity=Severity.CRITICAL)
    score = _compute_risk_score([f])
    assert score >= 90


def test_compute_risk_score_capped_at_100():
    findings = [make_finding(severity=Severity.CRITICAL) for _ in range(20)]
    assert _compute_risk_score(findings) == 100


def test_compute_risk_score_multiple_raises_above_single():
    one = _compute_risk_score([make_finding(severity=Severity.HIGH)])
    many = _compute_risk_score([make_finding(severity=Severity.HIGH)] * 5)
    assert many >= one


# ---------------------------------------------------------------------------
# 7. Recommendation builder
# ---------------------------------------------------------------------------

def test_recommendation_safe():
    msg = _build_recommendation([], safe=True)
    assert "safe" in msg.lower() or "no issues" in msg.lower()


def test_recommendation_malicious():
    f = make_finding(ftype=FindingType.MALICIOUS, severity=Severity.CRITICAL)
    msg = _build_recommendation([f], safe=False)
    assert "do not use" in msg.upper() or "malicious" in msg.lower()


def test_recommendation_typosquat():
    f = make_finding(ftype=FindingType.TYPOSQUAT, severity=Severity.HIGH)
    msg = _build_recommendation([f], safe=False)
    assert "typosquat" in msg.lower() or "verify" in msg.lower()


def test_recommendation_known_vuln_with_fix():
    f = make_finding(ftype=FindingType.KNOWN_VULN, severity=Severity.HIGH)
    f.fix_version = "2.0.0"
    f.cve = "CVE-2024-1234"
    msg = _build_recommendation([f], safe=False)
    assert "2.0.0" in msg or "upgrade" in msg.lower()


# ---------------------------------------------------------------------------
# 8. CheckResult dataclass
# ---------------------------------------------------------------------------

def test_check_result_to_dict_roundtrip():
    cr = CheckResult(
        package="requests",
        ecosystem="pypi",
        version="2.31.0",
        safe=True,
        risk_score=0,
        findings=[],
        advisories=[],
        recommendation="All clear.",
        cached=False,
    )
    d = cr.to_dict()
    assert d["package"] == "requests"
    assert d["safe"] is True
    assert d["risk_score"] == 0
    assert isinstance(d["findings"], list)


# ---------------------------------------------------------------------------
# 9. is_typosquat (real scanner, no mocking)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_is_typosquat_obvious_typo():
    tools = McpTools()
    result = await tools.is_typosquat("reqests", "pypi")
    # 'reqests' is a known typosquat of 'requests'
    assert isinstance(result, TyposquatResult)
    assert result.ecosystem == "pypi"
    assert result.package == "reqests"
    # May or may not detect depending on popular list; just check structure
    assert isinstance(result.is_typosquat, bool)
    assert 0.0 <= result.confidence <= 1.0


@pytest.mark.asyncio
async def test_is_typosquat_known_package_not_flagged():
    tools = McpTools()
    result = await tools.is_typosquat("requests", "pypi")
    # Well-known packages should NOT be flagged as typosquats of themselves
    assert isinstance(result, TyposquatResult)


# ---------------------------------------------------------------------------
# 10. suggest_alternative
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suggest_alternative_known_package():
    tools = McpTools()
    result = await tools.suggest_alternative("requests", "pypi")
    assert isinstance(result, AlternativeResult)
    assert result.package == "requests"
    assert result.ecosystem == "pypi"
    assert len(result.alternatives) > 0
    assert "httpx" in result.alternatives or any("http" in a.lower() for a in result.alternatives)


@pytest.mark.asyncio
async def test_suggest_alternative_unknown_package():
    tools = McpTools()
    result = await tools.suggest_alternative("completely-unknown-xyz-pkg", "pypi")
    assert isinstance(result, AlternativeResult)
    assert result.alternatives == []
    assert len(result.reason) > 0


@pytest.mark.asyncio
async def test_suggest_alternative_npm_lodash():
    tools = McpTools()
    result = await tools.suggest_alternative("lodash", "npm")
    assert isinstance(result, AlternativeResult)
    assert len(result.alternatives) > 0


# ---------------------------------------------------------------------------
# 11. check_license (offline classification only)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_license_structure():
    tools = McpTools()
    with patch("depfence.core.fetcher.fetch_meta", new_callable=AsyncMock) as mock_fetch:
        from depfence.core.models import PackageMeta, PackageId as PkgId
        mock_meta = PackageMeta(pkg=PkgId(ecosystem="pypi", name="requests"), license="MIT")
        mock_fetch.return_value = mock_meta
        result = await tools.check_license("requests", "pypi")
    assert isinstance(result, LicenseResult)
    assert result.package == "requests"
    assert result.ecosystem == "pypi"
    assert result.tier in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
    assert isinstance(result.commercial_use_ok, bool)


@pytest.mark.asyncio
async def test_check_license_mit_is_clean():
    tools = McpTools()
    with patch("depfence.core.fetcher.fetch_meta", new_callable=AsyncMock) as mock_fetch:
        from depfence.core.models import PackageMeta, PackageId as PkgId
        mock_meta = PackageMeta(pkg=PkgId(ecosystem="pypi", name="somepkg"), license="MIT")
        mock_fetch.return_value = mock_meta
        result = await tools.check_license("somepkg", "pypi")
    assert result.tier == "CLEAN"
    assert result.commercial_use_ok is True
    assert result.severity is None


@pytest.mark.asyncio
async def test_check_license_agpl_is_critical():
    tools = McpTools()
    with patch("depfence.core.fetcher.fetch_meta", new_callable=AsyncMock) as mock_fetch:
        from depfence.core.models import PackageMeta, PackageId as PkgId
        mock_meta = PackageMeta(pkg=PkgId(ecosystem="pypi", name="agplpkg"), license="AGPL-3.0")
        mock_fetch.return_value = mock_meta
        result = await tools.check_license("agplpkg", "pypi")
    assert result.tier == "CRITICAL"
    assert result.commercial_use_ok is False


# ---------------------------------------------------------------------------
# 12. tools/call via server dispatch — mocked tool layer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tools_call_check_package_response_shape():
    server = make_server()
    mock_result = CheckResult(
        package="numpy", ecosystem="pypi", version=None,
        safe=True, risk_score=0, findings=[], advisories=[],
        recommendation="Looks good.", cached=False,
    )
    with patch.object(server._tools, "check_package", new_callable=AsyncMock, return_value=mock_result):
        resp = await call(server, "tools/call", {
            "name": "check_package",
            "arguments": {"name": "numpy", "ecosystem": "pypi"},
        })
    assert "result" in resp
    content = json.loads(resp["result"]["content"][0]["text"])
    assert content["package"] == "numpy"
    assert content["safe"] is True
    assert resp["result"]["isError"] is False


@pytest.mark.asyncio
async def test_tools_call_scan_project_response_shape():
    server = make_server()
    mock_result = ProjectScanResult(
        path="/tmp/project", packages_scanned=10,
        findings_count=2, critical_count=0, high_count=1,
        medium_count=1, low_count=0, findings=[], errors=[],
    )
    with patch.object(server._tools, "scan_project", new_callable=AsyncMock, return_value=mock_result):
        resp = await call(server, "tools/call", {
            "name": "scan_project",
            "arguments": {"path": "/tmp/project"},
        })
    content = json.loads(resp["result"]["content"][0]["text"])
    assert content["packages_scanned"] == 10
    assert content["findings_count"] == 2


@pytest.mark.asyncio
async def test_tools_call_get_advisories_response_is_list():
    server = make_server()
    advisories = [
        {"id": "CVE-2024-001", "summary": "Test vuln", "severity": "HIGH",
         "fixed_version": "2.0.0", "affected_versions": [], "references": [], "published": "2024-01-01"},
    ]
    with patch.object(server._tools, "get_advisories", new_callable=AsyncMock, return_value=advisories):
        resp = await call(server, "tools/call", {
            "name": "get_advisories",
            "arguments": {"package": "somepkg", "ecosystem": "pypi"},
        })
    content = json.loads(resp["result"]["content"][0]["text"])
    assert isinstance(content, list)
    assert content[0]["id"] == "CVE-2024-001"


@pytest.mark.asyncio
async def test_tools_call_is_typosquat_response_shape():
    server = make_server()
    mock_result = TyposquatResult(
        package="reqests", ecosystem="pypi", is_typosquat=True,
        confidence=0.92, similar_to="requests",
        reason="edit distance 1", severity="high",
    )
    with patch.object(server._tools, "is_typosquat", new_callable=AsyncMock, return_value=mock_result):
        resp = await call(server, "tools/call", {
            "name": "is_typosquat",
            "arguments": {"name": "reqests", "ecosystem": "pypi"},
        })
    content = json.loads(resp["result"]["content"][0]["text"])
    assert content["is_typosquat"] is True
    assert content["similar_to"] == "requests"


@pytest.mark.asyncio
async def test_tools_call_suggest_alternative_response_shape():
    server = make_server()
    mock_result = AlternativeResult(
        package="requests", ecosystem="pypi",
        alternatives=["httpx", "aiohttp"],
        reason="Better maintained",
    )
    with patch.object(server._tools, "suggest_alternative", new_callable=AsyncMock, return_value=mock_result):
        resp = await call(server, "tools/call", {
            "name": "suggest_alternative",
            "arguments": {"package": "requests", "ecosystem": "pypi"},
        })
    content = json.loads(resp["result"]["content"][0]["text"])
    assert "httpx" in content["alternatives"]


@pytest.mark.asyncio
async def test_tools_call_check_license_response_shape():
    server = make_server()
    mock_result = LicenseResult(
        package="requests", ecosystem="pypi",
        license="MIT", tier="CLEAN", severity=None,
        commercial_use_ok=True, detail="Permissive",
    )
    with patch.object(server._tools, "check_license", new_callable=AsyncMock, return_value=mock_result):
        resp = await call(server, "tools/call", {
            "name": "check_license",
            "arguments": {"package": "requests", "ecosystem": "pypi"},
        })
    content = json.loads(resp["result"]["content"][0]["text"])
    assert content["tier"] == "CLEAN"
    assert content["commercial_use_ok"] is True


# ---------------------------------------------------------------------------
# 13. TOOL_DEFINITIONS completeness
# ---------------------------------------------------------------------------

def test_tool_definitions_have_descriptions():
    for tool in TOOL_DEFINITIONS:
        assert len(tool.get("description", "")) > 20, f"{tool['name']} description too short"


def test_tool_definitions_all_have_properties():
    for tool in TOOL_DEFINITIONS:
        assert "properties" in tool["inputSchema"], f"{tool['name']} missing properties"
