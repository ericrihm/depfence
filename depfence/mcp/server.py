"""Official MCP SDK server for depfence.

The SDK owns protocol negotiation and stdio framing. A single server supports
both current stateless clients and legacy clients using ``initialize``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Literal

from mcp.server import MCPServer
from mcp.types import LATEST_PROTOCOL_VERSION

from depfence import __version__
from depfence.mcp.tools import (
    AdvisoryResult,
    AlternativeResult,
    CheckResult,
    LicenseResult,
    McpTools,
    ProjectScanResult,
    TyposquatResult,
)

log = logging.getLogger(__name__)

PROTOCOL_VERSION = LATEST_PROTOCOL_VERSION
SERVER_NAME = "depfence"
SERVER_VERSION = __version__

Ecosystem = Literal["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"]


def create_server(
    *,
    root: Path | None = None,
    tool_provider: McpTools | None = None,
) -> MCPServer:
    """Create an SDK server whose project scans are contained beneath *root*."""
    tools = tool_provider or McpTools(root=root)
    server = MCPServer(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "Check packages and projects with depfence. Project scan paths must "
            "be relative to the server's configured root."
        ),
    )

    @server.tool()
    async def check_package(
        name: str,
        ecosystem: Ecosystem,
        version: str | None = None,
    ) -> CheckResult:
        """Check a package before installing it for security and supply-chain risk."""
        return await tools.check_package(name=name, ecosystem=ecosystem, version=version)

    @server.tool()
    async def scan_project(path: str | None = None) -> ProjectScanResult:
        """Scan a project below the configured root; the path must be relative."""
        return await tools.scan_project(path=path)

    @server.tool()
    async def is_typosquat(name: str, ecosystem: Ecosystem) -> TyposquatResult:
        """Check whether a package name resembles a well-known package."""
        return await tools.is_typosquat(name=name, ecosystem=ecosystem)

    @server.tool()
    async def get_advisories(
        package: str,
        ecosystem: Ecosystem,
        version: str | None = None,
    ) -> AdvisoryResult:
        """Fetch known OSV advisories for a package."""
        return await tools.get_advisories(package=package, ecosystem=ecosystem, version=version)

    @server.tool()
    async def suggest_alternative(package: str, ecosystem: Ecosystem) -> AlternativeResult:
        """Suggest indexed, better-maintained alternatives to a package."""
        return await tools.suggest_alternative(package=package, ecosystem=ecosystem)

    @server.tool()
    async def check_license(
        package: str,
        ecosystem: Ecosystem,
        version: str | None = None,
    ) -> LicenseResult:
        """Check a package license for commercial-use compatibility."""
        return await tools.check_license(package=package, ecosystem=ecosystem, version=version)

    return server


class DepfenceMcpServer:
    """Compatibility facade around the official SDK server.

    New callers should use :func:`create_server` with :class:`mcp.Client`.
    ``handle_request`` remains only for older in-process integrations; tool
    execution still goes through SDK validation and result conversion.
    """

    def __init__(self, *, root: Path | None = None) -> None:
        self._tools = McpTools(root=root)
        self.server = create_server(tool_provider=self._tools)

    async def run_stdio(self) -> None:
        await self.server.run_stdio_async()

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        if request_id is None:
            return None

        method = request.get("method")
        try:
            if method == "initialize":
                result: dict[str, Any] = {
                    "protocolVersion": request.get("params", {}).get(
                        "protocolVersion", PROTOCOL_VERSION
                    ),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                sdk_tools = await self.server.list_tools()
                result = {
                    "tools": [
                        tool.model_dump(by_alias=True, mode="json", exclude_none=True)
                        for tool in sdk_tools
                    ]
                }
            elif method == "tools/call":
                params = request.get("params") or {}
                call_result = await self.server.call_tool(
                    params.get("name", ""), params.get("arguments") or {}
                )
                result = call_result.model_dump(by_alias=True, mode="json", exclude_none=True)
            else:
                return _legacy_error(request_id, -32601, f"Method not found: {method}")
        except Exception as exc:  # SDK validation/tool errors are fail-closed.
            log.debug("MCP compatibility request failed", exc_info=True)
            result = {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _legacy_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


async def _run_stdio() -> None:
    await create_server().run_stdio_async()


async def _self_test(package: str, ecosystem: Ecosystem) -> tuple[list[str], dict[str, Any]]:
    """Exercise the server through the official in-memory modern client."""
    from mcp import Client

    server = create_server()
    async with Client(server, mode="auto") as client:
        listed = await client.list_tools()
        called = await client.call_tool(
            "check_package", {"name": package, "ecosystem": ecosystem}
        )
    names = [tool.name for tool in listed.tools]
    if called.is_error or called.structured_content is None:
        text = "\n".join(getattr(block, "text", "") for block in called.content)
        raise RuntimeError(text or "check_package returned no structured result")
    return names, called.structured_content


def main() -> None:
    """Run the depfence MCP stdio server."""
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(_run_stdio())
