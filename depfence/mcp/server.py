"""depfence MCP server — JSON-RPC over stdio, Model Context Protocol compliant.

Wire protocol
-------------
Each message is a newline-delimited JSON object.  The server reads one
request per line from stdin and writes one response per line to stdout.
Errors are written to stderr.

MCP spec: https://spec.modelcontextprotocol.io/
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "depfence"
SERVER_VERSION = "0.5.0"

# Tool definitions — used for tools/list response
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "check_package",
        "description": (
            "Instant security check for a single package. "
            "Returns risk score, findings (typosquats, CVEs, dep-confusion, malicious patterns), "
            "and a plain-English recommendation. Use this before recommending any package."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Package name (e.g. 'requests', 'lodash')",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem: npm, pypi, cargo, go, maven, nuget, rubygems",
                    "enum": ["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
                },
                "version": {
                    "type": "string",
                    "description": "Optional specific version to check (e.g. '1.2.3')",
                },
            },
            "required": ["name", "ecosystem"],
        },
    },
    {
        "name": "scan_project",
        "description": (
            "Full security scan of a project directory. "
            "Discovers lockfiles (package-lock.json, requirements.txt, Cargo.lock, go.sum, etc.) "
            "and runs all depfence scanners. Returns aggregated findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the project directory. Defaults to current directory.",
                },
            },
        },
    },
    {
        "name": "is_typosquat",
        "description": (
            "Check whether a package name looks like a typosquat of a well-known package. "
            "Returns confidence score and the package it resembles."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Package name to check",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem: npm, pypi, cargo, go",
                    "enum": ["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
                },
            },
            "required": ["name", "ecosystem"],
        },
    },
    {
        "name": "get_advisories",
        "description": (
            "Fetch known CVEs and security advisories for a package from OSV.dev. "
            "Returns advisory IDs, severity, fixed versions, and references."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem: npm, pypi, cargo, go, maven, nuget, rubygems",
                    "enum": ["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
                },
                "version": {
                    "type": "string",
                    "description": "Optional version to narrow results",
                },
            },
            "required": ["package", "ecosystem"],
        },
    },
    {
        "name": "suggest_alternative",
        "description": (
            "Suggest safer or better-maintained alternatives for a package. "
            "Useful when a package is flagged as risky or deprecated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem: npm, pypi, cargo, go",
                    "enum": ["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
                },
            },
            "required": ["package", "ecosystem"],
        },
    },
    {
        "name": "check_license",
        "description": (
            "License compliance check for a package. "
            "Returns the license tier (CLEAN, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN) "
            "and whether commercial use is permitted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name",
                },
                "ecosystem": {
                    "type": "string",
                    "description": "Package ecosystem: npm, pypi, cargo, go",
                    "enum": ["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
                },
                "version": {
                    "type": "string",
                    "description": "Optional version",
                },
            },
            "required": ["package", "ecosystem"],
        },
    },
]


# ---------------------------------------------------------------------------
# DepfenceMcpServer
# ---------------------------------------------------------------------------

class DepfenceMcpServer:
    """Async MCP server backed by depfence scanners.

    Reads JSON-RPC requests from *reader* and writes responses to *writer*.
    The default implementation uses sys.stdin/sys.stdout (stdio transport).
    """

    def __init__(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        from depfence.mcp.tools import McpTools
        self._tools = McpTools()
        self._reader = reader
        self._writer = writer
        self._initialized = False

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def run_stdio(self) -> None:
        """Run the server reading from stdin and writing to stdout."""
        loop = asyncio.get_event_loop()
        # Wrap synchronous stdin/stdout in async streams
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        write_transport, write_protocol = await loop.connect_write_pipe(
            lambda: asyncio.BaseProtocol(), sys.stdout.buffer
        )

        async def _write(data: bytes) -> None:
            write_transport.write(data)

        await self._serve(reader, _write)

    async def run_with_streams(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Run the server with explicit stream objects (for testing)."""
        async def _write(data: bytes) -> None:
            writer.write(data)
            await writer.drain()

        await self._serve(reader, _write)

    # ------------------------------------------------------------------
    # Core serve loop
    # ------------------------------------------------------------------

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        write: Any,  # Callable[[bytes], Coroutine]
    ) -> None:
        while True:
            try:
                line = await reader.readline()
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            response = await self._handle_raw(line)
            if response is not None:
                await write(response + b"\n")

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    async def _handle_raw(self, raw: bytes) -> bytes | None:
        """Parse raw bytes, dispatch, and serialise the response."""
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as exc:
            return self._error_response(None, -32700, f"Parse error: {exc}")

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}

        try:
            result = await self._dispatch(method, params)
        except McpError as exc:
            return self._error_response(req_id, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001
            log.exception("Unhandled error in %s", method)
            return self._error_response(req_id, -32603, f"Internal error: {exc}")

        # Notifications (no id) don't need a response
        if req_id is None:
            return None

        return self._ok_response(req_id, result)

    async def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        """Route a method name to the appropriate handler."""
        if method == "initialize":
            return self._handle_initialize(params)
        if method == "initialized":
            self._initialized = True
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            return self._handle_tools_list()
        if method == "tools/call":
            return await self._handle_tools_call(params)
        if method == "notifications/initialized":
            return None
        raise McpError(-32601, f"Method not found: {method}")

    # ------------------------------------------------------------------
    # Handler implementations
    # ------------------------------------------------------------------

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        self._initialized = True
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    def _handle_tools_list(self) -> dict[str, Any]:
        return {"tools": TOOL_DEFINITIONS}

    async def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        tool_name: str = params.get("name", "")
        args: dict[str, Any] = params.get("arguments") or {}

        if tool_name == "check_package":
            result = await self._tools.check_package(
                name=_require_str(args, "name"),
                ecosystem=_require_str(args, "ecosystem"),
                version=args.get("version"),
            )
            content = result.to_dict()

        elif tool_name == "scan_project":
            result = await self._tools.scan_project(
                path=args.get("path"),
            )
            content = result.to_dict()

        elif tool_name == "is_typosquat":
            result = await self._tools.is_typosquat(
                name=_require_str(args, "name"),
                ecosystem=_require_str(args, "ecosystem"),
            )
            content = result.to_dict()

        elif tool_name == "get_advisories":
            content = await self._tools.get_advisories(
                package=_require_str(args, "package"),
                ecosystem=_require_str(args, "ecosystem"),
                version=args.get("version"),
            )

        elif tool_name == "suggest_alternative":
            result = await self._tools.suggest_alternative(
                package=_require_str(args, "package"),
                ecosystem=_require_str(args, "ecosystem"),
            )
            content = result.to_dict()

        elif tool_name == "check_license":
            result = await self._tools.check_license(
                package=_require_str(args, "package"),
                ecosystem=_require_str(args, "ecosystem"),
                version=args.get("version"),
            )
            content = result.to_dict()

        else:
            raise McpError(-32602, f"Unknown tool: {tool_name}")

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(content, indent=2),
                }
            ],
            "isError": False,
        }

    # ------------------------------------------------------------------
    # Response builders
    # ------------------------------------------------------------------

    @staticmethod
    def _ok_response(req_id: Any, result: Any) -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }).encode()

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str) -> bytes:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }).encode()

    # ------------------------------------------------------------------
    # Convenience: process a single request dict (useful for testing)
    # ------------------------------------------------------------------

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single request dict and return the response dict (or None)."""
        raw = json.dumps(request).encode()
        resp_bytes = await self._handle_raw(raw)
        if resp_bytes is None:
            return None
        return json.loads(resp_bytes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class McpError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _require_str(args: dict[str, Any], key: str) -> str:
    val = args.get(key)
    if not isinstance(val, str) or not val.strip():
        raise McpError(-32602, f"Invalid params: '{key}' is required and must be a non-empty string")
    return val


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

async def _self_test() -> None:
    """Run a quick self-test to verify tools work end-to-end."""
    import sys

    server = DepfenceMcpServer()

    print("depfence MCP self-test", file=sys.stderr)
    print("=" * 40, file=sys.stderr)

    # 1. initialize
    resp = await server.handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test"}},
    })
    assert resp and resp.get("result", {}).get("serverInfo", {}).get("name") == "depfence"
    print("[OK] initialize", file=sys.stderr)

    # 2. tools/list
    resp = await server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = resp["result"]["tools"]
    assert len(tools) == 6
    print(f"[OK] tools/list — {len(tools)} tools registered", file=sys.stderr)

    # 3. check_package (fast, may use cached results)
    resp = await server.handle_request({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "check_package", "arguments": {"name": "requests", "ecosystem": "pypi"}},
    })
    content_str = resp["result"]["content"][0]["text"]
    content = json.loads(content_str)
    print(f"[OK] check_package requests/pypi — risk_score={content['risk_score']}", file=sys.stderr)

    # 4. is_typosquat
    resp = await server.handle_request({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "is_typosquat", "arguments": {"name": "reqests", "ecosystem": "pypi"}},
    })
    ts = json.loads(resp["result"]["content"][0]["text"])
    print(f"[OK] is_typosquat 'reqests' — is_typosquat={ts['is_typosquat']}", file=sys.stderr)

    # 5. suggest_alternative
    resp = await server.handle_request({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "suggest_alternative", "arguments": {"package": "requests", "ecosystem": "pypi"}},
    })
    alts = json.loads(resp["result"]["content"][0]["text"])
    print(f"[OK] suggest_alternative — {alts['alternatives']}", file=sys.stderr)

    # 6. check_license
    resp = await server.handle_request({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "check_license", "arguments": {"package": "requests", "ecosystem": "pypi"}},
    })
    lic = json.loads(resp["result"]["content"][0]["text"])
    print(f"[OK] check_license requests — {lic['license']} ({lic['tier']})", file=sys.stderr)

    print("", file=sys.stderr)
    print("All self-tests passed.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point for the depfence-mcp script."""
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(_run_stdio())


async def _run_stdio() -> None:
    server = DepfenceMcpServer()
    await server.run_stdio()
