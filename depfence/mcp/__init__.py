"""depfence MCP server — exposes depfence scanners over the Model Context Protocol.

AI coding assistants (Claude Code, Cursor, etc.) can call these tools
mid-conversation to check packages before recommending them.

Usage:
    depfence-mcp          # stdio MCP server (for IDE integration)
    depfence mcp serve    # same via the main CLI
    depfence mcp test     # self-test query
"""

from depfence.mcp.server import DepfenceMcpServer, main
from depfence.mcp.tools import CheckResult, McpTools

__all__ = ["DepfenceMcpServer", "CheckResult", "McpTools", "main"]
