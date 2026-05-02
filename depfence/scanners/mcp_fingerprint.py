"""MCP server schema fingerprinting and rug-pull detection.

Tracks tool schema snapshots across scans and alerts when definitions change
after initial installation — the "rug pull" attack pattern where a legitimate-
looking server later injects malicious tool descriptions or capabilities.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_DB_PATH = Path.home() / ".depfence" / "mcp_fingerprints.db"

_INJECTION_PATTERNS = [
    (r"ignore\s+previous", "Prompt injection: 'ignore previous'"),
    (r"ignore\s+above", "Prompt injection: 'ignore above'"),
    (r"ignore\s+all\s+(instructions|prompts)", "Prompt injection: 'ignore all instructions'"),
    (r"system\s*prompt", "Prompt injection: system prompt reference"),
    (r"<\|im_start\|>", "Prompt injection: ChatML delimiter"),
    (r"exfiltrate", "Exfiltration language in tool description"),
    (r"send\s+to\s+https?://", "Exfiltration URL in tool description"),
    (r"send\s+to\s+http", "Exfiltration URL in tool description"),
    (r"[​-‏⁠﻿]", "Invisible Unicode characters in description"),
]


def _open_db(db_path: Path = _DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fingerprints (
            server_name TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            schema_snapshot TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def fingerprint_mcp_server(server_name: str, config: dict) -> tuple[str, dict]:
    """Return (sha256_hex, schema_dict) derived from a server's tool definitions.

    The fingerprint covers the structural shape of tools: names, descriptions,
    and input parameter keys. It intentionally excludes volatile fields like
    env values and runtime command arguments so routine config tweaks do not
    create false positives — only tool-level changes trigger alerts.
    """
    tools = config.get("tools", [])
    schema: dict = {
        "server": server_name,
        "tools": [],
    }
    for tool in tools:
        entry = {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "input_keys": sorted(
                (tool.get("inputSchema") or tool.get("input_schema") or {})
                .get("properties", {})
                .keys()
            ),
        }
        schema["tools"].append(entry)

    # Sort for stability — tool order in the wire response must not matter.
    schema["tools"].sort(key=lambda t: t["name"])
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    return fingerprint, schema


def check_fingerprint(
    server_name: str,
    current_fingerprint: str,
    db_path: Path = _DB_PATH,
) -> tuple[bool, str | None]:
    """Return (changed, previous_fingerprint_or_None).

    Returns (False, None) when the server has never been seen before.
    Returns (False, prev) when the fingerprint is unchanged.
    Returns (True, prev) when the fingerprint differs from the stored value.
    """
    conn = _open_db(db_path)
    try:
        row = conn.execute(
            "SELECT fingerprint FROM fingerprints WHERE server_name = ?",
            (server_name,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return False, None
    stored = row[0]
    if stored == current_fingerprint:
        return False, stored
    return True, stored


def store_fingerprint(
    server_name: str,
    fingerprint: str,
    schema_snapshot: dict,
    db_path: Path = _DB_PATH,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    snapshot_json = json.dumps(schema_snapshot, separators=(",", ":"))
    conn = _open_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO fingerprints (server_name, fingerprint, schema_snapshot, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(server_name) DO UPDATE SET
                fingerprint = excluded.fingerprint,
                schema_snapshot = excluded.schema_snapshot,
                last_seen = excluded.last_seen
            """,
            (server_name, fingerprint, snapshot_json, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _scan_descriptions_for_injection(
    server_name: str,
    config: dict,
    source: str,
) -> list[Finding]:
    findings: list[Finding] = []
    pkg = PackageId("mcp", server_name)
    tools = config.get("tools", [])
    for tool in tools:
        description = tool.get("description", "")
        tool_name = tool.get("name", "<unnamed>")
        for pattern, label in _INJECTION_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"MCP server '{server_name}': {label}",
                    detail=(
                        f"Tool '{tool_name}' description contains suspicious content "
                        f"matching pattern: {label}"
                    ),
                    confidence=0.9,
                    metadata={
                        "source": source,
                        "tool_name": tool_name,
                        "pattern": pattern,
                    },
                ))
                break  # one finding per tool per scan pass is sufficient
    return findings


def _extract_mcp_servers(data: dict) -> dict:
    if "mcpServers" in data:
        return data["mcpServers"]
    if "mcp" in data and isinstance(data["mcp"], dict):
        return data["mcp"].get("servers", {})
    if "servers" in data:
        return data["servers"]
    return {}


_MCP_CONFIG_LOCATIONS = [
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "settings.local.json",
    Path.home() / ".claude.json",
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".vscode" / "settings.json",
    Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    Path(".mcp.json"),
    Path(".cursor/mcp.json"),
    Path(".vscode/mcp.json"),
    Path(".vscode/settings.json"),
    Path(".claude/settings.json"),
]


class McpFingerprintScanner:
    name = "mcp_fingerprint"
    ecosystems = ["mcp"]

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self._db_path = db_path

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        seen_paths: set[Path] = set()

        for config_path in _MCP_CONFIG_LOCATIONS:
            resolved = config_path if config_path.is_absolute() else project_dir / config_path
            if resolved in seen_paths or not resolved.exists():
                continue
            seen_paths.add(resolved)
            findings.extend(self._scan_config(resolved))

        return findings

    def _scan_config(self, config_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        servers = _extract_mcp_servers(data)
        source = str(config_path)

        for server_name, server_config in servers.items():
            pkg = PackageId("mcp", server_name)

            fingerprint, schema = fingerprint_mcp_server(server_name, server_config)
            changed, prev = check_fingerprint(server_name, fingerprint, self._db_path)

            if changed:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"MCP server '{server_name}': tool schema changed since last scan",
                    detail=(
                        "The tool definitions for this MCP server differ from the previously "
                        "recorded snapshot. This may indicate a rug-pull attack where a "
                        "server's behavior was modified after initial installation. "
                        f"Previous fingerprint: {prev[:16]}…  Current: {fingerprint[:16]}…"
                    ),
                    confidence=0.95,
                    metadata={
                        "source": source,
                        "previous_fingerprint": prev,
                        "current_fingerprint": fingerprint,
                    },
                ))

            store_fingerprint(server_name, fingerprint, schema, self._db_path)

            findings.extend(
                _scan_descriptions_for_injection(server_name, server_config, source)
            )

        return findings
