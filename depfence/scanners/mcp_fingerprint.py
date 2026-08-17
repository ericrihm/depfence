"""MCP server schema fingerprinting and rug-pull detection.

Tracks tool schema snapshots across scans and alerts when definitions change
after initial installation — the "rug pull" attack pattern where a legitimate-
looking server later injects malicious tool descriptions or capabilities.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, cast

from depfence.core.fingerprint_store import (
    FingerprintStatus,
    FingerprintStore,
    FingerprintStoreError,
)
from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.core.scan_scope import (
    MalformedInputError,
    PartialScanError,
    ScanIncompleteError,
    ScanScope,
)

_GLOBAL_CONFIG_LIMIT = 4 * 1024 * 1024

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


def fingerprint_mcp_server(server_name: str, config: dict) -> tuple[str, dict]:
    """Return (sha256_hex, schema_dict) derived from a server's tool definitions.

    The fingerprint covers the structural shape of tools: names, descriptions,
    and input parameter keys. It intentionally excludes volatile fields like
    env values and runtime command arguments so routine config tweaks do not
    create false positives — only tool-level changes trigger alerts.
    """
    tools = config.get("tools", [])
    if not isinstance(tools, list):
        raise MalformedInputError(f"MCP server {server_name!r} tools must be an array")
    schema: dict = {
        "server": server_name,
        "tools": [],
    }
    for tool in tools:
        if not isinstance(tool, dict):
            raise MalformedInputError(f"MCP server {server_name!r} tool must be an object")
        tool_name = tool.get("name", "")
        description = tool.get("description", "")
        if not isinstance(tool_name, str) or not isinstance(description, str):
            raise MalformedInputError(
                f"MCP server {server_name!r} tool name/description must be strings"
            )
        input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            raise MalformedInputError(
                f"MCP server {server_name!r} input schema must be an object"
            )
        properties = input_schema.get("properties", {})
        if not isinstance(properties, dict):
            raise MalformedInputError(
                f"MCP server {server_name!r} input properties must be an object"
            )
        if not all(isinstance(key, str) for key in properties):
            raise MalformedInputError(
                f"MCP server {server_name!r} input property names must be strings"
            )
        entry = {
            "name": tool_name,
            "description": description,
            "input_keys": sorted(properties.keys()),
        }
        schema["tools"].append(entry)

    # Sort for stability — tool order in the wire response must not matter.
    schema["tools"].sort(key=lambda t: t["name"])
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    return fingerprint, schema


def _server_identity_material(server_name: str, config: dict[str, Any]) -> str:
    """Return stable launcher identity material without persisting it in cleartext."""
    identity = {
        "server": server_name,
        "command": config.get("command"),
        "args": config.get("args"),
        "url": config.get("url"),
        "transport": config.get("transport", config.get("type")),
        "env_keys": sorted(str(key) for key in (config.get("env") or {})),
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)


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


def _extract_mcp_servers(data: dict[Any, Any]) -> dict[Any, Any]:
    if "mcpServers" in data:
        return cast(dict[Any, Any], data["mcpServers"])
    if "mcp" in data and isinstance(data["mcp"], dict):
        return cast(dict[Any, Any], data["mcp"].get("servers", {}))
    if "servers" in data:
        return cast(dict[Any, Any], data["servers"])
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

    def __init__(
        self,
        db_path: Path | None = None,
        *,
        include_global: bool = False,
        private_root: Path | None = None,
    ) -> None:
        self._db_path = db_path
        self.include_global = include_global
        self._private_root = private_root

    def _store(self, project_dir: Path) -> FingerprintStore:
        return FingerprintStore.open(
            project_root=project_dir,
            private_root=self._private_root,
            database_path=self._db_path,
        )

    def statuses(self, project_dir: Path) -> list[FingerprintStatus]:
        project = project_dir.resolve()
        store = self._store(project)
        return store.statuses(kind="mcp_schema", project_id=store.project_id(project))

    def approve(
        self, project_dir: Path, *, subject_id: str, digest: str
    ) -> FingerprintStatus:
        project = project_dir.resolve()
        store = self._store(project)
        return store.approve(
            kind="mcp_schema",
            project_id=store.project_id(project),
            subject_id=subject_id,
            digest=digest,
        )

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        scope = ScanScope(project_dir)
        store: FingerprintStore | None = None
        project_id = ""
        findings: list[Finding] = []
        unapproved: list[str] = []
        errors: list[str] = []
        seen_paths: set[Path] = set()

        for config_path in _MCP_CONFIG_LOCATIONS:
            if config_path.is_absolute():
                if not self.include_global:
                    continue
                source = f"global:{config_path.name}"
                try:
                    info = config_path.lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    errors.append(f"{source}: cannot inspect opted-in global input")
                    continue
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    errors.append(f"{source}: opted-in global input must be a regular non-symlink file")
                    continue
                if info.st_size > _GLOBAL_CONFIG_LIMIT:
                    errors.append(
                        f"{source}: opted-in global input exceeds {_GLOBAL_CONFIG_LIMIT} byte limit"
                    )
                    continue
                try:
                    resolved = config_path.resolve(strict=True)
                except (OSError, RuntimeError):
                    errors.append(f"{source}: cannot resolve opted-in global input")
                    continue
                identity_source = str(resolved)
            else:
                candidate = scope.root / config_path
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    errors.append(f"{config_path.as_posix()}: cannot inspect input: {exc}")
                    continue
                try:
                    resolved = scope.resolve(candidate)
                except ScanIncompleteError as exc:
                    errors.append(f"{config_path.as_posix()}: {exc}")
                    continue
                source = config_path.as_posix()
                identity_source = source
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            if store is None:
                store = self._store(scope.root)
                project_id = store.project_id(scope.root)
            try:
                findings.extend(
                    self._scan_config(
                        resolved,
                        store=store,
                        project_id=project_id,
                        source=source,
                        identity_source=identity_source,
                        scope=None if source.startswith("global:") else scope,
                        unapproved=unapproved,
                    )
                )
            except ScanIncompleteError as exc:
                message = (
                    "opted-in global input is unavailable or malformed"
                    if source.startswith("global:")
                    else str(exc)
                )
                errors.append(f"{source}: {message}")

        if unapproved or errors:
            reasons: list[str] = []
            if unapproved:
                reasons.append(
                    f"{len(unapproved)} MCP fingerprint identity/identities require exact approval"
                )
            reasons.extend(errors)
            raise PartialScanError(
                "; ".join(reasons),
                findings,
            )
        return findings

    def _scan_config(
        self,
        config_path: Path,
        *,
        store: FingerprintStore,
        project_id: str,
        source: str,
        identity_source: str,
        scope: ScanScope | None = None,
        unapproved: list[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        if scope is not None:
            data = scope.parse_json(config_path)
        else:
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeError) as exc:
                raise MalformedInputError(f"malformed MCP config {config_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise MalformedInputError(f"expected an object in MCP config {config_path}")

        servers = _extract_mcp_servers(data)
        if not isinstance(servers, dict):
            raise MalformedInputError(f"expected MCP server mapping in {config_path}")
        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                raise MalformedInputError(
                    f"expected object for MCP server {server_name!r} in {config_path}"
                )
            if not isinstance(server_name, str):
                raise MalformedInputError("MCP server name must be a string")
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            url = server_config.get("url", "")
            env = server_config.get("env", {})
            transport = server_config.get("transport", server_config.get("type", ""))
            if (
                not isinstance(command, str)
                or not isinstance(args, list)
                or not all(isinstance(arg, str) for arg in args)
                or not isinstance(url, str)
                or not isinstance(env, dict)
                or not isinstance(transport, str)
            ):
                raise MalformedInputError(
                    f"MCP server {server_name!r} launcher identity has invalid field types"
                )
            pkg = PackageId("mcp", server_name)

            fingerprint, schema = fingerprint_mcp_server(server_name, server_config)
            subject_id = store.subject_id(
                kind="mcp_schema",
                source=identity_source,
                name=_server_identity_material(str(server_name), server_config),
            )
            try:
                status = store.observe(
                    kind="mcp_schema",
                    project_id=project_id,
                    subject_id=subject_id,
                    digest=fingerprint,
                    snapshot=schema,
                )
            except FingerprintStoreError as exc:
                raise ScanIncompleteError(f"MCP fingerprint state is unavailable: {exc}") from exc

            if status.state == "DRIFT":
                assert status.approved_digest is not None
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"MCP server '{server_name}': tool schema changed since last scan",
                    detail=(
                        "The tool definitions for this MCP server differ from the previously "
                        "recorded snapshot. This may indicate a rug-pull attack where a "
                        "server's behavior was modified after initial installation. "
                        f"Approved fingerprint: {status.approved_digest[:16]}…  "
                        f"Current: {fingerprint[:16]}…"
                    ),
                    confidence=0.95,
                    metadata={
                        "source": source,
                        "subject_id": subject_id,
                        "approved_fingerprint": status.approved_digest,
                        "current_fingerprint": fingerprint,
                    },
                ))
            elif status.state == "UNAPPROVED":
                unapproved.append(subject_id)
                changed_before_approval = (
                    status.previous_observed_digest is not None
                    and status.previous_observed_digest != fingerprint
                )
                findings.append(Finding(
                    finding_type=(
                        FindingType.MALICIOUS
                        if changed_before_approval else FindingType.UNVERIFIED_REF
                    ),
                    severity=Severity.CRITICAL if changed_before_approval else Severity.INFO,
                    package=pkg,
                    title=(
                        f"MCP server '{server_name}': schema changed before approval"
                        if changed_before_approval
                        else f"MCP server '{server_name}': fingerprint is not approved"
                    ),
                    detail=(
                        "The observed tool schema changed before any exact fingerprint was approved."
                        if changed_before_approval
                        else "First observation is evidence, not trust. Approve the exact subject "
                        "identity and SHA-256 before this server can receive verified coverage."
                    ),
                    confidence=1.0,
                    metadata={
                        "source": source,
                        "subject_id": subject_id,
                        "current_fingerprint": fingerprint,
                        "assurance": "unproven",
                    },
                ))

            findings.extend(
                _scan_descriptions_for_injection(server_name, server_config, source)
            )

        return findings
