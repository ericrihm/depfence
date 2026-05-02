"""MCP server security scanner — analyzes MCP configurations for threats.

Scans MCP server declarations in Claude Code, Cursor, VS Code, Windsurf,
and Zed configs for prompt injection, tool shadowing, credential leakage,
excessive permissions, suspicious commands, and known-malicious servers.

Competitive advantages over Cisco MCP Scanner / Snyk Agent Scan:
- Fully offline, deterministic — no cloud API calls or LLM-as-judge
- Multi-pass encoding normalization before pattern matching
- Tool shadowing detection against canonical tool name registry
- Rug-pull baseline pinning (via mcp_fingerprint.py)
- uvx/pipx launcher analysis (not just npx)
- npx version pinning enforcement
- TLS enforcement for HTTP/SSE transports
"""

from __future__ import annotations

import base64
import json
import platform
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Config locations — covers all major MCP-enabled editors/tools
# ---------------------------------------------------------------------------

def _mcp_config_locations() -> list[Path]:
    """Build platform-aware list of MCP config paths."""
    paths = [
        # Claude Code
        Path.home() / ".claude" / "settings.json",
        Path.home() / ".claude" / "settings.local.json",
        Path.home() / ".claude.json",
        # Cursor
        Path.home() / ".cursor" / "mcp.json",
        # VS Code
        Path.home() / ".vscode" / "settings.json",
        # Windsurf
        Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    # Claude Desktop — platform-dependent
    if platform.system() == "Darwin":
        paths.append(
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    else:
        paths.append(Path.home() / ".config" / "Claude" / "claude_desktop_config.json")
    # Zed
    paths.append(Path.home() / ".config" / "zed" / "settings.json")
    # Continue.dev
    paths.append(Path.home() / ".continue" / "config.json")
    return paths


_PROJECT_CONFIG_LOCATIONS = [
    Path(".mcp.json"),
    Path(".cursor/mcp.json"),
    Path(".vscode/mcp.json"),
    Path(".vscode/settings.json"),
    Path(".claude/settings.json"),
]

# ---------------------------------------------------------------------------
# Threat data (loaded lazily from data/mcp_threat_intel.json)
# ---------------------------------------------------------------------------

_THREAT_DATA: dict | None = None


def _load_threat_data() -> dict:
    global _THREAT_DATA
    if _THREAT_DATA is not None:
        return _THREAT_DATA
    data_file = Path(__file__).parent.parent / "data" / "mcp_threat_intel.json"
    if data_file.exists():
        _THREAT_DATA = json.loads(data_file.read_text())
    else:
        _THREAT_DATA = {"malicious_packages": {"npm": [], "pypi": []}, "well_known_tools": {}, "sensitive_env_vars": []}
    return _THREAT_DATA


def _known_malicious_set() -> set[str]:
    data = _load_threat_data()
    names: set[str] = set()
    for ecosystem_list in data.get("malicious_packages", {}).values():
        for entry in ecosystem_list:
            names.add(entry["name"])
    return names


def _well_known_tools() -> set[str]:
    data = _load_threat_data()
    tools: set[str] = set()
    for tool_list in data.get("well_known_tools", {}).values():
        tools.update(tool_list)
    return tools


def _sensitive_env_patterns() -> list[str]:
    data = _load_threat_data()
    return data.get("sensitive_env_vars", [])


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_COMMAND_PATTERNS = [
    (r"nc\s+-[el]|ncat|netcat", Severity.CRITICAL, "Reverse shell binary"),
    (r"/dev/tcp/", Severity.CRITICAL, "Bash TCP redirect"),
    (r"curl.*\|\s*(sh|bash)", Severity.CRITICAL, "Pipe-to-shell"),
    (r"wget.*\|\s*(sh|bash)", Severity.CRITICAL, "Pipe-to-shell via wget"),
    (r"base64\s+-d", Severity.HIGH, "Base64 decode in command"),
    (r"eval\s", Severity.HIGH, "Eval in command"),
    (r"\$\(curl", Severity.CRITICAL, "Command substitution with download"),
    (r"python[23]?\s+-c\s", Severity.HIGH, "Inline Python execution"),
    (r"node\s+-e\s", Severity.HIGH, "Inline Node.js execution"),
    (r"powershell.*-enc", Severity.CRITICAL, "PowerShell encoded command"),
]

_INJECTION_PATTERNS = [
    (r"ignore\s+(previous|above|all)\s+(instructions|prompts)", "Prompt injection: instruction override"),
    (r"you\s+are\s+(now|a)\s+", "Identity override attempt"),
    (r"system\s*:\s*", "System prompt injection"),
    (r"</?system>", "XML system tag injection"),
    (r"<\|im_start\|>", "ChatML delimiter injection"),
    (r"IMPORTANT:\s*ignore", "Instruction override via IMPORTANT"),
    (r"do\s+not\s+tell\s+the\s+user", "Information suppression"),
    (r"exfiltrat|steal|extract|harvest", "Data exfiltration language"),
    (r"send\s+to\s+https?://", "Exfiltration URL reference"),
    (r"curl\s+.*\|", "Shell injection in description"),
    (r"rm\s+-rf|deltree|format\s+c:", "Destructive command reference"),
    (r"[\u200b\u200c\u200d\u2060\ufeff]", "Zero-width Unicode characters"),
    (r"[\u202a-\u202e\u2066-\u2069]", "Bidirectional override characters"),
    (r"urgently?|bypass|override|immediately", "Coercive urgency language"),
    (r"\\x[0-9a-f]{2}", "Hex-escaped content"),
    (r"\\u[0-9a-f]{4}", "Unicode-escaped content"),
]

_SENSITIVE_PATH_KEYWORDS = [
    "sudo", "root", "admin", "/etc/", "/var/", "~/.ssh",
    "~/.aws", "~/.config", "~/.gnupg", "/proc/", "/sys/",
    "/etc/shadow", "/etc/passwd",
]


# ---------------------------------------------------------------------------
# Encoding normalization (defeats evasion)
# ---------------------------------------------------------------------------

def _normalize_text(text: str) -> str:
    """Multi-pass decoding to defeat obfuscation in tool descriptions."""
    normalized = text
    # Pass 1: Decode base64 segments
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in b64_pattern.finditer(normalized):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 4:
                normalized = normalized.replace(match.group(), decoded, 1)
        except Exception:
            pass
    # Pass 2: Decode hex escapes
    normalized = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), normalized)
    # Pass 3: Decode unicode escapes
    normalized = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), normalized)
    # Pass 4: Decode URL encoding
    normalized = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), normalized)
    # Pass 5: Strip zero-width characters for cleaner matching
    normalized = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", normalized)
    return normalized


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def _extract_mcp_servers(data: dict) -> dict:
    if "mcpServers" in data:
        return data["mcpServers"]
    if "mcp" in data and isinstance(data["mcp"], dict):
        return data["mcp"].get("servers", {})
    if "servers" in data:
        return data["servers"]
    return {}


class McpScanner:
    """Comprehensive MCP security scanner.

    Detects:
    - Suspicious/malicious commands (reverse shells, pipe-to-shell, etc.)
    - Known-malicious MCP packages (npm + PyPI threat intel)
    - Tool shadowing (name collisions with well-known tools)
    - Credential leakage via env vars
    - Prompt injection in tool descriptions (with encoding normalization)
    - Parameter description injection
    - TLS enforcement for HTTP/SSE transports
    - Unpinned package versions (npx/uvx supply chain risk)
    - Non-standard transports
    """

    name = "mcp_scanner"
    ecosystems = ["mcp"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        # Project-level configs
        for config_path in _PROJECT_CONFIG_LOCATIONS:
            resolved = project_dir / config_path
            if resolved.exists() and resolved not in seen:
                seen.add(resolved)
                findings.extend(self._scan_config(resolved))

        # Global configs
        for path in _mcp_config_locations():
            if path.exists() and path not in seen:
                seen.add(path)
                findings.extend(self._scan_config(path))

        return findings

    def _scan_config(self, config_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        servers = _extract_mcp_servers(data)

        for server_name, server_config in servers.items():
            pkg = PackageId("mcp", server_name)
            source = str(config_path)

            findings.extend(self._check_command(server_name, server_config, pkg, source))
            findings.extend(self._check_env_vars(server_name, server_config, pkg, source))
            findings.extend(self._check_transport(server_name, server_config, pkg, source))
            findings.extend(self._check_url(server_name, server_config, pkg, source))
            findings.extend(self._check_package_launcher(server_name, server_config, pkg, source))
            findings.extend(self._check_tool_shadowing(server_name, server_config, pkg, source))
            findings.extend(self._check_tool_descriptions(server_name, server_config, pkg, source))

        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_command(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        command = config.get("command", "")
        args = config.get("args", [])
        full_cmd = f"{command} {' '.join(str(a) for a in args)}"

        for pattern, severity, desc in _SUSPICIOUS_COMMAND_PATTERNS:
            if re.search(pattern, full_cmd, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=severity,
                    package=pkg,
                    title=f"MCP server '{name}': {desc}",
                    detail=f"Command: {full_cmd[:200]}",
                    confidence=0.8,
                    metadata={"config_path": source, "command": full_cmd},
                ))
        return findings

    def _check_env_vars(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        env = config.get("env", {})
        sensitive_patterns = _sensitive_env_patterns()

        for key, value in env.items():
            # Check if env key IS a sensitive credential being passed to server
            key_upper = key.upper()
            if any(pat == key_upper for pat in sensitive_patterns):
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"MCP server '{name}': credential passed via env '{key}'",
                    detail=(
                        f"Sensitive credential '{key}' is being passed to this MCP server. "
                        f"Verify this server requires these credentials and is from a trusted source."
                    ),
                    confidence=0.7,
                    metadata={"config_path": source, "env_key": key},
                ))
            # Check if value references sensitive paths
            elif any(kw in str(value).lower() for kw in _SENSITIVE_PATH_KEYWORDS):
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.MEDIUM,
                    package=pkg,
                    title=f"MCP server '{name}': sensitive path in env '{key}'",
                    detail=f"Environment variable '{key}' references sensitive system path",
                    confidence=0.5,
                    metadata={"config_path": source, "env_key": key},
                ))
        return findings

    def _check_transport(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        transport = config.get("transport", config.get("type", "stdio"))

        if transport not in ("stdio", "sse", "streamable-http"):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"MCP server '{name}': non-standard transport '{transport}'",
                detail="Non-standard MCP transport may indicate a modified or malicious server.",
                confidence=0.4,
                metadata={"config_path": source, "transport": transport},
            ))
        return findings

    def _check_url(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        url = config.get("url", "")
        if not url:
            return findings

        # Hardcoded IP
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg,
                title=f"MCP server '{name}': hardcoded IP address",
                detail=f"URL: {url}",
                confidence=0.7,
                metadata={"config_path": source, "url": url},
            ))

        # TLS enforcement — HTTP without TLS to non-localhost
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=pkg,
                title=f"MCP server '{name}': unencrypted HTTP transport",
                detail=(
                    f"URL '{url}' uses plain HTTP to a non-localhost endpoint. "
                    f"MCP traffic may contain sensitive data and should use TLS (https://)."
                ),
                confidence=0.8,
                metadata={"config_path": source, "url": url},
            ))
        return findings

    def _check_package_launcher(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Check npx/uvx/pipx launched servers for known-malicious packages and version pinning."""
        findings: list[Finding] = []
        command = config.get("command", "")
        args = config.get("args", [])
        malicious = _known_malicious_set()

        # Detect launcher type
        launcher = None
        pkg_arg = ""
        if command in ("npx", "npm", "bunx"):
            launcher = "npm"
            pkg_arg = args[0] if args else ""
        elif command in ("uvx", "pipx"):
            launcher = "pypi"
            pkg_arg = args[0] if args else ""
            # uvx run <pkg> pattern
            if pkg_arg == "run" and len(args) > 1:
                pkg_arg = args[1]

        if not launcher or not pkg_arg:
            return findings

        # Strip flags (e.g., -y, --yes)
        if pkg_arg.startswith("-"):
            for a in args[1:]:
                if not a.startswith("-"):
                    pkg_arg = a
                    break
            else:
                return findings

        # Check against malicious list
        clean_name = pkg_arg.split("@")[0] if "@" in pkg_arg and not pkg_arg.startswith("@") else pkg_arg
        # Handle scoped packages: @scope/name@version
        if pkg_arg.startswith("@") and "@" in pkg_arg[1:]:
            clean_name = pkg_arg.rsplit("@", 1)[0]

        if clean_name in malicious:
            findings.append(Finding(
                finding_type=FindingType.MALICIOUS,
                severity=Severity.CRITICAL,
                package=pkg,
                title=f"Known malicious MCP package: {clean_name}",
                detail=f"Package '{clean_name}' is flagged as malicious. Remove immediately.",
                confidence=1.0,
                metadata={"config_path": source, "package": clean_name, "launcher": launcher},
            ))

        # Version pinning check — unpinned packages fetch latest on every run
        has_version = False
        if pkg_arg.startswith("@") and pkg_arg.count("@") >= 2:
            has_version = True
        elif not pkg_arg.startswith("@") and "@" in pkg_arg:
            has_version = True

        if not has_version:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"MCP server '{name}': unpinned package version",
                detail=(
                    f"'{command} {pkg_arg}' fetches the latest version on every run. "
                    f"Pin to a specific version (e.g., '{pkg_arg}@1.2.3') to prevent "
                    f"supply-chain attacks via malicious updates."
                ),
                confidence=0.6,
                metadata={"config_path": source, "package": pkg_arg, "launcher": command},
            ))

        return findings

    def _check_tool_shadowing(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Detect tools that shadow well-known tool names from Claude or popular servers."""
        findings: list[Finding] = []
        tools = config.get("tools", [])
        well_known = _well_known_tools()

        for tool in tools:
            tool_name = tool.get("name", "")
            if tool_name in well_known:
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.CRITICAL,
                    package=pkg,
                    title=f"MCP server '{name}': tool '{tool_name}' shadows well-known tool",
                    detail=(
                        f"This server defines a tool named '{tool_name}' which conflicts with "
                        f"a well-known built-in or standard MCP tool. This is a tool shadowing "
                        f"attack — the malicious tool may intercept calls intended for the "
                        f"legitimate tool and exfiltrate data or execute arbitrary actions."
                    ),
                    confidence=0.9,
                    metadata={"config_path": source, "tool_name": tool_name},
                ))
        return findings

    def _check_tool_descriptions(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Scan tool descriptions AND parameter descriptions for injection patterns."""
        findings: list[Finding] = []
        tools = config.get("tools", [])

        for tool in tools:
            tool_name = tool.get("name", "<unnamed>")

            # Check tool-level description
            description = tool.get("description", "")
            if description:
                findings.extend(
                    self._scan_text_for_injection(name, tool_name, description, "description", pkg, source)
                )

            # Check parameter-level descriptions (P1 gap: missed by all other scanners)
            input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            properties = input_schema.get("properties", {})
            for param_name, param_def in properties.items():
                param_desc = param_def.get("description", "")
                if param_desc:
                    findings.extend(
                        self._scan_text_for_injection(
                            name, tool_name, param_desc,
                            f"parameter '{param_name}' description", pkg, source
                        )
                    )

        return findings

    def _scan_text_for_injection(
        self,
        server_name: str,
        tool_name: str,
        text: str,
        location: str,
        pkg: PackageId,
        source: str,
    ) -> list[Finding]:
        """Apply injection patterns against normalized text."""
        findings: list[Finding] = []
        # Normalize to defeat encoding evasion
        normalized = _normalize_text(text)

        for pattern, label in _INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.MALICIOUS,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"MCP server '{server_name}': {label}",
                    detail=(
                        f"Tool '{tool_name}' {location} contains suspicious content: {label}"
                    ),
                    confidence=0.85,
                    metadata={
                        "config_path": source,
                        "tool_name": tool_name,
                        "location": location,
                        "pattern": pattern,
                    },
                ))
                break  # one finding per text block
        return findings


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def scan_mcp_configs(project_dir: Path | None = None) -> list[Finding]:
    """Convenience function to scan MCP configs."""
    import asyncio
    scanner = McpScanner()
    if project_dir:
        return asyncio.run(scanner.scan_project(project_dir))
    # Global-only scan
    findings: list[Finding] = []
    for path in _mcp_config_locations():
        if path.exists():
            findings.extend(scanner._scan_config(path))
    return findings
