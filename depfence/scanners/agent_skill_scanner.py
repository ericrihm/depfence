"""Agent skill security scanner — detects deferred-payload and domain-spoof attacks.

Covers the attack pattern from the brand-landingpage incident (2026-06):
a fake AI agent skill that passed all security scanners by keeping the package
clean and loading malicious instructions from an attacker-controlled URL
post-install.

Detects:
1. External instruction fetch — tool descriptions/args that reference URLs
   for setup, configuration, or runtime instructions
2. Domain spoofing — referenced domains that are Levenshtein-close to
   well-known services (stitch-design.ai vs stitch.withgoogle.com)
3. Deferred payload — content at referenced URLs changed since last scan
   (the bait-and-switch pattern)
4. Dynamic DNS / free hosting — domains on infrastructure commonly used
   for throwaway C2
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

from depfence.analyzers.typosquat_detector import levenshtein_distance
from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Well-known service domains for similarity comparison
# ---------------------------------------------------------------------------

_WELL_KNOWN_SERVICES: dict[str, str] = {
    "withgoogle.com": "Google",
    "google.com": "Google",
    "googleapis.com": "Google",
    "accounts.google.com": "Google",
    "cloud.google.com": "Google",
    "firebase.google.com": "Google",
    "anthropic.com": "Anthropic",
    "claude.ai": "Anthropic",
    "openai.com": "OpenAI",
    "platform.openai.com": "OpenAI",
    "github.com": "GitHub",
    "github.io": "GitHub",
    "githubusercontent.com": "GitHub",
    "gitlab.com": "GitLab",
    "microsoft.com": "Microsoft",
    "azure.com": "Microsoft",
    "login.microsoftonline.com": "Microsoft",
    "aws.amazon.com": "AWS",
    "amazonaws.com": "AWS",
    "huggingface.co": "Hugging Face",
    "replicate.com": "Replicate",
    "vercel.com": "Vercel",
    "netlify.com": "Netlify",
    "cloudflare.com": "Cloudflare",
    "slack.com": "Slack",
    "discord.com": "Discord",
    "notion.so": "Notion",
    "stripe.com": "Stripe",
    "twilio.com": "Twilio",
    "docker.com": "Docker",
    "docker.io": "Docker",
    "npmjs.com": "npm",
    "npmjs.org": "npm",
    "pypi.org": "PyPI",
    "crates.io": "Crates.io",
    "rubygems.org": "RubyGems",
    "cursor.com": "Cursor",
    "cursor.sh": "Cursor",
    "linear.app": "Linear",
    "figma.com": "Figma",
    "canva.com": "Canva",
    "shopify.com": "Shopify",
    "atlassian.com": "Atlassian",
    "jira.com": "Jira",
    "confluence.com": "Confluence",
    "sentry.io": "Sentry",
    "datadog.com": "Datadog",
    "grafana.com": "Grafana",
    "supabase.com": "Supabase",
    "planetscale.com": "PlanetScale",
    "mongodb.com": "MongoDB",
    "redis.io": "Redis",
    "elastic.co": "Elastic",
    "hashicorp.com": "HashiCorp",
    "terraform.io": "Terraform",
    "vault.hashicorp.com": "Vault",
}

_SAFE_DOMAINS: set[str] = set(_WELL_KNOWN_SERVICES.keys()) | {
    "registry.npmjs.org", "files.pythonhosted.org",
    "api.github.com", "raw.githubusercontent.com",
    "cdn.jsdelivr.net", "unpkg.com",
    "docs.python.org", "nodejs.org",
    "readthedocs.io", "docs.rs",
    "localhost", "127.0.0.1", "::1",
}

_DYNDNS_SUFFIXES: set[str] = {
    "duckdns.org", "no-ip.org", "ddns.net", "hopto.org",
    "ngrok.io", "ngrok-free.app", "workers.dev", "trycloudflare.com",
    "serveo.net", "loca.lt", "localhost.run",
    "repl.co", "replit.dev", "glitch.me",
    "pages.dev",  # Cloudflare Pages — free, often ephemeral
    "vercel.app",  # free tier
    "netlify.app",  # free tier
    "web.app",  # Firebase free tier
    "fly.dev",
    "render.com",
    "railway.app",
    "onrender.com",
}

_FREE_DOMAIN_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom (historically abused)
    ".top", ".xyz", ".icu", ".buzz", ".monster",
    ".click", ".link", ".surf", ".rest",
}

# ---------------------------------------------------------------------------
# URL extraction patterns
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"""(?:https?://)([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?:/[^\s'"<>)*\]]*)?""",
)

_INSTRUCTION_FETCH_PATTERNS = [
    (r"(?:follow|see|read|visit|check|open|go\s+to)\s+(?:the\s+)?(?:\w+\s+){0,2}(?:instructions?|setup|docs?|documentation|guide|tutorial|steps?)\s+(?:at|on|from|here)\s*:?\s*(?:https?://)", "Instruction fetch via natural language"),
    (r"(?:download|install|get|fetch|load|import|source|pull)\s+(?:\w+\s+){0,2}(?:from|via|at)\s*:?\s*(?:https?://)", "Download directive"),
    (r"(?:setup|config(?:uration)?|init(?:ialize)?)\s+(?:\w+\s+){0,2}(?:instructions?|guide|docs?)\s*(?:at|from|here)?\s*:?\s*(?:https?://)", "Setup instructions at external URL"),
    (r"(?:more\s+(?:info|details?|documentation)|full\s+(?:docs?|guide))\s*(?:at|from|here)?\s*:?\s*(?:https?://)", "External documentation reference"),
    (r"run\s+(?:this|the)\s+(?:script|command)\s+from\s*:?\s*(?:https?://)", "External script execution"),
]

# ---------------------------------------------------------------------------
# Fingerprint DB for deferred payload detection
# ---------------------------------------------------------------------------

_SKILL_DB_PATH = Path.home() / ".depfence" / "skill_url_fingerprints.db"


def _open_skill_db(db_path: Path = _SKILL_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS url_fingerprints (
            url TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            server_name TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _check_url_fingerprint(
    url: str, current_hash: str, db_path: Path = _SKILL_DB_PATH
) -> tuple[bool, str | None]:
    """Return (changed, previous_hash_or_None)."""
    conn = _open_skill_db(db_path)
    try:
        row = conn.execute(
            "SELECT content_hash FROM url_fingerprints WHERE url = ?", (url,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return False, None
    if row[0] == current_hash:
        return False, row[0]
    return True, row[0]


def _store_url_fingerprint(
    url: str, content_hash: str, server_name: str,
    db_path: Path = _SKILL_DB_PATH,
) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn = _open_skill_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO url_fingerprints (url, content_hash, server_name, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
                content_hash = excluded.content_hash,
                last_seen = excluded.last_seen
            """,
            (url, content_hash, server_name, now, now),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Domain analysis
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str | None:
    """Extract the domain from a URL string."""
    match = re.match(r"https?://([^/:]+)", url)
    return match.group(1).lower() if match else None


def _is_safe_domain(domain: str) -> bool:
    """Check if domain is in the safe list (exact or suffix match)."""
    if domain in _SAFE_DOMAINS:
        return True
    for safe in _SAFE_DOMAINS:
        if domain.endswith("." + safe):
            return True
    return False


def _is_dyndns(domain: str) -> bool:
    for suffix in _DYNDNS_SUFFIXES:
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def _is_free_tld(domain: str) -> bool:
    for tld in _FREE_DOMAIN_TLDS:
        if domain.endswith(tld):
            return True
    return False


def _strip_tld(domain: str) -> str:
    """Return the domain without its TLD (e.g., 'openai.com' -> 'openai')."""
    parts = domain.split(".")
    if len(parts) <= 1:
        return domain
    # Handle two-part TLDs like .co.uk
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac"):
        return ".".join(parts[:-2])
    return ".".join(parts[:-1])


def _check_domain_spoofing(domain: str) -> tuple[str, str, int] | None:
    """Check if domain is suspiciously similar to a well-known service.

    Returns (matched_domain, service_name, edit_distance) or None.
    Compares both full domain (for typosquats) and name-without-TLD
    (for TLD-swap impersonation like openai.org → openai.com).
    """
    if _is_safe_domain(domain):
        return None

    parts = domain.split(".")
    if len(parts) < 2:
        return None

    domain_name = _strip_tld(domain)
    base_domain = ".".join(parts[-2:])

    for well_known, service_name in _WELL_KNOWN_SERVICES.items():
        wk_name = _strip_tld(well_known)

        # Exact name with different TLD (openai.org vs openai.com)
        if domain_name == wk_name and domain != well_known:
            return well_known, service_name, 1

        # Levenshtein on name-without-TLD (catches close typosquats)
        name_dist = levenshtein_distance(domain_name, wk_name)
        max_name_dist = max(1, min(3, len(wk_name) // 3))
        if 0 < name_dist <= max_name_dist:
            return well_known, service_name, name_dist

        # Levenshtein on full domain (catches single-char typos like githuh.com)
        full_dist = levenshtein_distance(base_domain, well_known)
        max_full_dist = max(1, min(3, len(well_known) // 4))
        if 0 < full_dist <= max_full_dist:
            return well_known, service_name, full_dist

    return None


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract all HTTP(S) URLs from a block of text."""
    return [m.group(0) for m in re.finditer(r"https?://[^\s'\"<>)\]]+", text)]


# ---------------------------------------------------------------------------
# Config location constants (shared with mcp_scanner)
# ---------------------------------------------------------------------------

_MCP_CONFIG_LOCATIONS = [
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "settings.local.json",
    Path.home() / ".claude.json",
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".config" / "zed" / "settings.json",
    Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    Path.home() / ".continue" / "config.json",
]

_PROJECT_CONFIG_LOCATIONS = [
    Path(".mcp.json"),
    Path(".cursor/mcp.json"),
    Path(".vscode/mcp.json"),
    Path(".vscode/settings.json"),
    Path(".claude/settings.json"),
    Path(".continue/config.json"),
]


def _extract_mcp_servers(data: dict) -> dict:
    if "mcpServers" in data:
        return data["mcpServers"]
    if "mcp" in data and isinstance(data["mcp"], dict):
        return data["mcp"].get("servers", {})
    if "servers" in data:
        return data["servers"]
    return {}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AgentSkillScanner:
    """Detects agent skill attacks: external instruction fetch, domain
    spoofing, deferred payload bait-and-switch, and suspicious hosting."""

    name = "agent_skill"
    ecosystems = ["mcp"]

    def __init__(self, db_path: Path = _SKILL_DB_PATH) -> None:
        self._db_path = db_path

    async def scan(self, packages: list) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        for config_path in _PROJECT_CONFIG_LOCATIONS:
            resolved = project_dir / config_path
            if resolved.exists() and resolved not in seen:
                seen.add(resolved)
                findings.extend(self._scan_config(resolved))

        for path in _MCP_CONFIG_LOCATIONS:
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
        source = str(config_path)

        for server_name, server_config in servers.items():
            pkg = PackageId("mcp", server_name)
            findings.extend(self._check_external_instructions(server_name, server_config, pkg, source))
            findings.extend(self._check_domain_spoofing(server_name, server_config, pkg, source))
            findings.extend(self._check_suspicious_hosting(server_name, server_config, pkg, source))

        return findings

    def _collect_all_text(self, config: dict) -> list[tuple[str, str]]:
        """Collect all text fields from a server config with their location labels."""
        text_fields: list[tuple[str, str]] = []

        # Args
        for i, arg in enumerate(config.get("args", [])):
            if isinstance(arg, str):
                text_fields.append((str(arg), f"args[{i}]"))

        # URL field
        url = config.get("url", "")
        if url:
            text_fields.append((url, "url"))

        # Tool descriptions and parameter descriptions
        for tool in config.get("tools", []):
            tool_name = tool.get("name", "<unnamed>")
            desc = tool.get("description", "")
            if desc:
                text_fields.append((desc, f"tool '{tool_name}' description"))

            input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            for param_name, param_def in input_schema.get("properties", {}).items():
                param_desc = param_def.get("description", "")
                if param_desc:
                    text_fields.append((param_desc, f"tool '{tool_name}' param '{param_name}'"))

        # Env vars (values only)
        for key, value in config.get("env", {}).items():
            if isinstance(value, str) and re.match(r"https?://", value):
                text_fields.append((value, f"env[{key}]"))

        return text_fields

    def _check_external_instructions(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Detect tool descriptions that direct the agent to fetch external instructions."""
        findings: list[Finding] = []

        for text, location in self._collect_all_text(config):
            # Check for instruction-fetch language patterns
            for pattern, label in _INSTRUCTION_FETCH_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    urls = _extract_urls_from_text(text)
                    external_urls = []
                    for url in urls:
                        domain = _extract_domain(url)
                        if domain and not _is_safe_domain(domain):
                            external_urls.append(url)

                    if external_urls:
                        findings.append(Finding(
                            finding_type=FindingType.EXTERNAL_INSTRUCTION_FETCH,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"MCP server '{name}': external instruction fetch in {location}",
                            detail=(
                                f"{label}. The {location} directs the agent to fetch instructions "
                                f"from external URL(s): {', '.join(external_urls[:3])}. "
                                f"A real attacker can swap the content at this URL after the skill "
                                f"passes initial vetting (deferred payload attack)."
                            ),
                            confidence=0.85,
                            metadata={
                                "config_path": source,
                                "location": location,
                                "pattern": label,
                                "urls": external_urls[:5],
                            },
                        ))
                    break

            # Also flag any non-safe URL in tool descriptions even without
            # instruction-fetch language — the URL itself is the risk
            urls = _extract_urls_from_text(text)
            for url in urls:
                domain = _extract_domain(url)
                if domain and not _is_safe_domain(domain):
                    # Only flag in tool descriptions, not in env/args (those
                    # are expected to have URLs for legitimate config)
                    if "description" in location or "param" in location:
                        findings.append(Finding(
                            finding_type=FindingType.EXTERNAL_INSTRUCTION_FETCH,
                            severity=Severity.MEDIUM,
                            package=pkg,
                            title=f"MCP server '{name}': external URL in {location}",
                            detail=(
                                f"Tool {location} references external URL: {url}. "
                                f"Domain '{domain}' is not in the known-safe list. "
                                f"External URLs in tool descriptions can be used for "
                                f"deferred payload delivery."
                            ),
                            confidence=0.6,
                            metadata={
                                "config_path": source,
                                "location": location,
                                "url": url,
                                "domain": domain,
                            },
                        ))

        return findings

    def _check_domain_spoofing(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Detect domains that are suspiciously similar to well-known services."""
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for text, location in self._collect_all_text(config):
            for url in _extract_urls_from_text(text):
                domain = _extract_domain(url)
                if not domain or domain in seen_domains or _is_safe_domain(domain):
                    continue
                seen_domains.add(domain)

                spoof = _check_domain_spoofing(domain)
                if spoof:
                    matched, service, dist = spoof
                    findings.append(Finding(
                        finding_type=FindingType.DOMAIN_SPOOF,
                        severity=Severity.CRITICAL,
                        package=pkg,
                        title=f"MCP server '{name}': domain '{domain}' spoofs {service}",
                        detail=(
                            f"Domain '{domain}' in {location} is {dist} edit(s) away from "
                            f"the legitimate '{matched}' ({service}). This is a classic "
                            f"brand-impersonation pattern used in the brand-landingpage "
                            f"attack to trick agents into trusting attacker-controlled URLs."
                        ),
                        confidence=min(0.95, 1.0 - (dist * 0.1)),
                        metadata={
                            "config_path": source,
                            "location": location,
                            "domain": domain,
                            "spoofed_domain": matched,
                            "service": service,
                            "edit_distance": dist,
                        },
                    ))

        return findings

    def _check_suspicious_hosting(
        self, name: str, config: dict, pkg: PackageId, source: str
    ) -> list[Finding]:
        """Flag domains on dynamic DNS, free hosting, or suspicious TLDs."""
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for text, location in self._collect_all_text(config):
            for url in _extract_urls_from_text(text):
                domain = _extract_domain(url)
                if not domain or domain in seen_domains or _is_safe_domain(domain):
                    continue
                seen_domains.add(domain)

                if _is_dyndns(domain):
                    findings.append(Finding(
                        finding_type=FindingType.EXTERNAL_INSTRUCTION_FETCH,
                        severity=Severity.HIGH,
                        package=pkg,
                        title=f"MCP server '{name}': dynamic DNS domain in {location}",
                        detail=(
                            f"URL references '{domain}' which uses a dynamic DNS / free "
                            f"hosting service. These domains are trivially created and "
                            f"commonly used for throwaway C2 infrastructure."
                        ),
                        confidence=0.75,
                        metadata={
                            "config_path": source,
                            "location": location,
                            "domain": domain,
                            "hosting_type": "dyndns",
                        },
                    ))

                if _is_free_tld(domain):
                    findings.append(Finding(
                        finding_type=FindingType.EXTERNAL_INSTRUCTION_FETCH,
                        severity=Severity.MEDIUM,
                        package=pkg,
                        title=f"MCP server '{name}': suspicious TLD in {location}",
                        detail=(
                            f"URL references '{domain}' which uses a TLD historically "
                            f"associated with abuse ({domain.split('.')[-1]}). While not "
                            f"conclusive, this warrants manual review."
                        ),
                        confidence=0.5,
                        metadata={
                            "config_path": source,
                            "location": location,
                            "domain": domain,
                            "hosting_type": "free_tld",
                        },
                    ))

        return findings

    def check_url_content(
        self, url: str, content: bytes, server_name: str = "",
    ) -> Finding | None:
        """Check if content at a URL has changed since last scan (deferred payload).

        Call this with the fetched content of URLs found by the scanner.
        Returns a CRITICAL finding if content changed, None otherwise.
        Stores the fingerprint for future comparison.
        """
        content_hash = hashlib.sha256(content).hexdigest()
        changed, prev_hash = _check_url_fingerprint(url, content_hash, self._db_path)

        _store_url_fingerprint(url, content_hash, server_name, self._db_path)

        if changed:
            domain = _extract_domain(url) or url
            return Finding(
                finding_type=FindingType.DEFERRED_PAYLOAD,
                severity=Severity.CRITICAL,
                package=PackageId("mcp", server_name or domain),
                title=f"Deferred payload: content changed at {domain}",
                detail=(
                    f"The content at '{url}' has changed since the last scan. "
                    f"Previous hash: {prev_hash[:16]}…  Current: {content_hash[:16]}…  "
                    f"This is the bait-and-switch pattern: legitimate content at scan time, "
                    f"malicious payload delivered later."
                ),
                confidence=0.9,
                metadata={
                    "url": url,
                    "previous_hash": prev_hash,
                    "current_hash": content_hash,
                    "server_name": server_name,
                },
            )
        return None
