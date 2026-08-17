"""Network telemetry scanner — detects packages that phone home.

Identifies:
1. Hardcoded URLs/IPs in install scripts
2. DNS exfiltration patterns (long subdomain encoding)
3. HTTP requests to suspicious endpoints during install/import
4. Webhook/callback URLs that could exfiltrate data
5. Cryptocurrency mining pool connections
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageMeta, Severity


class NetworkScanner:
    ecosystems = ["npm", "pypi"]

    _URL_PATTERN = re.compile(
        r"""(?:https?://|wss?://)([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?:/[^\s'"]*)?""",
    )
    _IP_PATTERN = re.compile(
        r"""(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?""",
    )
    _DNS_EXFIL = re.compile(
        r"""[a-zA-Z0-9]{30,}\.(?:[a-zA-Z0-9-]+\.){1,5}[a-zA-Z]{2,}""",
    )
    _WEBHOOK_URLS = re.compile(
        r"""(?:https?://)?(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|"""
        r"""webhook\.site|pipedream\.net|requestbin|ngrok\.io|burpcollaborator)""",
        re.IGNORECASE,
    )
    _MINING_POOLS = re.compile(
        r"""(?:stratum\+tcp://|pool\.|xmr\.|monero|coinhive|cryptonight|"""
        r"""minergate|nicehash|hashvault)""",
        re.IGNORECASE,
    )

    _SAFE_DOMAINS = {
        "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
        "github.com", "raw.githubusercontent.com", "api.github.com",
        "gitlab.com", "bitbucket.org",
        "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "nodejs.org", "python.org", "docs.python.org",
        "npmjs.com", "yarnpkg.com",
        "googleapis.com", "azure.com", "amazonaws.com",
        "sentry.io", "bugsnag.com", "datadog.com",
        "mozilla.org", "microsoft.com", "firebase.com",
        "cloudflare.com", "vercel.com", "netlify.com",
        "rubygems.org", "crates.io", "packagist.org",
        "docs.rs", "readthedocs.io", "github.io",
    }

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    _DYNDNS_SUFFIXES = {
        "duckdns.org", "no-ip.org", "ddns.net", "hopto.org",
        "ngrok.io", "workers.dev", "trycloudflare.com",
    }

    _PROJECT_SCAN_DIRS = [
        ".github", "scripts", ".vscode", "src", "tools",
        ".claude", ".cursor", ".gemini",
    ]
    _PROJECT_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}

    _ENV_GATE = re.compile(
        r"process\.env\[|os\.getenv\(|if\s*\(.*env",
        re.IGNORECASE,
    )
    _NET_PRIMITIVE = re.compile(
        r"\bfetch\(|\baxios\b|\bhttps?\.request\b|\bnet\.connect\b"
        r"|\burllib\b|\brequests\b|\bsocket\b",
        re.IGNORECASE,
    )
    _RAW_SOCKET_TLS = re.compile(
        r"(?:net|tls)\.(?:connect|createConnection)\s*\("
        r"|socket\.(?:socket|create_connection).*connect\(\(.*,\s*\d+\)\)"
        r"|\bnc\s+\S+\s+\d+",
        re.IGNORECASE,
    )
    _OBFUSCATION_EVAL = re.compile(
        r"\beval\s*\(|\bFunction\s*\(|\bexec\s*\(",
        re.IGNORECASE,
    )

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Walk repo root + common payload dirs for network indicators."""
        files = self._find_project_files(project_dir)
        return await self.scan_files(project_dir, files)

    def _find_project_files(self, project_dir: Path) -> list[Path]:
        extensions = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh"}
        files: list[Path] = []
        seen: set[Path] = set()

        def _add(f: Path) -> None:
            rp = f.resolve()
            if rp not in seen and f.suffix in extensions:
                seen.add(rp)
                files.append(f)

        for item in project_dir.iterdir():
            if item.name in self._PROJECT_SKIP_DIRS:
                continue
            if item.is_file():
                _add(item)

        for subdir_name in self._PROJECT_SCAN_DIRS:
            subdir = project_dir / subdir_name
            if not subdir.is_dir():
                continue
            for f in subdir.rglob("*"):
                if any(skip in f.parts for skip in self._PROJECT_SKIP_DIRS):
                    continue
                if f.is_file():
                    _add(f)

        # Also check the extended install-file set (c2net-05)
        extra_patterns = [
            ".github/setup.js", ".github/setup.sh",
            ".claude/settings.json", ".gemini/settings.json",
            ".vscode/tasks.json",
        ]
        for pat in extra_patterns:
            f = project_dir / pat
            if f.is_file():
                rp = f.resolve()
                if rp not in seen:
                    seen.add(rp)
                    files.append(f)
        for mdc in (project_dir / ".cursor" / "rules").glob("*.mdc") if (project_dir / ".cursor" / "rules").is_dir() else []:
            rp = mdc.resolve()
            if rp not in seen:
                seen.add(rp)
                files.append(mdc)

        return files

    async def scan_files(self, project_dir: Path, files: list[Path] | None = None) -> list[Finding]:
        """Scan package source for network-related indicators."""
        findings: list[Finding] = []

        if files is None:
            files = self._find_install_files(project_dir)

        for fpath in files:
            try:
                content = fpath.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            findings.extend(self._analyze(content, fpath, project_dir))

        return findings

    def scan_content(self, content: str, source_name: str = "unknown") -> list[Finding]:
        """Scan arbitrary content string for network indicators."""
        findings: list[Finding] = []

        if self._MINING_POOLS.search(content):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.CRITICAL,
                package=f"file:{source_name}",
                title="Cryptocurrency mining pool connection",
                detail="Code contains references to mining pools — likely cryptojacking.",
            ))

        if match := self._WEBHOOK_URLS.search(content):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=f"file:{source_name}",
                title="Webhook/exfiltration endpoint detected",
                detail=f"Code contacts webhook service: {match.group(0)[:50]}",
            ))

        urls = self._URL_PATTERN.findall(content)
        suspicious_urls = [u for u in urls if not self._is_safe_domain(u)]
        if suspicious_urls and self._has_data_collection(content):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=f"file:{source_name}",
                title="Data exfiltration pattern detected",
                detail=(
                    f"Code collects system data and sends to: "
                    f"{', '.join(suspicious_urls[:3])}"
                ),
            ))

        ips = self._IP_PATTERN.findall(content)
        suspicious_ips = [ip for ip in ips if self._is_suspicious_ip(ip)]
        if suspicious_ips:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=f"file:{source_name}",
                title="Hardcoded IP address in package code",
                detail=f"IPs found: {', '.join(suspicious_ips[:5])}",
            ))

        if self._DNS_EXFIL.search(content):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=f"file:{source_name}",
                title="DNS exfiltration pattern",
                detail="Long encoded subdomain suggests DNS-based data exfiltration.",
            ))

        # c2net-01: standalone non-allowlisted external URL
        urls_for_c2 = self._URL_PATTERN.findall(content)
        non_safe_urls = [u for u in urls_for_c2 if not self._is_safe_domain(u)]
        if non_safe_urls and not self._has_data_collection(content):
            has_obfuscation = bool(self._OBFUSCATION_EVAL.search(content))
            sev = Severity.HIGH if has_obfuscation else Severity.MEDIUM
            findings.append(Finding(
                finding_type=FindingType.NETWORK,
                severity=sev,
                package=f"file:{source_name}",
                title="Non-allowlisted external URL in source file",
                detail=(
                    f"Code contains URL(s) to non-standard domains: "
                    f"{', '.join(non_safe_urls[:3])}"
                    + (" — combined with obfuscation/eval patterns" if has_obfuscation else "")
                ),
            ))

        # c2net-02: dormant egress (env-gated network call)
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if self._ENV_GATE.search(line):
                window = "\n".join(lines[max(0, i - 2):i + 8])
                if self._NET_PRIMITIVE.search(window):
                    findings.append(Finding(
                        finding_type=FindingType.NETWORK,
                        severity=Severity.HIGH,
                        package=f"file:{source_name}",
                        title="Environment-gated network egress (dormant C2)",
                        detail=(
                            "Network call is guarded by an environment variable check — "
                            "may activate only in CI or on specific hosts."
                        ),
                    ))
                    break

        # c2net-03: raw socket/TLS egress
        if self._RAW_SOCKET_TLS.search(content):
            findings.append(Finding(
                finding_type=FindingType.NETWORK,
                severity=Severity.MEDIUM,
                package=f"file:{source_name}",
                title="Raw socket or TLS connection with explicit port",
                detail="Code creates a raw socket/TLS connection — uncommon in packages.",
            ))

        # c2net-04: dynamic DNS domain suspicion
        for domain in non_safe_urls:
            if self._is_dyndns_domain(domain):
                findings.append(Finding(
                    finding_type=FindingType.NETWORK,
                    severity=Severity.HIGH,
                    package=f"file:{source_name}",
                    title="Dynamic DNS domain in source code",
                    detail=f"Domain '{domain}' uses a public dynamic DNS provider.",
                ))
                break

        return findings

    def _is_dyndns_domain(self, domain: str) -> bool:
        dl = domain.lower()
        return any(dl.endswith(f".{s}") or dl == s for s in self._DYNDNS_SUFFIXES)

    def _analyze(self, content: str, fpath: Path, project_dir: Path) -> list[Finding]:
        rel_path = str(fpath.relative_to(project_dir)) if project_dir in fpath.parents else str(fpath)
        return self.scan_content(content, rel_path)

    def _find_install_files(self, project_dir: Path) -> list[Path]:
        """Find files likely executed during install."""
        patterns = [
            "setup.py", "setup.cfg",
            "package.json",
            "**/postinstall*", "**/preinstall*",
            "**/install.js", "**/install.py",
        ]
        files: list[Path] = []
        for pattern in patterns:
            if "*" in pattern:
                files.extend(project_dir.glob(pattern))
            else:
                f = project_dir / pattern
                if f.exists():
                    files.append(f)
        return files

    def _is_safe_domain(self, domain: str) -> bool:
        domain_lower = domain.lower()
        return any(
            domain_lower == safe or domain_lower.endswith(f".{safe}")
            for safe in self._SAFE_DOMAINS
        )

    @staticmethod
    def _is_suspicious_ip(ip: str) -> bool:
        """Check if IP is non-RFC1918 and non-localhost."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        if octets[0] == 127:
            return False
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 0:
            return False
        return True

    @staticmethod
    def _has_data_collection(content: str) -> bool:
        """Check if code collects system/env data."""
        indicators = [
            "os.environ", "process.env", "os.hostname",
            "os.platform", "os.userInfo", "os.homedir",
            "child_process", "subprocess", "whoami",
            "hostname", "getpass", ".ssh/",
        ]
        return sum(1 for i in indicators if i in content) >= 2
