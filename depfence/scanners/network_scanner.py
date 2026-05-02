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
    }

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

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

        if self._WEBHOOK_URLS.search(content):
            match = self._WEBHOOK_URLS.search(content)
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

        return findings

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
        files = []
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
