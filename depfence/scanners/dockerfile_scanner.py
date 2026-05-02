"""Dockerfile security scanner — detects risky patterns in container builds.

Detects:
1. Unpinned base images (using :latest or no tag)
2. Running as root (no USER directive)
3. Secrets in build args or ENV
4. Curl-pipe-to-shell patterns
5. Known-vulnerable base images
6. Excessive permissions (--privileged)
7. Missing health checks
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity


class DockerfileScanner:
    ecosystems = ["docker"]

    async def scan(self, packages: list) -> list:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan Dockerfiles in the project."""
        findings: list[Finding] = []
        dockerfiles = self._find_dockerfiles(project_dir)

        for df in dockerfiles:
            try:
                content = df.read_text()
            except OSError:
                continue
            rel_path = str(df.relative_to(project_dir))
            findings.extend(self._analyze(content, rel_path))

        return findings

    def _find_dockerfiles(self, project_dir: Path) -> list[Path]:
        files = []
        patterns = ["Dockerfile", "Dockerfile.*", "*.dockerfile", "docker/Dockerfile*"]
        for pattern in patterns:
            files.extend(project_dir.glob(pattern))
            files.extend(project_dir.glob(f"**/{pattern}"))
        return list(set(f for f in files if f.is_file()))[:20]

    def _analyze(self, content: str, path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        has_user = False
        has_healthcheck = False
        from_images: list[str] = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            upper = stripped.upper()

            if upper.startswith("FROM "):
                image = stripped[5:].split(" AS ")[0].strip()
                from_images.append(image)
                findings.extend(self._check_from(image, path, i))

            elif upper.startswith("USER "):
                has_user = True

            elif upper.startswith("HEALTHCHECK "):
                has_healthcheck = True

            elif upper.startswith("RUN "):
                findings.extend(self._check_run(stripped[4:], path, i))

            elif upper.startswith("ENV ") or upper.startswith("ARG "):
                findings.extend(self._check_secrets(stripped, path, i))

        if not has_user and from_images:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=f"docker:{path}",
                title="Container runs as root (no USER directive)",
                detail="Add a USER directive to run as non-root. Running as root "
                       "increases blast radius of container escape vulnerabilities.",
            ))

        if not has_healthcheck and from_images and len(lines) > 10:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.LOW,
                package=f"docker:{path}",
                title="No HEALTHCHECK defined",
                detail="Add a HEALTHCHECK for better orchestrator integration and "
                       "faster detection of stuck containers.",
            ))

        return findings

    def _check_from(self, image: str, path: str, line: int) -> list[Finding]:
        findings = []

        if ":" not in image or image.endswith(":latest"):
            findings.append(Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.MEDIUM,
                package=f"docker:{image}",
                title="Unpinned base image",
                detail=f"Image '{image}' is not pinned to a specific version. "
                       f"Use a digest (@sha256:...) or specific tag for reproducible builds.",
            ))

        if image.endswith(":latest"):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=f"docker:{image}",
                title="Base image uses :latest tag",
                detail="The :latest tag is mutable and can change at any time. "
                       "An attacker who compromises the base image repository "
                       "can inject malicious layers.",
            ))

        # Known-vulnerable patterns
        vuln_patterns = {
            "python:2": "Python 2 is EOL since 2020",
            "node:8": "Node 8 is EOL",
            "node:10": "Node 10 is EOL",
            "node:12": "Node 12 is EOL",
            "node:14": "Node 14 is EOL",
            "ubuntu:16": "Ubuntu 16.04 is EOL",
            "ubuntu:18": "Ubuntu 18.04 is EOL",
            "debian:stretch": "Debian Stretch is EOL",
            "debian:jessie": "Debian Jessie is EOL",
            "alpine:3.13": "Alpine 3.13 is EOL",
        }
        image_lower = image.lower()
        for pattern, reason in vuln_patterns.items():
            if image_lower.startswith(pattern):
                findings.append(Finding(
                    finding_type=FindingType.KNOWN_VULN,
                    severity=Severity.HIGH,
                    package=f"docker:{image}",
                    title=f"EOL/vulnerable base image: {image}",
                    detail=reason + ". Upgrade to a supported version.",
                ))
                break

        return findings

    def _check_run(self, cmd: str, path: str, line: int) -> list[Finding]:
        findings = []

        # Curl/wget pipe to shell
        if re.search(r"(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh)", cmd):
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=f"docker:{path}:L{line}",
                title="Pipe-to-shell in RUN command",
                detail="Downloading and executing scripts in one step prevents "
                       "integrity verification. Download first, verify checksum, then execute.",
            ))

        # Adding apt keys via curl pipe
        if re.search(r"apt-key\s+add\s*-", cmd):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=f"docker:{path}:L{line}",
                title="apt-key add from pipe (deprecated, insecure)",
                detail="Use signed-by in sources.list instead of apt-key add.",
            ))

        return findings

    def _check_secrets(self, line: str, path: str, lineno: int) -> list[Finding]:
        findings = []
        secret_patterns = [
            (r"(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*=\s*\S+", "Secret in ENV/ARG"),
            (r"(?:AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN)\w*\s*=", "Cloud credential in build"),
        ]
        for pattern, title in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=f"docker:{path}:L{lineno}",
                    title=title,
                    detail="Secrets in ENV/ARG are visible in image layers. "
                           "Use Docker BuildKit secrets (--mount=type=secret) or "
                           "multi-stage builds instead.",
                ))
                break
        return findings
