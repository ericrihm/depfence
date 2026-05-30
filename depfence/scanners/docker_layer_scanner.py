"""Docker layer scanner — detects prompt injection in Docker image metadata.

Scans two surfaces:
1. Dockerfile files: comments, LABEL directives, ENV/ARG values
2. Local Docker images (via `docker inspect`): image labels, environment
   variables, and entrypoint/cmd strings

Reuses injection patterns from prompt_injection_scanner so both scanners
stay in sync as the pattern set evolves.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta
from depfence.scanners.prompt_injection_scanner import (
    _INJECTION_PATTERNS,
    _normalize_for_matching,
)

# Dockerfile directives whose values carry user-controlled text
_INJECTABLE_DIRECTIVES = {"LABEL", "ENV", "ARG", "MAINTAINER"}

# Max bytes to read per Dockerfile
_MAX_DOCKERFILE_SIZE = 512_000  # 512 KB


def _parse_dockerfile_tokens(text: str) -> list[tuple[int, str, str]]:
    """Return (line_num, directive, value) tuples for scannable content.

    Also yields (line_num, "COMMENT", text) for # lines.
    """
    tokens: list[tuple[int, str, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        # Comments
        if stripped.startswith("#"):
            comment = stripped[1:].strip()
            if len(comment) > 5:
                tokens.append((lineno, "COMMENT", comment))
            continue
        # Continuation lines are included with their directive on the previous
        # pass — here we split on the first whitespace to get the directive.
        m = re.match(r"^([A-Z]+)\s+(.*)", stripped, re.DOTALL)
        if m:
            directive = m.group(1)
            value = m.group(2).strip()
            if directive in _INJECTABLE_DIRECTIVES and len(value) > 3:
                tokens.append((lineno, directive, value))
    return tokens


class DockerLayerScanner:
    """Detects prompt injection payloads in Docker image metadata and Dockerfiles."""

    name = "docker_layer_scanner"
    ecosystems = ["docker"]

    # ------------------------------------------------------------------
    # Scanner Protocol
    # ------------------------------------------------------------------

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        """Scan package metadata — delegates to Docker image inspection."""
        return await self._scan_local_images()

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan Dockerfiles in project_dir, then inspect local Docker images."""
        findings: list[Finding] = []
        findings.extend(self._scan_dockerfiles(project_dir))
        findings.extend(await self._scan_local_images())
        return findings

    # ------------------------------------------------------------------
    # Dockerfile scanning
    # ------------------------------------------------------------------

    def _scan_dockerfiles(self, project_dir: Path) -> list[Finding]:
        """Find and scan all Dockerfiles under project_dir."""
        findings: list[Finding] = []
        for df_path in self._find_dockerfiles(project_dir):
            try:
                size = df_path.stat().st_size
                if size > _MAX_DOCKERFILE_SIZE:
                    continue
                text = df_path.read_text(errors="ignore")
            except OSError:
                continue
            rel = _rel(df_path, project_dir)
            findings.extend(self._scan_dockerfile_text(text, rel))
        return findings

    def _find_dockerfiles(self, project_dir: Path) -> list[Path]:
        """Locate Dockerfile* files, excluding .git."""
        results: list[Path] = []
        for candidate in project_dir.rglob("Dockerfile*"):
            if ".git" in candidate.parts:
                continue
            if candidate.is_file():
                results.append(candidate)
        return results

    def _scan_dockerfile_text(self, text: str, source_label: str) -> list[Finding]:
        """Scan parsed tokens from a Dockerfile for injection patterns."""
        findings: list[Finding] = []
        pkg = PackageId(ecosystem="docker", name=source_label)
        seen: set[str] = set()

        for lineno, directive, value in _parse_dockerfile_tokens(text):
            normalized = _normalize_for_matching(value)
            for pattern, label, severity in _INJECTION_PATTERNS:
                key = f"{directive}:{label}"
                if key in seen:
                    continue
                if pattern.search(normalized):
                    seen.add(key)
                    loc = f"{directive} at line {lineno}"
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=severity,
                        package=pkg,
                        title=f"Prompt injection in Dockerfile {directive}: {label}",
                        detail=f"{source_label} — {loc}: '{value[:200].strip()}'",
                        cwe="CWE-77",
                        references=[
                            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        ],
                        confidence=0.85,
                        metadata={
                            "file": source_label,
                            "directive": directive,
                            "line": lineno,
                            "matched_pattern": label,
                        },
                    ))
        return findings

    # ------------------------------------------------------------------
    # Docker image inspection (live CLI)
    # ------------------------------------------------------------------

    async def _scan_local_images(self) -> list[Finding]:
        """Inspect all local Docker images for injection in metadata fields."""
        if not shutil.which("docker"):
            return []

        try:
            image_ids = self._list_local_image_ids()
        except Exception:
            return []

        findings: list[Finding] = []
        for image_id in image_ids:
            try:
                inspect_data = self._docker_inspect(image_id)
            except Exception:
                continue
            findings.extend(self._scan_image_inspect(inspect_data, image_id))
        return findings

    def _list_local_image_ids(self) -> list[str]:
        """Return short IDs of all locally available Docker images."""
        result = subprocess.run(
            ["docker", "images", "-q", "--no-trunc"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _docker_inspect(self, image_id: str) -> list[dict]:
        """Run `docker inspect` on an image and return parsed JSON."""
        result = subprocess.run(
            ["docker", "inspect", image_id],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout)

    def _scan_image_inspect(self, inspect_data: list[dict], image_id: str) -> list[Finding]:
        """Extract and scan metadata fields from docker inspect output."""
        findings: list[Finding] = []
        if not inspect_data or not isinstance(inspect_data, list):
            return findings

        for image in inspect_data:
            if not isinstance(image, dict):
                continue

            # Resolve a human-readable image name for reporting
            repo_tags = image.get("RepoTags") or []
            image_name = repo_tags[0] if repo_tags else image_id[:12]
            pkg = PackageId(ecosystem="docker", name=image_name)

            # Config subtree holds most interesting metadata
            config = image.get("Config") or {}

            # Labels: dict[str, str]
            labels = config.get("Labels") or {}
            if isinstance(labels, dict):
                for key, val in labels.items():
                    if not isinstance(val, str) or len(val) < 5:
                        continue
                    self._check_value(
                        val, pkg, findings,
                        location=f"label:{key}",
                        title_prefix="Docker image label",
                    )

            # Env vars: list of "KEY=VALUE" strings
            env_list = config.get("Env") or []
            if isinstance(env_list, list):
                for entry in env_list:
                    if not isinstance(entry, str) or len(entry) < 5:
                        continue
                    self._check_value(
                        entry, pkg, findings,
                        location="env",
                        title_prefix="Docker image ENV",
                    )

            # Entrypoint and Cmd: list of strings
            for field_name in ("Entrypoint", "Cmd"):
                cmd_list = config.get(field_name) or []
                if isinstance(cmd_list, list):
                    joined = " ".join(str(s) for s in cmd_list if s)
                    if len(joined) > 5:
                        self._check_value(
                            joined, pkg, findings,
                            location=field_name.lower(),
                            title_prefix=f"Docker image {field_name}",
                        )

        return findings

    def _check_value(
        self,
        value: str,
        pkg: PackageId,
        findings: list[Finding],
        *,
        location: str,
        title_prefix: str,
    ) -> None:
        """Scan a single string value for injection patterns, appending to findings."""
        normalized = _normalize_for_matching(value)
        for pattern, label, severity in _INJECTION_PATTERNS:
            if pattern.search(normalized):
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=severity,
                    package=pkg,
                    title=f"Prompt injection in {title_prefix}: {label}",
                    detail=f"Image '{pkg.name}' — {location}: '{value[:200].strip()}'",
                    cwe="CWE-77",
                    references=[
                        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    ],
                    confidence=0.80,
                    metadata={
                        "image": pkg.name,
                        "location": location,
                        "matched_pattern": label,
                    },
                ))
                break  # one finding per location per value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rel(path: Path, base: Path) -> str:
    """Return a relative path string, falling back to absolute if not under base."""
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)
