"""Ruby lifecycle scanner — detects malicious patterns in Ruby build/install files.

Scans extconf.rb, Rakefile, *.gemspec, and Gemfile for exec/exfil shapes:
backticks, %x{}, system/exec/spawn/Kernel.exec, eval, dangerous requires
(open3, net/http, open-uri), download-piped-to-sh, and ENV token+net combos.

Allowlists benign native-build patterns: create_makefile, have_header,
have_library, dir_config, pkg_config.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "vendor", "bundle"}

_TARGET_FILES = {"extconf.rb", "Rakefile", "Gemfile"}
_TARGET_EXTENSIONS = {".gemspec"}

_RUBY_EXEC = re.compile(
    r"`[^`]+`"
    r"|%x\{[^}]+\}"
    r"|\bsystem\s*\("
    r"|\bexec\s*\("
    r"|\bspawn\s*\("
    r"|\bKernel\.exec\b",
)

_RUBY_EVAL = re.compile(r"\beval\s*\(")

_RUBY_NET_REQUIRE = re.compile(
    r"require\s+['\"](?:open3|net/http|open-uri|net/https|net/ftp)['\"]",
)

_RUBY_DOWNLOAD_EXEC = re.compile(
    r"(?:open|URI\.open|Net::HTTP|curl|wget)\s*\([^)]*https?://[^)]*\)"
    r".*?\|\s*(?:sh|bash|ruby|eval)",
    re.DOTALL | re.IGNORECASE,
)

_RUBY_ENV_CRED = re.compile(
    r"ENV\[[^\]]*(?:TOKEN|KEY|SECRET|PASS|CRED|AUTH)[^\]]*\]",
    re.IGNORECASE,
)

_SAFE_NATIVE_BUILD = re.compile(
    r"\b(?:create_makefile|have_header|have_library|dir_config|pkg_config"
    r"|find_header|find_library|have_func|have_type|check_sizeof)\b",
)


class RubyLifecycleScanner:
    name = "ruby_lifecycle"
    ecosystems = ["rubygems"]

    async def scan(self, packages: list) -> list:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for fpath in self._collect_files(project_dir):
            try:
                content = fpath.read_text(errors="ignore")
            except OSError:
                continue
            rel = str(fpath.relative_to(project_dir))
            findings.extend(self._analyze(content, rel))
        return findings

    def _collect_files(self, project_dir: Path) -> list[Path]:
        files: list[Path] = []
        for f in project_dir.rglob("*"):
            if any(skip in f.parts for skip in _SKIP_DIRS):
                continue
            if not f.is_file():
                continue
            if f.name in _TARGET_FILES or f.suffix in _TARGET_EXTENSIONS:
                files.append(f)
        return files

    def _analyze(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []

        has_safe_native = bool(_SAFE_NATIVE_BUILD.search(content))
        has_exec = bool(_RUBY_EXEC.search(content)) or bool(_RUBY_EVAL.search(content))
        has_net = bool(_RUBY_NET_REQUIRE.search(content))
        has_cred = bool(_RUBY_ENV_CRED.search(content))
        has_download_exec = bool(_RUBY_DOWNLOAD_EXEC.search(content))

        if has_download_exec:
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Ruby download-and-execute pattern",
                "Code downloads from a URL and pipes to a shell interpreter.",
            ))

        if has_net and has_cred:
            findings.append(self._finding(
                rel_path, Severity.CRITICAL,
                "Ruby credential access with network egress",
                "Build file reads credential env vars and imports network libraries.",
            ))
        elif has_exec and has_net:
            if has_safe_native:
                findings.append(self._finding(
                    rel_path, Severity.MEDIUM,
                    "Ruby exec + network in native extension build",
                    "Build file with native extension helpers also uses exec and "
                    "network — review for legitimate build-time downloads.",
                ))
            else:
                findings.append(self._finding(
                    rel_path, Severity.HIGH,
                    "Ruby exec with network access in build file",
                    "Build file uses shell execution and network imports without "
                    "native extension build patterns.",
                ))
        elif has_exec and not has_safe_native:
            if bool(_RUBY_EVAL.search(content)):
                findings.append(self._finding(
                    rel_path, Severity.HIGH,
                    "Ruby eval in build file",
                    "Build file uses eval() which may execute untrusted code.",
                ))

        return findings

    @staticmethod
    def _finding(path: str, severity: Severity, title: str, detail: str) -> Finding:
        return Finding(
            finding_type=FindingType.INSTALL_SCRIPT,
            severity=severity,
            package=f"file:{path}",
            title=title,
            detail=detail,
            metadata={"file": path, "check": "ruby_lifecycle"},
        )
