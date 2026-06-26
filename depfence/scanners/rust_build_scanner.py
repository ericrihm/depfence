"""Rust build.rs scanner — detects supply-chain risks in Cargo build scripts.

build.rs runs arbitrary Rust code at `cargo build` time, before compilation.
This is the exact same attack class as npm preinstall scripts. Rust's high-trust
reputation makes this a blind spot — developers rarely audit build.rs in deps.

Detection rules:
  RS-01: build.rs with network access (reqwest, hyper, ureq, std::net, curl)
  RS-02: build.rs with process spawning (Command::new, process::Command)
  RS-03: build.rs with environment variable exfiltration (env::var patterns)
  RS-04: build.rs with filesystem writes outside OUT_DIR
  RS-05: Cargo.toml build-dependencies with broad permissions
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "target", ".build"}

_NETWORK_PATTERNS = [
    re.compile(r"\buse\s+(?:reqwest|hyper|ureq|curl|attohttpc)\b"),
    re.compile(r"\buse\s+std::net\b"),
    re.compile(r"\bTcpStream\s*::\s*connect\b"),
    re.compile(r"\bUdpSocket\s*::\s*bind\b"),
    re.compile(r"\bminreq\s*::\s*get\b"),
]

_PROCESS_PATTERNS = [
    re.compile(r"\bCommand\s*::\s*new\s*\("),
    re.compile(r"\bprocess\s*::\s*Command\b"),
    re.compile(r"\bstd::process::exit\b"),
]

_ENV_EXFIL_PATTERNS = [
    re.compile(r"\benv::var\s*\(\s*\"(?!OUT_DIR|CARGO_|TARGET|HOST|OPT_LEVEL|PROFILE|NUM_JOBS|DEBUG|RUSTC|RUSTDOC)"),
    re.compile(r"\benv::vars\s*\(\s*\)"),
    re.compile(r"\benv::var_os\s*\(\s*\"(?:HOME|USER|PATH|SSH|AWS_|GITHUB_TOKEN|API_KEY)"),
]

_FS_WRITE_OUTSIDE_OUT = [
    re.compile(r"(?:File|fs)\s*::\s*(?:create|write)\s*\([^)]*(?:\"/|std::path|PathBuf::from\(\s*\"/|home_dir)"),
    re.compile(r"\bfs::write\s*\(\s*\"(?!/)"),
]

_CC_BUILD_PATTERN = re.compile(r"\bcc::Build\b")

_CARGO_BUILD_DEPS = re.compile(
    r'\[build-dependencies\]\s*\n((?:[a-zA-Z0-9_-]+\s*=.*\n)*)',
    re.MULTILINE,
)

_SUSPICIOUS_BUILD_DEPS = {"reqwest", "hyper", "ureq", "curl", "attohttpc", "minreq", "openssl-sys"}


class RustBuildScanner:
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for build_rs in project_dir.rglob("build.rs"):
            if any(skip in build_rs.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_build_rs(build_rs, project_dir))

        for cargo_toml in project_dir.rglob("Cargo.toml"):
            if any(skip in cargo_toml.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_cargo_toml(cargo_toml, project_dir))

        return findings

    def _scan_build_rs(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        for pat in _NETWORK_PATTERNS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.CRITICAL,
                    package=PackageId("cargo", pkg_name),
                    title=f"RS-01: Network access in {rel}",
                    detail=(
                        f"build.rs imports networking code ({m.group()}). Build scripts "
                        f"with network access can download and execute payloads, "
                        f"exfiltrate source code, or phone home during cargo build."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "RS-01"},
                ))
                break

        for pat in _PROCESS_PATTERNS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("cargo", pkg_name),
                    title=f"RS-02: Process spawning in {rel}",
                    detail=(
                        f"build.rs spawns external processes ({m.group()}). While "
                        f"cc::Build uses Command internally, direct process spawning "
                        f"in build scripts can execute arbitrary commands."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "RS-02"},
                ))
                break

        for pat in _ENV_EXFIL_PATTERNS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("cargo", pkg_name),
                    title=f"RS-03: Environment variable access in {rel}",
                    detail=(
                        f"build.rs reads environment variables beyond standard Cargo "
                        f"vars ({m.group()}). This can exfiltrate secrets like API keys, "
                        f"SSH keys, or tokens available in the build environment."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "RS-03"},
                ))
                break

        for pat in _FS_WRITE_OUTSIDE_OUT:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("cargo", pkg_name),
                    title=f"RS-04: Filesystem write outside OUT_DIR in {rel}",
                    detail=(
                        f"build.rs writes files outside the designated OUT_DIR "
                        f"({m.group()}). Build scripts should only write to OUT_DIR; "
                        f"writes elsewhere can plant backdoors or modify system files."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "RS-04"},
                ))
                break

        return findings

    def _scan_cargo_toml(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        m = _CARGO_BUILD_DEPS.search(content)
        if m:
            deps_block = m.group(1)
            for dep in _SUSPICIOUS_BUILD_DEPS:
                if re.search(rf'\b{re.escape(dep)}\b', deps_block):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=PackageId("cargo", pkg_name),
                        title=f"RS-05: Suspicious build-dependency '{dep}' in {rel}",
                        detail=(
                            f"Cargo.toml lists '{dep}' as a build-dependency. This "
                            f"crate is available to build.rs at compile time. Network-capable "
                            f"build dependencies enable data exfiltration during builds."
                        ),
                        metadata={"file": str(rel), "dep": dep, "rule": "RS-05"},
                    ))

        return findings
