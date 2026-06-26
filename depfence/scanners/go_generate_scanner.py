"""Go generate scanner — detects arbitrary command execution via go:generate directives.

//go:generate directives run arbitrary shell commands during `go generate`.
While not invoked automatically by `go build`, many projects document
`go generate ./...` as a build step, and CI pipelines run it routinely.

Detection rules:
  GO-01: go:generate with shell command execution (sh -c, bash -c, cmd /c)
  GO-02: go:generate downloading/executing remote content (curl, wget)
  GO-03: go:generate running non-Go tools that could be trojaned
  GO-04: CGo enabled with external C dependencies (opens native code attack surface)
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "vendor"}

_GO_GENERATE = re.compile(r'^//go:generate\s+(.+)$', re.MULTILINE)

_SHELL_EXEC = re.compile(
    r'\b(?:sh|bash|zsh|dash|ksh|cmd)\s+(?:-c|/c)\b',
    re.IGNORECASE,
)

_DOWNLOAD_EXEC = re.compile(
    r'\b(?:curl|wget)\s+',
    re.IGNORECASE,
)

_CGO_IMPORT = re.compile(r'^import\s+"C"', re.MULTILINE)

_CGO_LDFLAGS = re.compile(r'#cgo\s+LDFLAGS:\s*(.+)$', re.MULTILINE)

_CGO_CFLAGS = re.compile(r'#cgo\s+CFLAGS:\s*(.+)$', re.MULTILINE)

_KNOWN_SAFE_GENERATORS = {
    "stringer", "mockgen", "protoc-gen-go", "goimports", "gofmt",
    "go-enum", "enumer", "go-bindata", "pkger", "statik",
    "counterfeiter", "moq", "minimock", "go-sumtype",
}


class GoGenerateScanner:
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for go_file in project_dir.rglob("*.go"):
            if any(skip in go_file.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_go_file(go_file, project_dir))
        return findings

    def _scan_go_file(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        for m in _GO_GENERATE.finditer(content):
            directive = m.group(1).strip()

            if _SHELL_EXEC.search(directive):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("go", pkg_name),
                    title=f"GO-01: Shell execution in go:generate in {rel}",
                    detail=(
                        f"go:generate runs a shell command: `{directive}`. "
                        f"Shell execution in generate directives can run arbitrary "
                        f"commands when `go generate` is invoked."
                    ),
                    metadata={"file": str(rel), "directive": directive, "rule": "GO-01"},
                ))
            elif _DOWNLOAD_EXEC.search(directive):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.CRITICAL,
                    package=PackageId("go", pkg_name),
                    title=f"GO-02: Remote download in go:generate in {rel}",
                    detail=(
                        f"go:generate downloads remote content: `{directive}`. "
                        f"This can fetch and execute malicious payloads during "
                        f"the generate phase."
                    ),
                    metadata={"file": str(rel), "directive": directive, "rule": "GO-02"},
                ))
            else:
                tool = directive.split()[0].rsplit("/", 1)[-1] if directive else ""
                if tool and tool not in _KNOWN_SAFE_GENERATORS and not tool.startswith("go"):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.MEDIUM,
                        package=PackageId("go", pkg_name),
                        title=f"GO-03: Unknown generator tool '{tool}' in {rel}",
                        detail=(
                            f"go:generate invokes '{tool}' which is not in the known-safe "
                            f"list. Verify this tool is trusted: `{directive}`."
                        ),
                        metadata={"file": str(rel), "tool": tool, "directive": directive, "rule": "GO-03"},
                    ))

        if _CGO_IMPORT.search(content):
            for pat, label in [(_CGO_LDFLAGS, "LDFLAGS"), (_CGO_CFLAGS, "CFLAGS")]:
                m = pat.search(content)
                if m:
                    flags = m.group(1).strip()
                    if any(s in flags for s in ["-L/", "-I/", "..", "http://", "https://"]):
                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            severity=Severity.HIGH,
                            package=PackageId("go", pkg_name),
                            title=f"GO-04: Suspicious CGo {label} in {rel}",
                            detail=(
                                f"CGo {label} references external paths: `{flags}`. "
                                f"This can link attacker-controlled native libraries "
                                f"or include headers from outside the project."
                            ),
                            metadata={"file": str(rel), "flags": flags, "rule": "GO-04"},
                        ))

        return findings
