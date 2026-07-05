"""Python build hook scanner — detects supply-chain risks in setup.py and pyproject.toml.

setup.py is executable Python that runs during `pip install`. Attackers use
cmdclass overrides, custom build_ext, and data_files to execute arbitrary code.
This is the xz-utils attack class. pyproject.toml build-system entries can also
specify custom build backends that execute arbitrary code.

Detection rules:
  PY-01: setup.py with cmdclass override (arbitrary code during pip install)
  PY-02: setup.py with dangerous imports (subprocess, os.system, urllib, socket)
  PY-03: setup.py with obfuscated execution (exec, eval, compile, __import__)
  PY-04: pyproject.toml with non-standard build backend
  PY-05: setup.py downloading remote content during install
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".tox", ".nox", "site-packages"}

_CMDCLASS_PATTERN = re.compile(
    r'\bcmdclass\s*=\s*\{',
    re.DOTALL,
)

_DANGEROUS_IMPORTS = [
    re.compile(r'^\s*(?:from\s+|import\s+)subprocess\b', re.MULTILINE),
    re.compile(r'\bos\.system\s*\(', re.DOTALL),
    re.compile(r'\bos\.popen\s*\(', re.DOTALL),
    re.compile(r'^\s*(?:from\s+|import\s+)socket\b', re.MULTILINE),
    re.compile(r'^\s*(?:from\s+|import\s+)ctypes\b', re.MULTILINE),
    re.compile(r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(', re.DOTALL),
]

_OBFUSCATION_PATTERNS = [
    re.compile(r'\bexec\s*\(\s*(?:compile|base64|codecs)', re.DOTALL),
    re.compile(r'\beval\s*\(\s*(?:compile|base64|codecs)', re.DOTALL),
    re.compile(r'\b__import__\s*\(', re.DOTALL),
    re.compile(r'\bcodecs\.decode\s*\(', re.DOTALL),
    re.compile(r'\bbase64\.b64decode\s*\(', re.DOTALL),
    re.compile(r'\bexec\s*\(\s*["\']', re.DOTALL),
]

_DOWNLOAD_PATTERNS = [
    re.compile(r'\burllib\.request\.urlretrieve\s*\(', re.DOTALL),
    re.compile(r'\burllib\.request\.urlopen\s*\(', re.DOTALL),
    re.compile(r'\brequests\.get\s*\(', re.DOTALL),
    re.compile(r'\bhttp\.client\b', re.DOTALL),
    re.compile(r'\burlopen\s*\(\s*["\']https?://', re.DOTALL),
]

_STANDARD_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "flit_core.buildapi",
    "flit.buildapi",
    "poetry.core.masonry.api",
    "poetry.masonry.api",
    "hatchling.build",
    "pdm.backend",
    "pdm.pep517.api",
    "maturin",
    "mesonpy",
    "scikit-build-core.build",
    "meson-python.build",
    "whey",
}


class PythonBuildScanner:
    ecosystems = ["pypi"]
    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for setup_py in project_dir.rglob("setup.py"):
            if any(skip in setup_py.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_setup_py(setup_py, project_dir))

        for pyproject in project_dir.rglob("pyproject.toml"):
            if any(skip in pyproject.parts for skip in _SKIP_DIRS):
                continue
            findings.extend(self._scan_pyproject(pyproject, project_dir))

        return findings

    def _scan_setup_py(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        if _CMDCLASS_PATTERN.search(content):
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=PackageId("pypi", pkg_name),
                title=f"PY-01: cmdclass override in {rel}",
                detail=(
                    "setup.py uses cmdclass to override build/install commands. "
                    "This executes arbitrary Python code during `pip install`. "
                    "This is the same mechanism used in the xz-utils backdoor."
                ),
                metadata={"file": str(rel), "rule": "PY-01"},
            ))

        for pat in _DANGEROUS_IMPORTS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=PackageId("pypi", pkg_name),
                    title=f"PY-02: Dangerous import in {rel}",
                    detail=(
                        f"setup.py imports dangerous modules ({m.group().strip()}). "
                        f"These enable process spawning, network access, or system "
                        f"calls during package installation."
                    ),
                    metadata={"file": str(rel), "match": m.group().strip(), "rule": "PY-02"},
                ))
                break

        for pat in _OBFUSCATION_PATTERNS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.CRITICAL,
                    package=PackageId("pypi", pkg_name),
                    title=f"PY-03: Obfuscated execution in {rel}",
                    detail=(
                        f"setup.py contains obfuscated code execution ({m.group()}). "
                        f"exec/eval with encoding is a strong signal of malicious "
                        f"payload hiding — legitimate packages don't need this."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "PY-03"},
                ))
                break

        for pat in _DOWNLOAD_PATTERNS:
            m = pat.search(content)
            if m:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.CRITICAL,
                    package=PackageId("pypi", pkg_name),
                    title=f"PY-05: Remote download in {rel}",
                    detail=(
                        f"setup.py downloads content during install ({m.group()}). "
                        f"This can fetch and execute arbitrary payloads at install time."
                    ),
                    metadata={"file": str(rel), "match": m.group(), "rule": "PY-05"},
                ))
                break

        return findings

    def _scan_pyproject(self, path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        rel = path.relative_to(project_dir)
        pkg_name = path.parent.name or "root"

        backend_match = re.search(
            r'build-backend\s*=\s*["\']([^"\']+)["\']',
            content,
        )
        if backend_match:
            backend = backend_match.group(1)
            if backend not in _STANDARD_BACKENDS:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.MEDIUM,
                    package=PackageId("pypi", pkg_name),
                    title=f"PY-04: Non-standard build backend '{backend}' in {rel}",
                    detail=(
                        f"pyproject.toml uses build backend '{backend}' which is not "
                        f"in the standard set. Custom build backends execute arbitrary "
                        f"Python code during package builds. Verify this is intentional."
                    ),
                    metadata={"file": str(rel), "backend": backend, "rule": "PY-04"},
                ))

        return findings
