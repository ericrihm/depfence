"""Dependency pinning enforcement scanner.

Detects unpinned or loosely pinned dependencies that could be exploited
via version substitution attacks:

- requirements.txt with >= or no version constraints
- package.json with ^, ~, >=, *, latest
- Cargo.toml with wildcard/open ranges
- Missing lockfiles (most dangerous — HIGH severity)

Each package is scored as:
  "pinned"   — exact version (==x.y.z, "1.2.3", =1.2.3)
  "range"    — semver range (^, ~, >=, ~=)
  "unpinned" — no constraint at all (*, latest, bare name)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-reuse-declared]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from depfence.core.models import Finding, FindingType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXACT_RE = re.compile(r"^[0-9]+\.[0-9]")  # bare "1.2.3" style (Cargo)
_CARGO_OPEN_RE = re.compile(r"^(>=|>|\*)")  # open-ended Cargo range


def _npm_score(version: str) -> str:
    """Return "pinned" / "range" / "unpinned" for an npm version string."""
    v = version.strip()
    if v in ("*", "latest", ""):
        return "unpinned"
    if v[0].isdigit():
        return "pinned"  # bare "1.2.3" — exact
    if v.startswith(("^", "~", ">=", ">", "<=", "<", "~=")):
        return "range"
    return "range"  # e.g. "x || y", "1.x"


def _pypi_score(constraint: str) -> str:
    """Return score for a single PyPI requirement line."""
    if "==" in constraint:
        return "pinned"
    if not any(op in constraint for op in (">=", "<=", ">", "<", "~=", "!=")):
        return "unpinned"
    return "range"


def _cargo_score(version: str) -> str:
    """Return score for a Cargo version specifier."""
    v = version.strip().strip('"\'\' \t')
    if not v or v == "*":
        return "unpinned"
    if v[0].isdigit() and ".." not in v and "*" not in v:
        # bare "1.2.3" means "^1.2.3" in Cargo — treat as range
        return "range"
    if v.startswith("=") and not v.startswith("==") and not v.startswith("=>"):
        return "pinned"  # "=1.2.3" exact pin
    if _CARGO_OPEN_RE.match(v):
        # "*" or bare ">" (no version bound) = truly unpinned
        # ">=" still has a lower bound = range
        return "unpinned" if "*" in v or (v.startswith(">") and not v.startswith(">=")) else "range"
    return "range"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PinningScanner:
    ecosystems = ["npm", "pypi", "cargo"]

    async def scan(self, packages: list) -> list:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_requirements(project_dir))
        findings.extend(self._check_package_json(project_dir))
        findings.extend(self._check_cargo(project_dir))
        findings.extend(self._check_lockfiles(project_dir))
        return findings

    # ------------------------------------------------------------------
    # requirements.txt
    # ------------------------------------------------------------------

    def _check_requirements(self, project_dir: Path) -> list[Finding]:
        findings = []
        for req_file in project_dir.glob("requirements*.txt"):
            try:
                content = req_file.read_text()
            except OSError:
                continue

            rel_path = str(req_file.relative_to(project_dir))
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                    continue

                pkg_name = re.split(r"[><=!~\[]", stripped)[0].strip()
                if not pkg_name:
                    continue

                score = _pypi_score(stripped)

                if score == "range":
                    findings.append(Finding(
                        finding_type=FindingType.UNPINNED,
                        severity=Severity.MEDIUM,
                        package=f"pypi:{pkg_name}",
                        title=f"Loosely pinned: {pkg_name} (range constraint)",
                        detail=(
                            f"In {rel_path}:L{i}, '{stripped}' uses a range constraint. "
                            f"Pin to exact version (==x.y.z) for reproducible builds."
                        ),
                        metadata={"pin_score": "range", "constraint": stripped, "file": rel_path},
                    ))
                elif score == "unpinned":
                    findings.append(Finding(
                        finding_type=FindingType.UNPINNED,
                        severity=Severity.MEDIUM,
                        package=f"pypi:{pkg_name}",
                        title=f"Unpinned dependency: {pkg_name}",
                        detail=(
                            f"In {rel_path}:L{i}, '{pkg_name}' has no version constraint. "
                            f"Any version could be installed, including malicious ones."
                        ),
                        metadata={"pin_score": "unpinned", "constraint": "", "file": rel_path},
                    ))
        return findings

    # ------------------------------------------------------------------
    # package.json
    # ------------------------------------------------------------------

    def _check_package_json(self, project_dir: Path) -> list[Finding]:
        findings = []
        pkg_json = project_dir / "package.json"
        if not pkg_json.exists():
            return findings

        try:
            data = json.loads(pkg_json.read_text())
        except (json.JSONDecodeError, OSError):
            return findings

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            for name, version in deps.items():
                score = _npm_score(str(version))

                if score == "unpinned":
                    findings.append(Finding(
                        finding_type=FindingType.UNPINNED,
                        severity=Severity.HIGH,
                        package=f"npm:{name}",
                        title=f"Wildcard version: {name}@{version}",
                        detail=(
                            f"Package '{name}' uses '{version}' which allows any version. "
                            f"An attacker publishing a malicious version would be immediately "
                            f"pulled on next install. Pin to a specific version."
                        ),
                        metadata={"pin_score": "unpinned", "constraint": version, "section": section},
                    ))
                elif score == "range":
                    v = str(version)
                    if v.startswith((">=", ">")):
                        # open-ended — MEDIUM
                        findings.append(Finding(
                            finding_type=FindingType.UNPINNED,
                            severity=Severity.MEDIUM,
                            package=f"npm:{name}",
                            title=f"Open-ended range: {name}@{version}",
                            detail=(
                                f"Package '{name}' uses '{version}' which accepts any newer version. "
                                f"Use ^ or ~ constraints with a lockfile for safer resolution."
                            ),
                            metadata={"pin_score": "range", "constraint": version, "section": section},
                        ))
                    else:
                        # caret/tilde — LOW (common, mitigated by lockfile)
                        findings.append(Finding(
                            finding_type=FindingType.UNPINNED,
                            severity=Severity.LOW,
                            package=f"npm:{name}",
                            title=f"Semver range: {name}@{version}",
                            detail=(
                                f"Package '{name}' uses '{version}' (caret/tilde range). "
                                f"This allows minor/patch updates. Ensure a lockfile is committed "
                                f"to prevent unexpected version resolution."
                            ),
                            metadata={"pin_score": "range", "constraint": version, "section": section},
                        ))
        return findings

    # ------------------------------------------------------------------
    # Cargo.toml
    # ------------------------------------------------------------------

    def _check_cargo(self, project_dir: Path) -> list[Finding]:
        findings = []
        cargo_toml = project_dir / "Cargo.toml"
        if not cargo_toml.exists():
            return findings

        if tomllib is None:
            # Fallback: regex-based parse when tomllib is unavailable
            return self._check_cargo_regex(cargo_toml, project_dir)

        try:
            data = tomllib.loads(cargo_toml.read_text())
        except Exception:
            return self._check_cargo_regex(cargo_toml, project_dir)

        rel_path = str(cargo_toml.relative_to(project_dir))

        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(section, {})
            for name, spec in deps.items():
                if isinstance(spec, dict):
                    version = str(spec.get("version", ""))
                elif isinstance(spec, str):
                    version = spec
                else:
                    continue

                score = _cargo_score(version)

                if score == "unpinned":
                    findings.append(Finding(
                        finding_type=FindingType.UNPINNED,
                        severity=Severity.MEDIUM,
                        package=f"cargo:{name}",
                        title=f"Unpinned Cargo dependency: {name}",
                        detail=(
                            f"In {rel_path} [{section}], '{name}' version is '{version or '*'}'. "
                            f"Use an exact pin (=x.y.z) or commit Cargo.lock for reproducible builds."
                        ),
                        metadata={"pin_score": "unpinned", "constraint": version, "section": section},
                    ))
                elif score == "range":
                    # bare "1.2.3" in Cargo is implicitly "^1.2.3" — LOW
                    findings.append(Finding(
                        finding_type=FindingType.UNPINNED,
                        severity=Severity.LOW,
                        package=f"cargo:{name}",
                        title=f"Semver range: {name} {version}",
                        detail=(
                            f"In {rel_path} [{section}], '{name}' version '{version}' is a semver "
                            f"range. Commit Cargo.lock or use =x.y.z for exact pinning."
                        ),
                        metadata={"pin_score": "range", "constraint": version, "section": section},
                    ))

        return findings

    def _check_cargo_regex(self, cargo_toml: Path, project_dir: Path) -> list[Finding]:
        """Regex fallback when tomllib is unavailable."""
        findings = []
        rel_path = str(cargo_toml.relative_to(project_dir))
        try:
            content = cargo_toml.read_text()
        except OSError:
            return findings

        in_deps = False
        dep_section_re = re.compile(
            r"^\[(dependencies|dev-dependencies|build-dependencies)\]", re.IGNORECASE
        )
        other_section_re = re.compile(r"^\[")
        inline_re = re.compile(r'^(\S+)\s*=\s*"([^"]*)"$')
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if dep_section_re.match(stripped):
                in_deps = True
                section = dep_section_re.match(stripped).group(1).lower()
                continue
            if other_section_re.match(stripped) and not dep_section_re.match(stripped):
                in_deps = False
                continue
            if not in_deps or not stripped or stripped.startswith("#"):
                continue
            m = inline_re.match(stripped)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            score = _cargo_score(version)
            if score in ("unpinned", "range"):
                sev = Severity.MEDIUM if score == "unpinned" else Severity.LOW
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=sev,
                    package=f"cargo:{name}",
                    title=f"{'Unpinned' if score == 'unpinned' else 'Semver range'} Cargo dependency: {name}",
                    detail=f"In {rel_path}:L{i}, '{name}' version is '{version}'. "
                           f"Use =x.y.z or commit Cargo.lock.",
                    metadata={"pin_score": score, "constraint": version},
                ))
        return findings

    # ------------------------------------------------------------------
    # Lockfile presence checks
    # ------------------------------------------------------------------

    def _check_lockfiles(self, project_dir: Path) -> list[Finding]:
        findings = []

        # --- npm ---
        has_pkg_json = (project_dir / "package.json").exists()
        if has_pkg_json:
            has_npm_lock = (
                (project_dir / "package-lock.json").exists()
                or (project_dir / "yarn.lock").exists()
                or (project_dir / "pnpm-lock.yaml").exists()
            )
            if not has_npm_lock:
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=Severity.HIGH,
                    package="npm:*",
                    title="No npm lockfile found",
                    detail=(
                        "No package-lock.json, yarn.lock, or pnpm-lock.yaml found. "
                        "Without a lockfile, transitive dependency versions are not pinned "
                        "and can change between installs, enabling supply chain attacks."
                    ),
                    metadata={"pin_score": "unpinned", "lockfile": None},
                ))

        # --- Python ---
        has_requirements = bool(list(project_dir.glob("requirements*.txt")))
        if has_requirements:
            has_py_lock = (
                (project_dir / "poetry.lock").exists()
                or (project_dir / "Pipfile.lock").exists()
                or (project_dir / "pdm.lock").exists()
                or (project_dir / "uv.lock").exists()
            )
            # requirements.txt itself is a form of pinning; only flag if ALL
            # requirement files are unpinned AND no higher-level lockfile exists
            all_req_files = list(project_dir.glob("requirements*.txt"))
            any_pinned_req = False
            for rf in all_req_files:
                try:
                    txt = rf.read_text()
                except OSError:
                    continue
                if any("==" in line for line in txt.splitlines()
                       if line.strip() and not line.strip().startswith("#")):
                    any_pinned_req = True
                    break

            if not has_py_lock and not any_pinned_req:
                findings.append(Finding(
                    finding_type=FindingType.UNPINNED,
                    severity=Severity.HIGH,
                    package="pypi:*",
                    title="No Python lockfile and requirements not pinned",
                    detail=(
                        "No poetry.lock, Pipfile.lock, pdm.lock, or uv.lock found, "
                        "and requirements files contain no exact (==) pins. "
                        "Transitive dependencies are fully unpinned."
                    ),
                    metadata={"pin_score": "unpinned", "lockfile": None},
                ))

        # --- Cargo ---
        has_cargo_toml = (project_dir / "Cargo.toml").exists()
        if has_cargo_toml and not (project_dir / "Cargo.lock").exists():
            findings.append(Finding(
                finding_type=FindingType.UNPINNED,
                severity=Severity.HIGH,
                package="cargo:*",
                title="No Cargo.lock found",
                detail=(
                    "Cargo.toml exists but Cargo.lock is missing. "
                    "Without Cargo.lock, dependency versions are resolved fresh on each build, "
                    "making the project vulnerable to version substitution attacks. "
                    "Commit Cargo.lock to the repository."
                ),
                metadata={"pin_score": "unpinned", "lockfile": None},
            ))

        return findings
