"""Auto-fix engine — generates safe version pins for vulnerable packages."""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import Finding

# (ecosystem, section heading, per-fix line format with {package}/{fix_version}/{current}/{severity})
_ECOSYSTEM_SECTIONS: list[tuple[str, str, str]] = [
    ("npm",   "## npm (package.json)",                       "  {package}: {current} → ^{fix_version}  [{severity}]"),
    ("pypi",  "## PyPI (requirements.txt / pyproject.toml)", "  {package}: {current} → >={fix_version}  [{severity}]"),
    ("cargo", "## Cargo (Cargo.toml)",                       "  {package}: {current} → {fix_version}  [{severity}]"),
    ("go",    "## Go (go.mod — run commands below)",         "  go get {package}@v{fix_version}  [{severity}]"),
]

_CARGO_PATTERNS = (
    re.compile(r'^(\s*)(\S+)(\s*=\s*)"([^"]*)"(.*)$'),
    re.compile(r'^(\s*)(\S+)(\s*=\s*\{.*version\s*=\s*)"([^"]*)"(.*)$'),
)

_CARGO_DEP_SECTIONS = frozenset({"[dependencies]", "[dev-dependencies]", "[build-dependencies]"})


def generate_fixes(findings: list[Finding], project_dir: Path) -> list[dict]:
    """Generate fix suggestions for findings that have fix_version set."""
    fixes: list[dict] = []

    for finding in findings:
        if not finding.fix_version:
            continue

        pkg_str = finding.package
        parts = pkg_str.split(":")
        if len(parts) != 2:
            continue
        ecosystem, name_ver = parts[0], parts[1]
        name = name_ver.split("@")[0] if "@" in name_ver else name_ver

        fix = {
            "package": name,
            "ecosystem": ecosystem,
            "current_version": name_ver.split("@")[1] if "@" in name_ver else None,
            "fix_version": finding.fix_version,
            "severity": finding.severity.name,
            "title": finding.title,
        }
        fixes.append(fix)

    return _deduplicate(fixes)


def apply_fixes_requirements(req_path: Path, fixes: list[dict]) -> list[str]:
    """Apply fixes to a requirements.txt file. Returns list of changes made."""
    if not req_path.exists():
        return []

    content = req_path.read_text()
    lines = content.splitlines()
    changes = []

    fix_map = {f["package"].lower(): f for f in fixes if f["ecosystem"] == "pypi"}

    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            new_lines.append(line)
            continue

        for sep in ("==", ">=", "<=", "~=", "!=", ">"):
            if sep in stripped:
                pkg_name = stripped.split(sep)[0].strip().split("[")[0].lower()
                if pkg_name in fix_map:
                    fix = fix_map[pkg_name]
                    new_line = f"{pkg_name}>={fix['fix_version']}"
                    new_lines.append(new_line)
                    changes.append(f"{pkg_name}: {stripped} → {new_line}")
                else:
                    new_lines.append(line)
                break
        else:
            new_lines.append(line)

    if changes:
        req_path.write_text("\n".join(new_lines) + "\n")

    return changes


def apply_fixes_package_json(pkg_json_path: Path, fixes: list[dict]) -> list[str]:
    """Apply fixes to package.json. Returns list of changes made."""
    if not pkg_json_path.exists():
        return []

    data = json.loads(pkg_json_path.read_text())
    changes = []

    fix_map = {f["package"]: f for f in fixes if f["ecosystem"] == "npm"}

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        for name, current_ver in list(deps.items()):
            if name in fix_map:
                fix = fix_map[name]
                new_ver = f"^{fix['fix_version']}"
                deps[name] = new_ver
                changes.append(f"{name}: {current_ver} → {new_ver}")

    if changes:
        pkg_json_path.write_text(json.dumps(data, indent=2) + "\n")

    return changes


def apply_fixes_pyproject_toml(pyproject_path: Path, fixes: list[dict]) -> list[str]:
    """Apply fixes to a pyproject.toml (Poetry) file. Returns list of changes made.

    Handles the [tool.poetry.dependencies] section.  Version values are updated
    using caret notation (^<major>.<minor>) when the existing constraint is a
    caret/tilde/plain version string, or >=<fix_version> otherwise.
    """
    if not pyproject_path.exists():
        return []

    content = pyproject_path.read_text()
    changes: list[str] = []

    fix_map = {f["package"].lower(): f for f in fixes if f["ecosystem"] == "pypi"}
    if not fix_map:
        return []

    # Find the [tool.poetry.dependencies] section boundaries.
    # We operate line-by-line to preserve everything else in the TOML file.
    lines = content.splitlines()
    in_section = False
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Detect section headers
        if stripped.startswith("["):
            in_section = stripped == "[tool.poetry.dependencies]"
            new_lines.append(line)
            continue

        if not in_section:
            new_lines.append(line)
            continue

        # Try to match a dependency entry: name = "..."  or  name = {version = "..."}
        # Simple string value: requests = "^2.28"
        m = re.match(r'^(\s*)(\S+)(\s*=\s*)"([^"]*)"(.*)$', line)
        if m:
            indent, pkg_name, eq_part, version_str, trailing = m.groups()
            if pkg_name.lower() in fix_map:
                fix = fix_map[pkg_name.lower()]
                fv = fix["fix_version"]
                # Determine new constraint format based on existing constraint
                if version_str.startswith("^") or version_str.startswith("~"):
                    # Use caret with major.minor of fix_version
                    parts = fv.split(".")
                    new_constraint = f"^{parts[0]}.{parts[1]}" if len(parts) >= 2 else f"^{fv}"
                elif re.match(r'[\d]', version_str):
                    # Plain version — keep as plain version
                    new_constraint = fv
                else:
                    new_constraint = f">={fv}"
                new_line = f'{indent}{pkg_name}{eq_part}"{new_constraint}"{trailing}'
                new_lines.append(new_line)
                changes.append(f"{pkg_name}: \"{version_str}\" → \"{new_constraint}\"")
                continue

        new_lines.append(line)

    if changes:
        pyproject_path.write_text("\n".join(new_lines) + "\n")

    return changes


def _cargo_new_version(version_str: str, fix_version: str) -> str:
    """Preserve the leading version sigil (^, =, >=) when bumping a Cargo version."""
    if version_str.startswith("^"):
        return f"^{fix_version}"
    if version_str.startswith("="):
        return f"={fix_version}"
    if version_str.startswith(">="):
        return f">={fix_version}"
    return fix_version


def _apply_cargo_fix(line: str, fix_map: dict) -> tuple[str, list[str]]:
    """Try to apply a fix to one Cargo.toml dependency line.

    Returns (replacement_line, changes_list). changes_list is empty when no fix applied.
    """
    m = next(filter(None, (p.match(line) for p in _CARGO_PATTERNS)), None)
    if not m:
        return line, []
    indent, crate, prefix, version_str, suffix = m.groups()
    if crate.lower() not in fix_map:
        return line, []
    new_ver = _cargo_new_version(version_str, fix_map[crate.lower()]["fix_version"])
    return f'{indent}{crate}{prefix}"{new_ver}"{suffix}', [f'{crate}: "{version_str}" → "{new_ver}"']


def apply_fixes_cargo_toml(cargo_path: Path, fixes: list[dict]) -> list[str]:
    """Apply fixes to Cargo.toml [dependencies] section. Returns list of changes made.

    Preserves the original version format (plain string or table with version key).
    """
    if not cargo_path.exists():
        return []

    fix_map = {f["package"].lower(): f for f in fixes if f["ecosystem"] == "cargo"}
    if not fix_map:
        return []

    in_deps = False
    new_lines: list[str] = []
    changes: list[str] = []

    for line in cargo_path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = stripped in _CARGO_DEP_SECTIONS
            new_lines.append(line)
            continue

        new_line, line_changes = _apply_cargo_fix(line, fix_map) if in_deps else (line, [])
        new_lines.append(new_line)
        changes.extend(line_changes)

    if changes:
        cargo_path.write_text("\n".join(new_lines) + "\n")

    return changes


def suggest_go_mod_commands(go_mod_path: Path, fixes: list[dict]) -> list[str]:
    """Return shell commands to update Go module dependencies.

    go.mod is managed by tooling (go get / go mod tidy), so we emit commands
    rather than directly editing the file.
    """
    if not go_mod_path.exists():
        return []

    go_fixes = [f for f in fixes if f["ecosystem"] == "go"]
    if not go_fixes:
        return []

    cmds: list[str] = []
    for fix in go_fixes:
        cmds.append(f"go get {fix['package']}@v{fix['fix_version']}")
    cmds.append("go mod tidy")
    return cmds


def apply_fixes(project_dir: Path, fixes: list[dict]) -> list[str]:
    """Apply all detected manifest fixes and return human-readable change descriptions.

    Detects manifests present in *project_dir* and delegates to the appropriate
    apply_fixes_* helper.  For Go modules a shell-command suggestion is returned
    instead of direct file edits.
    """
    descriptions: list[str] = []

    req = project_dir / "requirements.txt"
    if req.exists():
        for change in apply_fixes_requirements(req, fixes):
            descriptions.append(f"[requirements.txt] {change}")

    pkg_json = project_dir / "package.json"
    if pkg_json.exists():
        for change in apply_fixes_package_json(pkg_json, fixes):
            descriptions.append(f"[package.json] {change}")

    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        for change in apply_fixes_pyproject_toml(pyproject, fixes):
            descriptions.append(f"[pyproject.toml] {change}")

    cargo = project_dir / "Cargo.toml"
    if cargo.exists():
        for change in apply_fixes_cargo_toml(cargo, fixes):
            descriptions.append(f"[Cargo.toml] {change}")

    go_mod = project_dir / "go.mod"
    if go_mod.exists():
        for cmd in suggest_go_mod_commands(go_mod, fixes):
            descriptions.append(f"[go.mod] run: {cmd}")

    return descriptions


def _diff_section_lines(eco_fixes: list[dict], heading: str, line_fmt: str) -> list[str]:
    out = [heading]
    for f in eco_fixes:
        out.append(line_fmt.format(
            package=f["package"],
            fix_version=f["fix_version"],
            severity=f["severity"],
            current=f["current_version"] or "current",
        ))
    out.append("")
    return out


def generate_diff(findings: list[Finding], project_dir: Path) -> str:
    """Generate a unified diff showing recommended changes."""
    fixes = generate_fixes(findings, project_dir)
    if not fixes:
        return "No auto-fixable findings."

    lines = ["# depfence recommended fixes", ""]

    for ecosystem, heading, line_fmt in _ECOSYSTEM_SECTIONS:
        eco_fixes = [f for f in fixes if f["ecosystem"] == ecosystem]
        if eco_fixes:
            lines.extend(_diff_section_lines(eco_fixes, heading, line_fmt))

    lines.append(f"\nTotal: {len(fixes)} packages to update")
    return "\n".join(lines)


def _deduplicate(fixes: list[dict]) -> list[dict]:
    """Keep only the highest-severity fix per package."""
    seen: dict[str, dict] = {}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for fix in fixes:
        key = f"{fix['ecosystem']}:{fix['package']}"
        if key not in seen or severity_order.get(fix["severity"], 9) < severity_order.get(seen[key]["severity"], 9):
            seen[key] = fix

    return list(seen.values())
