"""Auto-fix engine — generates safe version pins for vulnerable packages."""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import Finding, PackageId


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
                old_line = line
                new_line = f'{indent}{pkg_name}{eq_part}"{new_constraint}"{trailing}'
                new_lines.append(new_line)
                changes.append(f"{pkg_name}: \"{version_str}\" → \"{new_constraint}\"")
                continue

        new_lines.append(line)

    if changes:
        pyproject_path.write_text("\n".join(new_lines) + "\n")

    return changes


def apply_fixes_cargo_toml(cargo_path: Path, fixes: list[dict]) -> list[str]:
    """Apply fixes to Cargo.toml [dependencies] section. Returns list of changes made.

    Preserves the original version format (plain string or table with version key).
    """
    if not cargo_path.exists():
        return []

    content = cargo_path.read_text()
    changes: list[str] = []

    fix_map = {f["package"].lower(): f for f in fixes if f["ecosystem"] == "cargo"}
    if not fix_map:
        return []

    lines = content.splitlines()
    in_deps = False
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("["):
            # [dependencies] or [dev-dependencies] / [build-dependencies]
            in_deps = stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
            new_lines.append(line)
            continue

        if not in_deps:
            new_lines.append(line)
            continue

        # Simple string value: serde = "1.0.100"
        m = re.match(r'^(\s*)(\S+)(\s*=\s*)"([^"]*)"(.*)$', line)
        if m:
            indent, crate, eq_part, version_str, trailing = m.groups()
            if crate.lower() in fix_map:
                fix = fix_map[crate.lower()]
                fv = fix["fix_version"]
                # Preserve leading ^ or = sigil if present
                if version_str.startswith("^"):
                    new_ver = f"^{fv}"
                elif version_str.startswith("="):
                    new_ver = f"={fv}"
                elif version_str.startswith(">="):
                    new_ver = f">={fv}"
                else:
                    new_ver = fv
                new_line = f'{indent}{crate}{eq_part}"{new_ver}"{trailing}'
                new_lines.append(new_line)
                changes.append(f"{crate}: \"{version_str}\" → \"{new_ver}\"")
                continue

        # Table value: serde = { version = "1.0.100", features = [...] }
        m2 = re.match(r'^(\s*)(\S+)(\s*=\s*\{.*version\s*=\s*)"([^"]*)"(.*)$', line)
        if m2:
            indent, crate, prefix, version_str, suffix = m2.groups()
            if crate.lower() in fix_map:
                fix = fix_map[crate.lower()]
                fv = fix["fix_version"]
                if version_str.startswith("^"):
                    new_ver = f"^{fv}"
                elif version_str.startswith("="):
                    new_ver = f"={fv}"
                elif version_str.startswith(">="):
                    new_ver = f">={fv}"
                else:
                    new_ver = fv
                new_line = f'{indent}{crate}{prefix}"{new_ver}"{suffix}'
                new_lines.append(new_line)
                changes.append(f"{crate}: \"{version_str}\" → \"{new_ver}\"")
                continue

        new_lines.append(line)

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


def generate_diff(findings: list[Finding], project_dir: Path) -> str:
    """Generate a unified diff showing recommended changes."""
    fixes = generate_fixes(findings, project_dir)
    if not fixes:
        return "No auto-fixable findings."

    lines = ["# depfence recommended fixes", ""]

    npm_fixes = [f for f in fixes if f["ecosystem"] == "npm"]
    pypi_fixes = [f for f in fixes if f["ecosystem"] == "pypi"]
    cargo_fixes = [f for f in fixes if f["ecosystem"] == "cargo"]
    go_fixes = [f for f in fixes if f["ecosystem"] == "go"]

    if npm_fixes:
        lines.append("## npm (package.json)")
        for f in npm_fixes:
            cur = f["current_version"] or "current"
            lines.append(f"  {f['package']}: {cur} → ^{f['fix_version']}  [{f['severity']}]")
        lines.append("")

    if pypi_fixes:
        lines.append("## PyPI (requirements.txt / pyproject.toml)")
        for f in pypi_fixes:
            cur = f["current_version"] or "current"
            lines.append(f"  {f['package']}: {cur} → >={f['fix_version']}  [{f['severity']}]")
        lines.append("")

    if cargo_fixes:
        lines.append("## Cargo (Cargo.toml)")
        for f in cargo_fixes:
            cur = f["current_version"] or "current"
            lines.append(f"  {f['package']}: {cur} → {f['fix_version']}  [{f['severity']}]")
        lines.append("")

    if go_fixes:
        lines.append("## Go (go.mod — run commands below)")
        for f in go_fixes:
            lines.append(f"  go get {f['package']}@v{f['fix_version']}  [{f['severity']}]")
        lines.append("")

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
