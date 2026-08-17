"""Lockfile parsers — extract package lists from npm, pip, cargo, etc."""

from __future__ import annotations

import json
import re
from pathlib import Path

from depfence.core.models import PackageId


class UnsupportedLockfileError(ValueError):
    """The file was recognized, but parsing it would require guessing."""


def detect_ecosystem(project_dir: Path) -> list[tuple[str, Path]]:
    lockfiles: list[tuple[str, Path]] = []
    candidates = [
        ("npm", "package-lock.json"),
        ("npm", "npm-shrinkwrap.json"),
        ("npm", "yarn.lock"),
        ("npm", "pnpm-lock.yaml"),
        ("npm", "bun.lockb"),
        ("npm", "bun.lock"),
        ("npm", "deno.lock"),
        ("pypi", "requirements.txt"),
        ("pypi", "poetry.lock"),
        ("pypi", "Pipfile.lock"),
        ("pypi", "uv.lock"),
        ("pypi", "pylock.toml"),
        ("cargo", "Cargo.lock"),
        ("go", "go.sum"),
        ("maven", "gradle.lockfile"),
        ("maven", "pom.xml"),
        ("maven", "gradle/libs.versions.toml"),
        ("swift", "Package.resolved"),
        ("swift", "Podfile.lock"),
        ("nuget", "packages.lock.json"),
        ("nuget", "packages.config"),
        ("dart", "pubspec.lock"),
        ("dart", "pubspec.yaml"),
        ("rubygems", "Gemfile.lock"),
        ("packagist", "composer.lock"),
    ]
    for eco, filename in candidates:
        path = project_dir / filename
        if path.exists():
            lockfiles.append((eco, path))
    known_paths = {path for _ecosystem, path in lockfiles}
    for pattern in ("requirements*.txt", "pylock.*.toml"):
        for path in sorted(project_dir.glob(pattern)):
            if path.is_file() and path not in known_paths:
                lockfiles.append(("pypi", path))
                known_paths.add(path)
    return lockfiles


def parse_lockfile(ecosystem: str, path: Path) -> list[PackageId]:
    parsers = {
        "npm": _parse_npm,
        "pypi": _parse_pypi_requirements,
        "cargo": _parse_cargo_lock,
        "go": _parse_go_sum,
        "maven": _parse_maven,
        "swift": _parse_swift,
        "nuget": _parse_nuget,
        "dart": _parse_dart,
        "rubygems": _parse_rubygems,
        "packagist": _parse_composer,
    }
    parser = parsers.get(ecosystem)
    if parser:
        return parser(path)
    return []


def _parse_npm(path: Path) -> list[PackageId]:
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _parse_package_lock_json(path)
    if path.name == "yarn.lock":
        return _parse_yarn_lock(path)
    if path.name == "pnpm-lock.yaml":
        return _parse_pnpm_lock(path)
    if path.name in {"bun.lock", "bun.lockb"}:
        return _parse_bun_lock(path)
    if path.name == "deno.lock":
        return _parse_deno_lock(path)
    return []


def _parse_maven(path: Path) -> list[PackageId]:
    """Dispatch to the appropriate Maven/Gradle parser based on filename."""
    if path.name == "gradle.lockfile" or path.suffix == ".lockfile":
        from depfence.parsers.gradle_lockfile import parse_gradle_lockfile
        return parse_gradle_lockfile(path)
    if path.name == "pom.xml":
        from depfence.parsers.jvm_lockfiles import parse_pom_xml
        return parse_pom_xml(path)
    if path.name == "libs.versions.toml":
        from depfence.parsers.gradle_lockfile import parse_gradle_version_catalog
        return parse_gradle_version_catalog(path)
    return []


def _parse_dart(path: Path) -> list[PackageId]:
    """Dispatch to the appropriate Dart/Flutter parser based on filename."""
    if path.name == "pubspec.lock":
        from depfence.parsers.pubspec_lockfile import parse_pubspec_lock
        return parse_pubspec_lock(path)
    if path.name == "pubspec.yaml":
        from depfence.parsers.pubspec_lockfile import parse_pubspec_yaml
        return parse_pubspec_yaml(path)
    return []


def _parse_swift(path: Path) -> list[PackageId]:
    """Dispatch to the appropriate Swift parser based on filename."""
    if path.name == "Package.resolved":
        from depfence.parsers.swift_lockfile import parse_package_resolved
        return parse_package_resolved(path)
    if path.name == "Podfile.lock":
        from depfence.parsers.swift_lockfile import parse_podfile_lock
        return parse_podfile_lock(path)
    return []


def _parse_nuget(path: Path) -> list[PackageId]:
    """Dispatch to the appropriate NuGet parser based on filename."""
    if path.name == "packages.lock.json":
        from depfence.parsers.nuget_lockfiles import parse_packages_lock_json
        return parse_packages_lock_json(path)
    if path.name == "packages.config":
        from depfence.parsers.nuget_lockfiles import parse_packages_config
        return parse_packages_config(path)
    return []


def _parse_rubygems(path: Path) -> list[PackageId]:
    """Dispatch to the Gemfile.lock parser."""
    if path.name == "Gemfile.lock":
        from depfence.parsers.gemfile_lockfile import parse_gemfile_lock
        return parse_gemfile_lock(path)
    return []


def _parse_package_lock_json(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    data = json.loads(path.read_text())

    # lockfileVersion 2/3: packages key
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key:  # root package
                continue
            name = key.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                packages.append(PackageId("npm", name, version))
    # lockfileVersion 1: dependencies key
    elif "dependencies" in data:
        for name, info in data["dependencies"].items():
            version = info.get("version", "")
            if version:
                packages.append(PackageId("npm", name, version))
            for sub_name, sub_info in info.get("dependencies", {}).items():
                sub_ver = sub_info.get("version", "")
                if sub_ver:
                    packages.append(PackageId("npm", sub_name, sub_ver))

    return packages


def _parse_yarn_lock(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    content = path.read_text()
    current_name = ""
    for line in content.splitlines():
        if not line.startswith(" ") and not line.startswith("#") and line.strip():
            parts = line.strip().rstrip(":").split("@")
            if len(parts) >= 2:
                current_name = parts[0].strip('"') if parts[0] else f"@{parts[1]}"
        elif line.strip().startswith("version"):
            version = line.split('"')[1] if '"' in line else line.split()[-1]
            if current_name and version:
                packages.append(PackageId("npm", current_name, version))
                current_name = ""
    return packages


def _parse_pypi_requirements(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    if path.name == "Pipfile.lock":
        return _parse_pipfile_lock(path)
    if path.name == "poetry.lock":
        return _parse_poetry_lock(path)
    if path.name == "uv.lock":
        return _parse_uv_lock(path)
    if path.name == "pylock.toml" or (path.name.startswith("pylock.") and path.suffix == ".toml"):
        return _parse_pylock(path)

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        for sep in ["==", ">=", "<=", "~=", "!=", ">"]:
            if sep in line:
                name, version = line.split(sep, 1)
                name = name.strip().split("[")[0]
                version = version.strip().split(",")[0].split(";")[0].strip()
                packages.append(PackageId("pypi", name, version))
                break
        else:
            name = line.split(";")[0].split("[")[0].strip()
            if name:
                packages.append(PackageId("pypi", name, None))
    return packages


def _parse_pipfile_lock(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    data = json.loads(path.read_text())
    for section in ["default", "develop"]:
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            packages.append(PackageId("pypi", name, version or None))
    return packages


def _parse_poetry_lock(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    content = path.read_text()
    name = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            name = line.split('"')[1]
        elif line.startswith("version = ") and name:
            version = line.split('"')[1]
            packages.append(PackageId("pypi", name, version))
            name = ""
    return packages


def _parse_pnpm_lock(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    try:
        import yaml
    except ImportError:
        return _parse_pnpm_lock_regex(path)

    try:
        data = yaml.safe_load(path.read_text())
    except Exception:
        return _parse_pnpm_lock_regex(path)

    if not isinstance(data, dict):
        return packages

    # pnpm v6+ uses "packages" key with /pkg@version format
    pkgs = data.get("packages") or {}
    for key in pkgs:
        if not key or key == ".":
            continue
        # Format: /package-name@version or /@scope/name@version
        key = key.lstrip("/")
        if "@" in key:
            at_idx = key.rfind("@")
            if at_idx > 0:
                name = key[:at_idx]
                version = key[at_idx + 1:].split("(")[0]
                packages.append(PackageId("npm", name, version))

    # pnpm v9+ uses "snapshots" and "packages" differently
    if not packages:
        for key, info in (data.get("importers", {}).get(".", {}).get("dependencies", {}) or {}).items():
            version = info if isinstance(info, str) else info.get("version", "")
            if version:
                packages.append(PackageId("npm", key, version.split("(")[0]))

    return packages


def _parse_pnpm_lock_regex(path: Path) -> list[PackageId]:
    """Fallback regex parser when yaml not available."""
    import re
    packages: list[PackageId] = []
    content = path.read_text()
    pattern = re.compile(r"^\s+\S*/?(@?[^@\s]+)@([^:\s(]+)", re.MULTILINE)
    for match in pattern.finditer(content):
        name, version = match.group(1), match.group(2)
        if name and version:
            packages.append(PackageId("npm", name, version))
    return packages


def _parse_bun_lock(path: Path) -> list[PackageId]:
    """Parse Bun's text lockfile; never invent packages from binary strings."""
    packages: list[PackageId] = []
    text_lock = path if path.name == "bun.lock" else path.parent / "bun.lock"
    if text_lock.exists():
        content = text_lock.read_text()
        # Package values begin with a resolved identifier such as
        # ["is-even@1.0.0", ...] or ["@scope/pkg@2.0.0", ...].
        for match in re.finditer(r':\s*\[\s*"(?:npm:)?(@?[^"\s]+)@([^"\s]+)"', content):
            name, version = match.groups()
            if name and version:
                packages.append(PackageId("npm", name, version))
        return packages

    raise UnsupportedLockfileError(
        "bun.lockb is a legacy binary format; generate bun.lock with a current Bun release"
    )


def _parse_deno_lock(path: Path) -> list[PackageId]:
    """Extract npm dependencies from supported Deno JSON lockfiles."""
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("Deno lockfile must contain a JSON object")
    version = str(data.get("version") or "")
    if version and version not in {"3", "4", "5"}:
        raise UnsupportedLockfileError(f"unsupported Deno lockfile version {version!r}")
    npm = (data.get("packages") or {}).get("npm") or data.get("npm") or {}
    packages: list[PackageId] = []
    for identifier in npm:
        value = str(identifier).removeprefix("npm:")
        name, separator, version = value.rpartition("@")
        if separator and name and version:
            packages.append(PackageId("npm", name, version))
    return packages


def _parse_pylock(path: Path) -> list[PackageId]:
    """Parse the standardized PEP 751 ``pylock.toml`` package table."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10 compatibility
        import tomli as tomllib

    data = tomllib.loads(path.read_text())
    lock_version = str(data.get("lock-version") or "")
    if lock_version != "1.0":
        label = lock_version or "missing"
        raise UnsupportedLockfileError(f"unsupported PEP 751 lock-version: {label}")
    packages: list[PackageId] = []
    for package in data.get("packages", []):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip() or None
        if name:
            packages.append(PackageId("pypi", name, version))
    return packages


def _parse_uv_lock(path: Path) -> list[PackageId]:
    """Parse uv.lock (TOML-like format)."""
    packages: list[PackageId] = []
    content = path.read_text()
    name = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            name = line.split('"')[1] if '"' in line else ""
        elif line.startswith("version = ") and name:
            version = line.split('"')[1] if '"' in line else ""
            packages.append(PackageId("pypi", name, version))
            name = ""
    return packages


def _parse_cargo_lock(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    content = path.read_text()
    name = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            name = line.split('"')[1]
        elif line.startswith("version = ") and name:
            version = line.split('"')[1]
            if name != path.parent.name:
                packages.append(PackageId("cargo", name, version))
            name = ""
    return packages


def _parse_go_sum(path: Path) -> list[PackageId]:
    packages: list[PackageId] = []
    seen: set[tuple[str, str]] = set()
    for line in path.read_text().splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        key = (module, version)
        if key not in seen:
            seen.add(key)
            packages.append(PackageId("go", module, version))
    return packages


def _parse_composer(path: Path) -> list[PackageId]:
    """Dispatch to the composer.lock parser."""
    from depfence.parsers.composer_lockfile import parse_composer_lock
    return parse_composer_lock(path)
