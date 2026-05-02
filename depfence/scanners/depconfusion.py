"""Dependency confusion scanner — detects private/public namespace collisions.

Enhanced detection covers:
- Namespace analysis (internal/corp naming patterns, org-prefixed names)
- Version anomaly detection (high-jump versions, 999.x.x squatter pattern)
- Scope/namespace validation for npm
- Registry cross-check simulation (private vs public registry shadowing)
- Install script analysis (network commands, env var access)
- User-configurable org internal prefixes via depfence.yml
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Sequence

import httpx

log = logging.getLogger(__name__)

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Names that strongly suggest internal/private origin
_INTERNAL_SEGMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(?:internal|private|corp|proprietary|intranet|infra|platform|mono)\b", re.I),
    re.compile(r"(?:^|[-_])(?:dev|staging|local|test|sandbox)(?:[-_]|$)", re.I),
]

# Typical org-prefixed name: "acme-auth", "mycompany-utils", "orgname-core"
_ORG_PREFIX_RE = re.compile(
    r"^([a-z][a-z0-9]{2,})-"
    r"(?:auth|api|sdk|cli|lib|core|utils?|helpers?|client|service|server|config|"
    r"setup|deploy|infra|common|shared|internal|private|tools?|base|data|models?|"
    r"types?|platform|components?|ui|backend|frontend|web|app)s?$",
    re.I,
)

# Version number anomaly patterns
_HIGH_VERSION_RE = re.compile(r"^(\d+)\.")
_SQUATTER_VERSION_RE = re.compile(r"^(?:999|9999|99999)\.\d+\.\d+")

# Network/env patterns for install scripts
_SCRIPT_NETWORK_RE = re.compile(
    r"\b(?:curl|wget|fetch|http\.get|https?\.get|request\.get|axios\.get|"
    r"node-fetch|got\.|superagent|needle)\b",
    re.I,
)
_SCRIPT_ENV_RE = re.compile(
    r"(?:process\.env\."
    r"|\$(?:ENV|\{)?[A-Z_]{3,}\}?"
    r"|os\.environ|getenv)"
    r".*(?:TOKEN|KEY|SECRET|PASS|CREDENTIAL|AUTH|API)",
    re.I,
)
_SCRIPT_EXEC_RE = re.compile(
    r"\b(?:child_process|execSync|spawnSync|execFileSync|"
    r"exec\b|spawn\b|execFile\b|fork\b|eval\b)\b",
    re.I,
)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_org_prefixes(project_dir: Path | None) -> list[str]:
    """Load user-configured org prefixes from depfence.yml, if present.

    Expected depfence.yml structure::

        dep_confusion:
          internal_prefixes:
            - acme
            - mycompany
    """
    if project_dir is None:
        return []
    config_path = project_dir / "depfence.yml"
    if not config_path.exists():
        return []
    try:
        import yaml  # type: ignore[import-untyped]
        data = yaml.safe_load(config_path.read_text())
    except ImportError:
        data = _minimal_yaml_load(config_path.read_text())
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    dep_confusion_cfg = data.get("dep_confusion", {})
    if not isinstance(dep_confusion_cfg, dict):
        return []
    prefixes = dep_confusion_cfg.get("internal_prefixes", [])
    if isinstance(prefixes, list):
        return [str(p).lower() for p in prefixes if p]
    return []


def _minimal_yaml_load(text: str) -> dict:
    """Parse a very minimal YAML subset for dep_confusion config (no pyyaml required)."""
    result: dict = {}
    current_section: str | None = None
    current_list: list | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.lstrip()
        if stripped.startswith("#") or not stripped:
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            # Flush previous accumulator
            if current_section and current_list is not None:
                result[current_section] = current_list
            current_list = None
            current_section = None
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                if val:
                    result[key] = val
                else:
                    # Could be a mapping — store empty dict as placeholder
                    result[key] = {}
                    current_section = key
        elif indent > 0:
            if stripped.startswith("- "):
                item = stripped[2:].strip()
                if current_list is None:
                    current_list = []
                current_list.append(item)
            elif ":" in stripped and current_section:
                # Nested key:value — store under current_section dict
                sub_key, _, sub_val = stripped.partition(":")
                sub_key = sub_key.strip()
                sub_val = sub_val.strip()
                if isinstance(result.get(current_section), dict):
                    result[current_section][sub_key] = sub_val
    if current_section and current_list is not None:
        result[current_section] = current_list
    return result


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class DepConfusionScanner:
    name = "dep_confusion"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    # Map of well-known bare package names -> their canonical npm scope
    _KNOWN_SCOPES: dict[str, str] = {
        "react": "facebook",
        "angular": "angular",
        "babel": "babel",
        "jest": "jest",
        "testing-library": "testing-library",
        "aws-sdk": "aws-sdk",
        "google-cloud": "google-cloud",
        "sentry": "sentry",
        "storybook": "storybook",
        "emotion": "emotion",
        "mui": "mui",
        "chakra-ui": "chakra-ui",
        "tanstack": "tanstack",
        "redwoodjs": "redwoodjs",
    }

    def __init__(
        self,
        org_prefixes: Sequence[str] = (),
        project_dir: Path | None = None,
    ) -> None:
        # Merge constructor-supplied prefixes with config-file prefixes
        file_prefixes = _load_org_prefixes(project_dir)
        all_prefixes = list(org_prefixes) + file_prefixes
        self._org_prefixes: list[str] = [p.lower() for p in all_prefixes]

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for meta in packages:
            pkg = meta.pkg

            # 1. Namespace / naming analysis (no network needed)
            findings.extend(self._check_namespace(pkg))

            # 2. Version anomaly detection
            if pkg.version:
                findings.extend(self._check_version_anomaly(pkg))

            # 3. npm-specific scope validation (offline)
            if pkg.ecosystem == "npm":
                findings.extend(self._check_npm_scope_offline(pkg))

            # 4. Live registry cross-check (npm only — scoped packages)
            if pkg.ecosystem == "npm" and pkg.name.startswith("@"):
                finding = await self._check_npm_scope_online(pkg)
                if finding:
                    findings.append(finding)

        return findings

    async def scan_project_configs(
        self, project_dir: Path, org_prefixes: Sequence[str] = ()
    ) -> list[Finding]:
        """Inspect project-level config files for registry misconfigurations."""
        findings: list[Finding] = []

        # ----------------------------------------------------------------
        # .npmrc
        # ----------------------------------------------------------------
        npmrc = project_dir / ".npmrc"
        if npmrc.exists():
            content = npmrc.read_text()
            if "registry=" in content and "always-auth" not in content:
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.MEDIUM,
                    package=PackageId(ecosystem="npm", name="project-config"),
                    title="Private registry without always-auth",
                    detail=(
                        ".npmrc configures a custom registry but does not set always-auth=true. "
                        "This may allow fallback to the public registry for unscoped packages."
                    ),
                    metadata={"file": str(npmrc), "check": "dep_confusion"},
                ))

            # Scopes with config lines but no registry pin are confusion risks
            scoped_without_registry = self._check_npmrc_scope_gaps(content)
            for scope in scoped_without_registry:
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.HIGH,
                    package=PackageId(ecosystem="npm", name=f"{scope}/*"),
                    title=f"Scope {scope} has no registry pin in .npmrc",
                    detail=(
                        f"Packages under {scope} are not pinned to a specific registry in "
                        f".npmrc. A public registry squatter could intercept installs."
                    ),
                    metadata={"scope": scope, "file": str(npmrc), "check": "dep_confusion_scope_gap"},
                ))

        # ----------------------------------------------------------------
        # pyproject.toml
        # ----------------------------------------------------------------
        pyproject = project_dir / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text()
            if "extra-index-url" in content:
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.HIGH,
                    package=PackageId(ecosystem="pypi", name="project-config"),
                    title="Extra index URL enables dependency confusion",
                    detail=(
                        "pyproject.toml uses extra-index-url which queries both private and "
                        "public PyPI. An attacker can register a higher-version package on "
                        "public PyPI to hijack installs. Use --index-url (exclusive) instead."
                    ),
                    metadata={"file": str(pyproject), "check": "dep_confusion"},
                ))

        # ----------------------------------------------------------------
        # pip.conf / .pip/pip.conf
        # ----------------------------------------------------------------
        for pip_conf in (
            project_dir / "pip.conf",
            project_dir / ".pip" / "pip.conf",
        ):
            if pip_conf.exists():
                content = pip_conf.read_text()
                if "extra-index-url" in content:
                    findings.append(Finding(
                        finding_type=FindingType.DEP_CONFUSION,
                        severity=Severity.HIGH,
                        package=PackageId(ecosystem="pypi", name="project-config"),
                        title="pip.conf extra-index-url enables dependency confusion",
                        detail=(
                            "pip.conf uses extra-index-url, which causes pip to query both "
                            "private and public PyPI. Use index-url exclusively instead."
                        ),
                        metadata={"file": str(pip_conf), "check": "dep_confusion"},
                    ))
                break

        # ----------------------------------------------------------------
        # package.json install scripts
        # ----------------------------------------------------------------
        package_json = project_dir / "package.json"
        if package_json.exists():
            findings.extend(self._check_package_json_scripts(package_json))

        return findings

    # ------------------------------------------------------------------
    # Namespace / naming analysis
    # ------------------------------------------------------------------

    def _check_namespace(self, pkg: PackageId) -> list[Finding]:
        findings: list[Finding] = []
        name_lower = pkg.name.lower()
        # Strip npm scope for segment analysis
        bare = name_lower.split("/", 1)[-1] if name_lower.startswith("@") else name_lower

        # 1. User-configured org prefix match
        for prefix in self._org_prefixes:
            if bare.startswith(prefix + "-") or bare.startswith(prefix + "_"):
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"Package name matches configured internal prefix '{prefix}'",
                    detail=(
                        f"'{pkg.name}' starts with the org prefix '{prefix}', which is "
                        f"configured as internal. If this package is being pulled from a "
                        f"public registry it may be a dependency confusion attack."
                    ),
                    confidence=0.85,
                    metadata={"prefix": prefix, "check": "dep_confusion_namespace"},
                ))

        # 2. Built-in internal segment patterns
        for pattern in _INTERNAL_SEGMENT_PATTERNS:
            if pattern.search(bare):
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.MEDIUM,
                    package=pkg,
                    title="Package name contains internal/private naming pattern",
                    detail=(
                        f"'{pkg.name}' contains a segment associated with internal packages "
                        f"(e.g. 'internal', 'private', 'corp', 'infra'). "
                        f"Verify this package is sourced from your private registry."
                    ),
                    confidence=0.65,
                    metadata={"pattern": pattern.pattern, "check": "dep_confusion_namespace"},
                ))
                break  # One finding per package for this category

        # 3. Org-prefix heuristic (unscoped npm packages that look company-prefixed)
        if not name_lower.startswith("@") and pkg.ecosystem == "npm":
            m = _ORG_PREFIX_RE.match(bare)
            if m:
                org_guess = m.group(1)
                short_name = bare[len(org_guess) + 1:]
                findings.append(Finding(
                    finding_type=FindingType.DEP_CONFUSION,
                    severity=Severity.LOW,
                    package=pkg,
                    title="Unscoped npm package with org-prefix naming pattern",
                    detail=(
                        f"'{pkg.name}' looks like it should be scoped under '@{org_guess}/' "
                        f"but is published unscoped. Internal packages without npm scopes are "
                        f"vulnerable to dependency confusion — consider migrating to "
                        f"@{org_guess}/{short_name}."
                    ),
                    confidence=0.5,
                    metadata={"guessed_org": org_guess, "check": "dep_confusion_unscoped"},
                ))

        return findings

    # ------------------------------------------------------------------
    # Version anomaly detection
    # ------------------------------------------------------------------

    def _check_version_anomaly(self, pkg: PackageId) -> list[Finding]:
        findings: list[Finding] = []
        version = pkg.version or ""

        # Classic squatter pattern: 999.x.x / 9999.x.x
        if _SQUATTER_VERSION_RE.match(version):
            findings.append(Finding(
                finding_type=FindingType.DEP_CONFUSION,
                severity=Severity.CRITICAL,
                package=pkg,
                title="Squatter version pattern detected (999.x.x)",
                detail=(
                    f"Version '{version}' matches the 999.x.x pattern used in known "
                    f"dependency confusion attacks (e.g., the Alex Birsan proof-of-concept). "
                    f"Attackers publish extremely high version numbers to ensure they win "
                    f"over private registry versions via semver resolution."
                ),
                confidence=0.95,
                metadata={"version": version, "check": "dep_confusion_version"},
            ))
            return findings  # CRITICAL already captured; skip the HIGH check

        # High major version (100+) outside the squatter range
        m = _HIGH_VERSION_RE.match(version)
        if m:
            try:
                major = int(m.group(1))
                if major >= 100:
                    findings.append(Finding(
                        finding_type=FindingType.DEP_CONFUSION,
                        severity=Severity.HIGH,
                        package=pkg,
                        title="Suspiciously high version number",
                        detail=(
                            f"Version '{version}' has a major version >= 100, which is unusual "
                            f"for most packages and may indicate a dependency confusion attack "
                            f"using an inflated version to override private registry packages."
                        ),
                        confidence=0.75,
                        metadata={"version": version, "major": major, "check": "dep_confusion_version"},
                    ))
            except (ValueError, IndexError):
                pass

        return findings

    # ------------------------------------------------------------------
    # npm scope / namespace validation (offline)
    # ------------------------------------------------------------------

    def _check_npm_scope_offline(self, pkg: PackageId) -> list[Finding]:
        """Flag scoped npm packages that may be scope-squatting well-known orgs."""
        findings: list[Finding] = []
        name_lower = pkg.name.lower()

        if not name_lower.startswith("@"):
            return findings

        scope, _, bare = name_lower.lstrip("@").partition("/")
        if bare and self._scope_shadows_project(scope, bare):
            findings.append(Finding(
                finding_type=FindingType.SCOPE_SQUAT,
                severity=Severity.HIGH,
                package=pkg,
                title="Scope may shadow a well-known project namespace",
                detail=(
                    f"The scope @{scope} is not the known official scope for the "
                    f"'{bare}' package. This could indicate scope squatting — "
                    f"registering a scope that mimics a legitimate organization."
                ),
                confidence=0.6,
                metadata={"scope": f"@{scope}", "bare_name": bare, "check": "dep_confusion_scope_squat"},
            ))

        return findings

    def _scope_shadows_project(self, scope: str, bare_name: str) -> bool:
        expected_scope = self._KNOWN_SCOPES.get(bare_name)
        return bool(expected_scope and scope != expected_scope)

    # ------------------------------------------------------------------
    # Registry cross-check (live npm registry)
    # ------------------------------------------------------------------

    async def _check_npm_scope_online(self, pkg: PackageId) -> Finding | None:
        scope = pkg.name.split("/")[0]
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(f"https://registry.npmjs.org/{pkg.name}")
                if resp.status_code == 404:
                    return Finding(
                        finding_type=FindingType.DEP_CONFUSION,
                        severity=Severity.HIGH,
                        package=pkg,
                        title="Scoped package absent from public registry",
                        detail=(
                            f"Package {pkg.name} uses scope {scope} but does not exist on "
                            f"the public npm registry. If this is a private package, ensure "
                            f"your .npmrc enforces registry scoping to prevent confusion attacks."
                        ),
                        metadata={"scope": scope, "check": "dep_confusion"},
                    )
            except httpx.HTTPError:
                log.debug("dep_confusion: HTTP error checking %s", pkg.name, exc_info=True)
        return None

    # ------------------------------------------------------------------
    # Install script analysis
    # ------------------------------------------------------------------

    def _check_package_json_scripts(self, package_json_path: Path) -> list[Finding]:
        """Scan package.json lifecycle hooks for suspicious patterns."""
        findings: list[Finding] = []
        try:
            data = json.loads(package_json_path.read_text())
        except (OSError, json.JSONDecodeError):
            return findings

        pkg_name = data.get("name", package_json_path.parent.name)
        pkg_id = PackageId(ecosystem="npm", name=pkg_name)
        scripts = data.get("scripts", {})

        for hook in ("preinstall", "postinstall", "install", "prepare", "prepack"):
            script = scripts.get(hook, "")
            if not script:
                continue

            has_network = bool(_SCRIPT_NETWORK_RE.search(script))
            has_env = bool(_SCRIPT_ENV_RE.search(script))
            has_exec = bool(_SCRIPT_EXEC_RE.search(script))

            if has_network:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=pkg_id,
                    title=f"Network call in {hook} script",
                    detail=(
                        f"The '{hook}' script in package.json makes network requests: "
                        f"{script[:300]}. This is a common exfiltration vector in "
                        f"dependency confusion attacks."
                    ),
                    metadata={"hook": hook, "script": script[:300], "check": "dep_confusion_install_script"},
                ))

            if has_env:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=pkg_id,
                    title=f"Sensitive env var access in {hook} script",
                    detail=(
                        f"The '{hook}' script reads potentially sensitive environment "
                        f"variables (TOKEN/KEY/SECRET/PASS). Script: {script[:300]}"
                    ),
                    metadata={"hook": hook, "script": script[:300], "check": "dep_confusion_env_access"},
                ))

            if has_exec and not has_network:
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.MEDIUM,
                    package=pkg_id,
                    title=f"Code execution in {hook} script",
                    detail=(
                        f"The '{hook}' script uses exec/spawn/eval: {script[:300]}. "
                        f"Review this script before installing."
                    ),
                    metadata={"hook": hook, "script": script[:300], "check": "dep_confusion_exec"},
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_npmrc_scope_gaps(content: str) -> list[str]:
        """Return scopes that appear in .npmrc config but have no registry pin."""
        scoped_registries: set[str] = set()
        for line in content.splitlines():
            m = re.match(r"^(@[^:=\s]+):registry\s*=", line.strip())
            if m:
                scoped_registries.add(m.group(1))

        scoped_other: set[str] = set()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = re.match(r"^(@[^:=\s]+):[^=]+=", stripped)
            if m:
                scope = m.group(1)
                if scope not in scoped_registries:
                    scoped_other.add(scope)

        return sorted(scoped_other)
