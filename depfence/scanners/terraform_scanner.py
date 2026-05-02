"""Terraform/IaC supply chain security scanner.

Analyzes .tf files for supply chain risks:
1. Unpinned module sources  — source without version/ref
2. Unpinned provider versions — required_providers without version constraints
3. HTTP module sources — modules fetched over plain HTTP
4. Unverified registry modules — Terraform registry modules without verified publisher
5. Git ref without commit hash — ?ref=main instead of a full commit SHA

Regex-based parsing is sufficient because HCL attribute assignments follow
predictable patterns and we are only interested in a handful of specific
block types / attributes.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Match a `source = "..."` attribute anywhere in a module block.
# We capture the quoted value; we don't assume HCL indentation.
_SOURCE_RE = re.compile(
    r'source\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

# Match a `version = "..."` attribute (providers / modules).
_VERSION_RE = re.compile(
    r'version\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

# Match full 40-char hex commit SHA (possibly embedded in a ?ref= query string)
_FULL_SHA_RE = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)

# ?ref= or ?rev= query-string component in git sources
_GIT_REF_RE = re.compile(r"[?&]ref=([^&\"]+)", re.IGNORECASE)

# Local and built-in source prefixes — safe to skip
_SKIP_SOURCE_PREFIXES = ("./", "../", "/")

# Terraform public registry pattern: <namespace>/<module>/<provider>
# e.g.  "hashicorp/consul/aws"  or  "registry.terraform.io/hashicorp/consul/aws"
_REGISTRY_RE = re.compile(
    r"^(?:registry\.terraform\.io/)?([^/]+)/([^/]+)/([^/]+)$"
)

# Known-verified registry namespaces (Terraform "verified" badge holders).
# Expand this list as needed; the scanner flags anything NOT in it.
_VERIFIED_NAMESPACES: frozenset[str] = frozenset(
    {
        "hashicorp",
        "aws",
        "azure",
        "azurerm",
        "google",
        "kubernetes",
        "helm",
        "vault",
        "consul",
        "nomad",
        "boundary",
        "terraform",
        "datadog",
        "pagerduty",
        "newrelic",
        "sumologic",
        "cloudflare",
        "fastly",
        "heroku",
        "digitalocean",
        "linode",
        "github",
        "gitlab",
        "bitbucket",
        "atlassian",
        "okta",
        "auth0",
        "snowflake",
        "databricks",
        "mongodb",
        "influxdata",
        "elastic",
        "splunk",
        "grafana",
        "spotinst",
        "lacework",
        "checkpoint",
        "fortios",
        "paloaltonetworks",
        "vmware",
        "vsphere",
        "nutanix",
        "ovh",
        "exoscale",
        "hetzner",
    }
)

# Semver / version-constraint pattern — any non-empty string containing a digit
# is treated as a constraint.  An empty or missing version attribute is the risk.
_HAS_VERSION_CONSTRAINT_RE = re.compile(r"\d")

# Git-URL prefixes recognised by Terraform
_GIT_SOURCE_RE = re.compile(r"^(?:git::|git@|https?://[^/]*\.git)", re.IGNORECASE)

# GitHub shorthand  github.com/org/repo (Terraform resolves it as HTTPS git)
_GITHUB_SHORTHAND_RE = re.compile(r"^github\.com/", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_local_or_builtin(source: str) -> bool:
    return any(source.startswith(p) for p in _SKIP_SOURCE_PREFIXES)


def _has_version_constraint(version_val: str) -> bool:
    return bool(_HAS_VERSION_CONSTRAINT_RE.search(version_val))


def _extract_provider_blocks(content: str) -> list[dict]:
    """Return list of {name, version} dicts for each required_providers entry.

    HCL required_providers block looks like:
        terraform {
          required_providers {
            aws = {
              source  = "hashicorp/aws"
              version = ">= 4.0"
            }
          }
        }

    We parse it with a simple brace-depth tracker rather than a full parser.
    """
    providers: list[dict] = []

    # Find required_providers { ... } blocks
    req_prov_re = re.compile(r"required_providers\s*\{", re.IGNORECASE)
    for m in req_prov_re.finditer(content):
        block_start = m.end()
        depth = 1
        pos = block_start
        while pos < len(content) and depth > 0:
            ch = content[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        block = content[block_start : pos - 1]

        # Each provider is a named block: name = { ... }
        entry_re = re.compile(r"(\w+)\s*=\s*\{([^}]*)\}", re.DOTALL)
        for entry in entry_re.finditer(block):
            name = entry.group(1)
            body = entry.group(2)
            version_match = _VERSION_RE.search(body)
            version = version_match.group(1) if version_match else None
            source_match = _SOURCE_RE.search(body)
            source = source_match.group(1) if source_match else None
            providers.append({"name": name, "version": version, "source": source})

    return providers


def _extract_module_blocks(content: str) -> list[dict]:
    """Return list of {label, source, version} dicts for each module block."""
    modules: list[dict] = []

    module_re = re.compile(r'module\s+"([^"]+)"\s*\{', re.IGNORECASE)
    for m in module_re.finditer(content):
        label = m.group(1)
        block_start = m.end()
        depth = 1
        pos = block_start
        while pos < len(content) and depth > 0:
            ch = content[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        body = content[block_start : pos - 1]

        source_match = _SOURCE_RE.search(body)
        source = source_match.group(1) if source_match else None
        version_match = _VERSION_RE.search(body)
        version = version_match.group(1) if version_match else None

        if source is not None:
            modules.append({"label": label, "source": source, "version": version})

    return modules


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class TerraformScanner:
    ecosystems = ["terraform"]

    async def scan(self, packages: list) -> list:  # type: ignore[type-arg]
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        tf_files = list(project_dir.rglob("*.tf"))

        for tf_file in sorted(tf_files):
            try:
                content = tf_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(tf_file.relative_to(project_dir))
            findings.extend(self._analyze(content, rel, tf_file))

        return findings

    # ------------------------------------------------------------------
    # Per-file analysis
    # ------------------------------------------------------------------

    def _analyze(self, content: str, rel_path: str, tf_file: Path) -> list[Finding]:
        findings: list[Finding] = []

        # Strip single-line comments so they don't produce false positives.
        # Use a negative lookbehind for ':' so that URL schemes like https://
        # are not accidentally treated as line comments.
        content_no_comments = re.sub(r"#[^\n]*", "", content)
        content_no_comments = re.sub(r"(?<!:)//[^\n]*", "", content_no_comments)

        findings.extend(self._check_providers(content_no_comments, rel_path))
        findings.extend(self._check_modules(content_no_comments, rel_path))

        return findings

    # ------------------------------------------------------------------
    # Provider checks
    # ------------------------------------------------------------------

    def _check_providers(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for provider in _extract_provider_blocks(content):
            name = provider["name"]
            version = provider["version"]
            pkg = PackageId("terraform", f"provider:{name}")

            if version is None or not _has_version_constraint(version):
                findings.append(
                    Finding(
                        finding_type=FindingType.PROVENANCE,
                        severity=Severity.HIGH,
                        package=pkg,
                        title=f"Unpinned provider version: {name}",
                        detail=(
                            f"Provider '{name}' in {rel_path} has no version constraint "
                            f"in required_providers. Without a constraint, 'terraform init' "
                            f"may silently pull a newer (potentially breaking or malicious) "
                            f"provider version. Add a version constraint such as "
                            f'version = ">= X.Y, < X+1.0".'
                        ),
                        references=[
                            "https://developer.hashicorp.com/terraform/language/providers/requirements#version-constraints"
                        ],
                        confidence=0.95,
                        metadata={"file": rel_path, "provider": name},
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Module checks
    # ------------------------------------------------------------------

    def _check_modules(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for module in _extract_module_blocks(content):
            label = module["label"]
            source = module["source"]
            version = module["version"]

            if _is_local_or_builtin(source):
                continue

            pkg = PackageId("terraform", f"module:{label}", version)

            # 1. HTTP (non-HTTPS) source
            if re.match(r"^http://", source, re.IGNORECASE):
                findings.append(
                    Finding(
                        finding_type=FindingType.PROVENANCE,
                        severity=Severity.HIGH,
                        package=pkg,
                        title=f"Module fetched over HTTP (not HTTPS): {label}",
                        detail=(
                            f"Module '{label}' in {rel_path} uses a plain HTTP source "
                            f"'{source}'. HTTP provides no transport integrity; an attacker "
                            f"can perform a MitM attack to serve malicious module code. "
                            f"Switch to an HTTPS URL."
                        ),
                        references=[
                            "https://developer.hashicorp.com/terraform/language/modules/sources"
                        ],
                        confidence=1.0,
                        metadata={"file": rel_path, "module": label, "source": source},
                    )
                )

            # 2. Git ref without a full commit SHA
            is_git = bool(
                _GIT_SOURCE_RE.match(source) or _GITHUB_SHORTHAND_RE.match(source)
            )
            if is_git:
                ref_match = _GIT_REF_RE.search(source)
                ref_value = ref_match.group(1) if ref_match else None

                if ref_value is None:
                    # No ?ref= at all — floats on default branch HEAD
                    findings.append(
                        Finding(
                            finding_type=FindingType.PROVENANCE,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"Unpinned git module source (no ref): {label}",
                            detail=(
                                f"Module '{label}' in {rel_path} has git source '{source}' "
                                f"with no '?ref=' parameter. Terraform will fetch the default "
                                f"branch HEAD, which changes with every commit. "
                                f"Pin to a full 40-character commit SHA: "
                                f"?ref=<sha>."
                            ),
                            references=[
                                "https://developer.hashicorp.com/terraform/language/modules/sources#selecting-a-revision"
                            ],
                            confidence=0.95,
                            metadata={
                                "file": rel_path,
                                "module": label,
                                "source": source,
                            },
                        )
                    )
                elif not _FULL_SHA_RE.search(ref_value):
                    # Has a ref but it's a branch/tag name, not a commit SHA
                    findings.append(
                        Finding(
                            finding_type=FindingType.PROVENANCE,
                            severity=Severity.MEDIUM,
                            package=pkg,
                            title=f"Git module ref is not a commit SHA: {label}",
                            detail=(
                                f"Module '{label}' in {rel_path} uses '?ref={ref_value}'. "
                                f"Branch and tag refs are mutable — a malicious commit pushed "
                                f"to that ref will be silently used on the next 'terraform init'. "
                                f"Pin to a full 40-character commit SHA instead of "
                                f"'{ref_value}'."
                            ),
                            references=[
                                "https://developer.hashicorp.com/terraform/language/modules/sources#selecting-a-revision",
                                "https://blog.gruntwork.io/how-to-use-terraform-as-a-team-e903cc2bbfb1",
                            ],
                            confidence=0.95,
                            metadata={
                                "file": rel_path,
                                "module": label,
                                "source": source,
                                "ref": ref_value,
                            },
                        )
                    )
                # else: full SHA — clean, no finding

            # 3. Terraform registry module without version pin
            registry_match = _REGISTRY_RE.match(source)
            if registry_match:
                namespace = registry_match.group(1).lower()
                module_name = registry_match.group(2)
                provider_name = registry_match.group(3)

                if version is None or not _has_version_constraint(version):
                    findings.append(
                        Finding(
                            finding_type=FindingType.PROVENANCE,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"Unpinned registry module version: {label}",
                            detail=(
                                f"Registry module '{source}' used by '{label}' in {rel_path} "
                                f"has no version constraint. Terraform will resolve to the "
                                f"latest available version on each run, which may silently "
                                f"introduce breaking changes or compromised releases. "
                                f'Add: version = "~> X.Y".'
                            ),
                            references=[
                                "https://developer.hashicorp.com/terraform/language/modules/sources#terraform-registry",
                                "https://developer.hashicorp.com/terraform/language/expressions/version-constraints",
                            ],
                            confidence=0.95,
                            metadata={
                                "file": rel_path,
                                "module": label,
                                "source": source,
                                "namespace": namespace,
                            },
                        )
                    )

                # 4. Unverified registry namespace
                if namespace not in _VERIFIED_NAMESPACES:
                    findings.append(
                        Finding(
                            finding_type=FindingType.PROVENANCE,
                            severity=Severity.MEDIUM,
                            package=pkg,
                            title=f"Registry module from unverified publisher: {namespace}/{module_name}/{provider_name}",
                            detail=(
                                f"Module '{source}' (label '{label}', file {rel_path}) comes "
                                f"from the namespace '{namespace}', which does not have a "
                                f"verified badge on the Terraform Registry. Unverified modules "
                                f"have not been audited by HashiCorp. Prefer verified publisher "
                                f"modules or audit the source before use."
                            ),
                            references=[
                                "https://developer.hashicorp.com/terraform/registry/modules/publish#requirements",
                            ],
                            confidence=0.7,
                            metadata={
                                "file": rel_path,
                                "module": label,
                                "source": source,
                                "namespace": namespace,
                            },
                        )
                    )

        return findings
