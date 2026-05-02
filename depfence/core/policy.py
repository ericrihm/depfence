"""Policy-as-code engine — org-wide rules for dependency governance.

Reads .depfence-policy.yml from the project root (or a path specified via env).
Supports allow/deny lists, severity thresholds, and per-ecosystem rules.

Policy file format:
```yaml
version: 1
rules:
  - name: block-critical
    action: block
    severity: critical

  - name: warn-high
    action: warn
    severity: high

  - name: block-agpl
    action: block
    finding_type: license_risk
    match: "AGPL"

  - name: allow-internal
    action: allow
    packages:
      - "@mycompany/*"
      - "internal-*"

  - name: block-packages
    action: block
    packages:
      - "event-stream"
      - "flatmap-stream"
      - "ua-parser-js"

  - name: require-provenance
    action: warn
    ecosystems: [npm]
    finding_type: provenance_missing
```
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

from depfence.core.models import Finding, Severity


@dataclass
class PolicyRule:
    name: str
    action: str  # "block", "warn", "allow", "monitor"
    severity: str | None = None
    finding_type: str | None = None
    match: str | None = None
    packages: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)


@dataclass
class PolicyViolation:
    rule: PolicyRule
    finding: Finding
    action: str

    @property
    def is_blocking(self) -> bool:
        return self.action == "block"


@dataclass
class PolicyResult:
    violations: list[PolicyViolation] = field(default_factory=list)
    allowed: list[Finding] = field(default_factory=list)
    warnings: list[PolicyViolation] = field(default_factory=list)

    @property
    def blocked(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.is_blocking]

    @property
    def should_fail(self) -> bool:
        return len(self.blocked) > 0


class PolicyEngine:
    def __init__(self, policy_path: Path | None = None) -> None:
        self._rules: list[PolicyRule] = []
        if policy_path and policy_path.exists():
            self._load(policy_path)

    @classmethod
    def from_project(cls, project_dir: Path) -> "PolicyEngine":
        """Load policy from project root or DEPFENCE_POLICY env var."""
        env_path = os.environ.get("DEPFENCE_POLICY")
        if env_path:
            return cls(Path(env_path))

        candidates = [
            project_dir / ".depfence-policy.yml",
            project_dir / ".depfence-policy.yaml",
            project_dir / "depfence-policy.yml",
        ]
        for p in candidates:
            if p.exists():
                return cls(p)
        return cls()

    @property
    def has_rules(self) -> bool:
        return len(self._rules) > 0

    def evaluate(self, findings: list[Finding]) -> PolicyResult:
        """Evaluate all findings against policy rules."""
        result = PolicyResult()

        for finding in findings:
            matched = False
            for rule in self._rules:
                if self._matches(rule, finding):
                    matched = True
                    if rule.action == "allow":
                        result.allowed.append(finding)
                        break
                    elif rule.action == "block":
                        v = PolicyViolation(rule=rule, finding=finding, action="block")
                        result.violations.append(v)
                        break
                    elif rule.action == "warn":
                        v = PolicyViolation(rule=rule, finding=finding, action="warn")
                        result.warnings.append(v)
                        break

        return result

    def _matches(self, rule: PolicyRule, finding: Finding) -> bool:
        """Check if a finding matches a policy rule."""
        # Ecosystem filter
        if rule.ecosystems:
            pkg_str = str(finding.package)
            eco = pkg_str.split(":")[0] if ":" in pkg_str else ""
            if eco not in rule.ecosystems:
                return False

        # Severity filter
        if rule.severity:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            rule_level = severity_order.get(rule.severity.lower(), 9)
            finding_level = severity_order.get(finding.severity.value, 9)
            if finding_level > rule_level:
                return False

        # Finding type filter
        if rule.finding_type:
            if finding.finding_type.value != rule.finding_type:
                return False

        # Text match filter
        if rule.match:
            match_lower = rule.match.lower()
            if (
                match_lower not in finding.title.lower()
                and match_lower not in finding.detail.lower()
                and match_lower not in str(finding.package).lower()
            ):
                return False

        # Package allowlist/blocklist
        if rule.packages:
            pkg_name = _extract_name(finding.package)
            if not any(fnmatch.fnmatch(pkg_name, pat) for pat in rule.packages):
                return False

        return True

    def _load(self, path: Path) -> None:
        """Parse YAML policy file."""
        try:
            import yaml
        except ImportError:
            self._load_simple(path)
            return

        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            return

        for rule_data in data.get("rules", []):
            rule = PolicyRule(
                name=rule_data.get("name", "unnamed"),
                action=rule_data.get("action", "warn"),
                severity=rule_data.get("severity"),
                finding_type=rule_data.get("finding_type"),
                match=rule_data.get("match"),
                packages=rule_data.get("packages", []),
                ecosystems=rule_data.get("ecosystems", []),
            )
            self._rules.append(rule)

    def _load_simple(self, path: Path) -> None:
        """Fallback parser when PyYAML not available."""
        import re

        content = path.read_text()
        current_rule: dict = {}

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("- name:"):
                if current_rule.get("name"):
                    self._rules.append(PolicyRule(**current_rule))
                current_rule = {"name": stripped.split(":", 1)[1].strip()}
            elif stripped.startswith("action:"):
                current_rule["action"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("severity:"):
                current_rule["severity"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("finding_type:"):
                current_rule["finding_type"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("match:"):
                val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                current_rule["match"] = val

        if current_rule.get("name"):
            self._rules.append(PolicyRule(
                name=current_rule.get("name", ""),
                action=current_rule.get("action", "warn"),
                severity=current_rule.get("severity"),
                finding_type=current_rule.get("finding_type"),
                match=current_rule.get("match"),
            ))


def _extract_name(package) -> str:
    """Extract package name from PackageId or string."""
    pkg_str = str(package)
    if ":" in pkg_str:
        pkg_str = pkg_str.split(":", 1)[1]
    if "@" in pkg_str:
        pkg_str = pkg_str.rsplit("@", 1)[0]
    return pkg_str

# ---------------------------------------------------------------------------
# Config-file discovery and YAML-based config loading (complements PolicyEngine)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_NAMES = ["depfence.yml", "depfence.yaml", ".depfence.yml", ".depfence.yaml",
                         ".depfence-policy.yml", ".depfence-policy.yaml", "depfence-policy.yml"]


@dataclass
class PolicyConfig:
    """Simplified config representation for the CLI init/policy commands."""
    fail_on: str = "high"
    scanners_enabled: list[str] = field(default_factory=list)
    scanners_disabled: list[str] = field(default_factory=list)
    rules: list[PolicyRule] = field(default_factory=list)
    trusted_registries: list[str] = field(default_factory=list)
    ignore_patterns: list[dict[str, str]] = field(default_factory=list)
    epss_enabled: bool = True
    epss_escalate_above: float = 0.5
    kev_enabled: bool = True
    kev_severity_override: bool = True
    sbom: bool = False
    sbom_format: str = "cyclonedx"
    report_formats: list[str] = field(default_factory=lambda: ["sarif"])


def find_config(project_dir: Path) -> Path | None:
    """Search for a depfence config file in the project directory."""
    for name in _DEFAULT_CONFIG_NAMES:
        candidate = project_dir / name
        if candidate.is_file():
            return candidate
    return None


def load_config(config_path: Path) -> PolicyConfig:
    """Load a PolicyConfig from a YAML file."""
    import yaml as _yaml
    raw = _yaml.safe_load(config_path.read_text()) or {}
    cfg = PolicyConfig()
    cfg.fail_on = raw.get("fail_on", "high")

    scanners = raw.get("scanners", {})
    cfg.scanners_enabled = scanners.get("enabled", [])
    cfg.scanners_disabled = scanners.get("disabled", [])

    for rule_data in raw.get("rules", []):
        cfg.rules.append(PolicyRule(
            name=rule_data.get("name", "unnamed"),
            action=rule_data.get("action", "warn"),
            severity=rule_data.get("severity"),
            finding_type=rule_data.get("finding_type"),
            match=rule_data.get("match"),
            packages=rule_data.get("packages", []),
            ecosystems=rule_data.get("ecosystems", []),
        ))

    cfg.trusted_registries = raw.get("trusted_registries", [])
    cfg.ignore_patterns = raw.get("ignore", [])

    epss = raw.get("epss", {})
    cfg.epss_enabled = epss.get("enabled", True)
    cfg.epss_escalate_above = epss.get("escalate_above", 0.5)

    kev = raw.get("kev", {})
    cfg.kev_enabled = kev.get("enabled", True)
    cfg.kev_severity_override = kev.get("severity_override", True)

    reporting = raw.get("reporting", {})
    cfg.report_formats = reporting.get("formats", ["sarif"])
    cfg.sbom = reporting.get("sbom", False)
    cfg.sbom_format = reporting.get("sbom_format", "cyclonedx")

    return cfg


def should_ignore(finding: Finding, ignore_patterns: list[dict[str, str]]) -> bool:
    """Check if a finding should be suppressed based on ignore patterns."""
    for pattern in ignore_patterns:
        if "package" in pattern:
            pkg_pattern = pattern["package"]
            pkg_name = _extract_name(finding.package)
            if fnmatch.fnmatch(pkg_name, pkg_pattern):
                return True
        if "cve" in pattern and finding.cve == pattern["cve"]:
            return True
    return False


def evaluate_policy(findings: list[Finding], config: PolicyConfig) -> tuple[list[Finding], list[Finding]]:
    """Apply policy config and return (blocked, warned) finding lists."""
    blocked: list[Finding] = []
    warned: list[Finding] = []

    filtered = [f for f in findings if not should_ignore(f, config.ignore_patterns)]

    severity_map = {
        "critical": [Severity.CRITICAL],
        "high": [Severity.CRITICAL, Severity.HIGH],
        "medium": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        "low": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        "any": list(Severity),
    }
    if config.fail_on == "none":
        return [], filtered

    block_severities = severity_map.get(config.fail_on, [Severity.CRITICAL])

    for f in filtered:
        if f.severity in block_severities:
            blocked.append(f)
        else:
            warned.append(f)

    return blocked, warned


def generate_default_config() -> str:
    """Generate a default depfence.yml config as a string."""
    return """\
# depfence.yml \u2014 Policy-as-code configuration
# Generated by: depfence init
# Docs: https://github.com/ericrihm/depfence

# Severity threshold for CI failure
fail_on: high

# Scanners to enable
scanners:
  enabled:
    - advisory
    - behavioral
    - slopsquat
    - reputation
    - provenance
    - secrets
    - license
    - freshness
    - dockerfile
    - terraform
    - gha_workflow
  disabled: []

# Policy rules
rules:
  - name: block-known-malicious
    description: Block packages in threat intelligence DB
    match:
      in_threat_db: true
    action: block

  - name: no-install-scripts
    description: Block packages with install scripts
    match:
      has_install_scripts: true
    action: warn
    ecosystems: [npm]

  - name: block-unpinned-actions
    description: Require SHA pinning for GitHub Actions
    match:
      unpinned_action: true
    action: block

# Ignore patterns
ignore: []

# Enrichment
epss:
  enabled: true
  escalate_above: 0.5

kev:
  enabled: true
  severity_override: true

# Reporting
reporting:
  formats: [sarif]
  sbom: false
  sbom_format: cyclonedx
"""
