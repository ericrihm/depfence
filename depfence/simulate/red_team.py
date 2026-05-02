"""Red team mode: run all attack simulations against a project and score defenses."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from depfence.simulate.attacks import AttackSimulator, RiskLevel, SimulationResult


@dataclass
class AttackOutcome:
    """Single attack result within a red-team run."""

    simulation: SimulationResult
    configuration_gap: str | None = None
    """Optional gap identified by inspecting project files."""


@dataclass
class RedTeamReport:
    """Full red-team assessment for a project."""

    project_dir: str
    outcomes: list[AttackOutcome] = field(default_factory=list)
    configuration_improvements: list[str] = field(default_factory=list)
    score: int = 0  # 0–100

    # -----------------------------------------------------------------------
    # Derived helpers
    # -----------------------------------------------------------------------

    @property
    def detected(self) -> list[AttackOutcome]:
        return [o for o in self.outcomes if o.simulation.would_be_detected]

    @property
    def undetected(self) -> list[AttackOutcome]:
        return [o for o in self.outcomes if not o.simulation.would_be_detected]

    @property
    def critical_gaps(self) -> list[AttackOutcome]:
        return [
            o for o in self.undetected
            if o.simulation.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]

    def to_dict(self) -> dict:
        return {
            "project_dir": self.project_dir,
            "score": self.score,
            "summary": {
                "total_attacks": len(self.outcomes),
                "detected": len(self.detected),
                "undetected": len(self.undetected),
                "critical_gaps": len(self.critical_gaps),
            },
            "attacks": [
                {
                    "attack_type": o.simulation.attack_type,
                    "risk_level": o.simulation.risk_level.value,
                    "would_be_detected": o.simulation.would_be_detected,
                    "detection_coverage": round(o.simulation.detection_coverage, 2),
                    "description": o.simulation.description,
                    "detection_methods": o.simulation.detection_methods,
                    "mitigations": o.simulation.mitigations,
                    "configuration_gap": o.configuration_gap,
                    "attacker_artifacts": o.simulation.attacker_artifacts,
                }
                for o in self.outcomes
            ],
            "configuration_improvements": self.configuration_improvements,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Project-level config inspection
# ---------------------------------------------------------------------------

def _detect_config_gaps(project_dir: Path) -> dict[str, list[str]]:
    """Inspect project files and return per-attack-type configuration gaps."""
    gaps: dict[str, list[str]] = {
        "typosquatting": [],
        "dependency_confusion": [],
        "maintainer_takeover": [],
        "build_script_injection": [],
        "star_jacking": [],
    }
    improvements: list[str] = []

    # --- .npmrc ---
    npmrc = project_dir / ".npmrc"
    if npmrc.exists():
        content = npmrc.read_text()
        if "always-auth" not in content:
            gaps["dependency_confusion"].append(
                ".npmrc is missing always-auth=true — public registry fallback possible"
            )
            improvements.append("Add `always-auth=true` to .npmrc")
        if "ignore-scripts" not in content:
            gaps["build_script_injection"].append(
                ".npmrc does not set ignore-scripts=true"
            )
            improvements.append("Add `ignore-scripts=true` to .npmrc for production installs")
    else:
        gaps["dependency_confusion"].append("No .npmrc found — registry configuration not enforced")
        improvements.append("Create .npmrc with scoped registry pins and always-auth=true")

    # --- pyproject.toml ---
    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        if "extra-index-url" in content:
            gaps["dependency_confusion"].append(
                "pyproject.toml uses extra-index-url — vulnerable to dep confusion"
            )
            improvements.append("Replace extra-index-url with index-url (exclusive) in pyproject.toml")

    # --- depfence.yml ---
    depfence_yml = project_dir / "depfence.yml"
    if depfence_yml.exists():
        content = depfence_yml.read_text()
        if "internal_prefixes" not in content:
            gaps["dependency_confusion"].append(
                "depfence.yml exists but dep_confusion.internal_prefixes not configured"
            )
            improvements.append(
                "Add dep_confusion.internal_prefixes list to depfence.yml with your org's package prefixes"
            )
    else:
        gaps["dependency_confusion"].append(
            "No depfence.yml found — org-specific dep confusion rules not active"
        )
        improvements.append(
            "Create depfence.yml with dep_confusion.internal_prefixes for your organisation"
        )

    # --- package.json ---
    package_json = project_dir / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text())
            scripts = data.get("scripts", {})
            hooks = [h for h in ("preinstall", "postinstall", "install", "prepare") if h in scripts]
            if hooks:
                gaps["build_script_injection"].append(
                    f"package.json has lifecycle hooks: {hooks} — ensure these are trusted"
                )
        except Exception:
            pass

    # --- lockfile presence ---
    lockfile_names = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum",
    ]
    found_lockfiles = [lf for lf in lockfile_names if (project_dir / lf).exists()]
    if not found_lockfiles:
        gaps["typosquatting"].append(
            "No lockfile found — exact versions not pinned, resolver can pick malicious versions"
        )
        improvements.append("Commit a lockfile (package-lock.json, poetry.lock, etc.) to pin exact versions")
    else:
        # Lockfile present = good for typosquat and maintainer takeover
        pass

    return {"gaps": gaps, "improvements": improvements}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

_WEIGHT: dict[str, float] = {
    "dependency_confusion": 0.30,   # highest impact in practice
    "maintainer_takeover": 0.25,
    "build_script_injection": 0.20,
    "typosquatting": 0.15,
    "star_jacking": 0.10,
}


def _compute_score(outcomes: list[AttackOutcome]) -> int:
    """Compute a 0–100 security posture score.

    Each attack type is weighted by real-world frequency/impact.
    Coverage score × weight contributes to the final total.
    """
    total = 0.0
    for outcome in outcomes:
        attack_type = outcome.simulation.attack_type
        weight = _WEIGHT.get(attack_type, 0.10)
        # Base: detection coverage; bonus if actually detected
        contribution = outcome.simulation.detection_coverage
        if outcome.simulation.would_be_detected:
            contribution = min(1.0, contribution + 0.05)
        total += contribution * weight

    # Normalise: sum of weights is ~1.0, so total is already 0–1
    return min(100, max(0, round(total * 100)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_red_team(project_dir: str | Path) -> RedTeamReport:
    """Run all attack simulations against *project_dir* and return a report.

    The function:
    1. Inspects project configuration files for known gaps.
    2. Runs all five attack simulations with project-specific context.
    3. Computes a security posture score (0–100).
    4. Generates prioritised configuration improvement suggestions.

    Args:
        project_dir: Path to the project root directory.

    Returns:
        RedTeamReport with outcomes, score, and recommendations.
    """
    project_path = Path(project_dir).resolve()
    sim = AttackSimulator()
    config_info = _detect_config_gaps(project_path)
    gaps: dict[str, list[str]] = config_info["gaps"]
    improvements: list[str] = config_info["improvements"]

    outcomes: list[AttackOutcome] = []

    # --- 1. Typosquatting ---
    # Infer a representative package name from the project
    pkg_name = _infer_primary_package(project_path)
    ts_result = sim.simulate_typosquat(pkg_name, ecosystem=_infer_ecosystem(project_path))
    outcomes.append(AttackOutcome(
        simulation=ts_result,
        configuration_gap="; ".join(gaps["typosquatting"]) or None,
    ))

    # --- 2. Dependency confusion ---
    org_prefix = _infer_org_prefix(project_path)
    dc_result = sim.simulate_dep_confusion(org_prefix)
    # If config gaps exist, adjust detection downward slightly
    if gaps["dependency_confusion"]:
        dc_result.detection_coverage = max(0.0, dc_result.detection_coverage - 0.15)
        dc_result.would_be_detected = dc_result.detection_coverage >= 0.5
    outcomes.append(AttackOutcome(
        simulation=dc_result,
        configuration_gap="; ".join(gaps["dependency_confusion"]) or None,
    ))

    # --- 3. Maintainer takeover ---
    mt_result = sim.simulate_maintainer_takeover(pkg_name)
    outcomes.append(AttackOutcome(
        simulation=mt_result,
        configuration_gap="; ".join(gaps["maintainer_takeover"]) or None,
    ))

    # --- 4. Build script injection ---
    package_json_path = project_path / "package.json"
    bsi_result = sim.simulate_build_script_injection(
        str(package_json_path) if package_json_path.exists() else None
    )
    if gaps["build_script_injection"]:
        bsi_result.detection_coverage = max(0.0, bsi_result.detection_coverage - 0.10)
        bsi_result.would_be_detected = bsi_result.detection_coverage >= 0.5
    outcomes.append(AttackOutcome(
        simulation=bsi_result,
        configuration_gap="; ".join(gaps["build_script_injection"]) or None,
    ))

    # --- 5. Star jacking ---
    repo_url = _infer_repo_url(project_path)
    sj_result = sim.simulate_star_jacking(repo_url)
    outcomes.append(AttackOutcome(
        simulation=sj_result,
        configuration_gap="; ".join(gaps["star_jacking"]) or None,
    ))

    score = _compute_score(outcomes)

    # Always include universal improvements at the top
    universal = [
        "Run `depfence scan` in CI on every pull request",
        "Pin all dependencies to exact versions in committed lockfiles",
        "Require SLSA provenance attestations for critical packages",
    ]
    all_improvements = universal + [i for i in improvements if i not in universal]

    return RedTeamReport(
        project_dir=str(project_path),
        outcomes=outcomes,
        configuration_improvements=all_improvements,
        score=score,
    )


# ---------------------------------------------------------------------------
# Heuristic helpers
# ---------------------------------------------------------------------------

def _infer_primary_package(project_path: Path) -> str:
    """Best-effort: read package name from manifest files."""
    # npm
    pj = project_path / "package.json"
    if pj.exists():
        try:
            return json.loads(pj.read_text()).get("name", project_path.name)
        except Exception:
            pass
    # Python
    for name in ("pyproject.toml", "setup.cfg", "setup.py"):
        f = project_path / name
        if f.exists():
            text = f.read_text()
            import re
            m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                return m.group(1)
    # Cargo
    cargo = project_path / "Cargo.toml"
    if cargo.exists():
        text = cargo.read_text()
        import re
        m = re.search(r'name\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    return project_path.name


def _infer_ecosystem(project_path: Path) -> str:
    if (project_path / "package.json").exists():
        return "npm"
    if (project_path / "pyproject.toml").exists() or (project_path / "setup.py").exists():
        return "pypi"
    if (project_path / "Cargo.toml").exists():
        return "cargo"
    if (project_path / "go.mod").exists():
        return "go"
    return "npm"


def _infer_org_prefix(project_path: Path) -> str:
    name = _infer_primary_package(project_path)
    # If name is hyphenated, use the first segment as org prefix
    parts = name.replace("_", "-").split("-")
    if len(parts) >= 2 and len(parts[0]) >= 2:
        return parts[0]
    return name[:4] if len(name) >= 4 else name


def _infer_repo_url(project_path: Path) -> str:
    """Try to read repository URL from project manifests."""
    pj = project_path / "package.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text())
            repo = data.get("repository", {})
            if isinstance(repo, dict):
                url = repo.get("url", "")
            else:
                url = str(repo)
            if "github.com" in url:
                import re
                m = re.search(r"github\.com[:/]([^/]+/[^/\s.]+)", url)
                if m:
                    return f"https://github.com/{m.group(1).removesuffix('.git')}"
        except Exception:
            pass
    return f"https://github.com/example/{project_path.name}"
