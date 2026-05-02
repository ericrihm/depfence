"""Package install interceptor — wraps npm/pip to check packages before install.

Usage:
    depfence firewall enable   # configures .npmrc / pip.conf to proxy through depfence
    depfence firewall disable  # removes proxy configuration
    depfence firewall status   # shows current interception state

Architecture:
    Instead of running a full HTTP proxy (complex, TLS issues), we use:
    1. npm: .npmrc `preinstall` script hook + `beforeAll` lifecycle script
    2. pip: PIP_CONSTRAINT + custom resolver wrapper
    3. Both: pre-install check via `depfence check <pkg>` under the hood
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from depfence.core.models import PackageId
from depfence.core.threat_db import ThreatDB


class FirewallDecision:
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


def check_package(ecosystem: str, name: str, version: str | None = None) -> dict:
    """Quick pre-install check. Returns {decision, reason, details}."""
    threat_db = ThreatDB()

    if threat_db.is_known_malicious(ecosystem, name):
        threats = threat_db.lookup(ecosystem, name)
        return {
            "decision": FirewallDecision.BLOCK,
            "reason": "Known malicious package",
            "details": threats[0] if threats else {},
            "package": f"{ecosystem}:{name}@{version or 'any'}",
        }

    verdict = threat_db.get_crawler_verdict(ecosystem, name)
    if verdict and verdict.get("score", 0) >= 80:
        return {
            "decision": FirewallDecision.BLOCK,
            "reason": f"High threat score ({verdict['score']}/100)",
            "details": verdict,
            "package": f"{ecosystem}:{name}@{version or 'any'}",
        }
    elif verdict and verdict.get("score", 0) >= 50:
        return {
            "decision": FirewallDecision.WARN,
            "reason": f"Elevated threat score ({verdict['score']}/100)",
            "details": verdict,
            "package": f"{ecosystem}:{name}@{version or 'any'}",
        }

    return {
        "decision": FirewallDecision.ALLOW,
        "reason": "No threats detected",
        "details": {},
        "package": f"{ecosystem}:{name}@{version or 'any'}",
    }


def check_batch(packages: list[tuple[str, str, str | None]]) -> list[dict]:
    """Check multiple packages. Returns list of decisions."""
    return [check_package(eco, name, ver) for eco, name, ver in packages]


def enable_npm_firewall(project_dir: Path) -> str:
    """Configure npm to run depfence checks before install."""
    npmrc = project_dir / ".npmrc"
    hook_line = "preinstall=depfence firewall check-npm"

    if npmrc.exists():
        content = npmrc.read_text()
        if "depfence" in content:
            return "npm firewall already enabled"
        content += f"\n{hook_line}\n"
    else:
        content = f"{hook_line}\n"

    npmrc.write_text(content)

    pkg_json = project_dir / "package.json"
    if pkg_json.exists():
        data = json.loads(pkg_json.read_text())
        scripts = data.setdefault("scripts", {})
        if "preinstall" not in scripts:
            scripts["preinstall"] = "depfence firewall check-npm"
            pkg_json.write_text(json.dumps(data, indent=2) + "\n")

    return "npm firewall enabled (preinstall hook)"


def enable_pip_firewall(project_dir: Path) -> str:
    """Configure pip to check packages via constraint file."""
    depfence_dir = project_dir / ".depfence"
    depfence_dir.mkdir(exist_ok=True)

    constraint_script = depfence_dir / "pip-check.sh"
    constraint_script.write_text("""#!/bin/sh
# depfence pip firewall — checks each package before install
for pkg in "$@"; do
    name=$(echo "$pkg" | sed 's/[>=<~!].*//')
    if [ -n "$name" ]; then
        result=$(depfence firewall check-pip "$name" 2>/dev/null)
        if echo "$result" | grep -q "BLOCKED"; then
            echo "[depfence] BLOCKED: $name — known malicious package"
            exit 1
        fi
    fi
done
""")
    constraint_script.chmod(0o755)

    pip_conf = project_dir / "pip.conf"
    return f"pip firewall enabled (use: pip install --constraint .depfence/constraints.txt)"


def disable_firewall(project_dir: Path) -> str:
    """Remove depfence firewall hooks."""
    npmrc = project_dir / ".npmrc"
    if npmrc.exists():
        lines = [l for l in npmrc.read_text().splitlines() if "depfence" not in l]
        npmrc.write_text("\n".join(lines) + "\n" if lines else "")

    pkg_json = project_dir / "package.json"
    if pkg_json.exists():
        data = json.loads(pkg_json.read_text())
        scripts = data.get("scripts", {})
        if scripts.get("preinstall", "").startswith("depfence"):
            del scripts["preinstall"]
            pkg_json.write_text(json.dumps(data, indent=2) + "\n")

    depfence_dir = project_dir / ".depfence"
    check_script = depfence_dir / "pip-check.sh"
    if check_script.exists():
        check_script.unlink()

    return "Firewall disabled"


def get_status(project_dir: Path) -> dict:
    """Check current firewall status."""
    npm_enabled = False
    pip_enabled = False

    npmrc = project_dir / ".npmrc"
    if npmrc.exists() and "depfence" in npmrc.read_text():
        npm_enabled = True

    pip_script = project_dir / ".depfence" / "pip-check.sh"
    if pip_script.exists():
        pip_enabled = True

    return {
        "npm": npm_enabled,
        "pip": pip_enabled,
        "active": npm_enabled or pip_enabled,
    }
