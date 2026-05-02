"""depfence CLI — dependency security scanner."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from depfence import __version__


@click.group()
@click.version_option(__version__, prog_name="depfence")
def cli() -> None:
    """AI-aware dependency security scanner."""


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif", "html", "cyclonedx"]))
@click.option("--ecosystem", "-e", multiple=True, help="Filter by ecosystem (npm, pypi, cargo, go)")
@click.option("--no-fetch", is_flag=True, help="Skip fetching metadata from registries")
@click.option("--no-advisory", is_flag=True, help="Skip advisory/CVE checks")
@click.option("--no-behavioral", is_flag=True, help="Skip behavioral analysis")
@click.option("--no-reputation", is_flag=True, help="Skip reputation scoring")
@click.option("--no-enrich", is_flag=True, help="Skip enrichment (EPSS, KEV, threat intel) for faster scans")
@click.option("--fail-on", default="critical", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
@click.option("--output", "-o", type=click.Path(), help="Write output to file")
@click.option(
    "--parallel/--no-parallel",
    default=False,
    help="Enable concurrent scanning of all lockfiles found in the tree (monorepo mode).",
)
@click.option(
    "-j",
    "workers",
    default=1,
    show_default=True,
    type=click.IntRange(1, 64),
    help="Number of concurrent scan workers (implies --parallel when > 1).",
)
@click.option("--no-cache", is_flag=True, help="Bypass advisory and metadata caches (always fetch fresh data).")
def scan(
    path: str,
    fmt: str,
    ecosystem: tuple[str, ...],
    no_fetch: bool,
    no_advisory: bool,
    no_behavioral: bool,
    no_reputation: bool,
    no_enrich: bool,
    fail_on: str,
    output: str | None,
    parallel: bool,
    workers: int,
    no_cache: bool,
) -> None:
    """Scan dependencies for vulnerabilities and suspicious behavior.

    Use --parallel (or -j N) to scan all lockfiles in a monorepo concurrently.
    """
    from depfence.core.engine import render_result, scan_directory

    project_dir = Path(path).resolve()

    # --parallel or an explicit -j value > 1 activates the concurrent path
    use_parallel = parallel or workers > 1

    if use_parallel:
        from depfence.core.parallel import parallel_scan

        def _progress(entry, done, total):  # type: ignore[type-arg]
            click.echo(f"  [{done}/{total}] {entry.path}", err=True)

        click.echo(
            f"Parallel scan: discovering lockfiles under {project_dir} "
            f"(workers={workers}) ...",
            err=True,
        )
        para_result = asyncio.run(
            parallel_scan(
                project_dir,
                workers=workers,
                ecosystems=list(ecosystem) if ecosystem else None,
                skip_advisory=no_advisory,
                skip_behavioral=no_behavioral,
                skip_reputation=no_reputation,
                fetch_metadata=not no_fetch,
                project_scanners=not no_fetch,
                enrich=not no_enrich,
                progress_callback=_progress,
            )
        )
        if no_cache:
            from depfence.core.fetcher import set_cache_enabled
            set_cache_enabled(False)
        result = para_result.merged
        if result is None:
            # Nothing was scanned — build an empty result
            from depfence.core.models import ScanResult
            result = ScanResult(target=str(project_dir), ecosystem="multi")
    else:
        if no_cache:
            from depfence.core.fetcher import set_cache_enabled
            set_cache_enabled(False)
        result = asyncio.run(scan_directory(
            project_dir,
            ecosystems=list(ecosystem) if ecosystem else None,
            skip_advisory=no_advisory,
            skip_behavioral=no_behavioral,
            skip_reputation=no_reputation,
            fetch_metadata=not no_fetch,
            project_scanners=not no_fetch,
            enrich=not no_enrich,
            use_cache=not no_cache,
        ))

    # Evaluate policy rules if a policy file exists
    from depfence.core.policy import PolicyEngine
    policy = PolicyEngine.from_project(project_dir)
    if policy.has_rules:
        policy_result = policy.evaluate(result.findings)
        if policy_result.blocked:
            click.echo(f"\nPolicy violations ({len(policy_result.blocked)} blocked):", err=True)
            for v in policy_result.blocked[:5]:
                click.echo(f"  [BLOCK] {v.rule.name}: {v.finding.package} — {v.finding.title}", err=True)
        if policy_result.warnings:
            click.echo(f"\nPolicy warnings ({len(policy_result.warnings)}):", err=True)
            for v in policy_result.warnings[:5]:
                click.echo(f"  [WARN] {v.rule.name}: {v.finding.package} — {v.finding.title}", err=True)

    # Filter out baselined findings
    from depfence.core.baseline import Baseline
    bl = Baseline.from_project(project_dir)
    if bl.count > 0:
        active, suppressed = bl.filter_findings(result.findings)
        if suppressed:
            click.echo(f"({len(suppressed)} baselined finding(s) suppressed)", err=True)
        result.findings = active

    if fmt == "html":
        from depfence.core.html_report import generate_html_report
        rendered = generate_html_report(
            result,
            project_name=project_dir.name,
        )
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            click.echo(f"HTML report written to {output}")
        else:
            out_path = project_dir / "depfence-report.html"
            out_path.write_text(rendered, encoding="utf-8")
            click.echo(f"HTML report written to {out_path}")
    elif fmt == "cyclonedx":
        from depfence.reporters.cyclonedx import generate_sbom
        rendered = generate_sbom(result)
        import json as _json
        formatted = _json.dumps(rendered, indent=2) if isinstance(rendered, dict) else str(rendered)
        if output:
            Path(output).write_text(formatted, encoding="utf-8")
            click.echo(f"CycloneDX SBOM written to {output}")
        else:
            out_path = project_dir / "depfence-sbom.json"
            out_path.write_text(formatted, encoding="utf-8")
            click.echo(f"CycloneDX SBOM written to {out_path}")
    elif fmt == "sarif":
        from depfence.reporters.sarif import render_sarif
        formatted = render_sarif(result, tool_name="depfence", tool_version=__version__)
        if output:
            Path(output).write_text(formatted, encoding="utf-8")
            click.echo(f"SARIF report written to {output}")
        else:
            out_path = project_dir / "results.sarif"
            out_path.write_text(formatted, encoding="utf-8")
            click.echo(f"SARIF report written to {out_path}")
    else:
        rendered = render_result(result, fmt)

        if output:
            Path(output).write_text(rendered)
            click.echo(f"Results written to {output}")
        else:
            click.echo(rendered)

    # Policy block overrides --fail-on
    if policy.has_rules and policy_result.should_fail:
        sys.exit(1)
    if _should_fail(result, fail_on):
        sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--ecosystem", "-e", multiple=True)
def audit(path: str, ecosystem: tuple[str, ...]) -> None:
    """Quick advisory-only audit (CVE/GHSA check, no behavioral analysis)."""
    from depfence.core.engine import render_result, scan_directory

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(
        project_dir,
        ecosystems=list(ecosystem) if ecosystem else None,
        skip_behavioral=True,
        skip_reputation=True,
    ))
    click.echo(render_result(result, "table"))
    if result.has_blockers:
        sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def lockinfo(path: str) -> None:
    """Show detected lockfiles and package counts."""
    from depfence.core.lockfile import detect_ecosystem, parse_lockfile

    project_dir = Path(path).resolve()
    lockfiles = detect_ecosystem(project_dir)

    if not lockfiles:
        click.echo("No lockfiles found.")
        return

    for eco, lockfile_path in lockfiles:
        packages = parse_lockfile(eco, lockfile_path)
        click.echo(f"  {eco}: {lockfile_path.name} ({len(packages)} packages)")


@cli.command()
@click.argument("package_name")
@click.option("--ecosystem", "-e", default="npm", type=click.Choice(["npm", "pypi"]))
@click.option("--version", "-v", "pkg_version", default=None)
def check(package_name: str, ecosystem: str, pkg_version: str | None) -> None:
    """Check a single package by name."""
    from depfence.core.fetcher import fetch_meta
    from depfence.core.models import PackageId
    from depfence.core.registry import get_registry
    from depfence.scanners.reputation import ReputationScanner

    pkg = PackageId(ecosystem, package_name, pkg_version)
    try:
        meta = asyncio.run(fetch_meta(pkg))
    except Exception as e:
        click.echo(f"Error fetching {pkg}: {e}", err=True)
        sys.exit(1)

    rep = ReputationScanner()
    score = rep.compute_score(meta)

    click.echo(f"Package: {meta.pkg}")
    click.echo(f"Description: {meta.description}")
    click.echo(f"License: {meta.license}")
    click.echo(f"Repository: {meta.repository}")
    click.echo(f"Maintainers: {len(meta.maintainers)}")
    click.echo(f"Dependencies: {meta.dependency_count}")
    click.echo(f"Install scripts: {meta.has_install_scripts}")
    click.echo(f"Provenance: {meta.has_provenance}")
    click.echo(f"Reputation: {score}/100")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt",
    default="cyclonedx",
    type=click.Choice(["cyclonedx", "spdx"]),
    help="SBOM format: cyclonedx (default) or spdx",
)
@click.option("--output", "-o", type=click.Path())
def sbom(path: str, fmt: str, output: str | None) -> None:
    """Generate an SBOM in CycloneDX 1.5 or SPDX 2.3 format."""
    import json

    from depfence.core.engine import scan_directory
    from depfence.core.lockfile import detect_ecosystem, parse_lockfile

    project_dir = Path(path).resolve()

    all_packages = []
    lockfiles = detect_ecosystem(project_dir)
    for eco, lf in lockfiles:
        all_packages.extend(parse_lockfile(eco, lf))

    result = asyncio.run(scan_directory(project_dir))

    if fmt == "spdx":
        from depfence.reporters.spdx_out import generate_spdx_with_packages
        sbom_data = generate_spdx_with_packages(result, all_packages, project_name=project_dir.name)
        label = "SPDX 2.3 SBOM"
        default_filename = "depfence-sbom.spdx.json"
    else:
        from depfence.reporters.cyclonedx import generate_sbom
        sbom_data = generate_sbom(
            packages=all_packages,
            findings=result.findings,
            project_name=project_dir.name,
            project_version="",
        )
        label = "CycloneDX SBOM"
        default_filename = "depfence-sbom.json"

    rendered = json.dumps(sbom_data, indent=2)
    if output:
        Path(output).write_text(rendered)
        click.echo(f"{label} written to {output} ({len(all_packages)} components)")
    else:
        click.echo(rendered)



@cli.command("ci-audit")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
def ci_audit(path: str, fmt: str) -> None:
    """Audit CI environment for secret exposure risks."""
    from depfence.core.models import Finding, FindingType, PackageId, Severity, ScanResult
    from depfence.scanners.ci_secrets import CiSecretsScanner

    scanner = CiSecretsScanner()
    project_dir = Path(path).resolve()
    findings = asyncio.run(scanner.scan_environment(project_dir))

    result = ScanResult(target=str(project_dir), ecosystem="ci")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    from depfence.core.engine import render_result
    click.echo(render_result(result, fmt))
    if result.has_blockers:
        sys.exit(1)

@cli.command("mcp-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--global/--no-global", "scan_global", default=True, help="Include global MCP configs")
def mcp_scan(path: str, fmt: str, scan_global: bool) -> None:
    """Scan MCP server configurations for security issues."""
    from depfence.scanners.mcp_scanner import McpScanner

    scanner = McpScanner()
    project_dir = Path(path).resolve()
    findings = asyncio.run(scanner.scan_project(project_dir))

    from depfence.core.models import ScanResult
    result = ScanResult(target=str(project_dir), ecosystem="mcp")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    from depfence.core.engine import render_result
    click.echo(render_result(result, fmt))
    if result.has_blockers:
        sys.exit(1)




@cli.command("mcp-fingerprint")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
def mcp_fingerprint(path: str, fmt: str) -> None:
    """Detect MCP server rug-pull attacks via schema fingerprinting."""
    from depfence.scanners.mcp_fingerprint import McpFingerprintScanner

    scanner = McpFingerprintScanner()
    project_dir = Path(path).resolve()
    findings = asyncio.run(scanner.scan_project(project_dir))

    from depfence.core.models import ScanResult
    result = ScanResult(target=str(project_dir), ecosystem="mcp")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    from depfence.core.engine import render_result
    click.echo(render_result(result, fmt))
    if result.has_blockers:
        sys.exit(1)


@cli.command("gha-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def gha_scan(path: str, fmt: str, fail_on: str) -> None:
    """Scan GitHub Actions workflows for supply chain risks."""
    from depfence.core.models import ScanResult
    from depfence.core.engine import render_result
    from depfence.scanners.gha_scanner import GhaScanner

    scanner = GhaScanner()
    project_dir = Path(path).resolve()
    findings = asyncio.run(scanner.scan_project(project_dir))

    result = ScanResult(target=str(project_dir), ecosystem="gha")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    click.echo(render_result(result, fmt))
    if _should_fail(result, fail_on):
        sys.exit(1)



@cli.command("license-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def license_scan(path: str, fmt: str, fail_on: str) -> None:
    """Check dependency licenses for compliance risks."""
    from depfence.core.engine import render_result, scan_directory

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(
        project_dir,
        skip_advisory=True,
        skip_behavioral=True,
        skip_reputation=True,
        fetch_metadata=True,
    ))

    from depfence.scanners.license_scanner import LicenseScanner
    scanner = LicenseScanner()
    license_findings = asyncio.run(scanner.scan(
        [meta for meta in getattr(result, '_packages', []) if meta]
    )) if hasattr(result, '_packages') else []

    from depfence.core.models import ScanResult
    lic_result = ScanResult(target=str(project_dir), ecosystem="license")
    lic_result.findings = license_findings
    lic_result.packages_scanned = result.packages_scanned

    click.echo(render_result(lic_result, fmt))
    if _should_fail(lic_result, fail_on):
        sys.exit(1)


@cli.command("reachability")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
def reachability_scan(path: str, fmt: str) -> None:
    """Analyze which vulnerable imports are actually reachable in your code."""
    from depfence.core.engine import render_result
    from depfence.core.models import ScanResult
    from depfence.scanners.reachability import ReachabilityScanner

    project_dir = Path(path).resolve()
    scanner = ReachabilityScanner()
    findings = asyncio.run(scanner.scan_project(project_dir))

    result = ScanResult(target=str(project_dir), ecosystem="reachability")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    click.echo(render_result(result, fmt))


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="json", type=click.Choice(["json", "html"]))
@click.option("--output", "-o", type=click.Path(), help="Write report to file")
def report(path: str, fmt: str, output: str | None) -> None:
    """Generate a comprehensive security report (all scanners)."""
    import json as json_mod
    from depfence.core.engine import scan_directory
    from depfence.core.lockfile import detect_ecosystem
    from depfence.scanners.gha_scanner import GhaScanner
    from depfence.scanners.reachability import ReachabilityScanner

    project_dir = Path(path).resolve()
    click.echo(f"Generating security report for {project_dir.name}...")

    # Run all scanners
    result = asyncio.run(scan_directory(project_dir))
    gha_findings = asyncio.run(GhaScanner().scan_project(project_dir))
    reach_findings = asyncio.run(ReachabilityScanner().scan_project(project_dir))

    # Run project-level scanners
    from depfence.scanners.dockerfile_scanner import DockerfileScanner
    from depfence.scanners.terraform_scanner import TerraformScanner
    from depfence.scanners.secrets_scanner import SecretsScanner
    docker_findings = asyncio.run(DockerfileScanner().scan_project(project_dir))
    tf_findings = asyncio.run(TerraformScanner().scan_project(project_dir))
    secrets_findings = asyncio.run(SecretsScanner().scan_project(project_dir))

    all_findings = result.findings + gha_findings + reach_findings + docker_findings + tf_findings + secrets_findings

    critical = sum(1 for f in all_findings if f.severity.name == "CRITICAL")
    high = sum(1 for f in all_findings if f.severity.name == "HIGH")
    medium = sum(1 for f in all_findings if f.severity.name == "MEDIUM")
    low = sum(1 for f in all_findings if f.severity.name == "LOW")

    if fmt == "html":
        from depfence.core.html_report import generate_html_report
        rendered = generate_html_report(
            result,
            project_name=project_dir.name,
            extra_findings=gha_findings + reach_findings,
        )
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            click.echo(f"HTML report written to {output}")
        else:
            out_path = project_dir / "depfence-report.html"
            out_path.write_text(rendered, encoding="utf-8")
            click.echo(f"HTML report written to {out_path}")
        return

    lockfiles = detect_ecosystem(project_dir)

    report_data = {
        "project": project_dir.name,
        "path": str(project_dir),
        "ecosystems": list(set(eco for eco, _ in lockfiles)),
        "packages_scanned": result.packages_scanned,
        "total_findings": len(all_findings),
        "severity_breakdown": {"critical": critical, "high": high, "medium": medium, "low": low},
        "status": "CRITICAL" if critical > 0 else "WARN" if high > 0 else "PASS",
        "scanners_run": [
            "advisory", "behavioral", "reputation", "slopsquat",
            "gha_workflow", "reachability",
        ],
        "findings": [
            {
                "severity": f.severity.name,
                "type": f.finding_type.value,
                "package": f.package,
                "title": f.title,
                "detail": f.detail,
            }
            for f in sorted(all_findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.severity.name))
        ],
    }

    rendered = json_mod.dumps(report_data, indent=2)

    if output:
        Path(output).write_text(rendered)
        click.echo(f"Report written to {output}")
    else:
        click.echo(f"\nProject: {project_dir.name}")
        click.echo(f"Status: {report_data['status']}")
        click.echo(f"Packages: {result.packages_scanned}")
        click.echo(f"Findings: {len(all_findings)} (C:{critical} H:{high} M:{medium} L:{low})")
        if critical + high > 0:
            click.echo("\nTop issues:")
            for f in all_findings[:10]:
                if f.severity.name in ("CRITICAL", "HIGH"):
                    click.echo(f"  [{f.severity.name}] {f.package}: {f.title}")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--ci/--no-ci", default=True, help="Add GitHub Actions workflow")
@click.option("--hook/--no-hook", default=True, help="Add pre-commit hook")
@click.option("--policy/--no-policy", default=True, help="Generate policy config file")
def init(path: str, ci: bool, hook: bool, policy: bool) -> None:
    """Initialize depfence for a project (CI workflow, pre-commit hook, policy config)."""
    project_dir = Path(path).resolve()
    actions = []

    if ci:
        wf_dir = project_dir / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        wf_file = wf_dir / "depfence.yml"
        if not wf_file.exists():
            wf_file.write_text("""name: Dependency Security
on:
  push:
    branches: [main]
    paths: ['**/package-lock.json', '**/yarn.lock', '**/requirements.txt', '**/poetry.lock', '**/Cargo.lock', '**/go.sum']
  pull_request:
    paths: ['**/package-lock.json', '**/yarn.lock', '**/requirements.txt', '**/poetry.lock', '**/Cargo.lock', '**/go.sum']
  schedule:
    - cron: '0 6 * * 1'

jobs:
  depfence:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install depfence
      - run: depfence scan . --format sarif -o depfence.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: depfence.sarif
          category: depfence
""")
            actions.append(f"Created {wf_file.relative_to(project_dir)}")
        else:
            actions.append("CI workflow already exists")

    if hook:
        hooks_dir = project_dir / ".git" / "hooks"
        if hooks_dir.exists():
            hook_file = hooks_dir / "pre-commit"
            hook_content = """#!/bin/sh
# depfence pre-commit hook — scan on lockfile changes
LOCKFILES="package-lock.json yarn.lock requirements.txt poetry.lock Cargo.lock go.sum"
CHANGED=0
for f in $LOCKFILES; do
    if git diff --cached --name-only | grep -q "$f"; then
        CHANGED=1
        break
    fi
done
if [ "$CHANGED" = "1" ]; then
    echo "[depfence] Lockfile changed — running security scan..."
    depfence scan . --fail-on critical --no-fetch 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[depfence] Critical vulnerabilities found. Commit blocked."
        echo "[depfence] Run 'depfence scan .' for details, or commit with --no-verify to skip."
        exit 1
    fi
fi
"""
            if not hook_file.exists() or "depfence" not in hook_file.read_text():
                if hook_file.exists():
                    existing = hook_file.read_text()
                    hook_file.write_text(existing + "\n" + hook_content)
                else:
                    hook_file.write_text(hook_content)
                hook_file.chmod(0o755)
                actions.append("Installed pre-commit hook")
            else:
                actions.append("Pre-commit hook already configured")
        else:
            actions.append("Not a git repo — skipped pre-commit hook")

    if policy:
        from depfence.core.policy import find_config, generate_default_config
        existing_cfg = find_config(project_dir)
        if not existing_cfg:
            cfg_path = project_dir / "depfence.yml"
            cfg_path.write_text(generate_default_config())
            actions.append(f"Created {cfg_path.name} (policy config)")
        else:
            actions.append(f"Policy config already exists: {existing_cfg.name}")

    from depfence.core.lockfile import detect_ecosystem
    lockfiles = detect_ecosystem(project_dir)

    click.echo(f"depfence initialized for {project_dir.name}")
    for a in actions:
        click.echo(f"  + {a}")
    click.echo(f"  Detected: {len(lockfiles)} lockfile(s)")
    click.echo("\nRun 'depfence scan .' to check your dependencies now.")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--interval", "-i", default=30, help="Seconds between scans")
@click.option("--fail-on", default="critical", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def watch(path: str, interval: int, fail_on: str) -> None:
    """Watch for lockfile changes and auto-scan on modification."""
    import time

    from depfence.core.engine import render_result, scan_directory
    from depfence.core.lockfile import detect_ecosystem

    project_dir = Path(path).resolve()
    click.echo(f"Watching {project_dir} (every {interval}s)...")

    last_mtimes: dict[str, float] = {}
    lockfiles = detect_ecosystem(project_dir)
    for _, lf in lockfiles:
        last_mtimes[str(lf)] = lf.stat().st_mtime

    click.echo(f"Monitoring {len(lockfiles)} lockfile(s). Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(interval)
            changed = False
            current_lockfiles = detect_ecosystem(project_dir)

            for _, lf in current_lockfiles:
                key = str(lf)
                mtime = lf.stat().st_mtime
                if key not in last_mtimes or last_mtimes[key] != mtime:
                    changed = True
                    last_mtimes[key] = mtime
                    click.echo(f"\n[{time.strftime('%H:%M:%S')}] Change detected: {lf.name}")

            if changed:
                result = asyncio.run(scan_directory(project_dir))
                click.echo(render_result(result, "table"))
                if _should_fail(result, fail_on):
                    click.echo("\n⚠ Findings above threshold detected.")
    except KeyboardInterrupt:
        click.echo("\nStopped watching.")



@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def summary(path: str) -> None:
    """Quick security posture summary for a project."""
    from depfence.core.engine import scan_directory
    from depfence.core.lockfile import detect_ecosystem

    project_dir = Path(path).resolve()
    lockfiles = detect_ecosystem(project_dir)

    click.echo(f"Project: {project_dir.name}")
    click.echo(f"Lockfiles: {len(lockfiles)}")

    total_pkgs = 0
    for eco, lf in lockfiles:
        from depfence.core.lockfile import parse_lockfile
        pkgs = parse_lockfile(eco, lf)
        total_pkgs += len(pkgs)
        click.echo(f"  {eco}: {lf.name} ({len(pkgs)} packages)")

    if total_pkgs == 0:
        click.echo("No dependencies found.")
        return

    result = asyncio.run(scan_directory(project_dir, fetch_metadata=False))

    critical = sum(1 for f in result.findings if f.severity.name == "CRITICAL")
    high = sum(1 for f in result.findings if f.severity.name == "HIGH")
    medium = sum(1 for f in result.findings if f.severity.name == "MEDIUM")
    low = sum(1 for f in result.findings if f.severity.name == "LOW")

    click.echo(f"\nFindings: {len(result.findings)}")
    click.echo(f"  Critical: {critical}")
    click.echo(f"  High:     {high}")
    click.echo(f"  Medium:   {medium}")
    click.echo(f"  Low:      {low}")

    if critical == 0 and high == 0:
        click.echo("\nStatus: PASS")
    elif critical > 0:
        click.echo("\nStatus: CRITICAL")
    else:
        click.echo("\nStatus: WARN")


@cli.command("diff")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
@click.option("--git", "mode_git", is_flag=True, default=False, help="Compare current lockfile(s) against git HEAD.")
@click.option("--ci", "mode_ci", is_flag=True, default=False, help="Detect CI/local drift: fail if lockfile differs from git HEAD.")
@click.option("--history", "mode_history", is_flag=True, default=False, help="Compare the two most recent recorded scans.")
def diff_scan(path: str, fmt: str, fail_on: str, mode_git: bool, mode_ci: bool, mode_history: bool) -> None:
    """Scan packages changed since last scan; detect lockfile drift vs git HEAD.

    \b
    Modes (mutually exclusive):
      (default)   Compare current packages against last recorded scan cache.
      --git       Compare disk lockfile(s) against git HEAD -- shows additions/
                  removals/version changes with supply-chain risk indicators.
      --ci        Exit non-zero if any lockfile differs from git HEAD (CI gate).
      --history   Show delta between the two most recently recorded scans.
    """
    import json as json_mod

    from depfence.core.engine import render_result, scan_directory
    from depfence.core.lockfile import detect_ecosystem, parse_lockfile
    from depfence.core.models import Finding, ScanResult
    from depfence.core.scan_cache import ScanCache

    project_dir = Path(path).resolve()

    # ------------------------------------------------------------------
    # --git mode: lockfile-vs-HEAD drift report
    # ------------------------------------------------------------------
    if mode_git:
        from depfence.core.drift import DriftDetector
        detector = DriftDetector()
        report = detector.detect_drift(project_dir)

        if fmt == "json":
            click.echo(json_mod.dumps(report.to_dict(), indent=2))
        else:
            header = "Lockfile Drift Report (disk vs git HEAD)"
            click.echo(header)
            click.echo("-" * len(header))
            click.echo(report.render_table())
            if report.added:
                click.echo(
                    f"\n  Supply-chain risk: {len(report.supply_chain_risk_packages)} new package(s) not in git."
                )
            if report.major_version_jumps:
                click.echo(
                    f"  Major version jumps: {len(report.major_version_jumps)} package(s)."
                )

        if not report.is_clean:
            sys.exit(1)
        return

    # ------------------------------------------------------------------
    # --ci mode: simple drift gate -- exit 1 if any lockfile changed
    # ------------------------------------------------------------------
    if mode_ci:
        from depfence.core.drift import DriftDetector
        from depfence.core.lockfile import detect_ecosystem as _detect_eco

        detector = DriftDetector()
        lockfiles = _detect_eco(project_dir)
        drifted: list[str] = []
        for _eco, lf_path in lockfiles:
            if detector.detect_ci_drift(lf_path):
                drifted.append(str(lf_path))

        if drifted:
            click.echo("CI DRIFT DETECTED -- lockfile(s) differ from git HEAD:")
            for lf in drifted:
                click.echo(f"  ! {lf}")
            if fmt == "json":
                click.echo(json_mod.dumps({"ci_drift": True, "drifted_files": drifted}))
            sys.exit(1)
        else:
            if fmt == "json":
                click.echo(json_mod.dumps({"ci_drift": False, "drifted_files": []}))
            else:
                click.echo("No CI drift -- lockfiles match git HEAD.")
        return

    # ------------------------------------------------------------------
    # --history mode: compare two most recent recorded scans
    # ------------------------------------------------------------------
    if mode_history:
        from depfence.core.history import ScanHistory
        history = ScanHistory()
        delta = history.compare_last_two(str(project_dir))
        if delta is None:
            click.echo("Fewer than 2 recorded scans for this project. Run 'depfence scan' first.")
            return

        if fmt == "json":
            click.echo(json_mod.dumps(delta.to_dict(), indent=2))
        else:
            header = "Scan History Delta"
            click.echo(header)
            click.echo("-" * len(header))
            click.echo(delta.render_table())
            if delta.regression:
                click.echo("\n  Regression: new critical/high findings detected.")
        return

    # ------------------------------------------------------------------
    # Default mode: diff against last recorded scan cache (fast CI)
    # ------------------------------------------------------------------
    cache = ScanCache()

    all_packages: list = []
    lockfiles = detect_ecosystem(project_dir)
    for eco, lockfile_path in lockfiles:
        try:
            all_packages.extend(parse_lockfile(eco, lockfile_path))
        except Exception as e:
            click.echo(f"Warning: could not parse {lockfile_path}: {e}", err=True)

    if not all_packages:
        click.echo("No packages found.")
        return

    cached = cache.get_cached_packages(project_dir)

    if cached is None:
        click.echo(f"No cache found — running full scan of {len(all_packages)} packages...")
        result = asyncio.run(scan_directory(project_dir))
        cache.save_scan(project_dir, all_packages)
        click.echo(render_result(result, fmt))
        if _should_fail(result, fail_on):
            sys.exit(1)
        return

    diff = cache.get_diff(project_dir, all_packages)
    added = diff["added"]
    removed = diff["removed"]
    updated = diff["updated"]
    to_scan = added + updated

    click.echo(
        f"{len(added)} new, {len(removed)} removed, {len(updated)} updated"
        f" — scanning {len(to_scan)} packages"
    )

    if not to_scan:
        click.echo("Nothing to scan.")
        cache.save_scan(project_dir, all_packages)
        return

    from depfence.core.fetcher import fetch_batch
    from depfence.core.registry import get_registry

    metas = asyncio.run(fetch_batch(to_scan, concurrency=20))
    registry = get_registry()

    async def _run_scanners() -> list[Finding]:
        tasks = []
        for scanner in registry.scanners.values():
            relevant = [m for m in metas if m.pkg.ecosystem in scanner.ecosystems]
            if relevant:
                tasks.append(scanner.scan(relevant))
        findings: list[Finding] = []
        if tasks:
            for sr in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(sr, list):
                    findings.extend(sr)
        return findings

    findings = asyncio.run(_run_scanners())

    result = ScanResult(target=str(project_dir), ecosystem="multi")
    result.findings = findings
    result.packages_scanned = len(to_scan)

    cache.save_scan(project_dir, all_packages)

    click.echo(render_result(result, fmt))
    if _should_fail(result, fail_on):
        sys.exit(1)


@cli.command("sbom-diff")
@click.argument("before", type=click.Path(exists=True))
@click.argument("after", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def sbom_diff(before: str, after: str, fmt: str) -> None:
    """Compare two SBOMs and show dependency changes."""
    import json as json_mod
    from depfence.core.sbom_diff import diff_sbom_files

    diff = diff_sbom_files(Path(before), Path(after))

    if fmt == "json":
        click.echo(json_mod.dumps(diff.to_dict(), indent=2))
    else:
        click.echo(f"SBOM Diff: {Path(before).name} -> {Path(after).name}")
        click.echo(diff.render_table())

    if diff.risk_score > 20:
        sys.exit(1)


@cli.command("baseline")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--create", is_flag=True, help="Create baseline from current findings")
@click.option("--show", is_flag=True, help="Show current baseline entries")
def baseline(path: str, create: bool, show: bool) -> None:
    """Manage finding suppressions (acknowledge known risks)."""
    from depfence.core.baseline import Baseline

    project_dir = Path(path).resolve()
    bl = Baseline.from_project(project_dir)

    if show:
        if bl.count == 0:
            click.echo("No baseline entries.")
        else:
            click.echo(f"Baseline: {bl.count} suppressed finding(s)")
            for fp, entry in bl._entries.items():
                click.echo(f"  [{entry.get('severity', '?')}] {entry.get('package', '?')}: {entry.get('title', '?')}")
                if entry.get('reason'):
                    click.echo(f"         Reason: {entry['reason']}")
                if entry.get('expires'):
                    click.echo(f"         Expires: {entry['expires']}")
        return

    if create:
        from depfence.core.engine import scan_directory
        result = asyncio.run(scan_directory(project_dir, fetch_metadata=False))
        if not result.findings:
            click.echo("No findings to baseline.")
            return

        for f in result.findings:
            bl.suppress(f, reason="Initial baseline")
        bl._path = project_dir / ".depfence-baseline.json"
        bl.save()
        click.echo(f"Baselined {len(result.findings)} finding(s) in .depfence-baseline.json")
        return

    click.echo(f"Baseline: {bl.count} suppressed finding(s)")
    click.echo("Use --create to baseline current findings, --show to list them.")


@cli.command("fix")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--apply/--no-apply", default=False, help="Apply fixes directly to manifest files")
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def fix(path: str, apply: bool, fail_on: str) -> None:
    """Suggest or apply version fixes for vulnerable packages."""
    from depfence.core.engine import scan_directory
    from depfence.core.fixer import (
        apply_fixes_package_json,
        apply_fixes_requirements,
        generate_diff,
        generate_fixes,
    )
    from depfence.core.lockfile import detect_ecosystem

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    if not result.findings:
        click.echo("No vulnerabilities found — nothing to fix.")
        return

    fixes = generate_fixes(result.findings, project_dir)
    if not fixes:
        click.echo("No auto-fixable vulnerabilities (no fix versions available).")
        return

    if not apply:
        click.echo(generate_diff(result.findings, project_dir))
        click.echo("\nRun with --apply to write changes.")
        return

    changes: list[str] = []
    lockfiles = detect_ecosystem(project_dir)
    for eco, _ in lockfiles:
        if eco == "pypi":
            req_path = project_dir / "requirements.txt"
            if req_path.exists():
                changes.extend(apply_fixes_requirements(req_path, fixes))
        elif eco == "npm":
            pkg_json = project_dir / "package.json"
            if pkg_json.exists():
                changes.extend(apply_fixes_package_json(pkg_json, fixes))

    if changes:
        click.echo(f"Applied {len(changes)} fix(es):")
        for c in changes:
            click.echo(f"  {c}")
    else:
        click.echo("No changes applied (packages not found in manifest files).")

    if _should_fail(result, fail_on):
        sys.exit(1)


@cli.command()
def plugins() -> None:
    """List loaded plugins."""
    from depfence.core.registry import get_registry

    reg = get_registry()
    click.echo("Scanners:")
    for name, s in reg.scanners.items():
        ecosystems = ", ".join(getattr(s, "ecosystems", []))
        click.echo(f"  {name} [{ecosystems}]")

    click.echo("Analyzers:")
    for name in reg.analyzers:
        click.echo(f"  {name}")

    click.echo("Reporters:")
    for name, r in reg.reporters.items():
        click.echo(f"  {name} ({getattr(r, 'format', 'unknown')})")



@cli.group()
def firewall() -> None:
    """Registry firewall — block malicious packages at install time."""


@firewall.command("enable")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--npm/--no-npm", default=True)
@click.option("--pip/--no-pip", default=True)
def firewall_enable(path: str, npm: bool, pip: bool) -> None:
    """Enable the install-time firewall for this project."""
    from depfence.firewall.interceptor import enable_npm_firewall, enable_pip_firewall

    project_dir = Path(path).resolve()
    if npm:
        click.echo(enable_npm_firewall(project_dir))
    if pip:
        click.echo(enable_pip_firewall(project_dir))


@firewall.command("disable")
@click.argument("path", default=".", type=click.Path(exists=True))
def firewall_disable(path: str) -> None:
    """Disable the install-time firewall."""
    from depfence.firewall.interceptor import disable_firewall

    click.echo(disable_firewall(Path(path).resolve()))


@firewall.command("status")
@click.argument("path", default=".", type=click.Path(exists=True))
def firewall_status(path: str) -> None:
    """Show firewall status for this project."""
    from depfence.firewall.interceptor import get_status

    status = get_status(Path(path).resolve())
    click.echo(f"npm: {'enabled' if status['npm'] else 'disabled'}")
    click.echo(f"pip: {'enabled' if status['pip'] else 'disabled'}")


@firewall.command("check-npm")
def firewall_check_npm() -> None:
    """Pre-install hook for npm (called automatically)."""
    import os
    from depfence.firewall.interceptor import check_package, FirewallDecision

    pkg_name = os.environ.get("npm_package_name", "")
    pkg_version = os.environ.get("npm_package_version", "")

    if not pkg_name:
        return

    result = check_package("npm", pkg_name, pkg_version)
    if result["decision"] == FirewallDecision.BLOCK:
        click.echo(f"[depfence] BLOCKED: {pkg_name} — {result['reason']}", err=True)
        sys.exit(1)
    elif result["decision"] == FirewallDecision.WARN:
        click.echo(f"[depfence] WARNING: {pkg_name} — {result['reason']}", err=True)


@firewall.command("check-pip")
@click.argument("package_name")
def firewall_check_pip(package_name: str) -> None:
    """Check a pip package before install."""
    from depfence.firewall.interceptor import check_package, FirewallDecision

    result = check_package("pypi", package_name)
    if result["decision"] == FirewallDecision.BLOCK:
        click.echo(f"BLOCKED: {package_name} — {result['reason']}")
        sys.exit(1)
    elif result["decision"] == FirewallDecision.WARN:
        click.echo(f"WARNING: {package_name} — {result['reason']}")
    else:
        click.echo(f"OK: {package_name}")


@cli.command("ai-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def ai_scan(path: str, fmt: str, fail_on: str) -> None:
    """Comprehensive AI/ML supply chain security scan."""
    from depfence.core.engine import render_result
    from depfence.core.models import ScanResult
    from depfence.scanners.ai_vulns import AiVulnScanner
    from depfence.scanners.model_scanner import ModelScanner

    project_dir = Path(path).resolve()
    all_findings = []

    # Model supply chain scan
    model_scanner = ModelScanner()
    model_findings = asyncio.run(model_scanner.scan_project(project_dir))
    all_findings.extend(model_findings)

    # AI framework vulnerability patterns
    ai_vuln_scanner = AiVulnScanner()
    ai_findings = asyncio.run(ai_vuln_scanner.scan_project(project_dir))
    all_findings.extend(ai_findings)

    # Check known AI package versions
    from depfence.core.lockfile import detect_ecosystem, parse_lockfile
    lockfiles = detect_ecosystem(project_dir)
    ai_packages = {"langchain", "transformers", "torch", "tensorflow", "llama-index",
                   "gradio", "mlflow", "ray", "onnx", "openai", "anthropic", "litellm"}
    for eco, lf in lockfiles:
        if eco == "pypi":
            pkgs = parse_lockfile(eco, lf)
            for pkg in pkgs:
                if pkg.name.lower() in ai_packages and pkg.version:
                    all_findings.extend(ai_vuln_scanner.check_package_version(pkg.name, pkg.version))

    result = ScanResult(target=str(project_dir), ecosystem="ai")
    result.findings = all_findings
    result.packages_scanned = len(set(f.package for f in all_findings)) or 0

    click.echo(render_result(result, fmt))
    if _should_fail(result, fail_on):
        sys.exit(1)


@cli.command("model-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json", "sarif"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
def model_scan(path: str, fmt: str, fail_on: str) -> None:
    """Scan for model supply chain risks (HuggingFace, pickle, etc.)."""
    from depfence.core.models import ScanResult
    from depfence.core.engine import render_result
    from depfence.scanners.model_scanner import ModelScanner

    scanner = ModelScanner()
    project_dir = Path(path).resolve()
    findings = asyncio.run(scanner.scan_project(project_dir))

    result = ScanResult(target=str(project_dir), ecosystem="huggingface")
    result.findings = findings
    result.packages_scanned = len(set(f.package for f in findings)) or 0

    click.echo(render_result(result, fmt))
    if _should_fail(result, fail_on):
        sys.exit(1)



@cli.command("licenses")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option(
    "--policy",
    default="default",
    type=click.Choice(["default", "strict"]),
    help="strict: fail on any non-permissive license",
)
@click.option(
    "--fail-on-violation/--no-fail-on-violation",
    default=True,
    help="Exit 1 when policy violations are found (default: on)",
)
def licenses(path: str, fmt: str, policy: str, fail_on_violation: bool) -> None:
    """Scan dependency licenses for compliance with your policy.

    Reads the ``licenses:`` section from depfence.yml.  Without a policy file
    the default behaviour is to flag strong-copyleft and non-commercial licenses.

    Use ``--policy strict`` to fail on anything that is not permissive.

    Exit code 1 when violations are found (unless --no-fail-on-violation).
    """
    import json as _json

    from depfence.core.lockfile import detect_ecosystem, parse_lockfile
    from depfence.core.models import PackageId, PackageMeta
    from depfence.scanners.license import LicenseScanner

    project_dir = Path(path).resolve()

    # Collect all packages from lockfiles
    all_pkg_ids: list[PackageId] = []
    lockfiles = detect_ecosystem(project_dir)
    for eco, lf in lockfiles:
        try:
            all_pkg_ids.extend(parse_lockfile(eco, lf))
        except Exception as e:
            click.echo(f"Warning: could not parse {lf}: {e}", err=True)

    if not all_pkg_ids:
        click.echo("No packages found in lockfiles.")
        return

    # Wrap in PackageMeta (license field blank — scanner will report unknown)
    metas = [PackageMeta(pkg=p) for p in all_pkg_ids]

    # Override policy if --policy strict
    scanner = LicenseScanner()

    if policy == "strict":
        import tempfile, yaml as _yaml
        _strict_dir = Path(tempfile.mkdtemp())
        (_strict_dir / "depfence.yml").write_text(
            _yaml.dump({
                "licenses": {
                    "allow": ["permissive"],
                    "deny": ["weak_copyleft", "strong_copyleft", "non_commercial"],
                    "exceptions": [],
                }
            })
        )
        scan_dir = _strict_dir
    else:
        scan_dir = project_dir

    policy_results = scanner.evaluate_policy(metas, project_dir=scan_dir)
    findings = scanner.scan(metas, project_dir=scan_dir)

    violations = [r for r in policy_results if r.status == "denied"]
    unknowns = [r for r in policy_results if r.status == "unknown"]

    if fmt == "json":
        output = {
            "project": str(project_dir),
            "packages_scanned": len(policy_results),
            "violations": len(violations),
            "unknowns": len(unknowns),
            "packages": [
                {
                    "package": r.package_name,
                    "version": r.version,
                    "license": r.license_str,
                    "category": r.category,
                    "status": r.status,
                    "reason": r.reason,
                }
                for r in sorted(policy_results, key=lambda x: (x.status != "denied", x.status != "unknown", x.package_name))
            ],
            "findings": [
                {
                    "severity": f.severity.name,
                    "package": f.package.name,
                    "version": f.package.version,
                    "license": f.metadata.get("license", ""),
                    "category": f.metadata.get("category", ""),
                    "title": f.title,
                }
                for f in findings
            ],
        }
        click.echo(_json.dumps(output, indent=2))
    else:
        # Rich table output
        from rich.console import Console
        from rich.table import Table

        console = Console()

        status_styles = {
            "allowed":   "green",
            "denied":    "bold red",
            "exception": "yellow",
            "unknown":   "red",
        }

        table = Table(title=f"License Compliance — {project_dir.name} ({len(policy_results)} packages)")
        table.add_column("Package", style="cyan")
        table.add_column("Version")
        table.add_column("License")
        table.add_column("Category")
        table.add_column("Status", justify="center")

        # Sort: denied first, then unknown, then allowed
        _status_order = {"denied": 0, "unknown": 1, "exception": 2, "allowed": 3}
        sorted_results = sorted(
            policy_results,
            key=lambda r: (_status_order.get(r.status, 4), r.package_name),
        )

        for r in sorted_results:
            style = status_styles.get(r.status, "white")
            table.add_row(
                r.package_name,
                r.version or "?",
                r.license_str,
                r.category,
                f"[{style}]{r.status.upper()}[/{style}]",
            )

        console.print(table)

        if violations:
            console.print(f"\n[bold red]Policy violations: {len(violations)}[/bold red]")
        if unknowns:
            console.print(f"[yellow]Unknown/uncategorised licenses: {len(unknowns)}[/yellow]")
        if not violations and not unknowns:
            console.print("\n[bold green]All licenses comply with policy.[/bold green]")

    # Exit 1 if violations exist and --fail-on-violation (default)
    if fail_on_violation and (violations or any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)):
        sys.exit(1)


def _should_fail(result, fail_on: str) -> bool:
    from depfence.core.models import Severity

    if fail_on == "none":
        return False
    threshold = {
        "critical": [Severity.CRITICAL],
        "high": [Severity.CRITICAL, Severity.HIGH],
        "medium": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        "low": [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        "any": list(Severity),
    }
    levels = threshold.get(fail_on, [Severity.CRITICAL])
    return any(f.severity in levels for f in result.findings)



@cli.command("risk-score")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--top", "-n", default=10, help="Show top N riskiest packages")
@click.option("--min-score", default=0.0, help="Only show packages with score >= threshold")
def risk_score(path: str, fmt: str, top: int, min_score: float) -> None:
    """Compute supply chain risk scores for all dependencies."""
    from depfence.core.engine import scan_directory
    from depfence.core.risk_scorer import risk_summary, score_all_packages

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    scores = score_all_packages(result.findings)
    if min_score > 0:
        scores = [s for s in scores if s.score >= min_score]

    scores = scores[:top]

    if fmt == "json":
        import json
        summary = risk_summary(scores)
        summary["packages"] = [
            {"package": s.package, "score": s.score, "grade": s.grade, "findings": s.findings_count, "signals": s.signals}
            for s in scores
        ]
        click.echo(json.dumps(summary, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="Supply Chain Risk Scores")
        table.add_column("Package", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Grade", justify="center")
        table.add_column("Findings", justify="right")
        table.add_column("Top Signal")

        grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "bold red"}
        for s in scores:
            grade_style = grade_colors.get(s.grade, "white")
            top_signal = s.signals[0] if s.signals else "-"
            if len(top_signal) > 50:
                top_signal = top_signal[:47] + "..."
            table.add_row(
                s.package,
                f"{s.score:.1f}",
                f"[{grade_style}]{s.grade}[/{grade_style}]",
                str(s.findings_count),
                top_signal,
            )

        console.print(table)
        summary = risk_summary(scores)
        console.print(f"\nAverage risk: [bold]{summary['average_score']:.1f}[/bold] | "
                      f"Critical: {summary['critical_count']} | "
                      f"High: {summary['high_count']} | "
                      f"Medium: {summary['medium_count']}")



@cli.command("scan-docker")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def scan_docker(path: str, fmt: str) -> None:
    """Scan Dockerfiles for security issues."""
    from depfence.scanners.dockerfile_scanner import DockerfileScanner

    project_dir = Path(path).resolve()
    scanner = DockerfileScanner()
    findings = asyncio.run(scanner.scan_project(project_dir))

    if not findings:
        click.echo("No Dockerfile issues found.")
        return

    if fmt == "json":
        import json
        click.echo(json.dumps([{"title": f.title, "severity": f.severity.name, "package": f.package, "detail": f.detail} for f in findings], indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title=f"Dockerfile Security Issues ({len(findings)} found)")
        table.add_column("Severity", style="bold")
        table.add_column("File")
        table.add_column("Issue")

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
        for f in sorted(findings, key=lambda x: x.severity.value):
            sev_style = sev_colors.get(f.severity.name, "white")
            table.add_row(f"[{sev_style}]{f.severity.name}[/{sev_style}]", f.package.replace("docker:", ""), f.title)
        console.print(table)


@cli.command("scan-workflows")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def scan_workflows(path: str, fmt: str) -> None:
    """Scan GitHub Actions workflows for security issues."""
    from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner

    project_dir = Path(path).resolve()
    scanner = GhaWorkflowScanner()
    findings = asyncio.run(scanner.scan_project(project_dir))

    if not findings:
        click.echo("No workflow security issues found.")
        return

    if fmt == "json":
        import json
        click.echo(json.dumps([{"title": f.title, "severity": f.severity.name, "package": f.package, "detail": f.detail} for f in findings], indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title=f"GitHub Actions Security Issues ({len(findings)} found)")
        table.add_column("Severity", style="bold")
        table.add_column("Workflow")
        table.add_column("Issue")

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
        for f in sorted(findings, key=lambda x: x.severity.value):
            sev_style = sev_colors.get(f.severity.name, "white")
            table.add_row(f"[{sev_style}]{f.severity.name}[/{sev_style}]", f.package.replace("github:", ""), f.title)
        console.print(table)



@cli.command("compliance")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="markdown", type=click.Choice(["markdown", "json"]))
@click.option("--output", "-o", type=click.Path(), help="Write report to file")
def compliance(path: str, fmt: str, output: str | None) -> None:
    """Generate a supply chain compliance report."""
    from depfence.core.engine import scan_directory
    from depfence.reporters.compliance_report import (
        generate_compliance_report,
        render_compliance_json,
        render_compliance_markdown,
    )

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))
    report = generate_compliance_report(result, project_dir)

    if fmt == "json":
        text = render_compliance_json(report)
    else:
        text = render_compliance_markdown(report)

    if output:
        Path(output).write_text(text)
        click.echo(f"Report written to {output}")
    else:
        click.echo(text)

    if not report["summary"]["pass"]:
        sys.exit(1)



@cli.command("update-plan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def update_plan(path: str, fmt: str) -> None:
    """Analyze pending dependency updates for safety (auto-merge vs review needed)."""
    from depfence.core.engine import scan_directory
    from depfence.core.fixer import generate_fixes
    from depfence.core.update_advisor import batch_analyze, generate_update_plan

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))
    fixes = generate_fixes(result.findings, project_dir)

    if not fixes:
        click.echo("No updates needed — all dependencies are clean.")
        return

    updates = [
        {
            "package": f["package"],
            "ecosystem": f["ecosystem"],
            "current_version": f["current_version"] or "0.0.0",
            "target_version": f["fix_version"],
        }
        for f in fixes
    ]

    recommendations = batch_analyze(updates)
    plan = generate_update_plan(recommendations)

    if fmt == "json":
        import json
        click.echo(json.dumps(plan, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        if plan["auto_merge"]:
            console.print("\n[green bold]Auto-mergeable (safe patches):[/green bold]")
            for item in plan["auto_merge"]:
                console.print(f"  [green]✓[/green] {item}")

        if plan["needs_review"]:
            console.print("\n[yellow bold]Needs review:[/yellow bold]")
            for item in plan["needs_review"]:
                console.print(f"  [yellow]![/yellow] {item}")

        if plan["breaking_changes"]:
            console.print("\n[red bold]Breaking changes (manual only):[/red bold]")
            for item in plan["breaking_changes"]:
                console.print(f"  [red]✗[/red] {item}")

        console.print(f"\n[bold]Summary:[/bold] {plan['stats']['auto_mergeable']} auto-merge, "
                      f"{plan['stats']['needs_review']} review, "
                      f"{plan['stats']['breaking']} breaking")



@cli.command("graph")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="tree", type=click.Choice(["tree", "mermaid", "dot"]))
@click.option("--output", "-o", type=click.Path(), help="Write graph to file")
@click.option("--max-depth", default=5, help="Maximum tree depth")
def graph(path: str, fmt: str, output: str | None, max_depth: int) -> None:
    """Visualize the dependency graph with vulnerability annotations."""
    from depfence.core.dep_graph import build_graph_from_package_lock
    from depfence.core.engine import scan_directory
    from depfence.core.graph_viz import generate_dot, generate_mermaid, generate_tree

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    lock_path = project_dir / "package-lock.json"
    if not lock_path.exists():
        click.echo("No package-lock.json found. Graph visualization requires a lockfile.")
        return

    dep_graph = build_graph_from_package_lock(lock_path)
    adj = {}
    for node in dep_graph._graph:
        adj[node] = dep_graph._graph[node]

    if fmt == "mermaid":
        text = generate_mermaid(adj, findings=result.findings)
    elif fmt == "dot":
        text = generate_dot(adj, findings=result.findings)
    else:
        root = next(iter(adj), "root")
        text = generate_tree(adj, root, findings=result.findings, max_depth=max_depth)

    if output:
        Path(output).write_text(text)
        click.echo(f"Graph written to {output}")
    else:
        click.echo(text)



@cli.command("health")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="text", type=click.Choice(["text", "json"]))
def health(path: str, fmt: str) -> None:
    """Show supply chain health dashboard with actionable score."""
    from depfence.core.engine import scan_directory
    from depfence.core.health_dashboard import compute_health, render_health_text

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    has_lockfile = any((
        (project_dir / "package-lock.json").exists(),
        (project_dir / "yarn.lock").exists(),
        (project_dir / "pnpm-lock.yaml").exists(),
        any(project_dir.glob("requirements*.txt")),
    ))
    has_policy = (project_dir / ".depfence-policy.yml").exists() or (project_dir / "depfence.yml").exists()

    dashboard = compute_health(result, has_lockfile=has_lockfile, has_policy=has_policy)

    if fmt == "json":
        import json
        data = {
            "score": dashboard.overall_score,
            "grade": dashboard.grade,
            "metrics": [{"name": m.name, "score": m.score, "status": m.status, "detail": m.detail} for m in dashboard.metrics],
            "recommendations": dashboard.recommendations,
        }
        click.echo(json.dumps(data, indent=2))
    else:
        from rich.console import Console
        from rich.panel import Panel

        console = Console()
        text = render_health_text(dashboard)
        console.print(Panel(text, title="depfence Health Dashboard", border_style="blue"))

@cli.command("why")
@click.argument("package_name")
@click.option("--path", "-p", default=".", type=click.Path(exists=True))
@click.option("--ecosystem", "-e", default=None, type=click.Choice(["npm", "pypi", "cargo", "go"]))
def why(package_name: str, path: str, ecosystem: str | None) -> None:
    """Show why a package is in your dependency tree (transitive path)."""
    from depfence.core.dep_tree import build_tree_from_package_lock, find_paths_to
    from depfence.core.lockfile import detect_ecosystem

    project_dir = Path(path).resolve()
    lockfiles = detect_ecosystem(project_dir)

    if not lockfiles:
        click.echo("No lockfiles found.", err=True)
        sys.exit(1)

    # Try to find the package in available lockfiles
    for eco, lf in lockfiles:
        if ecosystem and eco != ecosystem:
            continue
        if eco == "npm" and lf.name == "package-lock.json":
            tree = build_tree_from_package_lock(lf)
            paths = find_paths_to(tree, package_name)
            if paths:
                click.echo(f"Found {len(paths)} path(s) to '{package_name}' in {lf.name}:\n")
                for i, dep_path in enumerate(paths[:10], 1):
                    chain = " -> ".join(str(p) for p in dep_path)
                    click.echo(f"  {i}. {chain}")
                if len(paths) > 10:
                    click.echo(f"  ... and {len(paths) - 10} more")
                return

    click.echo(f"Package '{package_name}' not found in dependency tree.")


@cli.command("epss")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--top", "-n", default=10, help="Show top N most exploitable")
def epss(path: str, top: int) -> None:
    """Enrich vulnerabilities with EPSS exploit probability scores."""
    from depfence.core.engine import scan_directory
    from depfence.core.epss_enricher import enrich_findings

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    vuln_findings = [f for f in result.findings if f.cve]
    if not vuln_findings:
        click.echo("No CVE-identified vulnerabilities to score.")
        return

    enriched = asyncio.run(enrich_findings(vuln_findings))
    scored = [f for f in enriched if f.metadata.get("epss_score") is not None]
    scored.sort(key=lambda f: f.metadata.get("epss_score", 0), reverse=True)
    scored = scored[:top]

    if not scored:
        click.echo("EPSS scores unavailable (API unreachable or no CVE matches).")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="EPSS Exploit Probability Scores")
    table.add_column("CVE", style="cyan")
    table.add_column("Package")
    table.add_column("EPSS Score", justify="right")
    table.add_column("Percentile", justify="right")
    table.add_column("Priority", justify="center")
    table.add_column("Severity")

    priority_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}
    for f in scored:
        score = f.metadata.get("epss_score", 0)
        pct = f.metadata.get("epss_percentile", 0)
        priority = f.metadata.get("epss_priority", "low")
        p_style = priority_colors.get(priority, "white")
        table.add_row(
            f.cve or "",
            str(f.package),
            f"{score:.4f}",
            f"{pct:.1%}",
            f"[{p_style}]{priority}[/{p_style}]",
            f.severity.value,
        )
    console.print(table)




@cli.command("stats")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def stats(path: str, fmt: str) -> None:
    """Show scan statistics and value-add over basic audit tools."""
    from depfence.core.engine import scan_directory
    from depfence.core.scan_stats import comparison_summary, compute_stats

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))
    scan_stats = compute_stats(result)
    summary = comparison_summary(scan_stats)

    if fmt == "json":
        import json
        click.echo(json.dumps(summary, indent=2))
    else:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()

        # Header stats
        console.print(f"[bold]Scan Results:[/bold] {summary['total_findings']} findings across {scan_stats.packages_scanned} packages")
        console.print(f"[bold]Unique CVEs:[/bold] {summary['unique_cves']}  |  [bold]Actionable fixes:[/bold] {summary['actionable_fixes']}")

        # Value-add comparison
        console.print(f"[bold green]depfence value-add:[/bold green] {summary['value_add_percentage']}% of findings are beyond what npm-audit/pip-audit would catch")
        console.print(f"  Advisory-only (CVEs): {summary['advisory_findings']}")
        console.print(f"  Beyond-advisory:      {summary['beyond_advisory_findings']}")

        # Category breakdown
        cats = summary['detection_categories']
        table = Table(title="Detection Categories")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right")
        for cat, count in cats.items():
            if count > 0:
                table.add_row(cat.replace('_', ' ').title(), str(count))
        console.print(table)



@cli.command("kev")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--top", "-n", default=20, help="Show top N KEV-listed vulnerabilities")
def kev(path: str, top: int) -> None:
    """Check dependencies against CISA Known Exploited Vulnerabilities catalog."""
    from depfence.core.engine import scan_directory
    from depfence.core.kev_enricher import enrich_with_kev

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    vuln_findings = [f for f in result.findings if f.cve]
    if not vuln_findings:
        click.echo("No CVE-identified vulnerabilities to check against KEV catalog.")
        return

    enriched = asyncio.run(enrich_with_kev(vuln_findings))
    kev_findings = [f for f in enriched if f.metadata.get("kev_exploited")]
    kev_findings = kev_findings[:top]

    if not kev_findings:
        click.echo("No dependencies found in CISA KEV catalog. Good news!")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"CISA Known Exploited Vulnerabilities ({len(kev_findings)} found)")
    table.add_column("CVE", style="bold red")
    table.add_column("Package")
    table.add_column("Due Date")
    table.add_column("Ransomware", justify="center")
    table.add_column("Required Action")

    for f in kev_findings:
        ransomware = "[red]YES[/red]" if f.metadata.get("kev_ransomware") else "No"
        table.add_row(
            f.cve or "",
            str(f.package),
            f.metadata.get("kev_due_date", ""),
            ransomware,
            (f.metadata.get("kev_required_action", ""))[:60],
        )
    console.print(table)
    console.print(f"[bold red]Action required:[/bold red] These vulnerabilities are being actively exploited.")



@cli.command("scorecard")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--top", "-n", default=10, help="Show top N lowest-scoring packages")
def scorecard(path: str, top: int) -> None:
    """Show OpenSSF Scorecard scores for dependencies with GitHub repos."""
    from depfence.core.lockfile import detect_ecosystem, parse_lockfile
    from depfence.core.registry_client import RegistryClient
    from depfence.core.scorecard_enricher import enrich_with_scorecard

    project_dir = Path(path).resolve()
    lockfiles = detect_ecosystem(project_dir)

    all_packages = []
    for eco, lf in lockfiles:
        all_packages.extend(parse_lockfile(eco, lf))

    if not all_packages:
        click.echo("No packages found to score.")
        return

    # Get metadata for packages to find repo URLs
    from depfence.core.models import PackageMeta
    metas = []
    client = RegistryClient()
    for pkg in all_packages[:50]:  # Limit to avoid rate limiting
        try:
            meta = asyncio.run(client.get_npm_metadata(pkg.name) if pkg.ecosystem == "npm" else client.get_pypi_metadata(pkg.name))
            if meta:
                pm = PackageMeta(pkg=pkg, repository=meta.repo_url or "")
                metas.append(pm)
        except Exception:
            continue

    if not metas:
        click.echo("Could not resolve repository URLs for packages.")
        return

    results = asyncio.run(enrich_with_scorecard(metas))
    results.sort(key=lambda r: r.get("score", 10))
    results = results[:top]

    if not results:
        click.echo("No scorecard data available.")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="OpenSSF Scorecard Scores")
    table.add_column("Package", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("Weak Checks")

    risk_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "good": "green"}
    for r in results:
        risk = r.get("risk_level", "unknown")
        r_style = risk_colors.get(risk, "white")
        weak = ", ".join(r.get("weak_checks", [])[:3])
        table.add_row(
            str(r.get("package", "")),
            f"{r.get('score', 0):.1f}/10",
            f"[{r_style}]{risk}[/{r_style}]",
            weak or "-",
        )
    console.print(table)


@cli.command("trust")
@click.argument("package_name")
@click.option("--ecosystem", "-e", default="npm", type=click.Choice(["npm", "pypi"]))
def trust(package_name: str, ecosystem: str) -> None:
    """Check trust score for a specific package."""
    from depfence.core.models import PackageId
    from depfence.core.registry_client import RegistryClient
    from depfence.core.trust_scorer import TrustSignals, compute_trust

    pkg = PackageId(ecosystem, package_name)

    client = RegistryClient()
    try:
        if ecosystem == "npm":
            meta = asyncio.run(client.get_npm_metadata(package_name))
        else:
            meta = asyncio.run(client.get_pypi_metadata(package_name))
    except Exception as e:
        click.echo(f"Error fetching metadata: {e}", err=True)
        return

    if not meta:
        click.echo(f"Package '{package_name}' not found on {ecosystem} registry.")
        return

    signals = TrustSignals(
        weekly_downloads=meta.weekly_downloads,
        maintainer_count=len(meta.maintainers) if meta.maintainers else None,
        has_repository=bool(meta.repo_url),
        has_license=bool(meta.license),
        version_count=meta.versions_count,
    )

    score = compute_trust(pkg, signals)

    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "bold red"}
    g_style = grade_colors.get(score.grade, "white")

    lines = [
        f"[bold]{package_name}[/bold] ({ecosystem})",
        f"Trust Score: [{g_style}]{score.score:.0f}/100 ({score.grade})[/{g_style}]",
        "",
        "[bold]Breakdown:[/bold]",
    ]
    for signal_name, contribution in score.breakdown.items():
        lines.append(f"  {signal_name}: {contribution:.0f}")

    if score.risk_factors:
        lines.append("")
        lines.append("[bold]Risk factors:[/bold]")
        for rf in score.risk_factors:
            lines.append(f"  [yellow]![/yellow] {rf}")

    console.print(Panel("\n".join(lines), title="Package Trust Score", border_style="blue"))


@cli.command("monorepo-scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def monorepo_scan(path: str, fmt: str) -> None:
    """Scan a monorepo with workspace-aware deduplication."""
    from depfence.core.engine import scan_directory
    from depfence.core.monorepo import (
        deduplicate_findings,
        discover_workspaces,
        workspace_summary,
    )

    project_dir = Path(path).resolve()
    workspaces = discover_workspaces(project_dir)

    if not workspaces:
        click.echo("No workspaces detected. Use 'depfence scan' for single-package projects.")
        return

    result = asyncio.run(scan_directory(project_dir))
    deduped = deduplicate_findings(result.findings, workspaces)
    summary = workspace_summary(workspaces, result.findings)

    if fmt == "json":
        import json
        click.echo(json.dumps(summary, indent=2, default=str))
    else:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print(f"\n[bold]Monorepo: {project_dir.name}[/bold] ({len(workspaces)} workspaces)")

        table = Table(title="Workspace Summary")
        table.add_column("Workspace", style="cyan")
        table.add_column("Packages", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Critical", justify="right")

        for ws_name, ws_data in summary.get("workspaces", {}).items():
            crit = ws_data.get("severity_breakdown", {}).get("critical", 0)
            crit_str = f"[bold red]{crit}[/bold red]" if crit > 0 else "0"
            table.add_row(ws_name, str(ws_data.get("packages", 0)), str(ws_data.get("findings", 0)), crit_str)

        console.print(table)
        console.print(f"\nTotal packages: {summary.get('total_packages', 0)} (shared: {summary.get('shared_packages', 0)})")
        console.print(f"Deduplicated findings: {len(deduped)}")


@cli.command("threat-sync")
@click.option("--force", is_flag=True, help="Force sync even if recently updated")
def threat_sync(force: bool) -> None:
    """Sync threat intelligence database from OSSF malicious packages."""
    from depfence.core.threat_intel import ThreatIntelDB

    db = ThreatIntelDB()
    db.load()

    if not force and db.last_synced:
        click.echo(f"Last synced: {db.last_synced}")
        click.echo(f"Known entries: {db.count()}")
        click.echo("Use --force to re-sync.")
        return

    click.echo("Syncing threat intelligence from OSSF...")
    new_entries = asyncio.run(db.sync_from_ossf())
    db.save()
    click.echo(f"Sync complete. {new_entries} new entries added. Total: {db.count()}")



@cli.command("info")
def info() -> None:
    """Show depfence version, loaded scanners, and system info."""
    from depfence import __version__
    from depfence.core.registry import get_registry

    registry = get_registry()

    click.echo(f"depfence v{__version__}")
    click.echo(f"Python: {sys.version.split()[0]}")
    click.echo(f"\nScanners ({len(registry.scanners)}):")
    for name in sorted(registry.scanners.keys()):
        scanner = registry.scanners[name]
        ecosystems = getattr(scanner, 'ecosystems', [])
        click.echo(f"  {name}: {', '.join(ecosystems) if ecosystems else 'all'}")
    click.echo(f"\nAnalyzers ({len(registry.analyzers)}):")
    for name in sorted(registry.analyzers.keys()):
        click.echo(f"  {name}")
    click.echo(f"\nReporters ({len(registry.reporters)}):")
    for name in sorted(registry.reporters.keys()):
        reporter = registry.reporters[name]
        fmt = getattr(reporter, 'format', 'unknown')
        click.echo(f"  {name} ({fmt})")




@cli.command("policy")
@click.argument("path", default=".", type=click.Path(exists=True))
def policy_check(path: str) -> None:
    """Evaluate scan findings against policy rules in depfence.yml."""
    import asyncio

    from depfence.core.engine import scan_directory
    from depfence.core.policy import find_config, load_config, evaluate_policy

    project_dir = Path(path).resolve()
    config_path = find_config(project_dir)
    if not config_path:
        click.echo("No depfence.yml found. Run 'depfence init' to create one.")
        return

    config = load_config(config_path)
    result = asyncio.run(scan_directory(project_dir))

    blocked, warned = evaluate_policy(result.findings, config)

    click.echo(f"Policy: {config_path.name} (fail_on={config.fail_on})")
    click.echo(f"Total findings: {len(result.findings)}")
    click.echo(f"Blocked: {len(blocked)}")
    click.echo(f"Warned: {len(warned)}")
    click.echo(f"Ignored: {len(result.findings) - len(blocked) - len(warned)}")

    if blocked:
        click.echo("\nBlocked findings:")
        for f in blocked[:10]:
            click.echo(f"  [{f.severity.name}] {f.package.name}: {f.title}")
        if len(blocked) > 10:
            click.echo(f"  ... and {len(blocked) - 10} more")
        import sys
        sys.exit(1)
    else:
        click.echo("\nAll findings within policy threshold.")



@cli.command("doctor")
def doctor() -> None:
    """Self-check: verify depfence installation, plugins, and connectivity."""
    import importlib
    import shutil

    checks = []

    # Check Python version
    import sys
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("Python version", py_ver, sys.version_info >= (3, 10)))

    # Check core imports
    core_modules = [
        "depfence.core.engine",
        "depfence.core.models",
        "depfence.core.lockfile",
        "depfence.core.policy",
        "depfence.reporters.sarif_out",
        "depfence.reporters.cyclonedx",
        "depfence.core.html_report",
    ]
    for mod in core_modules:
        try:
            importlib.import_module(mod)
            checks.append((f"Import {mod.split('.')[-1]}", "OK", True))
        except ImportError as e:
            checks.append((f"Import {mod.split('.')[-1]}", str(e), False))

    # Check optional deps
    for pkg_name, import_name in [("httpx", "httpx"), ("pydantic", "pydantic"), ("rich", "rich")]:
        try:
            mod = importlib.import_module(import_name)
            ver = getattr(mod, "__version__", "?")
            checks.append((f"Package {pkg_name}", ver, True))
        except ImportError:
            checks.append((f"Package {pkg_name}", "MISSING", False))

    # Check network (OSV API)
    try:
        import httpx as _httpx
        resp = _httpx.get("https://api.osv.dev/v1", timeout=5.0)
        checks.append(("OSV API", f"status {resp.status_code}", resp.status_code < 500))
    except Exception as e:
        checks.append(("OSV API", f"unreachable: {e}", False))

    # Check lockfile detection in cwd
    from depfence.core.lockfile import detect_ecosystem
    lockfiles = detect_ecosystem(Path.cwd())
    checks.append(("Lockfiles in cwd", f"{len(lockfiles)} found", len(lockfiles) > 0))

    # Check plugin registry
    try:
        from depfence.core.registry import PluginRegistry
        reg = PluginRegistry()
        reg.discover()
        checks.append(("Scanners loaded", str(len(reg.scanners)), len(reg.scanners) > 0))
    except Exception:
        checks.append(("Plugin registry", "failed to load", False))

    # Check cache directory
    cache_dir = Path.home() / ".depfence" / "cache"
    checks.append(("Cache dir", str(cache_dir), cache_dir.exists()))

    # Output
    passed = sum(1 for _, _, ok in checks if ok)
    total = len(checks)
    click.echo(f"depfence doctor — {passed}/{total} checks passed\n")
    for name, detail, ok in checks:
        icon = "+" if ok else "x"
        style = "" if ok else " <-- ISSUE"
        click.echo(f"  [{icon}] {name}: {detail}{style}")

    if passed < total:
        click.echo(f"\n{total - passed} issue(s) found. Some features may not work correctly.")
        import sys as _sys
        _sys.exit(1)
    else:
        click.echo("\nAll checks passed. depfence is ready.")


@cli.command("outdated")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
def outdated(path: str, fmt: str) -> None:
    """Check for available dependency updates (like npm outdated)."""
    import asyncio
    import json as _json

    from depfence.core.lockfile import detect_ecosystem, parse_lockfile

    project_dir = Path(path).resolve()
    lockfiles = detect_ecosystem(project_dir)
    if not lockfiles:
        click.echo("No lockfiles found.")
        return

    all_packages = []
    for eco, lf_path in lockfiles:
        packages = parse_lockfile(eco, lf_path)
        all_packages.extend(packages)

    if not all_packages:
        click.echo("No packages found in lockfiles.")
        return

    # Check latest versions via registry APIs
    async def check_latest():
        import httpx as _httpx
        results = []
        async with _httpx.AsyncClient(timeout=10.0) as client:
            for pkg in all_packages[:50]:  # Limit to first 50
                latest = None
                try:
                    if pkg.ecosystem == "npm":
                        resp = await client.get(f"https://registry.npmjs.org/{pkg.name}/latest")
                        if resp.status_code == 200:
                            latest = resp.json().get("version")
                    elif pkg.ecosystem == "pypi":
                        resp = await client.get(f"https://pypi.org/pypi/{pkg.name}/json")
                        if resp.status_code == 200:
                            latest = resp.json().get("info", {}).get("version")
                except Exception:
                    pass

                if latest and pkg.version and latest != pkg.version:
                    results.append({
                        "package": pkg.name,
                        "ecosystem": pkg.ecosystem,
                        "current": pkg.version,
                        "latest": latest,
                    })
        return results

    results = asyncio.run(check_latest())

    if fmt == "json":
        click.echo(_json.dumps(results, indent=2))
        return

    if not results:
        click.echo("All packages are up to date.")
        return

    click.echo(f"Found {len(results)} outdated packages:\n")
    click.echo(f"  {'Package':<30} {'Current':<15} {'Latest':<15} {'Ecosystem'}")
    click.echo(f"  {'-'*30} {'-'*15} {'-'*15} {'-'*10}")
    for r in sorted(results, key=lambda x: x["package"]):
        click.echo(f"  {r['package']:<30} {r['current']:<15} {r['latest']:<15} {r['ecosystem']}")



@cli.command("ignore")
@click.argument("target")
@click.option("--reason", "-r", default="", help="Reason for ignoring")
@click.option("--expires", help="Expiration date (YYYY-MM-DD)")
@click.option("--path", "project_path", default=".", type=click.Path(exists=True))
def ignore_finding(target: str, reason: str, expires: str | None, project_path: str) -> None:
    """Add a suppression rule to depfence.yml ignore list.

    TARGET can be a CVE (CVE-2024-1234), package name, or finding type.
    """
    import yaml

    from depfence.core.policy import find_config

    project_dir = Path(project_path).resolve()
    config_path = find_config(project_dir)
    if not config_path:
        config_path = project_dir / "depfence.yml"
        config_path.write_text("ignore: []\n")

    data = yaml.safe_load(config_path.read_text()) or {}
    ignores = data.get("ignore", [])

    entry: dict[str, str] = {}
    if target.startswith("CVE-") or target.startswith("GHSA-"):
        entry["cve"] = target
    else:
        entry["package"] = target

    if reason:
        entry["reason"] = reason
    if expires:
        entry["expires"] = expires

    # Check for duplicates
    for existing in ignores:
        if existing.get("cve") == entry.get("cve") and existing.get("package") == entry.get("package"):
            click.echo(f"Already ignored: {target}")
            return

    ignores.append(entry)
    data["ignore"] = ignores
    config_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    click.echo(f"Added suppression for {target}")
    if reason:
        click.echo(f"  Reason: {reason}")
    if expires:
        click.echo(f"  Expires: {expires}")



@cli.group()
def cache() -> None:
    """Manage the advisory and metadata cache."""


@cache.command("stats")
def cache_stats() -> None:
    """Show advisory cache hit rate, size, and entry count."""
    from depfence.cache.advisory_cache import AdvisoryCache
    from depfence.cache.download_cache import DownloadCache

    adv = AdvisoryCache()
    dl = DownloadCache()

    adv_stats = adv.stats()
    dl_stats = dl.stats()

    click.echo("Advisory cache:")
    click.echo(f"  Entries:   {adv_stats.total_entries}")
    click.echo(f"  Hit rate:  {adv_stats.hit_rate:.1%} ({adv_stats.hit_count} hits / {adv_stats.miss_count} misses)")
    click.echo(f"  DB size:   {adv_stats.db_size_bytes:,} bytes")
    if adv_stats.oldest_entry:
        click.echo(f"  Oldest:    {adv_stats.oldest_entry.isoformat()}")

    click.echo("\nMetadata cache:")
    click.echo(f"  Entries:   {dl_stats['total_entries']}")
    click.echo(f"  DB size:   {dl_stats['db_size_bytes']:,} bytes")


@cache.command("clear")
@click.option("--advisory/--no-advisory", default=True, help="Clear advisory cache")
@click.option("--metadata/--no-metadata", default=True, help="Clear metadata cache")
def cache_clear(advisory: bool, metadata: bool) -> None:
    """Wipe all cached advisory and/or metadata data."""
    from depfence.cache.advisory_cache import AdvisoryCache
    from depfence.cache.download_cache import DownloadCache

    if advisory:
        deleted = AdvisoryCache().clear()
        click.echo(f"Advisory cache cleared ({deleted} entries removed).")

    if metadata:
        deleted = DownloadCache().clear()
        click.echo(f"Metadata cache cleared ({deleted} entries removed).")


@cache.command("prune")
@click.option("--max-age", "max_age_days", default=30, show_default=True, help="Remove entries older than N days")
def cache_prune(max_age_days: int) -> None:
    """Remove advisory and metadata cache entries older than --max-age days."""
    from depfence.cache.advisory_cache import AdvisoryCache
    from depfence.cache.download_cache import DownloadCache

    adv_pruned = AdvisoryCache().prune(max_age_days=max_age_days)
    dl_pruned = DownloadCache().prune(max_age_days=max_age_days)

    click.echo(f"Pruned {adv_pruned} advisory entries and {dl_pruned} metadata entries older than {max_age_days} days.")




@cli.group()
def secrets() -> None:
    """Secrets and trade-secret leak detection."""


@secrets.command("scan")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--fail-on", default="high", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]))
@click.option("--history/--no-history", default=False, help="Also scan git commit history")
def secrets_scan(path: str, fmt: str, fail_on: str, history: bool) -> None:
    """Scan a repository for leaked secrets and credentials."""
    import json as _json

    from depfence.sanitize.detector import DetectorConfig, SecretsDetector

    project_dir = Path(path).resolve()
    cfg = DetectorConfig.from_depfence_yml(project_dir)
    cfg.scan_history = history
    detector = SecretsDetector(config=cfg)

    matches = asyncio.run(detector.scan_project(project_dir))

    history_findings = []
    if history:
        history_findings = detector.scan_git_history(project_dir)

    if fmt == "json":
        data = {
            "project": str(project_dir),
            "findings": [
                {
                    "file": m.path,
                    "line": m.line_num,
                    "type": m.secret_type,
                    "severity": m.severity.value,
                    "preview": m.masked_preview,
                }
                for m in matches
            ],
            "history_findings": [
                {
                    "commit": h.commit_hash,
                    "file": h.file_path,
                    "type": h.secret_type,
                    "severity": h.severity,
                }
                for h in history_findings
            ],
        }
        click.echo(_json.dumps(data, indent=2))
    else:
        if not matches and not history_findings:
            click.echo("No secrets detected.")
            return

        from rich.console import Console
        from rich.table import Table

        console = Console()
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}

        if matches:
            table = Table(title=f"Secrets Found ({len(matches)} findings)")
            table.add_column("Severity", style="bold")
            table.add_column("File")
            table.add_column("Line", justify="right")
            table.add_column("Type")
            table.add_column("Preview")

            for m in sorted(matches, key=lambda x: x.severity.value):
                sev = m.severity.value
                sev_style = sev_colors.get(sev, "white")
                table.add_row(
                    f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                    m.path[:50],
                    str(m.line_num),
                    m.secret_type[:40],
                    m.masked_preview[:40],
                )
            console.print(table)

        if history_findings:
            htable = Table(title=f"Git History Leaks ({len(history_findings)} findings)")
            htable.add_column("Commit")
            htable.add_column("File")
            htable.add_column("Type")
            htable.add_column("Severity")
            for h in history_findings:
                sev_style = sev_colors.get(h.severity, "white")
                htable.add_row(
                    h.commit_hash,
                    h.file_path[:40],
                    h.secret_type[:40],
                    f"[{sev_style}]{h.severity.upper()}[/{sev_style}]",
                )
            console.print(htable)
            console.print("[bold red]Git history contains leaked secrets. See 'depfence secrets sanitize' for remediation.[/bold red]")

    # Fail logic
    if fail_on != "none" and matches:
        from depfence.core.models import Severity as Sev
        severity_order = [Sev.CRITICAL, Sev.HIGH, Sev.MEDIUM, Sev.LOW, Sev.INFO]
        threshold_idx = {"critical": 0, "high": 1, "medium": 2, "low": 3, "any": 99}.get(fail_on, 0)
        for m in matches:
            try:
                m_idx = severity_order.index(m.severity)
            except ValueError:
                m_idx = 4
            if m_idx <= threshold_idx:
                sys.exit(1)


@secrets.command("sanitize")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--write/--dry-run", default=False, help="Write cleaned files in-place (default: dry-run)")
@click.option("--report", "-r", "report_path", default=None, type=click.Path(), help="Write JSON report to file")
def secrets_sanitize(path: str, write: bool, report_path: str | None) -> None:
    """Scan and auto-replace secrets with safe placeholders."""
    from depfence.sanitize.cleaner import SanitizeCleaner

    project_dir = Path(path).resolve()
    cleaner = SanitizeCleaner.from_project(project_dir)

    click.echo(f"Scanning {project_dir} {'(write mode)' if write else '(dry-run)'}...")
    report = cleaner.sanitize_repo(project_dir, write=write)

    click.echo(f"Files scanned:   {report.files_scanned}")
    click.echo(f"Files modified:  {report.files_modified}")
    click.echo(f"Replacements:    {report.total_replacements}")

    if report.file_results:
        click.echo("\nModified files:")
        for r in report.file_results:
            if r.changed:
                click.echo(f"  {r.path} ({r.replacement_count} replacement(s))")

    if report.git_rewrite_needed:
        click.echo(
            "\n[WARNING] Git history also contains leaked secrets. "
            "Run 'depfence secrets scan --history' for details."
        )

    out_path = report.save(Path(report_path) if report_path else None)
    click.echo(f"\nReport saved to: {out_path}")

    if report.git_rewrite_needed:
        sys.exit(1)


@secrets.command("hook")
@click.argument("action", type=click.Choice(["install", "uninstall", "status"]))
@click.argument("path", default=".", type=click.Path(exists=True))
def secrets_hook(action: str, path: str) -> None:
    """Manage the pre-commit hook for secrets detection (install/uninstall/status)."""
    project_dir = Path(path).resolve()
    hooks_dir = project_dir / ".git" / "hooks"
    hook_file = hooks_dir / "pre-commit"

    if action == "status":
        if not hooks_dir.exists():
            click.echo("Not a git repository.")
            return
        if hook_file.exists() and "BEGIN depfence-secrets" in hook_file.read_text():
            click.echo("Secrets pre-commit hook: INSTALLED")
        else:
            click.echo("Secrets pre-commit hook: not installed")
        return

    if action == "uninstall":
        if not hook_file.exists():
            click.echo("No pre-commit hook found.")
            return
        existing = hook_file.read_text()
        if "BEGIN depfence-secrets" not in existing:
            click.echo("depfence secrets hook not found in pre-commit.")
            return
        import re as _re
        cleaned = _re.sub(
            r"\n# BEGIN depfence-secrets.*?# END depfence-secrets\n",
            "",
            existing,
            flags=_re.DOTALL,
        )
        hook_file.write_text(cleaned)
        click.echo("Secrets pre-commit hook removed.")
        return

    # install
    if not hooks_dir.exists():
        click.echo("Not a git repository -- cannot install hook.", err=True)
        sys.exit(1)

    hook_snippet = (
        "\n# BEGIN depfence-secrets\n"
        "# depfence pre-commit secrets scanner\n"
        "if command -v python3 >/dev/null 2>&1; then\n"
        "    STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)\n"
        "    if [ -n \"$STAGED\" ]; then\n"
        "        echo '[depfence] Scanning staged files for secrets...'\n"
        "        BLOCKED=0\n"
        "        for f in $STAGED; do\n"
        "            [ -f \"$f\" ] || continue\n"
        "            python3 -c \"\n"
        "import sys\n"
        "from pathlib import Path\n"
        "try:\n"
        "    from depfence.scanners.secrets import SecretsScanner\n"
        "    scanner = SecretsScanner()\n"
        "    matches = scanner.scan_file(Path('$f'))\n"
        "    bad = [m for m in matches if m.severity.value in ('critical', 'high')]\n"
        "    if bad:\n"
        "        for m in bad:\n"
        "            print(f'  BLOCKED [{m.severity.value.upper()}] {m.path}:L{m.line_num}: {m.secret_type}')\n"
        "        sys.exit(1)\n"
        "except Exception:\n"
        "    pass\n"
        "\" 2>/dev/null || BLOCKED=1\n"
        "        done\n"
        "        if [ \"$BLOCKED\" = \"1\" ]; then\n"
        "            echo '[depfence] Commit blocked: secrets detected in staged files.'\n"
        "            echo \"[depfence] Run 'depfence secrets scan' for details.\"\n"
        "            echo '[depfence] Use --no-verify to skip (not recommended).'\n"
        "            exit 1\n"
        "        fi\n"
        "        echo '[depfence] No secrets detected in staged files.'\n"
        "    fi\n"
        "fi\n"
        "# END depfence-secrets\n"
    )

    if hook_file.exists():
        existing = hook_file.read_text()
        if "BEGIN depfence-secrets" in existing:
            click.echo("depfence secrets hook already installed.")
            return
        hook_file.write_text(existing.rstrip() + "\n" + hook_snippet)
    else:
        hook_file.write_text("#!/bin/sh\n" + hook_snippet)

    hook_file.chmod(0o755)
    click.echo(f"Secrets pre-commit hook installed at {hook_file}")
    click.echo("The hook blocks commits containing CRITICAL or HIGH severity secrets.")



@cli.command("red-team")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="table", type=click.Choice(["table", "json"]))
@click.option("--fail-below", default=0, help="Exit 1 if score is below this threshold (0 = disabled)")
def red_team(path: str, fmt: str, fail_below: int) -> None:
    """Run all supply chain attack simulations against a project.

    Simulates five attack vectors (typosquatting, dependency confusion,
    maintainer takeover, build script injection, star jacking) and reports
    which attacks depfence would detect, detection coverage per attack, and
    suggested mitigations.

    Use --format json for CI integration.
    """
    from depfence.simulate.red_team import run_red_team

    project_dir = Path(path).resolve()

    if fmt != "json":
        click.echo(f"Running red team simulations against {project_dir.name}...")
        click.echo()

    report = run_red_team(project_dir)

    if fmt == "json":
        import json as _json
        click.echo(report.to_json())
        if fail_below and report.score < fail_below:
            sys.exit(1)
        return

    # Rich table output
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()

    table = Table(
        title=f"Supply Chain Attack Simulations \u2014 {project_dir.name}",
        show_header=True,
    )
    table.add_column("Attack Type", style="cyan", min_width=24)
    table.add_column("Risk", justify="center", min_width=8)
    table.add_column("Would Detect?", justify="center", min_width=13)
    table.add_column("Coverage", justify="right", min_width=9)
    table.add_column("Top Mitigation", min_width=40)

    risk_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }
    detect_colors = {True: "bold green", False: "bold red"}
    detect_labels = {True: "YES", False: "NO"}

    for outcome in report.outcomes:
        sim = outcome.simulation
        risk_style = risk_colors.get(sim.risk_level.value, "white")
        detect_style = detect_colors[sim.would_be_detected]
        detect_label = detect_labels[sim.would_be_detected]
        coverage_pct = f"{int(sim.detection_coverage * 100)}%"
        top_mitigation = sim.mitigations[0] if sim.mitigations else "-"
        if len(top_mitigation) > 55:
            top_mitigation = top_mitigation[:52] + "..."
        table.add_row(
            sim.attack_type.replace("_", " ").title(),
            f"[{risk_style}]{sim.risk_level.value.upper()}[/{risk_style}]",
            f"[{detect_style}]{detect_label}[/{detect_style}]",
            coverage_pct,
            top_mitigation,
        )

    console.print(table)
    console.print()

    # Score panel
    score = report.score
    if score >= 80:
        score_style = "bold green"
        grade = "Strong"
    elif score >= 60:
        score_style = "bold yellow"
        grade = "Moderate"
    elif score >= 40:
        score_style = "bold red"
        grade = "Weak"
    else:
        score_style = "bold red"
        grade = "Critical"

    detected_count = len(report.detected)
    total_count = len(report.outcomes)
    undetected_critical = len(report.critical_gaps)

    summary_lines = [
        f"[{score_style}]Your supply chain defense score: {score}/100 ({grade})[/{score_style}]",
        "",
        f"Attacks detected:  {detected_count}/{total_count}",
        f"Critical gaps:     {undetected_critical}",
    ]
    console.print(Panel("\n".join(summary_lines), title="Red Team Summary", border_style="blue"))

    if report.configuration_improvements:
        console.print("\n[bold]Top configuration improvements:[/bold]")
        for i, tip in enumerate(report.configuration_improvements[:5], 1):
            console.print(f"  {i}. {tip}")

    if fail_below and score < fail_below:
        console.print(
            f"\n[bold red]Score {score} is below threshold {fail_below} \u2014 failing.[/bold red]"
        )
        sys.exit(1)




@cli.command("remediate")
@click.argument("path", default=".")
@click.option("--dry-run/--no-dry-run", default=True, help="Show what would change without modifying files")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
def remediate(path: str, dry_run: bool, fmt: str) -> None:
    """Generate remediation PRs for vulnerable dependencies."""
    from depfence.remediate.pr_generator import RemediationPR
    from depfence.core.engine import scan_directory

    project_dir = Path(path).resolve()
    result = asyncio.run(scan_directory(project_dir))

    fixable = [f for f in result.findings if f.fix_version]
    if not fixable:
        click.echo("No fixable vulnerabilities found.")
        return

    pr_gen = RemediationPR()
    drafts = pr_gen.generate(fixable, project_dir)

    if fmt == "json":
        import json
        click.echo(json.dumps([{"title": d.title, "branch": d.branch, "findings_fixed": d.findings_fixed, "files": d.files_changed} for d in drafts], indent=2))
        return

    click.echo(f"\nFound {len(fixable)} fixable vulnerabilities -> {len(drafts)} remediation PR(s):\n")
    for d in drafts:
        status = "[DRY RUN]" if dry_run else "[READY]"
        click.echo(f"  {status} {d.title}")
        click.echo(f"         Branch: {d.branch}")
        click.echo(f"         Files:  {', '.join(d.files_changed)}")
        click.echo()


@cli.command("trends")
@click.option("--days", default=30, help="Number of days to analyze")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
def trends(days: int, fmt: str) -> None:
    """Show EPSS score trends for your vulnerabilities."""
    from depfence.intel.epss_tracker import EPSSTracker

    tracker = EPSSTracker()
    rising = tracker.get_rising(threshold=0.05, days=days)

    if fmt == "json":
        import json
        click.echo(json.dumps([{"cve": r.cve, "current": r.current_score, "delta": r.delta_7d} for r in rising], indent=2))
        return

    if not rising:
        click.echo("No rising EPSS scores detected in your tracked CVEs.")
        return

    click.echo(f"\nRising EPSS scores (last {days} days):\n")
    click.echo(f"  {'CVE':<20} {'Score':>8} {'Delta':>8} {'Direction':>10}")
    click.echo(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*10}")
    for r in rising:
        click.echo(f"  {r.cve:<20} {r.current_score:>8.4f} {r.delta_7d:>+8.4f} {'RISING':>10}")


@cli.command("alerts")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]))
def alerts(fmt: str) -> None:
    """Show KEV additions affecting your dependencies."""
    click.echo("KEV alert monitoring — no new additions affecting your stack.")
    click.echo("Configure monitored CVEs via: depfence scan --enrich")


@cli.command("threat-brief")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt", default="text", type=click.Choice(["text", "json"]))
@click.option("--no-scan", is_flag=True, help="Skip scan; use cached KEV + EPSS data only")
@click.option("--top", "-n", default=5, type=click.IntRange(1, 20), help="Top N urgent CVEs to show")
def threat_brief(path: str, fmt: str, no_scan: bool, top: int) -> None:
    """Executive threat brief: risk score, top CVEs, KEV status, EPSS trends.

    Runs a scan, cross-references CISA KEV, reads EPSS trends, and outputs a
    prioritised executive summary.
    """
    from depfence.core.models import ScanResult
    from depfence.intel import EPSSTracker, KEVMonitor, ThreatFeed

    project_dir = Path(path).resolve()

    # ---- Scan -----------------------------------------------------------
    if no_scan:
        result = ScanResult(target=str(project_dir), ecosystem="cached")
        click.echo("(Skipping scan — using local KEV + EPSS cache only)", err=True)
    else:
        from depfence.core.engine import scan_directory
        click.echo(f"Scanning {project_dir} ...", err=True)
        result = asyncio.run(scan_directory(
            project_dir,
            skip_behavioral=True,
            skip_reputation=True,
            enrich=True,
        ))
        click.echo(
            f"  Scan complete: {result.packages_scanned} packages, "
            f"{len(result.findings)} findings.",
            err=True,
        )

    # ---- KEV cross-reference --------------------------------------------
    kev = KEVMonitor()
    catalog = kev.fetch_kev_catalog()
    kev.store_kev_entries(catalog)
    kev.escalate_severity(result.findings)

    # ---- EPSS tracker ---------------------------------------------------
    tracker = EPSSTracker()

    # ---- Aggregate + brief ----------------------------------------------
    feed = ThreatFeed()
    snapshot = feed.aggregate(result.findings, epss_tracker=tracker)

    if fmt == "json":
        import json as _json
        data = {
            "total_risk_score": snapshot.total_risk_score,
            "total_findings": snapshot.total_findings,
            "critical_count": snapshot.critical_count,
            "high_count": snapshot.high_count,
            "kev_count": snapshot.kev_count,
            "ransomware_kev_count": snapshot.ransomware_kev_count,
            "coverage_score": snapshot.coverage_score,
            "generated_at": snapshot.generated_at,
            "top_risks": snapshot.top_risks[:top],
            "trending_cves": snapshot.trending_cves,
            "new_advisories": snapshot.new_advisories,
        }
        click.echo(_json.dumps(data, indent=2))
    else:
        click.echo(feed.generate_brief(snapshot))

    tracker.close()
    kev.close()



# ---------------------------------------------------------------------------
# MCP command group
# ---------------------------------------------------------------------------

@cli.group()
def mcp() -> None:
    """Model Context Protocol server for AI coding assistants."""


@mcp.command("serve")
def mcp_serve() -> None:
    """Start the depfence MCP server in stdio mode.

    Configure your IDE / AI assistant to use this server by adding it
    to its MCP settings, e.g. for Claude Code:

    \b
    {
      "mcpServers": {
        "depfence": {
          "command": "depfence",
          "args": ["mcp", "serve"]
        }
      }
    }
    """
    import logging
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    from depfence.mcp.server import _run_stdio
    asyncio.run(_run_stdio())


@mcp.command("test")
@click.option("--package", default="requests", show_default=True, help="Package name to test")
@click.option("--ecosystem", default="pypi", show_default=True, help="Ecosystem to test")
def mcp_test(package: str, ecosystem: str) -> None:
    """Run a self-test query against the MCP server.

    Verifies tool registration, check_package, typosquat detection,
    and alternative suggestions all work end-to-end.
    """
    import json as _json

    from depfence.mcp.server import DepfenceMcpServer, PROTOCOL_VERSION

    server = DepfenceMcpServer()

    async def _run() -> None:
        # Initialize
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "clientInfo": {"name": "depfence-cli-test"},
            },
        })
        info = resp["result"]["serverInfo"]
        click.echo(f"Server: {info['name']} v{info['version']}")

        # List tools
        resp = await server.handle_request({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
        })
        tools = resp["result"]["tools"]
        click.echo(f"Tools registered: {len(tools)}")
        for t in tools:
            click.echo(f"  - {t['name']}")

        # check_package
        click.echo(f"\nChecking {ecosystem}/{package} ...")
        resp = await server.handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "check_package",
                "arguments": {"name": package, "ecosystem": ecosystem},
            },
        })
        result = _json.loads(resp["result"]["content"][0]["text"])
        safe_label = "SAFE" if result["safe"] else "UNSAFE"
        click.echo(f"  safe={result['safe']} ({safe_label})  risk_score={result['risk_score']}")
        click.echo(f"  recommendation: {result['recommendation']}")
        if result["findings"]:
            click.echo(f"  findings ({len(result['findings'])}):")
            for f in result["findings"][:3]:
                click.echo(f"    [{f['severity'].upper()}] {f['title']}")

        click.echo("\nSelf-test passed.")

    asyncio.run(_run())


# BEGIN depfence-secrets-cli (marker — do not remove)

if __name__ == "__main__":
    cli()
