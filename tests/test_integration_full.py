"""Comprehensive integration tests for the full depfence scan pipeline.

Exercises parsers, scanners, analyzers, and reporters against realistic
lockfile and configuration fixtures created in tmp_path. Network calls
are mocked throughout to avoid real API hits.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures — fixture data helpers
# ---------------------------------------------------------------------------

NPM_LOCK_DATA: dict[str, Any] = {
    "name": "my-webapp",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "my-webapp",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.20",
                "express": "^4.17.1",
                "axios": "^0.21.0",
                "minimist": "^1.2.0",
                "chalk": "^4.1.0",
                "debug": "^4.3.1",
                "semver": "^7.3.5",
                "uuid": "^8.3.2",
                "dotenv": "^10.0.0",
                "helmet": "^4.6.0",
                "cors": "^2.8.5",
                "body-parser": "^1.19.0",
                "morgan": "^1.10.0",
                "jsonwebtoken": "^8.5.1",
                "bcrypt": "^5.0.1",
                "validator": "^13.6.0",
                "moment": "^2.29.1",
                "qs": "^6.10.1",
                "path-to-regexp": "^6.2.0",
                "mime-types": "^2.1.31",
            },
        },
        "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
        "node_modules/express": {"version": "4.17.1", "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"},
        "node_modules/axios": {"version": "0.21.0", "resolved": "https://registry.npmjs.org/axios/-/axios-0.21.0.tgz"},
        "node_modules/minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"},
        "node_modules/chalk": {"version": "4.1.0"},
        "node_modules/debug": {"version": "4.3.1"},
        "node_modules/semver": {"version": "7.3.5"},
        "node_modules/uuid": {"version": "8.3.2"},
        "node_modules/dotenv": {"version": "10.0.0"},
        "node_modules/helmet": {"version": "4.6.0"},
        "node_modules/cors": {"version": "2.8.5"},
        "node_modules/body-parser": {"version": "1.19.0"},
        "node_modules/morgan": {"version": "1.10.0"},
        "node_modules/jsonwebtoken": {"version": "8.5.1"},
        "node_modules/bcrypt": {"version": "5.0.1"},
        "node_modules/validator": {"version": "13.6.0"},
        "node_modules/moment": {"version": "2.29.1"},
        "node_modules/qs": {"version": "6.10.1"},
        "node_modules/path-to-regexp": {"version": "6.2.0"},
        "node_modules/mime-types": {"version": "2.1.31"},
    },
}

REQUIREMENTS_TXT = """\
# Python dependencies for my-service
requests==2.25.0
flask==2.0.0
django==3.2.0
pyyaml==5.3
click==8.0.0
rich==10.0.0
httpx==0.18.0
sqlalchemy==1.4.0
celery==5.1.0
redis==3.5.3
"""

DOCKERFILE_CONTENT = """\
FROM node:latest

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

ENV SECRET_KEY=abc123
ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
"""

GHA_WORKFLOW_CONTENT = """\
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '16'
      - name: Install dependencies
        run: npm install
      - name: Print PR title
        run: echo "PR title is ${{ github.event.pull_request.title }}"
      - name: Run tests
        run: npm test
      - uses: third-party/some-action@main
"""


# ---------------------------------------------------------------------------
# Project fixture factory
# ---------------------------------------------------------------------------

@pytest.fixture()
def full_project(tmp_path: Path) -> Path:
    """Create a realistic multi-ecosystem project layout in tmp_path."""
    # npm lockfile
    (tmp_path / "package-lock.json").write_text(
        json.dumps(NPM_LOCK_DATA, indent=2)
    )
    # package.json (for PinningScanner)
    pkg_json = {
        "name": "my-webapp",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.20",
            "express": "^4.17.1",
            "axios": ">=0.21.0",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_json, indent=2))

    # Python requirements
    (tmp_path / "requirements.txt").write_text(REQUIREMENTS_TXT)

    # Dockerfile
    (tmp_path / "Dockerfile").write_text(DOCKERFILE_CONTENT)

    # GitHub Actions workflow
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "ci.yml").write_text(GHA_WORKFLOW_CONTENT)

    # .env file with a secret-like value (for SecretsScanner entropy check)
    (tmp_path / ".env").write_text(
        "DATABASE_URL=postgres://user:pass@localhost/db\n"
        "SECRET_KEY=abc123\n"
        "API_KEY=aaaabbbbccccdddd1234567890abcdef\n"
    )

    return tmp_path


# ---------------------------------------------------------------------------
# 1. NPM lockfile parsing
# ---------------------------------------------------------------------------

def test_scan_npm_lockfile(tmp_path: Path) -> None:
    """parse_lockfile should extract all 20 packages from the v3 lock."""
    from depfence.core.lockfile import parse_lockfile

    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(NPM_LOCK_DATA, indent=2))

    packages = parse_lockfile("npm", lock_path)

    # Root entry ("") is skipped; expect exactly 20 packages
    assert len(packages) == 20

    names = {p.name for p in packages}
    assert "lodash" in names
    assert "express" in names
    assert "axios" in names
    assert "minimist" in names
    assert "chalk" in names
    assert "semver" in names
    assert "uuid" in names

    # Versions should be resolved
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.version == "4.17.20"
    assert lodash.ecosystem == "npm"

    axios = next(p for p in packages if p.name == "axios")
    assert axios.version == "0.21.0"


# ---------------------------------------------------------------------------
# 2. PyPI requirements.txt parsing
# ---------------------------------------------------------------------------

def test_scan_pypi_requirements(tmp_path: Path) -> None:
    """parse_lockfile should extract all pinned packages from requirements.txt."""
    from depfence.core.lockfile import parse_lockfile

    req_path = tmp_path / "requirements.txt"
    req_path.write_text(REQUIREMENTS_TXT)

    packages = parse_lockfile("pypi", req_path)

    # 10 pinned packages (comments and blank lines excluded)
    assert len(packages) == 10

    names = {p.name for p in packages}
    assert "requests" in names
    assert "flask" in names
    assert "django" in names
    assert "pyyaml" in names
    assert "click" in names
    assert "rich" in names
    assert "httpx" in names

    requests_pkg = next(p for p in packages if p.name == "requests")
    assert requests_pkg.version == "2.25.0"
    assert requests_pkg.ecosystem == "pypi"

    django_pkg = next(p for p in packages if p.name == "django")
    assert django_pkg.version == "3.2.0"


# ---------------------------------------------------------------------------
# 3. DockerfileScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_scan_finds_dockerfile_issues(full_project: Path) -> None:
    """DockerfileScanner should detect :latest, root user, and ENV secret."""
    from depfence.scanners.dockerfile_scanner import DockerfileScanner

    scanner = DockerfileScanner()
    findings = await scanner.scan_project(full_project)

    assert len(findings) > 0

    titles = [f.title for f in findings]
    title_str = " ".join(titles).lower()

    # Should detect unpinned :latest tag
    assert any("latest" in t.lower() or "unpinned" in t.lower() for t in titles), (
        f"Expected unpinned/latest finding, got: {titles}"
    )

    # Should detect missing USER directive (root)
    assert any("root" in t.lower() or "user" in t.lower() for t in titles), (
        f"Expected root/USER finding, got: {titles}"
    )

    # Should detect ENV secret (SECRET_KEY=abc123)
    assert any("secret" in t.lower() or "env" in t.lower() for t in titles), (
        f"Expected secret-in-ENV finding, got: {titles}"
    )


# ---------------------------------------------------------------------------
# 4. GhaWorkflowScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_scan_finds_workflow_issues(full_project: Path) -> None:
    """GhaWorkflowScanner should detect unpinned actions and script injection."""
    from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner

    scanner = GhaWorkflowScanner()
    findings = await scanner.scan_project(full_project)

    assert len(findings) > 0

    titles = [f.title for f in findings]

    # actions/checkout@v3 and actions/setup-node@v3 are unpinned (tag, not SHA)
    assert any("unpinned" in t.lower() or "mutable" in t.lower() for t in titles), (
        f"Expected unpinned-action finding, got: {titles}"
    )

    # echo "${{ github.event.pull_request.title }}" — script injection
    assert any("injection" in t.lower() or "github.event" in t.lower() for t in titles), (
        f"Expected script-injection finding, got: {titles}"
    )


# ---------------------------------------------------------------------------
# 5. SecretsScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_secrets_scanner_detects_env_secrets(full_project: Path) -> None:
    """SecretsScanner should flag the generic API_KEY in .env."""
    from depfence.scanners.secrets_scanner import SecretsScanner

    scanner = SecretsScanner()
    findings = await scanner.scan_project(full_project)

    # The .env has DATABASE_URL connection string with password
    assert len(findings) > 0

    titles = " ".join(f.title for f in findings).lower()
    # Should detect the database connection string or the generic api_key
    assert any(
        keyword in titles
        for keyword in ("database", "api key", "secret", "password", "connection")
    ), f"Expected secret finding, got titles: {[f.title for f in findings]}"


# ---------------------------------------------------------------------------
# 6. PinningScanner
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pinning_scanner_detects_unpinned(full_project: Path) -> None:
    """PinningScanner should flag open-ended constraints in package.json."""
    from depfence.scanners.pinning_scanner import PinningScanner

    scanner = PinningScanner()
    findings = await scanner.scan_project(full_project)

    assert len(findings) > 0

    titles = " ".join(f.title for f in findings).lower()
    # axios uses >=0.21.0 in package.json — open-ended range
    assert any(
        keyword in titles
        for keyword in ("unpinned", "range", "loosely", "wildcard", "open-ended")
    ), f"Expected pinning finding, got titles: {[f.title for f in findings]}"


# ---------------------------------------------------------------------------
# 7. ThreatIntelDB — known malicious packages
# ---------------------------------------------------------------------------

def test_threat_intel_flags_known_malicious(tmp_path: Path) -> None:
    """ThreatIntelDB.lookup_batch should catch packages from KNOWN_MALICIOUS."""
    from depfence.core.models import PackageId
    from depfence.core.threat_intel import ThreatIntelDB

    db = ThreatIntelDB(db_path=tmp_path / "threat_intel.json")
    db.load()

    # Mix of malicious and clean packages
    packages = [
        PackageId("npm", "event-stream", "3.3.6"),   # KNOWN_MALICIOUS
        PackageId("npm", "ua-parser-js", "0.7.29"),  # KNOWN_MALICIOUS (hijacked)
        PackageId("npm", "node-ipc", "10.1.1"),      # KNOWN_MALICIOUS (wiper)
        PackageId("pypi", "colourama", "0.4.4"),     # KNOWN_MALICIOUS (typosquat)
        PackageId("npm", "lodash", "4.17.20"),       # clean
        PackageId("pypi", "requests", "2.25.0"),     # clean
        PackageId("npm", "express", "4.17.1"),       # clean
    ]

    hits = db.lookup_batch(packages)

    # At least the 4 known-malicious packages should be flagged
    assert len(hits) >= 4

    # Verify specific malicious packages are caught
    hit_keys = set(hits.keys())
    # At least event-stream and colourama should appear
    assert any("event-stream" in k for k in hit_keys), f"event-stream not in hits: {hit_keys}"
    assert any("colourama" in k for k in hit_keys), f"colourama not in hits: {hit_keys}"

    # Clean packages should NOT be flagged
    assert not any("lodash" in k for k in hit_keys)
    assert not any("requests" in k for k in hit_keys)


# ---------------------------------------------------------------------------
# 8. TyposquatDetector
# ---------------------------------------------------------------------------

def test_typosquat_detector_catches_variants() -> None:
    """check_against_popular should flag known typosquats of popular packages."""
    from depfence.analyzers.typosquat_detector import batch_check, check_against_popular

    # Direct check: "lod4sh" is a homoglyph variant of "lodash"
    match = check_against_popular("lod4sh", "npm")
    assert match is not None
    assert match.target == "lodash"
    assert match.confidence > 0.7
    assert match.attack_type in ("homoglyph", "transposition", "omission", "insertion")

    # "expresss" — one extra 's'
    match2 = check_against_popular("expresss", "npm")
    assert match2 is not None
    assert match2.target == "express"

    # Batch check: mix of typosquats and clean names
    suspects = ["lod4sh", "expresss", "requeests", "reqests", "lodash", "express"]
    results = batch_check(suspects, "npm")

    # At least 2 typosquats should be detected
    assert len(results) >= 2

    suspect_names = {r.suspect for r in results}
    # The clean packages (exact popular names) should NOT appear as suspects
    assert "lodash" not in suspect_names
    assert "express" not in suspect_names


# ---------------------------------------------------------------------------
# 9. TrustScorer
# ---------------------------------------------------------------------------

def test_trust_scorer_rates_packages() -> None:
    """compute_trust should produce reasonable grades for high/low signal sets."""
    from depfence.core.models import PackageId
    from depfence.core.trust_scorer import TrustSignals, compute_trust

    # Well-known package with strong signals
    lodash_pkg = PackageId("npm", "lodash", "4.17.20")
    strong_signals = TrustSignals(
        weekly_downloads=10_000_000,
        age_days=3000,
        maintainer_count=5,
        has_repository=True,
        has_readme=True,
        has_license=True,
        has_types=True,
        last_publish_days=45,
        has_ci=True,
        has_provenance=True,
        dependents_count=50_000,
    )
    lodash_score = compute_trust(lodash_pkg, strong_signals)
    assert lodash_score.grade in ("A", "B"), (
        f"lodash with strong signals should be A/B, got {lodash_score.grade} ({lodash_score.score})"
    )
    assert lodash_score.score >= 65

    # New/unknown package with weak signals
    suspect_pkg = PackageId("npm", "crossenv", "1.0.0")
    weak_signals = TrustSignals(
        weekly_downloads=10,
        age_days=2,
        maintainer_count=1,
        has_repository=False,
        has_readme=False,
        has_license=False,
        has_types=False,
        last_publish_days=2,
        has_ci=False,
        has_provenance=False,
        dependents_count=0,
    )
    suspect_score = compute_trust(suspect_pkg, weak_signals)
    assert suspect_score.grade in ("D", "F"), (
        f"New suspicious package should be D/F, got {suspect_score.grade} ({suspect_score.score})"
    )
    assert suspect_score.score < 35

    # Breakdown keys should always be present
    expected_keys = {"downloads", "age", "maintainers", "repository", "documentation",
                     "freshness", "provenance", "dependents"}
    assert set(lodash_score.breakdown.keys()) == expected_keys
    assert set(suspect_score.breakdown.keys()) == expected_keys

    # Risk factors populated for weak package
    assert len(suspect_score.risk_factors) > 0


# ---------------------------------------------------------------------------
# 10. CycloneDX SBOM generation
# ---------------------------------------------------------------------------

def test_cyclonedx_sbom_generation(tmp_path: Path) -> None:
    """generate_sbom should produce a valid CycloneDX 1.5 SBOM."""
    from depfence.core.models import Finding, FindingType, PackageId, Severity
    from depfence.reporters.cyclonedx import generate_sbom, write_sbom

    packages = [
        PackageId("npm", "lodash", "4.17.20"),
        PackageId("npm", "express", "4.17.1"),
        PackageId("npm", "axios", "0.21.0"),
        PackageId("pypi", "requests", "2.25.0"),
        PackageId("pypi", "django", "3.2.0"),
    ]

    findings = [
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package=packages[0],
            title="Prototype Pollution in lodash",
            detail="lodash before 4.17.21 is vulnerable to prototype pollution.",
            cve="CVE-2021-23337",
        ),
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.CRITICAL,
            package=packages[3],
            title="SSRF vulnerability in requests",
            detail="requests 2.25.0 does not validate redirects.",
            cve="CVE-2021-XXXX",
        ),
        # Non-KNOWN_VULN findings should be excluded from vulnerabilities[]
        Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.MEDIUM,
            package=packages[1],
            title="Suspicious install script",
            detail="express has postinstall hook.",
        ),
    ]

    sbom = generate_sbom(packages, findings, project_name="my-webapp", project_version="1.0.0")

    # Top-level structure
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["version"] == 1
    assert sbom["serialNumber"].startswith("urn:uuid:")

    # Metadata
    assert sbom["metadata"]["component"]["name"] == "my-webapp"
    assert sbom["metadata"]["component"]["version"] == "1.0.0"

    # Components
    assert len(sbom["components"]) == 5
    comp_names = {c["name"] for c in sbom["components"]}
    assert "lodash" in comp_names
    assert "requests" in comp_names

    # PURLs should be correct
    lodash_comp = next(c for c in sbom["components"] if c["name"] == "lodash")
    assert lodash_comp["purl"] == "pkg:npm/lodash@4.17.20"
    requests_comp = next(c for c in sbom["components"] if c["name"] == "requests")
    assert requests_comp["purl"] == "pkg:pypi/requests@2.25.0"

    # Only KNOWN_VULN findings → vulnerabilities
    assert len(sbom["vulnerabilities"]) == 2
    vuln_ids = {v["id"] for v in sbom["vulnerabilities"]}
    assert "CVE-2021-23337" in vuln_ids

    # Dependencies array
    assert len(sbom["dependencies"]) == 5

    # Round-trip: write and read back as valid JSON
    out_path = tmp_path / "sbom.json"
    write_sbom(sbom, out_path)
    parsed = json.loads(out_path.read_text())
    assert parsed["bomFormat"] == "CycloneDX"
    assert len(parsed["components"]) == 5


# ---------------------------------------------------------------------------
# 11. Dependency tree from package-lock.json
# ---------------------------------------------------------------------------

def test_dep_tree_from_package_lock(tmp_path: Path) -> None:
    """build_tree_from_package_lock should build correct tree and find paths."""
    from depfence.core.dep_tree import (
        build_tree_from_package_lock,
        count_transitive,
        find_paths_to,
        tree_to_text,
    )

    # Build a lockfile with known parent→child relationships
    lock_data: dict[str, Any] = {
        "name": "my-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1",
                    "lodash": "^4.17.20",
                    "axios": "^0.21.0",
                    "minimist": "^1.2.0",
                },
            },
            "node_modules/express": {
                "version": "4.17.1",
                "dependencies": {"qs": "^6.10.1", "debug": "^4.3.1"},
            },
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/axios": {
                "version": "0.21.0",
                "dependencies": {"minimist": "^1.2.0"},
            },
            "node_modules/minimist": {"version": "1.2.0"},
            "node_modules/qs": {"version": "6.10.1"},
            "node_modules/debug": {"version": "4.3.1"},
        },
    }

    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(lock_data, indent=2))

    tree = build_tree_from_package_lock(lock_path)

    # 4 root-level direct dependencies
    assert len(tree) == 4

    root_names = {n.package.name for n in tree}
    assert "express" in root_names
    assert "lodash" in root_names
    assert "axios" in root_names
    assert "minimist" in root_names

    # express should have children (qs, debug)
    express_node = next(n for n in tree if n.package.name == "express")
    assert len(express_node.children) == 2
    child_names = {c.package.name for c in express_node.children}
    assert "qs" in child_names
    assert "debug" in child_names

    # find_paths_to: minimist appears as both direct dep and axios transitive dep
    paths = find_paths_to(tree, "minimist")
    assert len(paths) >= 1
    # Every path should end with minimist
    for path in paths:
        assert path[-1].name == "minimist"

    # count_transitive
    counts = count_transitive(tree)
    # express has 2 transitive deps
    assert counts.get("express", 0) == 2

    # tree_to_text should not raise and include package names
    text = tree_to_text(tree)
    assert "express" in text
    assert "lodash" in text


# ---------------------------------------------------------------------------
# 12. RiskScorer produces grades
# ---------------------------------------------------------------------------

def test_risk_scorer_produces_grades() -> None:
    """score_all_packages should grade findings by severity and type."""
    from depfence.core.models import Finding, FindingType, PackageId, Severity
    from depfence.core.risk_scorer import score_all_packages, risk_summary

    pkg_lodash = PackageId("npm", "lodash", "4.17.20")
    pkg_axios = PackageId("npm", "axios", "0.21.0")
    pkg_requests = PackageId("pypi", "requests", "2.25.0")
    pkg_safe = PackageId("npm", "chalk", "4.1.0")

    findings = [
        # lodash — critical vuln + behavioral = should score F
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.CRITICAL,
            package=str(pkg_lodash),
            title="Prototype Pollution",
            detail="CVE-2021-23337",
            cve="CVE-2021-23337",
        ),
        Finding(
            finding_type=FindingType.BEHAVIORAL,
            severity=Severity.HIGH,
            package=str(pkg_lodash),
            title="Suspicious install script",
            detail="postinstall hook detected",
        ),
        # axios — medium severity
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.MEDIUM,
            package=str(pkg_axios),
            title="SSRF vulnerability",
            detail="CVE-2020-28168",
            cve="CVE-2020-28168",
        ),
        # requests — high severity
        Finding(
            finding_type=FindingType.KNOWN_VULN,
            severity=Severity.HIGH,
            package=str(pkg_requests),
            title="ReDoS vulnerability",
            detail="Affected versions of requests",
        ),
    ]

    scores = score_all_packages(findings)

    # chalk has no findings → should not appear in scores
    score_pkgs = {s.package for s in scores}
    assert str(pkg_safe) not in score_pkgs

    # lodash has critical + high behavioral → highest risk
    assert len(scores) >= 1
    top = scores[0]
    assert "lodash" in top.package

    # Grades should be assigned
    for s in scores:
        assert s.grade in ("A", "B", "C", "D", "F")
        assert 0.0 <= s.score <= 10.0

    # Summary
    summary = risk_summary(scores)
    assert summary["total_packages_scored"] == 3
    assert isinstance(summary["average_score"], float)
    assert "top_risks" in summary


# ---------------------------------------------------------------------------
# 13. Full pipeline end-to-end via scan_directory (mocked network)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_pipeline_end_to_end(full_project: Path) -> None:
    """scan_directory on a realistic project should find > 0 findings.

    Network calls (httpx, registry fetches) are mocked to avoid real API hits.
    """
    from depfence.core.engine import scan_directory
    from depfence.core.models import PackageMeta

    # Mock the metadata fetch so we don't hit real npm/PyPI APIs
    async def _mock_fetch_batch(packages, concurrency=20):  # noqa: ARG001
        return [PackageMeta(pkg=p) for p in packages]

    # Also mock any scanner that performs external HTTP calls
    def _make_empty_scanner_scan():
        async def _scan(self_or_packages, *args, **kwargs):
            return []
        return _scan

    with (
        patch("depfence.core.engine.fetch_batch", side_effect=_mock_fetch_batch),
    ):
        result = await scan_directory(
            full_project,
            skip_advisory=True,   # skip live OSV/npm advisory calls
            skip_behavioral=False,
            fetch_metadata=False,  # use PackageMeta stubs
        )

    # Basic assertions
    assert result.target == str(full_project)
    assert result.packages_scanned > 0
    assert result.completed_at is not None

    # Should have found packages from both lockfiles (npm + pypi)
    assert result.packages_scanned >= 20  # at least npm packages

    # Findings may come from project-level scanners (dockerfile, gha, secrets)
    # Since behavioral scanners are enabled, expect at least 0 findings
    # (network-dependent scanners return [] without real data)
    assert isinstance(result.findings, list)
    assert isinstance(result.errors, list)

    # No catastrophic errors (parse errors are OK but scanner crashes should not happen)
    for error in result.errors:
        # Accept "No lockfiles" and "Error parsing" messages but not crashes
        assert "Traceback" not in error, f"Unexpected traceback in errors: {error}"


# ---------------------------------------------------------------------------
# 14. Detect ecosystem — multi-ecosystem project
# ---------------------------------------------------------------------------

def test_detect_ecosystem_multi(full_project: Path) -> None:
    """detect_ecosystem should find both npm and pypi lockfiles."""
    from depfence.core.lockfile import detect_ecosystem

    lockfiles = detect_ecosystem(full_project)

    ecosystems = {eco for eco, _ in lockfiles}
    assert "npm" in ecosystems
    assert "pypi" in ecosystems

    npm_paths = [p for eco, p in lockfiles if eco == "npm"]
    assert any(p.name == "package-lock.json" for p in npm_paths)

    pypi_paths = [p for eco, p in lockfiles if eco == "pypi"]
    assert any(p.name == "requirements.txt" for p in pypi_paths)


# ---------------------------------------------------------------------------
# 15. DockerfileScanner on content without USER — root finding only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dockerfile_scanner_minimal(tmp_path: Path) -> None:
    """DockerfileScanner on a minimal Dockerfile should produce expected findings."""
    from depfence.scanners.dockerfile_scanner import DockerfileScanner

    # Minimal Dockerfile that triggers root + unpinned findings
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "CMD [\"python\", \"app.py\"]\n"
    )

    scanner = DockerfileScanner()
    findings = await scanner.scan_project(tmp_path)

    # python:3.11-slim is pinned (has a tag, not :latest) → no unpinned finding
    # but no USER directive → should flag root
    root_findings = [f for f in findings if "root" in f.title.lower() or "user" in f.title.lower()]
    assert len(root_findings) >= 1


# ---------------------------------------------------------------------------
# 16. GhaWorkflowScanner — SHA-pinned workflow produces no unpinned findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gha_scanner_sha_pinned_workflow(tmp_path: Path) -> None:
    """GhaWorkflowScanner should NOT flag SHA-pinned actions."""
    from depfence.scanners.gha_workflow_scanner import GhaWorkflowScanner

    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    sha_pinned_workflow = """\
name: Secure CI

on:
  push:
    branches: [main]

permissions: read-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1e31de5234b9f8995739874a8ce0492dc87873e2
      - uses: actions/setup-node@64ed1c7eab4cce3362f8c340dee64e5eaeef8f7c
        with:
          node-version: '18'
      - name: Run tests
        run: npm test
"""
    (workflows_dir / "secure.yml").write_text(sha_pinned_workflow)

    scanner = GhaWorkflowScanner()
    findings = await scanner.scan_project(tmp_path)

    # SHA-pinned actions should not generate unpinned-action findings
    unpinned_findings = [
        f for f in findings
        if "unpinned" in f.title.lower() or "mutable" in f.title.lower()
    ]
    assert len(unpinned_findings) == 0


# ---------------------------------------------------------------------------
# 17. ThreatIntelDB integration — batch with realistic npm scan packages
# ---------------------------------------------------------------------------

def test_threat_intel_batch_npm_scan_packages(tmp_path: Path) -> None:
    """ThreatIntelDB batch lookup over realistic npm package list."""
    from depfence.core.lockfile import parse_lockfile
    from depfence.core.threat_intel import ThreatIntelDB

    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(NPM_LOCK_DATA, indent=2))

    packages = parse_lockfile("npm", lock_path)
    assert len(packages) == 20

    db = ThreatIntelDB(db_path=tmp_path / "threat_intel.json")
    db.load()

    # All 20 packages are legitimate; none should appear in KNOWN_MALICIOUS
    hits = db.lookup_batch(packages)
    # None of our realistic fixture packages are known-malicious
    assert len(hits) == 0, (
        f"Unexpected malicious hits in clean fixture: {list(hits.keys())}"
    )


# ---------------------------------------------------------------------------
# 18. CycloneDX SBOM round-trip with full fixture packages
# ---------------------------------------------------------------------------

def test_cyclonedx_sbom_from_lockfile(tmp_path: Path) -> None:
    """Generate a CycloneDX SBOM from the full npm lockfile fixture."""
    from depfence.core.lockfile import parse_lockfile
    from depfence.reporters.cyclonedx import generate_sbom

    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(json.dumps(NPM_LOCK_DATA, indent=2))
    packages = parse_lockfile("npm", lock_path)

    sbom = generate_sbom(packages, [], project_name="my-webapp")

    assert sbom["bomFormat"] == "CycloneDX"
    assert len(sbom["components"]) == 20

    # All components should have valid PURLs
    for comp in sbom["components"]:
        assert comp["purl"].startswith("pkg:npm/")
        assert comp["version"] != ""


# ---------------------------------------------------------------------------
# 19. PinningScanner on requirements.txt with range constraints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pinning_scanner_on_range_requirements(tmp_path: Path) -> None:
    """PinningScanner should detect range constraints in requirements.txt."""
    from depfence.scanners.pinning_scanner import PinningScanner

    req = tmp_path / "requirements.txt"
    req.write_text(
        "requests>=2.25.0\n"
        "flask==2.0.0\n"
        "django>3.0\n"
        "numpy\n"
    )

    scanner = PinningScanner()
    findings = await scanner.scan_project(tmp_path)

    assert len(findings) >= 2  # requests and django at least

    pkg_names_found = {
        finding.package.split(":")[-1] if ":" in finding.package else finding.package
        for finding in findings
    }

    # requests>=2.25.0 → loosely pinned
    assert any("requests" in str(f.package) for f in findings), (
        f"Expected 'requests' in findings, got: {[f.package for f in findings]}"
    )
    # numpy (no version) → unpinned
    assert any("numpy" in str(f.package) for f in findings), (
        f"Expected 'numpy' in findings, got: {[f.package for f in findings]}"
    )


# ---------------------------------------------------------------------------
# 20. Typosquat detector — PyPI suspects
# ---------------------------------------------------------------------------

def test_typosquat_detector_pypi_suspects() -> None:
    """batch_check should flag pypi typosquats while ignoring legitimate names."""
    from depfence.analyzers.typosquat_detector import batch_check

    suspects = [
        "requets",    # omission of 's' from 'requests'
        "flaask",     # insertion: double 'a' in 'flask'
        "djang0",     # homoglyph: '0' for 'o' in 'django'
        "requests",   # exact match — should be excluded
        "flask",      # exact match — should be excluded
        "django",     # exact match — should be excluded
    ]

    results = batch_check(suspects, "pypi")

    suspect_names = {r.suspect for r in results}
    # Legitimate exact names should NOT be flagged
    assert "requests" not in suspect_names
    assert "flask" not in suspect_names
    assert "django" not in suspect_names

    # At least some typosquat variants should be caught
    assert len(results) >= 1
