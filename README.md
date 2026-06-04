# depfence

Static analysis tool for dependency security. Scans lockfiles, workflow files, Dockerfiles, Terraform configs, and MCP server configurations for supply chain risks — including categories that CVE-based scanners don't cover: prompt injection payloads, typosquatting variants LLMs commonly hallucinate, fabricated version/SHA pins, and CI/CD workflow injection vectors.

[![CI](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/depfence.yml?branch=main&label=CI)](https://github.com/ericrihm/depfence/actions)

```bash
git clone https://github.com/ericrihm/depfence && cd depfence
pip install -e .
depfence scan .
```

Example output:

```
 depfence v0.5.0  scanning 142 packages across 3 lockfiles + 4 workflows

 CRITICAL  .github/workflows/ci   resolve_existence  SHA abc123def... resolves to no real commit (fabricated pin)
 CRITICAL  node_modules/jqwik     prompt_injection   ANSI-hidden instruction override in source
 CRITICAL  pytorch-cuda-nightly   slopsquat          LLM hallucination match for torch (0.94)
 HIGH      lodash 4.17.20         npm_advisory       CVE-2021-23337  EPSS 0.71  KEV
 HIGH      req-utils 1.0.3        preinstall         install script exfiltrates $HOME/.ssh
 HIGH      .github/workflows/ci   ci_ai_bot          untrusted PR input flows to AI triage bot
 MEDIUM    transformers 4.38.0    model_scanner      unsafe torch.load without weights_only
 MEDIUM    @angulr/core           scope_squat        typosquatting @angular/core
 LOW       leftpad 0.0.3          freshness          no release in 847 days

 9 findings  (3 critical, 2 high, 2 medium, 1 low)
```

---

## Architecture

depfence runs a four-stage pipeline:

```
lockfile detection → metadata fetch → scanner execution → enrichment
                                          │
                              ┌───────────┴───────────┐
                     entry-point scanners      project scanners
                     (36, via pip registry)    (6, filesystem-based)
                              │                       │
                     operate on PackageMeta    operate on project dir
                     (name, version, metadata) (walk .github/workflows/,
                                                Dockerfiles, .tf, etc.)
```

1. **Lockfile detection**: auto-discovers `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `uv.lock`, `packages.config`, `Gemfile.lock`, `composer.lock`, `Package.resolved`. Parses each into a `PackageId(name, version, ecosystem)` list.

2. **Metadata fetch**: async batch fetch (20 concurrent) from npm registry, PyPI JSON API, etc. Populates `PackageMeta` with maintainers, download counts, repository URLs, license, install scripts.

3. **Scanner execution**: two scanner types run concurrently via `asyncio.gather`:
   - **Entry-point scanners** (36): loaded via `[project.entry-points."depfence.scanners"]` in any installed package. Each implements `async def scan(self, packages: list[PackageMeta]) -> list[Finding]`. Custom scanners use the same interface.
   - **Project scanners** (6): hardcoded in `engine._run_project_scanners()`. Each implements `async def scan_project(self, project_dir: Path) -> list[Finding]`. These scan files directly — workflow YAML, Dockerfiles, Terraform configs, secrets patterns, and SHA pin resolution.

4. **Enrichment**: EPSS exploit probability, CISA KEV status, and reachability analysis are added to vulnerability findings as metadata. These are not scanners — they augment findings for triage.

After enrichment, inline `depfence:ignore` suppressions and baseline snapshots are applied, and results are rendered in the requested format (table, JSON, SARIF, HTML, CycloneDX, SPDX). Findings from multiple scanners targeting the same package are not deduplicated — each scanner produces independent findings.

**Architectural invariants**: depfence never executes package code during analysis. Source code and lockfiles are processed locally; no source code is transmitted to any external service. Network calls are limited to the endpoints listed in the [Network behavior](#network-behavior) section and can be fully disabled with `--no-fetch`.

Supported ecosystems: npm, PyPI, Cargo, Go, Maven, NuGet, RubyGems, Composer, Swift/SPM, Docker, HuggingFace, MCP, GitHub Actions.

---

## Scanners

37 total: 36 entry-point scanners + 1 project scanner (`resolve_existence`).

### Prompt injection and AI safety

| Scanner | Detection mechanism |
|---------|-------------------|
| `prompt_injection` | 34 compiled regex patterns run against source strings, comments, and docstrings extracted via Python AST. Multi-pass normalization strips hex/unicode/URL encoding and zero-width characters before matching. Scans `node_modules/`, `site-packages/`, and project source. 451 LOC. |
| `git_message` | Pattern matching on commit messages, PR templates, and issue templates for instruction-override payloads targeting AI code review bots |
| `ci_ai_bot` | Detects `${{ github.event.* }}` expressions flowing into `run:` blocks in workflows that invoke AI tools — the [Clinejection](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/) attack pattern |
| `mcp_scanner` | Parses MCP config files (Claude Desktop, Cursor, VS Code, Windsurf, Zed) for tool shadowing, credential leakage, missing TLS, and prompt injection in tool descriptions |
| `mcp_fingerprint` | Schema fingerprinting to detect MCP rug-pull attacks (servers that change tool definitions after initial approval) |

### AI/ML model security

| Scanner | Detection mechanism |
|---------|-------------------|
| `slopsquat` | Composite similarity scoring: Levenshtein distance (threshold ≤2), character confusion matrix (l/1, O/0, rn/m), QWERTY keyboard adjacency, prefix/suffix manipulation, and separator variation against curated lists of popular npm/PyPI packages. Score ≥0.8 triggers a finding. |
| `model_scanner` | AST scan for `torch.load()` without `weights_only=True`, pickle file detection, unverified HuggingFace pulls |
| `model_integrity` | Checksum verification, SafeTensors header validation, file size anomaly detection, prompt injection in model card metadata |
| `ai_vulns` | Pattern detection for LangChain RCE vectors, `trust_remote_code=True`, `eval(response)`, unsafe deserialization |
| `ai_bom` | Inventory generator: catalogues model files (.safetensors, .bin, .pkl, .pt, .onnx, .gguf), MCP configs, and AI framework packages into a structured BOM |
| `docker_layer` | Scans Dockerfile labels, ENV, ARG, entrypoint for prompt injection payloads and metadata exfiltration |

### Supply chain

| Scanner | Detection mechanism |
|---------|-------------------|
| `preinstall` | AST-level analysis of install scripts for pipe-to-shell, credential theft, and exfiltration patterns (Python). Regex-based for npm preinstall/postinstall hooks. |
| `dep_confusion` | Checks for private registry misconfiguration that enables namespace hijacking |
| `scope_squatting` | npm scope typosquatting detection (`@angulr` vs `@angular`) |
| `ownership` | Detects maintainer takeovers and version-order anomalies |
| `provenance` | Flags high-value packages missing SLSA build attestations |
| `provenance_checker` | Verifies SLSA/Sigstore attestation signatures for npm and PyPI packages |
| `behavioral` | Static pattern detection for runtime red flags: `eval`, `exec`, `child_process`, DNS resolve, exfiltration endpoints |
| `obfuscation` | Detects base64-exec, hex encoding, charcode obfuscation, high-entropy strings, ANSI escape content hiding |
| `network` | Flags hardcoded IPs, mining pool domains, webhook exfiltration URLs, DNS tunneling indicators |
| `reputation` | Low-trust heuristics: package age < 30 days, no source repository, single maintainer with no other packages |

### Vulnerabilities

| Scanner | Detection mechanism |
|---------|-------------------|
| `osv` | Queries [OSV.dev](https://osv.dev) for known vulnerabilities across npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` | npm-specific advisories from GitHub Advisory Database |
| `pypi_advisory` | PyPI-specific advisories from GitHub Advisory Database |

### CI/CD and infrastructure

| Scanner | Detection mechanism |
|---------|-------------------|
| `gha_workflow` | Detects `${{ }}` expression injection in `run:` blocks, `pull_request_target` trigger abuse, overly permissive `permissions:` blocks |
| `gha_scanner` | Flags unpinned GitHub Actions (tag refs instead of SHA pins) and actions with known compromised versions |
| `resolve_existence` | Resolves every `uses: owner/repo@<40-hex-sha>` against the GitHub API (`GET /repos/{owner}/{repo}/commits/{sha}`). HTTP 422 = non-existent commit (fabricated pin). HTTP 404 with repo unreachable = flagged separately. Emits INFO `unverified_reference` when API is unreachable rather than silently passing. Project scanner, not entry-point. Disable: `DEPFENCE_RESOLVE_EXISTENCE=0`. |
| `version_existence` | Resolves exact npm/PyPI version pins against registries. npm: checks `version in data['versions']` from full-package GET. PyPI: per-version endpoint 404 AND release-map membership (both must agree). Skips ranges, wildcards, git/url/local refs, dist-tags. Canonical version comparison (`1.0` == `1.0.0` via `packaging.version.Version`). PEP 503 name normalization. Yanked versions are real and not flagged. Disable: `DEPFENCE_VERSION_EXISTENCE=0`. |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG |
| `terraform` | Unpinned modules, HTTP sources, unverified registry namespaces |
| `secrets` | Regex patterns for AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | Correlates CI secret exposure with suspicious package behavior |

### Compliance and hygiene

| Scanner | Detection mechanism |
|---------|-------------------|
| `license_scanner` | SPDX license identification and copyleft compatibility checking |
| `reachability` | AST import tracing to determine which vulnerable packages are actually imported |
| `phantom_deps` | Cross-references declared dependencies against actual imports to find unused packages |
| `freshness` | Flags packages with no release in 2+ years |
| `pinning` | Detects unpinned versions, wildcard ranges, and missing lockfiles |

### Enrichment (not scanners)

These augment vulnerability findings with triage context:

- **EPSS** — FIRST.org Exploit Prediction Scoring System probability, added to every CVE finding
- **CISA KEV** — flags vulnerabilities on the Known Exploited Vulnerabilities catalog
- **Risk scoring** — composite A-F grades from EPSS + KEV + CVSS + reachability + OpenSSF Scorecard
- **SBOM generation** — CycloneDX 1.5 and SPDX 2.3

---

## Fabricated-pin verification

Most pinning linters verify that a SHA string is present in an action reference. The `resolve_existence` scanner additionally verifies that the SHA references an existing commit by querying the GitHub API.

**How it works**: for every `uses: owner/repo@<sha>` in `.github/workflows/*.yml`, the scanner calls `GET /repos/{owner}/{repo}/commits/{sha}` with `GITHUB_TOKEN`. Response codes:

| HTTP status | Interpretation |
|------------|----------------|
| 200 | Valid commit — no finding |
| 422 | Commit does not exist — `CRITICAL fabricated_reference` |
| 404 | Repository not found or inaccessible — `HIGH fabricated_reference` (possible private repo) |
| 401/403/429 | Auth/rate-limit — `INFO unverified_reference` (never false CRITICAL) |

When a fabricated pin carries a `# vX.Y.Z` comment, the scanner resolves the real tag to characterize the fault: if the fabricated SHA shares a long prefix with the tag's real SHA, it's labeled "conflation" (real prefix + hallucinated tail). A valid commit whose tag has moved is NOT flagged — that's normal pin aging, not fabrication.

The `version_existence` scanner applies the same principle to package versions: `requests==99.99.99` is syntactically valid but resolves to nothing on PyPI.

**False positive discipline**: yanked-but-real versions are never flagged. Network/auth failures degrade to INFO, never false CRITICAL. Both scanners gate on `fetch_enabled()` and respect `--no-fetch`.

**Performance**: each pinned SHA requires one GitHub API call. A workflow with 15 pinned actions costs 15 requests. With `GITHUB_TOKEN` (5,000 requests/hour authenticated, 60/hour unauthenticated), this is not a bottleneck for typical projects. The scanner emits INFO-level findings when rate-limited — never false CRITICALs.

---

## Installation

```bash
# PyPI publication pending — install from source
git clone https://github.com/ericrihm/depfence
cd depfence
pip install -e .                      # core
pip install -e ".[ml]"                # with scikit-learn behavioral scoring
```

Once published to PyPI: `pip install depfence` / `pipx install depfence`. See [PUBLISHING.md](PUBLISHING.md).

Python 3.10+. Tested on 3.10, 3.11, 3.12, 3.13. No native dependencies.

---

## Usage

### Core commands

```bash
depfence scan .                  # full scan: all scanners
depfence diff .                  # only packages changed since last scan
depfence audit .                 # advisory-only (skip behavioral/reputation)
depfence check requests -e pypi  # single package check
depfence fix . --apply           # auto-fix vulnerable dependencies
depfence init .                  # generate CI workflow + pre-commit hook + policy config
```

### Targeted scans

```bash
depfence ai-scan .               # prompt injection + slopsquatting + model threats
depfence model-scan .            # ML model file supply chain risks
depfence mcp-scan .              # MCP server configuration audit
depfence mcp-fingerprint .       # MCP rug-pull fingerprinting
depfence gha-scan .              # GitHub Actions: permissions, injection, unpinned actions
depfence scan-docker .           # Dockerfile security audit
depfence scan-workflows .        # workflow security audit
depfence ci-audit .              # CI secret exposure audit
depfence secrets scan .          # secrets scanning
depfence secrets scan . --history  # including git history
```

### SBOM and compliance

```bash
depfence sbom . -o sbom.json                       # CycloneDX 1.5
depfence sbom . --format spdx -o sbom.spdx.json    # SPDX 2.3
depfence sbom-diff before.json after.json           # compare SBOMs
depfence license-scan .                             # license compliance
depfence compliance . -o compliance.html            # full report
```

### Analysis

```bash
depfence risk-score .            # composite A-F risk grades
depfence epss .                  # EPSS exploit probability ranking
depfence kev .                   # CISA Known Exploited Vulnerabilities
depfence scorecard .             # OpenSSF Scorecard integration
depfence graph . -o deps.dot     # dependency graph (Graphviz)
depfence trust lodash npm        # package trust score
depfence why lodash              # dependency path trace
depfence threat-brief .          # threat landscape summary
depfence trends --days 30        # finding trends over time
```

### Operations

```bash
depfence watch . --interval 30   # auto-scan on lockfile change
depfence monorepo-scan .         # multi-workspace scanning
depfence baseline . --create     # snapshot current findings (suppress known issues)
depfence red-team .              # security assessment
depfence remediate .             # remediation suggestions
depfence outdated .              # outdated dependencies
depfence doctor                  # diagnostics
depfence plugins                 # list loaded scanners
```

---

## Output formats

```bash
depfence scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
depfence scan . --format sarif -o results.sarif
depfence scan . --format html -o report.html
```

| Format | Use case |
|--------|----------|
| `table` (default) | Terminal |
| `json` | Scripting, `jq` |
| `html` | Shareable reports |
| `sarif` | GitHub Code Scanning, Azure DevOps, VS Code |
| `cyclonedx` | CycloneDX 1.5 SBOM |
| `spdx` | SPDX 2.3 SBOM |

---

## CI/CD integration

### GitHub Actions

```yaml
# Install via pip (composite action tag not yet published)
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
- run: |
    pip install git+https://github.com/ericrihm/depfence.git
    depfence scan . --format sarif --fail-on high -o depfence-results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: depfence-results.sarif
    category: depfence
```

A composite GitHub Action is defined in [`action.yml`](action.yml). Once a release tag is published, usage simplifies to `uses: ericrihm/depfence@v1`.

<details>
<summary>Full workflow example</summary>

```yaml
name: Dependency Security
on:
  push:
    branches: [main]
    paths: ['**/package-lock.json', '**/requirements.txt', '**/Cargo.lock', '**/go.sum',
            '.github/workflows/*.yml', '.github/workflows/*.yaml']
  pull_request:
    paths: ['**/package-lock.json', '**/requirements.txt', '**/poetry.lock',
            '.github/workflows/*.yml', '.github/workflows/*.yaml']
  schedule:
    - cron: '0 6 * * 1'

jobs:
  depfence:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: |
          pip install git+https://github.com/ericrihm/depfence.git
          depfence scan . --format sarif --fail-on high -o depfence-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: depfence-results.sarif
          category: depfence
```

</details>

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ericrihm/depfence
    rev: main  # pin to a specific commit SHA for reproducibility
    hooks:
      - id: depfence
```

Triggers on lockfile and `.github/workflows/*.yml` changes. Runs resolve-existence and GHA workflow scanners on workflow edits.

### GitLab CI

```yaml
depfence:
  image: python:3.12-slim
  stage: test
  script:
    - pip install git+https://github.com/ericrihm/depfence.git
    - depfence scan . --format json -o depfence.json --fail-on high
  artifacts:
    reports:
      dependency_scanning: depfence.json
    when: always
```

---

## Configuration

`depfence.yml` at project root:

```yaml
scanners:
  exclude: [phantom_deps]
  fail_on: high

rules:
  - name: no-gpl-in-production
    match: { license_category: copyleft }
    action: block

  - name: require-provenance-for-popular
    match: { weekly_downloads_min: 100000, has_provenance: false }
    action: block

  - name: no-install-scripts-npm
    match: { has_install_scripts: true }
    action: block
    ecosystems: [npm]

ignore:
  - id: CVE-2021-23337
    package: lodash
    reason: "not reachable via our import path"
    expires: 2026-12-31
```

Generate a starter config with `depfence init .`.

### Inline suppression

```python
import lodash  # depfence:ignore[CVE-2021-23337] -- not reachable via our import path
```

### Baseline management

```bash
depfence baseline . --create     # snapshot current findings
depfence baseline . --show       # list baselined findings
depfence scan .                  # automatically filters baselined findings
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings above threshold |
| `1` | Findings at or above `--fail-on` severity |
| `2` | Scan error |

---

## Network behavior

All source code and lockfiles are processed locally. No source code is transmitted. Scanners that make network calls:

| Scanner | Endpoint | Data sent | Disable |
|---------|----------|-----------|---------|
| `resolve_existence` | GitHub API | repo owner/name, commit SHA | `DEPFENCE_RESOLVE_EXISTENCE=0` |
| `version_existence` | npm registry, PyPI JSON API | package name, version | `DEPFENCE_VERSION_EXISTENCE=0` |
| `osv` | OSV.dev | package name, version, ecosystem | `--no-advisory` |
| `npm_advisory` | GitHub Advisory DB | package name | `--no-advisory` |
| `pypi_advisory` | GitHub Advisory DB | package name | `--no-advisory` |
| `provenance_checker` | Sigstore/Rekor | package name | `--no-advisory` |

Fully offline: `depfence scan . --no-fetch`.

---

## MCP server

JSON-RPC over stdio, compatible with Claude Desktop, Cursor, VS Code, Windsurf, Zed.

```bash
depfence mcp serve
```

```json
{
  "mcpServers": {
    "depfence": {
      "command": "depfence-mcp",
      "args": []
    }
  }
}
```

| Tool | Description |
|------|-------------|
| `check_package` | Risk score, CVEs, typosquat detection for a single package |
| `scan_project` | Full project scan |
| `is_typosquat` | Typosquat/slopsquat check |
| `get_advisories` | CVE/GHSA advisories |
| `suggest_alternative` | Safer alternative suggestion |
| `check_license` | License compatibility |

---

## Plugin system

Custom scanners are discovered via pip entry points, `DEPFENCE_PLUGIN_PATH`, or `~/.depfence/plugins/`.

```python
from depfence.core.models import Finding, PackageMeta, Severity

class MyScanner:
    name = "my_scanner"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []
```

```toml
[project.entry-points."depfence.scanners"]
my_scanner = "my_package.scanner:MyScanner"
```

Project-level scanners use `async def scan_project(self, project_dir: Path) -> list[Finding]` instead. These are currently registered directly in `engine._run_project_scanners()`.

```bash
depfence plugins   # verify loaded scanners
```

---

## Limitations

- `resolve_existence` and `version_existence` require network access and valid tokens. Without `GITHUB_TOKEN`, GitHub API calls are rate-limited to 60/hour.
- Slopsquatting detection uses curated popular-package lists, not a complete registry mirror. Packages not in the curated list won't be matched.
- Prompt injection patterns are regex-based. Sophisticated obfuscation or novel injection techniques may evade detection.
- EPSS and KEV enrichment require network access to FIRST.org and CISA APIs.
- `reachability` scanner performs static import tracing, not runtime analysis. Dynamic imports (`importlib`, `__import__`) are not resolved.
- Behavioral, reputation, and obfuscation scanners are heuristic-based and will produce false positives. Legitimate use of `eval` (template engines), `child_process` (build tools), and base64 (data encoding) triggers findings. Use `depfence:ignore` or baseline management to suppress known-good patterns.
- All detection is static. depfence does not perform dynamic analysis, sandboxed execution, or runtime monitoring.
- depfence is not yet published on PyPI. Install from source (see [Installation](#installation)).
- The GitHub Action (`action.yml`) exists but has no release tag yet. See [CI/CD integration](#cicd-integration) for current usage.

### False positive expectations

Scanners that verify against authoritative sources (`resolve_existence`, `version_existence`, `osv`, `npm_advisory`, `pypi_advisory`) have zero expected false positives.

Heuristic scanners have non-zero false positive rates:

| Scanner | Common false positive scenario | Suppression |
|---------|-------------------------------|-------------|
| `behavioral` | Legitimate `eval` in template engines, `child_process` in build tools | `depfence:ignore` |
| `obfuscation` | Base64 data URIs, high-entropy generated code | `depfence:ignore` |
| `reputation` | New but legitimate packages from established maintainers | `depfence:ignore` or baseline |
| `slopsquat` | Legitimate packages with names similar to popular ones | `depfence:ignore` |
| `prompt_injection` | Security comments discussing injection attacks | `depfence:ignore` |

---

## When to use something else

- **CVE/advisory scanning only**: Dependabot, Snyk, or Grype have larger advisory databases and broader ecosystem maturity.
- **Runtime behavioral analysis** (sandboxed package execution): depfence is purely static.
- **Container image scanning** (not just Dockerfile linting): Trivy or Grype.
- **SAST** (vulnerabilities in your own source code): semgrep or CodeQL.

depfence covers the gap between these tools: AI-specific supply chain threats, fabricated version/SHA pins, prompt injection in dependencies, and CI/CD workflow security.

---

## Contributing

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

2,200+ tests across 93 test files. Run `ruff check` before opening a PR.

### Project structure

```
depfence/          36K LOC
  cli/             CLI commands (click), 3K LOC
  core/            Engine, lockfile parsing, policy, caching, enrichment
  scanners/        37 scanners (36 entry-point + 1 project scanner)
  reporters/       SARIF, CycloneDX, SPDX, HTML, JSON formatters
  analyzers/       AST analysis, install script analysis
  integrations/    Pre-commit hook, Claude Code PreToolUse hook
  mcp/             MCP server (JSON-RPC over stdio)
```

---

## Security policy

See [SECURITY.md](SECURITY.md) or open a [GitHub security advisory](https://github.com/ericrihm/depfence/security/advisories/new).

---

## License

MIT. See [LICENSE](LICENSE).
