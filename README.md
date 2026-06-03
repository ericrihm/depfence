# depfence

**Dependency security for the AI age.** 40+ scanners detect what Snyk, Dependabot, and Trivy miss -- prompt injection payloads, slopsquatting, MCP misconfigs, CI/CD bot abuse, and model supply chain attacks. One command. Zero config.

[![CI](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/depfence.yml?branch=main&label=CI)](https://github.com/ericrihm/depfence/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)

```bash
pip install depfence
depfence scan .
```

```
 depfence v0.5.0  scanning 142 packages across 3 lockfiles

 CRITICAL  node_modules/jqwik     prompt_injection  ANSI-hidden instruction override in source
 CRITICAL  pytorch-cuda-nightly   slopsquat         LLM hallucination match for torch (0.94)
 HIGH      lodash 4.17.20         npm_advisory      CVE-2021-23337  EPSS 0.71  KEV
 HIGH      req-utils 1.0.3        preinstall        install script exfiltrates $HOME/.ssh
 HIGH      .github/workflows/ci   ci_ai_bot         untrusted input to AI triage bot
 MEDIUM    transformers 4.38.0    model_scanner     unsafe torch.load without weights_only
 MEDIUM    @angulr/core           scope_squat       typosquatting @angular/core
 LOW       leftpad 0.0.3          freshness         no release in 847 days

 8 findings  (2 critical, 3 high, 2 medium, 1 low)
```

---

## Why depfence exists

Traditional dependency scanners check CVEs and stop. That was fine in 2020. Today, your dependencies are consumed by AI coding assistants, your CI pipelines run AI triage bots, and attackers have adapted:

- **Prompt injection in packages** -- malicious instructions hidden via ANSI escapes, zero-width Unicode, or bidi overrides that are invisible to human reviewers but executed by AI coding tools
- **Slopsquatting** -- attackers register package names that LLMs frequently hallucinate (`python-dateutil` vs `py-dateutil`), then serve malware to anyone who installs the AI's suggestion
- **MCP server attacks** -- tool shadowing, rug-pull schemas, credential leakage, and prompt injection in MCP tool descriptions
- **CI/CD bot abuse** -- [Clinejection](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)-class attacks where AI review bots in GitHub Actions consume untrusted issue/PR input
- **Model supply chain** -- pickle deserialization RCE, unsafe `torch.load`, malicious model card metadata on HuggingFace

depfence catches all of these alongside traditional CVE/advisory scanning.

---

## What depfence catches that others don't

| Threat | depfence | Snyk | Dependabot | Trivy | osv-scanner |
|--------|:--------:|:----:|:----------:|:-----:|:-----------:|
| Known CVEs (OSV/GHSA) | Yes | Yes | Yes | Yes | Yes |
| EPSS exploit probability | Yes | Partial | -- | -- | -- |
| CISA KEV flagging | Yes | Yes | -- | -- | -- |
| Prompt injection in source | **Yes** | -- | -- | -- | -- |
| ANSI/Unicode content hiding | **Yes** | -- | -- | -- | -- |
| Slopsquatting detection | **Yes** | -- | -- | -- | -- |
| MCP server misconfig audit | **Yes** | -- | -- | -- | -- |
| MCP rug-pull fingerprinting | **Yes** | -- | -- | -- | -- |
| CI/CD AI bot abuse | **Yes** | -- | -- | -- | -- |
| Git message injection | **Yes** | -- | -- | -- | -- |
| Install script exfiltration | **Yes** | -- | -- | Partial | -- |
| Dependency confusion | **Yes** | Yes | -- | -- | -- |
| Model supply chain (pickle/torch) | **Yes** | -- | -- | -- | -- |
| AI Bill of Materials | **Yes** | -- | -- | -- | -- |
| Unpinned GitHub Actions (SHA) | **Yes** | -- | Yes | -- | -- |
| GHA permissions audit | **Yes** | -- | -- | -- | -- |
| Docker layer injection | **Yes** | -- | -- | Partial | -- |
| Terraform module pinning | **Yes** | -- | -- | Yes | -- |
| Policy-as-code (block/warn rules) | **Yes** | Yes | -- | Yes | -- |
| CycloneDX SBOM | Yes | Yes | -- | Yes | -- |
| SPDX SBOM | Yes | -- | -- | Yes | -- |
| SARIF output | Yes | Yes | -- | Yes | Yes |

---

## Scanners

### Prompt injection and AI safety

Catches attacks targeting AI coding assistants, code review bots, and MCP tool consumers.

| Scanner | What it detects |
|---------|-----------------|
| `prompt_injection` | Adversarial LLM instructions in source: comments, docstrings, strings, README, build scripts, `package.json` fields. 25 patterns with multi-pass encoding normalization. Detects ANSI escapes, zero-width Unicode, bidi overrides, and homoglyphs. |
| `git_message` | Injection in commit messages and PR/issue templates targeting AI code review bots |
| `ci_ai_bot` | Clinejection-class attacks: AI bots in CI/CD consuming untrusted `${{ github.event }}` input |
| `mcp_scanner` | MCP server misconfigs: tool shadowing, rug-pull, credential leakage, prompt injection, TLS, version pinning. Offline analysis covering Claude Desktop, Cursor, VS Code, Windsurf, and Zed configs |
| `mcp_fingerprint` | MCP rug-pull detection via schema fingerprinting and parameter injection |

### AI/ML model security

| Scanner | What it detects |
|---------|-----------------|
| `slopsquat` | LLM-hallucinated package names registered by attackers |
| `model_scanner` | Unsafe `torch.load`, pickle files, unverified HuggingFace pulls |
| `model_integrity` | Checksum verification, SafeTensors header validation, size anomaly, prompt injection in model metadata |
| `ai_vulns` | LangChain RCE, unsafe deserialization, `trust_remote_code`, `eval(response)` |
| `ai_bom` | AI Bill of Materials: inventories models, MCP servers, and AI frameworks with risk scoring |
| `docker_layer` | Prompt injection in Dockerfile labels, ENV, ARG, entrypoint, and local image metadata |

### Supply chain attacks

| Scanner | What it detects |
|---------|-----------------|
| `preinstall` | Install scripts: pipe-to-shell, credential theft, exfiltration (AST-level analysis for Python) |
| `dep_confusion` | Private registry misconfigs enabling namespace hijacking |
| `scope_squatting` | npm scope typosquatting (`@angulr` vs `@angular`) |
| `ownership` | Maintainer takeovers and version-order anomalies |
| `provenance` | Missing or invalid SLSA attestations |
| `behavioral` | Runtime red flags: eval, exec, child_process, DNS resolve, exfiltration endpoints |
| `obfuscation` | Base64-exec, hex encoding, charcode, high entropy, ANSI escape content hiding |
| `network` | Mining pools, webhook exfiltration, DNS tunneling, hardcoded IPs |
| `reputation` | Low-trust signals: new package, no repository, single maintainer |

### Vulnerabilities

| Scanner | What it detects |
|---------|-----------------|
| `osv` | OSV database -- npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` / `pypi_advisory` | Ecosystem-specific advisories from GitHub Advisory DB |
| `epss` | EPSS exploit probability scores for triage |
| `kev` | CISA Known Exploited Vulnerabilities |

### CI/CD and infrastructure

| Scanner | What it detects |
|---------|-----------------|
| `gha_workflow` | Script injection, `pull_request_target` exploits, overly permissive permissions |
| `gha_scanner` | Unpinned and compromised GitHub Actions (SHA pinning check) |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG |
| `terraform` | Unpinned modules, HTTP sources, unverified namespaces |
| `secrets` | AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | CI secret exposure correlated with suspicious package behavior |

### Compliance and hygiene

| Scanner | What it detects |
|---------|-----------------|
| `license_scanner` / `license_compat` | Copyleft compliance, license conflict detection |
| `reachability` | Which vulnerable imports are actually reachable in your code |
| `phantom_deps` | Declared but never imported packages |
| `freshness` | Unmaintained dependencies (no release in 2+ years) |
| `pinning` | Unpinned versions, wildcard ranges, missing lockfiles |
| `sbom` | CycloneDX 1.5 and SPDX 2.3 generation |
| `risk-score` | Composite A-F risk grades with OpenSSF Scorecard integration |

---

## Supported ecosystems

npm, PyPI, Cargo, Go, Maven, NuGet, RubyGems, Composer, Swift/SPM, Docker, HuggingFace, MCP, GitHub Actions.

Lockfile auto-detection: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `uv.lock`, `packages.config`, `Gemfile.lock`, `composer.lock`, `Package.resolved`.

---

## Installation

```bash
pip install depfence                  # core
pip install "depfence[ml]"            # with scikit-learn behavioral scoring
pipx install depfence                 # isolated install
```

Python 3.10+. Tested on 3.10, 3.11, 3.12, 3.13. No native dependencies.

---

## Usage

### Core commands

```bash
# Full scan with all scanners
depfence scan .

# Fast CI scan -- only packages changed since last scan
depfence diff .

# Advisory-only audit (skip behavioral/reputation analysis)
depfence audit .

# Single package reputation check
depfence check requests -e pypi

# Auto-fix vulnerable dependencies
depfence fix . --apply

# Initialize depfence for a project (CI workflow + pre-commit hook + policy config)
depfence init .
```

### AI-specific commands

```bash
depfence ai-scan .              # prompt injection, slopsquatting, model threats
depfence model-scan .           # ML model file supply chain risks
depfence ai-bom .               # AI Bill of Materials
depfence mcp-scan .             # MCP server configuration audit
depfence mcp-fingerprint .      # MCP rug-pull fingerprinting
```

### CI/CD and infrastructure audit

```bash
depfence gha-scan .             # GitHub Actions: permissions, injection, unpinned actions
depfence scan-docker .          # Dockerfile security audit
depfence scan-workflows .       # Workflow security audit
depfence secrets scan . --history   # Secrets scanning (including git history)
depfence ci-audit .             # CI secret exposure audit
```

### SBOM and compliance

```bash
depfence sbom . -o sbom.json                       # CycloneDX 1.5 SBOM
depfence sbom . --format spdx -o sbom.spdx.json    # SPDX 2.3 SBOM
depfence sbom-diff before.json after.json           # Compare SBOMs between releases
depfence licenses .                                 # License compliance scan
depfence compliance . -o compliance.html            # Full compliance report
```

### Analysis and triage

```bash
depfence risk-score .           # Composite A-F risk grades
depfence epss .                 # EPSS exploit probability ranking
depfence kev .                  # CISA Known Exploited Vulnerabilities
depfence scorecard .            # OpenSSF Scorecard integration
depfence graph . -o deps.dot    # Dependency graph visualization
depfence trust lodash npm       # Package trust score
depfence why lodash             # Why is this package in my tree?
depfence health .               # Scan health dashboard
```

### Operational commands

```bash
depfence watch . --interval 30  # Watch lockfiles and auto-scan on change
depfence scan . --parallel -j 4 # Monorepo parallel scanning
depfence baseline . --create    # Baseline current findings (suppress known issues)
depfence red-team .             # Security red team assessment
depfence stats .                # Scan statistics
depfence plugins                # List loaded scanner plugins
depfence doctor                 # System diagnostics
```

---

## Output formats

```bash
depfence scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
depfence scan . --format sarif -o results.sarif
depfence scan . --format html -o report.html
depfence sbom . --format cyclonedx -o sbom.json
```

| Format | Use case |
|--------|----------|
| `table` (default) | Terminal output for local development |
| `json` | Pipeline integration, scripting, `jq` queries |
| `html` | Shareable reports with full finding details |
| `sarif` | GitHub Code Scanning, Azure DevOps, VS Code |
| `cyclonedx` | CycloneDX 1.5 SBOM for compliance |
| `spdx` | SPDX 2.3 SBOM for compliance |

---

## CI/CD integration

### GitHub Actions

```yaml
- uses: ericrihm/depfence@v1
  with:
    fail-on: high
    format: sarif
    upload-sarif: true
```

The action installs depfence, runs a scan, uploads SARIF to GitHub Code Scanning, and posts a job summary. Inputs: `path`, `fail-on`, `format`, `upload-sarif`, `enrich-epss`, `enrich-kev`, `sbom`, `python-version`. See [`action.yml`](action.yml) for defaults.

<details>
<summary>Full workflow example</summary>

```yaml
name: Dependency Security
on:
  push:
    branches: [main]
    paths: ['**/package-lock.json', '**/requirements.txt', '**/Cargo.lock', '**/go.sum']
  pull_request:
    paths: ['**/package-lock.json', '**/requirements.txt', '**/poetry.lock']
  schedule:
    - cron: '0 6 * * 1'

jobs:
  depfence:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ericrihm/depfence@v1
        with:
          fail-on: high
          upload-sarif: true
```

</details>

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ericrihm/depfence
    rev: v0.5.0
    hooks:
      - id: depfence
```

The hook triggers only when lockfiles change, keeping pre-commit fast for non-dependency changes.

### GitLab CI

```yaml
depfence:
  image: python:3.12-slim
  stage: test
  script:
    - pip install depfence
    - depfence scan . --format json -o depfence.json --fail-on high
  artifacts:
    reports:
      dependency_scanning: depfence.json
    when: always
```

---

## Configuration

Place `depfence.yml` at the project root for policy-as-code:

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

Suppress individual findings directly in source:

```python
import lodash  # depfence:ignore[CVE-2021-23337] -- not reachable via our import path
```

### Baseline management

Track known findings so new issues stand out in CI:

```bash
depfence baseline . --create    # snapshot current findings
depfence baseline . --show      # list baselined findings
depfence scan .                 # automatically filters baselined findings
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean -- no findings above threshold |
| `1` | Findings at or above `--fail-on` severity |
| `2` | Scan error |

---

## MCP server

depfence ships an MCP server for integration with AI coding tools (Claude Desktop, Cursor, VS Code, Windsurf, Zed). This lets AI assistants check package safety before recommending dependencies.

```bash
depfence mcp serve
```

Or configure it in your MCP client:

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

Available MCP tools:

| Tool | Description |
|------|-------------|
| `check_package` | Security check for a single package -- risk score, CVEs, typosquat detection |
| `scan_project` | Full project scan from within your editor |
| `is_typosquat` | Check if a package name is a known typosquat or slopsquat |
| `get_advisories` | Fetch CVE/GHSA advisories for a package |
| `suggest_alternative` | Suggest a safer alternative to a flagged package |
| `check_license` | License compatibility check |

---

## Plugin system

depfence discovers custom scanners via pip entry points, `DEPFENCE_PLUGIN_PATH`, or `~/.depfence/plugins/`.

```python
from depfence.core.models import Finding, PackageMeta, Severity

class MyScanner:
    name = "my_scanner"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        # Your detection logic here
        return []
```

Register it in your package's `pyproject.toml`:

```toml
[project.entry-points."depfence.scanners"]
my_scanner = "my_package.scanner:MyScanner"
```

```bash
depfence plugins   # verify your scanner is loaded
```

---

## Contributing

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The test suite has 91 test files covering all scanners and core functionality. Run `ruff check` and `mypy` before opening a PR.

### Project structure

```
depfence/
  cli/          CLI commands (click)
  core/         Engine, lockfile parsing, policy, caching, enrichment
  scanners/     35+ scanner modules (one file per scanner)
  reporters/    Output formatters (SARIF, CycloneDX, SPDX, HTML, JSON)
  analyzers/    AST analysis and install script analysis
  mcp/          MCP server (JSON-RPC over stdio)
```

---

## Security policy

To report a vulnerability in depfence itself, please open a [GitHub security advisory](https://github.com/ericrihm/depfence/security/advisories/new) or email the maintainers via the GitHub profile. Do not open a public issue for security vulnerabilities.

---

## License

MIT License. See [LICENSE](LICENSE).
