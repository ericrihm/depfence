# depfence — AI-Aware Supply Chain Security

**The dependency scanner built for the age of LLMs, MCP, and AI/ML supply chain attacks.**

[![PyPI](https://img.shields.io/pypi/v/depfence)](https://pypi.org/project/depfence/)
[![Tests](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/test.yml?label=1915%20tests)](https://github.com/ericrihm/depfence/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/depfence)](https://pypi.org/project/depfence/)

```bash
pip install depfence
depfence scan .
```

---

## Why depfence?

- **Slopsquatting defense** — LLMs hallucinate package names; attackers register them. depfence detects hallucinated names before they reach your lockfile.
- **MCP server auditing** — The only fully-offline, deterministic MCP security scanner. Detects tool shadowing, rug-pull attacks, prompt injection (with multi-pass encoding normalization), credential leakage, unpinned packages, and 23+ known-malicious servers. Covers Claude Desktop, Cursor, VS Code, Windsurf, and Zed — no cloud API calls required.
- **30+ scanners in one tool** — Vulnerability enrichment (EPSS, KEV, OSV, NVD), behavioral AST analysis, supply chain attack detection, IaC scanning, license compliance, SBOM generation, and red-team simulation — unified under a single CLI.
- **Beyond CVEs** — A package with zero advisories can still phone home at install time, exfiltrate env vars via DNS, or embed pickle-format model weights with arbitrary code execution. depfence catches all of it.

---

## Quick Start

```bash
# Install
pip install depfence

# Full scan — all ecosystems, all 30+ scanners
depfence scan .

# Fast CI scan — only changed packages
depfence diff .

# Single-package reputation check
depfence check requests -e pypi

# Auto-fix vulnerable dependencies
depfence fix . --apply
```

<details>
<summary>Sample output</summary>

```
$ depfence scan .

 depfence v0.4.0  scanning 142 packages across 3 lockfiles

 CRITICAL  pytorch-cuda-nightly   slopsquat     LLM hallucination match for torch (score 0.94)
 HIGH      lodash 4.17.20         npm_advisory  CVE-2021-23337  EPSS 0.71  KEV
 HIGH      req-utils 1.0.3        preinstall    install script exfiltrates $HOME/.ssh
 MEDIUM    transformers 4.38.0    model_scanner unsafe torch.load() without weights_only=True
 MEDIUM    @angulr/core           scope_squat   typosquatting @angular/core
 LOW       leftpad 0.0.3          freshness     no release in 847 days, 0 maintainers

 6 findings  (1 critical, 2 high, 2 medium, 1 low)
 Run `depfence fix .` for remediation suggestions.
```

</details>

---

## Features

### Vulnerability Detection

| Scanner | What it catches |
|---|---|
| `osv` | OSV database — covers npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` | OSV + GitHub Advisory DB for npm |
| `pypi_advisory` | OSV + GitHub Advisory DB for PyPI |
| `epss` | EPSS exploit probability scores for triage prioritization |
| `kev` | CISA Known Exploited Vulnerabilities list |

### AI/ML Supply Chain

| Scanner | What it catches |
|---|---|
| `slopsquat` | LLM-hallucinated package names registered by attackers |
| `model_scanner` | Unsafe `torch.load`, pickle model files, unverified HuggingFace pulls |
| `model_integrity` | Hash and provenance verification for model weight files |
| `ai_vulns` | AI/ML framework-specific vulnerability patterns |
| `mcp_scanner` | MCP server misconfigs, tool shadowing, credential leakage, known-malicious packages, TLS enforcement, version pinning, prompt injection with encoding normalization |
| `mcp_fingerprint` | MCP rug-pull detection via schema change fingerprinting + parameter-level injection scanning |

### Supply Chain Attacks

| Scanner | What it catches |
|---|---|
| `scope_squatting` | npm scope typosquatting (`@angulr` vs `@angular`) |
| `dep_confusion` | Private registry misconfigs enabling namespace hijacking |
| `ownership` | Maintainer takeovers and version-order anomalies |
| `preinstall` | Malicious install scripts: pipe-to-shell, credential theft, env exfiltration |
| `provenance` / `provenance_checker` | Missing or invalid SLSA attestations |
| `behavioral` | Suspicious API patterns: eval, exec, child_process |
| `obfuscation` | Base64-exec, hex strings, charcode encoding, high-entropy payloads |
| `network` | Mining pools, webhook exfil, DNS tunneling, hardcoded IPs |
| `reputation` | Low-trust packages: new, no repo, single maintainer |

### Compliance

| Scanner | What it catches |
|---|---|
| `license_scanner` | AGPL/GPL/copyleft compliance risks |
| `license_compat` | License conflict detection (GPL in MIT project, AGPL in proprietary) |
| `reachability` | Which vulnerable imports are actually reachable in your code |
| `phantom_deps` | Declared but never imported packages |
| `freshness` | Deprecated packages, unmaintained deps (no release in 2+ years) |
| `pinning` | Unpinned deps, wildcard versions, missing lockfiles |
| `sbom` | CycloneDX 1.5 and SPDX 2.3 generation |

### Security Operations

| Scanner | What it catches |
|---|---|
| `secrets` | AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | CI secret exposure risk correlated with suspicious package behavior |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG, EOL images |
| `terraform` | Unpinned modules/providers, HTTP sources, unverified namespaces |
| `gha_scanner` | Unpinned and compromised GitHub Actions |
| `gha_workflow` | Script injection, overly permissive permissions, `pull_request_target` attacks |
| `risk-score` | Composite A-F risk scores with OpenSSF Scorecard integration |

---

## Supported Ecosystems

| Ecosystem | Lockfiles / Manifests |
|---|---|
| npm / Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI / Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| Cargo / Rust | `Cargo.lock` |
| Go | `go.sum`, `go.mod` |
| Maven / Java | `pom.xml` |
| NuGet / .NET | `packages.lock.json`, `*.csproj` |
| RubyGems | `Gemfile.lock` |
| Composer / PHP | `composer.lock` |
| Swift / SPM | `Package.resolved` |

---

## Output Formats

All commands accept `--format` and `-o`:

| Format | Flag | Use case |
|---|---|---|
| Rich terminal table | `--format table` (default) | Local development |
| JSON | `--format json` | Pipeline integration, `jq` filtering |
| HTML | `--format html` | Shareable security reports |
| SARIF | `--format sarif` | GitHub Code Scanning, Azure DevOps |
| CycloneDX 1.5 | `depfence sbom --format cyclonedx` | SBOM delivery |
| SPDX 2.3 | `depfence sbom --format spdx` | SBOM delivery |

```bash
depfence scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
depfence scan . --format sarif -o results.sarif
depfence sbom . --format cyclonedx -o sbom.json
```

---

## CI/CD Integration

### GitHub Actions — one-liner composite action

```yaml
- uses: ericrihm/depfence@v1
  with:
    fail-on: high           # critical | high | medium | low | any | none
    format: sarif
    upload-sarif: true      # uploads to GitHub Code Scanning automatically
```

<details>
<summary>Full workflow with SARIF upload</summary>

```yaml
name: Dependency Security
on:
  push:
    branches: [main]
    paths:
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/requirements.txt'
      - '**/poetry.lock'
      - '**/Cargo.lock'
      - '**/go.sum'
  pull_request:
    paths:
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/requirements.txt'
      - '**/poetry.lock'
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
```

</details>

Findings appear in the repository Security tab under Code Scanning, with per-finding annotations at the relevant file and line.

---

## Configuration

Place `depfence.yml` at the project root for policy-as-code and scanner tuning.

<details>
<summary>depfence.yml example</summary>

```yaml
# depfence.yml
scanners:
  exclude: [phantom_deps]         # disable specific scanners
  fail_on: high                   # default --fail-on threshold

rules:
  - name: no-gpl-in-production
    description: Block copyleft-licensed packages
    match:
      license_category: copyleft
    action: block

  - name: require-provenance-for-popular
    description: Require SLSA provenance for high-download packages
    match:
      weekly_downloads_min: 100000
      has_provenance: false
    action: block

  - name: warn-on-ownership-change
    description: Flag packages whose maintainers changed recently
    match:
      ownership_changed_days: 30
    action: warn

  - name: no-install-scripts-npm
    description: Block npm packages that run code at install time
    match:
      has_install_scripts: true
    action: block
    ecosystems: [npm]

ignore:
  - id: CVE-2021-23337
    package: lodash
    reason: "not reachable via our import path"
    expires: 2026-12-31
```

</details>

**Environment variables**

| Variable | Description | Default |
|---|---|---|
| `DEPFENCE_PLUGIN_PATH` | Colon-separated plugin directories | — |
| `DEPFENCE_CACHE_DIR` | Cache for diff scans and MCP fingerprints | `~/.depfence/cache` |
| `DEPFENCE_TIMEOUT` | HTTP timeout for registry requests (seconds) | `30` |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | No findings above threshold, or `--fail-on none` |
| `1` | Findings at or above `--fail-on` threshold, or policy block triggered |
| `2` | Scan error (parse failure, network error) |

---

## Plugin System

depfence discovers plugins via pip entry points, `DEPFENCE_PLUGIN_PATH`, or `~/.depfence/plugins/`.

```python
# pyproject.toml:
# [project.entry-points."depfence.scanners"]
# my_scanner = "mypackage.scanner:MyScanner"

from depfence.core.models import Finding, PackageMeta, Severity

class MyScanner:
    name = "my_scanner"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings = []
        for pkg in packages:
            # detection logic
            pass
        return findings
```

```bash
depfence plugins   # list all loaded scanners, analyzers, reporters
```

---

## Installation

```bash
pip install depfence                  # stable
pip install "depfence[ml]"            # with scikit-learn behavioral scoring
pipx run depfence scan .              # no install required
```

Requires Python 3.10+. Tested on 3.10, 3.11, 3.12, 3.13.

---

## Contributing

Pull requests are welcome. To set up a development environment:

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Please run `ruff check` and `mypy` before opening a PR. The test suite covers 1,915 tests across all scanners, analyzers, reporters, and CLI commands.

---

## License

MIT. See [LICENSE](LICENSE).

---

*depfence is in active development. Scanner interfaces and policy schema may change between minor versions during the 0.x series.*
