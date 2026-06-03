# depfence

**Your dependencies have a new threat model.** AI coding assistants hallucinate package names that attackers register. CI bots consume attacker-controlled PR text. SHA pins written from memory point to commits that don't exist. Traditional scanners check CVEs and stop — depfence catches what comes next.

37 scanners. 13 ecosystems. One command.

[![CI](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/depfence.yml?branch=main&label=CI)](https://github.com/ericrihm/depfence/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![2,200+ tests](https://img.shields.io/badge/tests-2%2C200%2B-brightgreen)](https://github.com/ericrihm/depfence)

```bash
pip install depfence
depfence scan .
```

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

## The problem

In 2020, dependency security meant CVE scanning. In 2026, your attack surface includes:

**AI assistants hallucinate package names.** When Copilot or Claude suggests `pip install py-dateutil` instead of `python-dateutil`, an attacker who registered that name serves malware to everyone who trusts the suggestion. This is [slopsquatting](https://blog.socket.dev/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks) — and it's already happening at scale.

**SHA pins can be fabricated.** AI agents (and tired humans) SHA-pin GitHub Actions by writing the 40-hex commit from memory. A plausible-but-invented SHA passes every linter that checks "is it pinned?" (Scorecard, zizmor, actionlint) because none of them verify the pin actually resolves to a real commit. depfence does — it's the only tool that calls `GET /repos/{owner}/{repo}/commits/{sha}` and flags HTTP 422.

**CI bots eat attacker input.** [Clinejection](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)-class attacks feed prompt injection through `${{ github.event.issue.body }}` into AI review bots running in GitHub Actions. The bot has `contents: write`. The attacker has your repo.

**Packages carry invisible payloads.** ANSI escape sequences, zero-width Unicode, and bidirectional text overrides hide malicious instructions in source code. Humans can't see them. AI coding tools execute them.

depfence scans for all of this — alongside traditional CVE/advisory scanning — in a single pass. It is not a runtime scanner, WAF, or container image scanner. It scans your dependency graph, lockfiles, and AI tool configurations before deployment.

---

## Coverage comparison

depfence is designed to run alongside your existing scanner, not replace it. It catches the threats that CVE databases and traditional scanners were never designed to find.

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
| CI/CD AI bot injection | **Yes** | -- | -- | -- | -- |
| Fabricated SHA-pin detection | **Yes** | -- | -- | -- | -- |
| Fabricated package-version pins | **Yes** | -- | -- | -- | -- |
| Git message injection | **Yes** | -- | -- | -- | -- |
| Install script exfiltration | **Yes** | -- | -- | Partial | -- |
| Dependency confusion | **Yes** | Yes | -- | -- | -- |
| Model supply chain (pickle/torch) | **Yes** | -- | -- | -- | -- |
| AI Bill of Materials | **Yes** | -- | -- | -- | -- |
| GHA workflow security audit | **Yes** | -- | Yes | -- | -- |
| GHA permissions audit | **Yes** | -- | -- | -- | -- |
| Docker layer injection | **Yes** | -- | -- | Partial | -- |
| Terraform module pinning | **Yes** | -- | -- | Yes | -- |
| Policy-as-code rules | **Yes** | Yes | -- | Yes | -- |
| CycloneDX / SPDX SBOM | Yes | Yes | -- | Yes | Yes |
| SARIF output | Yes | Yes | -- | Yes | Yes |

> **The "resolve-never-predict" check** -- depfence doesn't just verify that a SHA pin exists in your workflow. It calls the GitHub API and verifies the commit is real. No linter, no scorecard check, no other scanner does this. [Details below.](#the-resolve-never-predict-philosophy)

---

## Scanners

### Prompt injection and AI safety

| Scanner | What it detects |
|---------|-----------------|
| `prompt_injection` | Adversarial LLM instructions hidden in source: comments, docstrings, strings, README, build scripts, `package.json` fields. 25 patterns with multi-pass encoding normalization (ANSI escapes, zero-width Unicode, bidi overrides, homoglyphs) |
| `git_message` | Injection payloads in commit messages and PR/issue templates targeting AI code review bots |
| `ci_ai_bot` | Clinejection-class attacks: AI bots in CI/CD consuming untrusted `${{ github.event }}` input |
| `mcp_scanner` | MCP server misconfigs: tool shadowing, rug-pull, credential leakage, prompt injection, TLS, version pinning. Covers Claude Desktop, Cursor, VS Code, Windsurf, and Zed configs |
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
| `provenance` | Missing SLSA attestations on high-value packages |
| `provenance_checker` | SLSA/Sigstore attestation signature verification (npm + PyPI) |
| `behavioral` | Runtime red flags: eval, exec, child_process, DNS resolve, exfiltration endpoints |
| `obfuscation` | Base64-exec, hex encoding, charcode, high entropy, ANSI escape content hiding |
| `network` | Mining pools, webhook exfiltration, DNS tunneling, hardcoded IPs |
| `reputation` | Low-trust signals: new package, no repository, single maintainer |

### Vulnerabilities

| Scanner | What it detects |
|---------|-----------------|
| `osv` | OSV database: npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` | npm-specific advisories from GitHub Advisory DB |
| `pypi_advisory` | PyPI-specific advisories from GitHub Advisory DB |

### CI/CD and infrastructure

| Scanner | What it detects |
|---------|-----------------|
| `gha_workflow` | Script injection (`${{ }}` in `run:`), `pull_request_target` exploits, overly permissive permissions |
| `gha_scanner` | Unpinned and compromised GitHub Actions (SHA pinning enforcement) |
| `resolve_existence` | **Fabricated action pins**: resolves every `uses: owner/repo@<sha>` against the GitHub API. HTTP 422 = the commit doesn't exist. The "resolve-never-predict" check that no linter does. Online; needs `GITHUB_TOKEN`. Disable: `DEPFENCE_RESOLVE_EXISTENCE=0` |
| `version_existence` | **Fabricated package-version pins**: resolves exact npm/PyPI version pins against registries. Catches never-published versions and hallucinated package names. Online; disable: `DEPFENCE_VERSION_EXISTENCE=0` |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG |
| `terraform` | Unpinned modules, HTTP sources, unverified namespaces |
| `secrets` | AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | CI secret exposure correlated with suspicious package behavior |

### Compliance and hygiene

| Scanner | What it detects |
|---------|-----------------|
| `license_scanner` | Copyleft compliance and license conflict detection |
| `reachability` | Which vulnerable imports are actually reachable in your code |
| `phantom_deps` | Declared but never imported packages |
| `freshness` | Unmaintained dependencies (no release in 2+ years) |
| `pinning` | Unpinned versions, wildcard ranges, missing lockfiles |

### Enrichment and analysis

These are not scanners -- they augment vulnerability findings with additional context for triage:

- **EPSS scores** (`depfence epss .`) -- FIRST.org Exploit Prediction Scoring, added to every CVE finding
- **CISA KEV** (`depfence kev .`) -- flags vulnerabilities on the Known Exploited Vulnerabilities catalog
- **Risk scoring** (`depfence risk-score .`) -- composite A-F grades combining EPSS, KEV, CVSS, reachability, and OpenSSF Scorecard
- **SBOM generation** (`depfence sbom .`) -- CycloneDX 1.5 and SPDX 2.3 output

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
depfence scan .                  # full scan: all 37 scanners
depfence diff .                  # only packages changed since last scan (fast CI mode)
depfence audit .                 # advisory-only (skip behavioral/reputation)
depfence check requests -e pypi  # single package reputation check
depfence fix . --apply           # auto-fix vulnerable dependencies
depfence init .                  # generate CI workflow + pre-commit hook + policy config
```

### AI-specific commands

```bash
depfence ai-scan .               # prompt injection, slopsquatting, model threats
depfence model-scan .            # ML model file supply chain risks
depfence mcp-scan .              # MCP server configuration audit
depfence mcp-fingerprint .       # MCP rug-pull fingerprinting
```

### CI/CD and infrastructure audit

```bash
depfence gha-scan .              # GitHub Actions: permissions, injection, unpinned actions
depfence scan-docker .           # Dockerfile security audit
depfence scan-workflows .        # workflow security audit
depfence ci-audit .              # CI secret exposure audit
depfence secrets scan .          # secrets scanning
depfence secrets scan . --history  # secrets scanning including git history
```

### SBOM and compliance

```bash
depfence sbom . -o sbom.json                       # CycloneDX 1.5 SBOM
depfence sbom . --format spdx -o sbom.spdx.json    # SPDX 2.3 SBOM
depfence sbom-diff before.json after.json           # compare SBOMs between releases
depfence license-scan .                             # license compliance
depfence compliance . -o compliance.html            # full compliance report
```

### Analysis and triage

```bash
depfence risk-score .            # composite A-F risk grades
depfence epss .                  # EPSS exploit probability ranking
depfence kev .                   # CISA Known Exploited Vulnerabilities
depfence scorecard .             # OpenSSF Scorecard integration
depfence graph . -o deps.dot     # dependency graph visualization
depfence trust lodash npm        # package trust score
depfence why lodash              # why is this package in my tree?
depfence threat-brief .          # threat landscape summary
depfence trends --days 30        # finding trends over time
```

### Operational commands

```bash
depfence watch . --interval 30   # watch lockfiles and auto-scan on change
depfence monorepo-scan .         # multi-workspace scanning
depfence baseline . --create     # baseline current findings (suppress known issues)
depfence red-team .              # security red team assessment
depfence remediate .             # automated remediation suggestions
depfence outdated .              # show outdated dependencies
depfence doctor                  # system diagnostics
depfence plugins                 # list loaded scanner plugins
depfence stats .                 # scan statistics
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
| `table` (default) | Terminal output |
| `json` | Pipeline integration, `jq` queries |
| `html` | Shareable reports with full finding details |
| `sarif` | GitHub Code Scanning, Azure DevOps, VS Code |
| `cyclonedx` | CycloneDX 1.5 SBOM |
| `spdx` | SPDX 2.3 SBOM |

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

Triggers when lockfiles **or workflow files** change. Runs resolve-existence and GHA workflow scanners on `.github/workflows/*.yml` edits, catching fabricated pins before they reach CI.

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
| `0` | Clean -- no findings above threshold |
| `1` | Findings at or above `--fail-on` severity |
| `2` | Scan error |

---

## The "resolve-never-predict" philosophy

Every other pinning linter asks: *"Is there a SHA?"* depfence asks: *"Does this SHA point to a real commit?"*

This matters because AI agents — and humans working fast — write SHA pins from memory. The resulting 40-hex string looks valid, passes regex checks, and satisfies every "is it pinned?" linter. But it resolves to nothing. Your workflow runs `actions/checkout@<fabricated-sha>`, GitHub returns an error, and your CI breaks in a way that's hard to diagnose.

Worse: a fabricated SHA for a less-common action might not break immediately. It might match a commit in a fork. Or it might sit unnoticed until the action maintainer force-pushes and the tag moves.

depfence's `resolve_existence` scanner calls the GitHub API for every pinned SHA and flags any that return HTTP 422 (non-existent commit). The `version_existence` scanner does the same for npm/PyPI version pins — catching `requests==99.99.99` or a hallucinated package name before it reaches production.

This is the check that closes the gap between "pinned" and "verified."

---

## Network and privacy

depfence processes all source code and lockfiles locally. No source code is ever transmitted. The following scanners make network calls when enabled:

| Scanner | What it contacts | Data sent | Disable with |
|---------|-----------------|-----------|--------------|
| `resolve_existence` | GitHub API | Repository owner/name, commit SHA | `DEPFENCE_RESOLVE_EXISTENCE=0` |
| `version_existence` | npm registry, PyPI | Package name, version string | `DEPFENCE_VERSION_EXISTENCE=0` |
| `osv` | OSV.dev API | Package name, version, ecosystem | `--no-advisory` |
| `npm_advisory` | GitHub Advisory DB | Package name | `--no-advisory` |
| `pypi_advisory` | GitHub Advisory DB | Package name | `--no-advisory` |
| `provenance_checker` | Sigstore/Rekor | Package name, attestation lookup | `--no-advisory` |

Run fully offline with `depfence scan . --no-fetch` (disables all network scanners).

---

## MCP server

depfence ships an MCP server for integration with AI coding tools (Claude Desktop, Cursor, VS Code, Windsurf, Zed). AI assistants can check package safety before recommending dependencies.

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

Available tools:

| Tool | Description |
|------|-------------|
| `check_package` | Security check for a single package: risk score, CVEs, typosquat detection |
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
        # Your detection logic
        return []
```

Register in `pyproject.toml`:

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

2,200+ tests across 93 test files covering all scanners and core functionality. Run `ruff check` before opening a PR.

### Project structure

```
depfence/
  cli/          CLI commands (click)
  core/         Engine, lockfile parsing, policy, caching, enrichment
  scanners/     37 scanners (36 entry-point + 1 project scanner)
  reporters/    Output formatters (SARIF, CycloneDX, SPDX, HTML, JSON)
  analyzers/    AST analysis, install script analysis
  integrations/ Pre-commit hook, Claude Code PreToolUse hook
  mcp/          MCP server (JSON-RPC over stdio)
```

---

## Security policy

To report a vulnerability in depfence itself, see [SECURITY.md](SECURITY.md) or open a [GitHub security advisory](https://github.com/ericrihm/depfence/security/advisories/new).

---

## License

MIT License. See [LICENSE](LICENSE).
