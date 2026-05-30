# depfence

**Dependency security for the AI age.** 40+ scanners. One command.

[![PyPI](https://img.shields.io/pypi/v/depfence)](https://pypi.org/project/depfence/)
[![Tests](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/test.yml?label=tests)](https://github.com/ericrihm/depfence/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/pypi/pyversions/depfence)](https://pypi.org/project/depfence/)

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

## The problem

Your dependencies are an attack surface. Traditional scanners stop at CVEs. depfence goes further:

| Traditional scanners check | depfence also catches |
|---|---|
| Known CVEs in lockfiles | Prompt injection hidden in source code targeting AI assistants |
| Outdated packages | ANSI escape sequences making malicious text invisible to reviewers |
| License compliance | LLM-hallucinated package names registered by attackers (slopsquatting) |
| | MCP server misconfigs: tool shadowing, credential leakage, rug-pull attacks |
| | Install scripts that exfiltrate SSH keys, env vars, or credentials |
| | AI coding bots in CI/CD consuming untrusted GitHub issue/PR input |
| | Commit messages and PR templates injecting instructions into AI reviewers |
| | Pickle model weights with arbitrary code execution opcodes |

---

## Quick start

```bash
# Install
pip install depfence

# Full scan
depfence scan .

# Fast CI scan — only changed packages
depfence diff .

# Single-package reputation check
depfence check requests -e pypi

# Auto-fix vulnerable dependencies
depfence fix . --apply

# Generate AI Bill of Materials
depfence ai-bom .
```

---

## Scanners

### Prompt injection & AI safety

Catches attacks that target AI coding assistants — the tools your developers use every day.

| Scanner | What it detects |
|---|---|
| `prompt_injection` | Adversarial LLM instructions in source code: comments, docstrings, strings, README, build scripts, package.json fields. 25 patterns with multi-pass encoding normalization. Detects ANSI escapes, zero-width Unicode, bidi overrides, and homoglyphs. [Background](https://arstechnica.com/security/2026/05/fed-up-with-vibe-coders-dev-sneaks-data-nuking-prompt-injection-into-their-code/) |
| `git_message` | Injection in git commit messages and PR/issue templates targeting AI code review bots |
| `ci_ai_bot` | [Clinejection](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)-class attacks: AI bots in CI/CD consuming untrusted `${{ github.event }}` input |
| `mcp_scanner` | MCP server misconfigs: tool shadowing, rug-pull, credential leakage, prompt injection, TLS, version pinning. Fully offline, covers Claude/Cursor/VS Code/Windsurf/Zed |
| `mcp_fingerprint` | MCP rug-pull detection via schema fingerprinting and parameter injection |

### AI/ML model security

| Scanner | What it detects |
|---|---|
| `slopsquat` | LLM-hallucinated package names registered by attackers |
| `model_scanner` | Unsafe `torch.load`, pickle files, unverified HuggingFace pulls |
| `model_integrity` | Checksum verification, SafeTensors header validation, size anomaly, prompt injection in model metadata |
| `ai_vulns` | LangChain RCE, unsafe deserialization, `trust_remote_code`, `eval(response)` |
| `ai_bom` | AI Bill of Materials: inventories models, MCP servers, and AI frameworks with risk scoring |
| `docker_layer` | Prompt injection in Dockerfile labels, ENV, ARG, entrypoint, and local image metadata |

### Supply chain attacks

| Scanner | What it detects |
|---|---|
| `preinstall` | Install scripts: pipe-to-shell, credential theft, exfiltration (AST-level for Python) |
| `dep_confusion` | Private registry misconfigs enabling namespace hijacking |
| `scope_squatting` | npm scope typosquatting (`@angulr` vs `@angular`) |
| `ownership` | Maintainer takeovers and version-order anomalies |
| `provenance` | Missing or invalid SLSA attestations |
| `behavioral` | Runtime red flags: eval, exec, child_process, DNS resolve, exfiltration endpoints |
| `obfuscation` | Base64-exec, hex encoding, charcode, high entropy, ANSI escape content hiding |
| `network` | Mining pools, webhook exfiltration, DNS tunneling, hardcoded IPs |
| `reputation` | Low-trust packages: new, no repo, single maintainer |

### Vulnerabilities

| Scanner | What it detects |
|---|---|
| `osv` | OSV database — npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` / `pypi_advisory` | Ecosystem-specific advisories from GitHub Advisory DB |
| `epss` | EPSS exploit probability scores for triage |
| `kev` | CISA Known Exploited Vulnerabilities |

### CI/CD & infrastructure

| Scanner | What it detects |
|---|---|
| `gha_workflow` | Script injection, `pull_request_target` exploits, overly permissive permissions |
| `gha_scanner` | Unpinned and compromised GitHub Actions |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG |
| `terraform` | Unpinned modules, HTTP sources, unverified namespaces |
| `secrets` | AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | CI secret exposure correlated with suspicious package behavior |

### Compliance & hygiene

| Scanner | What it detects |
|---|---|
| `license_scanner` / `license_compat` | Copyleft compliance, license conflict detection |
| `reachability` | Which vulnerable imports are actually reachable |
| `phantom_deps` | Declared but never imported packages |
| `freshness` | Unmaintained deps (no release in 2+ years) |
| `pinning` | Unpinned deps, wildcard versions, missing lockfiles |
| `sbom` | CycloneDX 1.5 and SPDX 2.3 generation |
| `risk-score` | Composite A-F risk scores with OpenSSF Scorecard |

---

## Ecosystems

npm, PyPI, Cargo, Go, Maven, NuGet, RubyGems, Composer, Swift/SPM, Docker, HuggingFace, MCP, GitHub Actions.

---

## Output formats

```bash
depfence scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
depfence scan . --format sarif -o results.sarif
depfence sbom . --format cyclonedx -o sbom.json
```

| Format | Use case |
|---|---|
| `table` (default) | Local development |
| `json` | Pipeline integration, scripting |
| `html` | Shareable reports |
| `sarif` | GitHub Code Scanning, Azure DevOps |
| `cyclonedx` / `spdx` | SBOM delivery |

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

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ericrihm/depfence
    rev: v0.5.0
    hooks:
      - id: depfence
```

---

## Configuration

Place `depfence.yml` at the project root for policy-as-code:

<details>
<summary>depfence.yml example</summary>

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

</details>

| Exit code | Meaning |
|---|---|
| `0` | Clean — no findings above threshold |
| `1` | Findings at or above `--fail-on` threshold |
| `2` | Scan error |

---

## Plugin system

depfence discovers plugins via pip entry points, `DEPFENCE_PLUGIN_PATH`, or `~/.depfence/plugins/`.

```python
from depfence.core.models import Finding, PackageMeta, Severity

class MyScanner:
    name = "my_scanner"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        # Your detection logic here
        return []
```

```bash
depfence plugins   # list all loaded scanners
```

---

## Install

```bash
pip install depfence                  # stable
pip install "depfence[ml]"            # with scikit-learn behavioral scoring
pipx run depfence scan .              # no install
```

Python 3.10+. Tested on 3.10, 3.11, 3.12, 3.13.

---

## Contributing

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Run `ruff check` and `mypy` before opening a PR.

---

MIT License. See [LICENSE](LICENSE).
