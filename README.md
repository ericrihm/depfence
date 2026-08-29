# depfence

Static analysis for dependency and CI/CD supply chain security. Catches attack classes that CVE-based scanners miss: prompt injection payloads, typosquatting variants LLMs hallucinate, fabricated SHA pins, Cordyceps-class CI/CD workflow attacks, MCP tool manipulation, and agent skill exploitation.

[![CI](https://img.shields.io/github/actions/workflow/status/ericrihm/depfence/depfence.yml?branch=main&label=CI)](https://github.com/ericrihm/depfence/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Scanners: 57](https://img.shields.io/badge/scanners-57-orange)](docs/site/docs.html)
[![Tests: 3963](https://img.shields.io/badge/tests-3963-brightgreen)](tests/)

<!-- <p align="center">
  <img src="docs/demo.gif" alt="depfence scanning a vulnerable project" width="800">
</p>
--> 
```bash
git clone https://github.com/ericrihm/depfence && cd depfence
pip install -e .
depfence scan .
```

---

## What depfence catches that others don't

| Attack class | Scanner | Real-world example |
|---|---|---|
| Prompt injection in dependencies | `prompt_injection`, `docker_layer`, `git_message` | ANSI-hidden overrides, AI code review manipulation |
| LLM-hallucinated packages | `slopsquat` | Typosquats matching names LLMs fabricate |
| Fabricated SHA/version pins | `resolve_existence`, `version_existence` | `actions/checkout@<hallucinated-sha>`, `requests==99.99.99` |
| MCP tool manipulation | `mcp_scanner`, `mcp_fingerprint` | Tool shadowing, rug-pull attacks, credential leaks |
| Agent skill attacks | `agent_skill` | External instruction fetch, domain spoofing, deferred payloads |
| CI/CD workflow exploitation | `gha_workflow` | Cordyceps `workflow_run` escalation, `issue_comment` TOCTOU |
| AI model file threats | `model_format`, `model_integrity` | TFLite custom ops, GGUF chat template SSTI, pickle RCE |
| Editor config injection | `editor_config` | Claude Code hook injection, Cursor `alwaysApply` |
| Phantom Gyp attacks | `binding_gyp` | `binding.gyp` without native code — stealth install hook |
| Protestware | `protestware` | Geofenced payloads, date-bombs, political messages in install hooks |
| Anti-analysis evasion | `prompt_injection` | [Gaslight](https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html)-style fake system messages, CBRN refusal triggers, classification markings, legal threats designed to make AI security agents abort analysis |
| Visual text deception | `visual_text_deception_scanner` | Font, PDF, and DOCX deception where rendered text disagrees with machine-readable text |

---

## Research contribution

Existing dependency scanners (Snyk, Dependabot, OSV-Scanner, Grype) focus on known CVEs in package version databases. depfence addresses a different threat model: attacks that exploit the AI-assisted development pipeline itself.

**Novel attack classes covered by depfence that no CVE scanner detects:**

- **Slopsquatting** — packages named after hallucinated recommendations from large language models. depfence maintains a detection heuristic that flags typosquats matching patterns LLMs are known to fabricate.
- **Anti-analysis evasion** — malware that uses fabricated system messages, CBRN refusal triggers, and legal threats to trick AI security agents into aborting analysis ([Gaslight technique](https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html), DPRK attribution).
- **MCP tool manipulation** — tool shadowing, rug-pull attacks, and credential leakage in Model Context Protocol configurations across Claude Desktop, Cursor, VS Code, Windsurf, and Zed.
- **Agent skill attacks** — external instruction fetch, domain spoofing, and deferred payload delivery targeting autonomous AI agents.
- **Fabricated pin verification** — SHA pins and version numbers that don't exist in any registry, often hallucinated by coding assistants into CI workflows.
- **Cordyceps-class CI/CD attacks** — `workflow_run` privilege escalation and `issue_comment` TOCTOU races in GitHub Actions.

depfence operates entirely via static analysis — no package code is executed, no source code leaves the local machine. All 57 scanners run concurrently with async metadata fetching across 14 package ecosystems.

---

## Architecture

```
lockfile detection -> metadata fetch -> scanner execution -> enrichment
                                            |
                              +-------------+-------------+
                     entry-point scanners      project scanners
                     (54, via pip registry)    (33, filesystem-based)
                              |                       |
                     operate on PackageMeta    operate on project dir
                     (name, version, metadata) (walk .github/workflows/,
                                                Dockerfiles, Package.swift, etc.)
```

1. **Lockfile detection** — auto-discovers `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`, `uv.lock`, `packages.config`, `Gemfile.lock`, `composer.lock`, `Package.resolved`, `Podfile.lock`, `pubspec.lock`, `pom.xml`, `libs.versions.toml`.
2. **Metadata fetch** — async batch fetch (20 concurrent) from npm, PyPI, etc.
3. **Scanner execution** — 54 entry-point scanners + 33 project scanners run concurrently.
4. **Enrichment** — EPSS exploit probability, CISA KEV status, OpenSSF Scorecard, and reachability analysis.

After enrichment, `depfence:ignore` suppressions and baseline snapshots are applied. Output formats: table, JSON, SARIF, HTML, CycloneDX, SPDX.

**Invariants**: depfence never executes package code. All analysis is local and static. No source code is transmitted to any external service. Network calls are limited to the endpoints in [Network behavior](#network-behavior) and can be fully disabled with `--no-fetch`.

**Ecosystems**: npm, PyPI, Cargo, Go, Maven/Gradle, NuGet, RubyGems, Composer, Swift/SPM, Dart/Flutter, Docker, HuggingFace, MCP, GitHub Actions.

---

## Scanners

54 entry-point scanners + 33 project scanners. 57 scanner files total — many serve both roles.

<details>
<summary><strong>Prompt injection and AI safety</strong> (6 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `prompt_injection` | 55+ regex patterns against source strings/comments/docstrings (AST-extracted). Multi-pass normalization strips hex/unicode/URL encoding and zero-width characters. Includes anti-analysis evasion detection (Gaslight-style fake system messages, resource exhaustion claims, classification/legal threats, emotional coercion), CBRN refusal-trigger shield detection, and a `strip_cbrn_shield()` preprocessor for safe AI-agent analysis of weaponized content. |
| `git_message` | Instruction-override payloads in commit messages, PR templates, and issue templates targeting AI code review bots |
| `ci_ai_bot` | `${{ github.event.* }}` flowing into AI tool invocations in workflows — the [Clinejection](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/) pattern |
| `mcp_scanner` | MCP config files (Claude Desktop, Cursor, VS Code, Windsurf, Zed): tool shadowing, credential leakage, missing TLS, domain spoofing, prompt injection in tool descriptions |
| `mcp_fingerprint` | Schema fingerprinting for MCP rug-pull attacks (servers that change tool definitions after initial approval) |
| `agent_skill` | External instruction fetch directives (NLP + URL analysis), domain spoofing via Levenshtein similarity against 50+ services, deferred payload bait-and-switch via content hash fingerprinting, suspicious hosting. Covers the [brand-landingpage](https://thehackernews.com/2026/06/fake-ai-agent-skill-passed-security.html) attack. |

</details>

<details>
<summary><strong>AI/ML model security</strong> (7 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `model_scanner` | `torch.load()` without `weights_only=True`, pickle file detection, unverified HuggingFace pulls |
| `model_integrity` | Checksum verification, SafeTensors header validation, file size anomalies, prompt injection in model card metadata |
| `model_format` | TFLite custom operator detection (FlexWriteFile, EagerPyFunc), NumPy object-dtype pickle, HDF5/Keras Lambda layers, ONNX custom operators, GGUF chat template SSTI (Jinja2 injection), GGUF header anomalies (CVE-2024-25664) |
| `ai_vulns` | LangChain RCE vectors, `trust_remote_code=True`, `eval(response)`, unsafe deserialization |
| `ai_bom` | Inventory: model files (.safetensors, .bin, .pkl, .pt, .onnx, .gguf), MCP configs, AI framework packages |
| `docker_layer` | Prompt injection payloads and metadata exfiltration in Dockerfile labels, ENV, ARG, entrypoint |
| `slopsquat` | Composite similarity scoring: Levenshtein (<=2), character confusion (l/1, O/0, rn/m), QWERTY adjacency, prefix/suffix manipulation against curated popular-package lists |

</details>

<details>
<summary><strong>Editor config injection and build hooks</strong> (12 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `editor_config` | Claude Code `SessionStart` hook injection, Gemini CLI hooks, Cursor `alwaysApply` prompt injection, VS Code `runOn: folderOpen` auto-run tasks, suspicious `.github/setup.*` scripts, backdated config-only commits with `[skip ci]` |
| `binding_gyp` | Phantom Gyp: `binding.gyp` without native C/C++ source — stealth `npm install` code execution that bypasses standard hook detection |
| `gradle_plugin` | Untrusted plugin repositories, buildSrc with network/exec, convention plugins, plugin version ranges, init.gradle injection, untrusted annotation processors (kapt/ksp) |
| `android_manifest` | Dangerous permissions in AAR dependencies, ProGuard rule injection, native `.so` libraries |
| `cocoapods_hook` | `script_phase` and `prepare_command` in podspecs (arbitrary shell at `pod install`), dangerous `post_install` hooks in Podfile |
| `flutter_pubspec` | `dependency_overrides`, git deps, external path deps, non-pub.dev registries |
| `spm_plugin` | SPM `.buildTool` and `.command` plugins, binary targets from remote URLs, `unsafeFlags`, mutable git deps (branch/revision), plugin source with process/network calls |
| `rust_build` | `build.rs` with network access (reqwest/hyper/ureq), process spawning, env var exfiltration, filesystem writes outside OUT_DIR, suspicious build-dependencies |
| `go_generate` | `//go:generate` with shell execution, remote downloads (curl/wget), unknown generator tools, CGo LDFLAGS/CFLAGS injection |
| `composer_script` | Composer lifecycle hooks (post-install-cmd, post-update-cmd) with shell commands, PHP class hooks, curl-pipe-to-sh, custom installer plugins |
| `python_build` | `setup.py` cmdclass overrides, dangerous imports (subprocess/socket/ctypes), obfuscated exec/eval, remote downloads, non-standard pyproject.toml build backends |
| `maven_plugin` | Untrusted plugin repositories, plugins bound to early lifecycle phases, maven-antrun-plugin shell execution, exec-maven-plugin, unpinned plugin versions |

</details>

<details>
<summary><strong>Supply chain</strong> (13 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `preinstall` | AST-level install script analysis: pipe-to-shell, credential theft, exfiltration patterns. Phantom Gyp cross-reference. |
| `payload_behavior` | Credential harvesting (`.aws/credentials`, `.kube/config`, `.npmrc`), destructive sinks, decode-then-execute, exfil co-location, env-token scraping, identity-forge patterns |
| `dep_confusion` | Private registry misconfiguration enabling namespace hijacking |
| `scope_squatting` | npm scope typosquatting (`@angulr` vs `@angular`). Well-known unscoped packages (express, lodash, react, etc.) are allowlisted to prevent false positives. |
| `ownership` | Maintainer takeovers and version-order anomalies |
| `provenance` | High-value packages missing SLSA build attestations |
| `provenance_checker` | SLSA/Sigstore attestation signature verification for npm and PyPI |
| `behavioral` | Runtime red flags: `eval`, `exec`, `child_process`, DNS resolve, exfiltration endpoints |
| `obfuscation` | Base64-exec, hex/charcode encoding, high-entropy strings, ANSI content hiding, large (>4MB) staged decryption (ROT/charcode + AES-128-GCM) |
| `network` | Hardcoded IPs, mining pool domains, webhook exfiltration URLs, DNS tunneling indicators |
| `reputation` | Low-trust heuristics: age < 30 days, no source repo, single maintainer |
| `protestware` | Geofencing by locale/timezone, date-bomb conditions, political/protest messages in install hooks, conditional payload delivery based on geography |
| `ruby_lifecycle` | Malicious Ruby build/install files: `extconf.rb`, `Rakefile`, `*.gemspec` exec/exfil patterns (backticks, `%x{}`, `system`, `eval`, dangerous requires, download-piped-to-sh, ENV token+net combos) |

</details>

<details>
<summary><strong>Vulnerabilities</strong> (3 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `osv` | Known vulnerabilities via [OSV.dev](https://osv.dev) across npm, PyPI, Cargo, Go, Maven, NuGet, Ruby, PHP, Swift |
| `npm_advisory` | npm-specific advisories from GitHub Advisory Database |
| `pypi_advisory` | PyPI-specific advisories from GitHub Advisory Database |

</details>

<details>
<summary><strong>CI/CD and infrastructure</strong> (8 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `gha_workflow` | 12 checks: `${{ }}` expression injection in `run:` blocks, `pull_request_target` + PR-head checkout, overly permissive `permissions:`, secrets in logs, self-hosted runner risks, self-propagation detection, and 5 Cordyceps-class checks — `workflow_run` privilege escalation via artifact download, `issue_comment` TOCTOU race, `actions/github-script` code injection, artifact trust boundary violations, `actions/checkout` < v7 missing fork-PR protection |
| `gha_scanner` | Unpinned GitHub Actions (tag refs instead of SHA pins) and actions with known compromised versions |
| `resolve_existence` | Resolves `uses: owner/repo@<sha>` against GitHub API. HTTP 422 = fabricated pin (CRITICAL). Emits INFO on auth/rate-limit (never false CRITICAL). Disable: `DEPFENCE_RESOLVE_EXISTENCE=0`. |
| `version_existence` | Resolves exact npm/PyPI version pins against registries. Canonical version comparison, PEP 503 normalization. Yanked versions NOT flagged. Disable: `DEPFENCE_VERSION_EXISTENCE=0`. |
| `dockerfile` | Unpinned base images, root user, secrets in ENV/ARG |
| `terraform` | Unpinned modules, HTTP sources, unverified registry namespaces |
| `secrets` | Regex patterns for AWS keys, GitHub PATs, private keys, Stripe tokens, DB connection strings |
| `ci_secrets` | CI secret exposure correlated with suspicious package behavior |

</details>

<details>
<summary><strong>Compliance and hygiene</strong> (5 scanners)</summary>

| Scanner | What it detects |
|---|---|
| `license_scanner` | SPDX license identification and copyleft compatibility |
| `reachability` | AST import tracing to identify which vulnerable packages are actually imported |
| `phantom_deps` | Declared dependencies never imported (unused attack surface) |
| `freshness` | Packages with no release in 2+ years |
| `pinning` | Unpinned versions, wildcard ranges, missing lockfiles |

</details>

<details>
<summary><strong>Enrichment</strong> (not scanners)</summary>

- **EPSS** — Exploit Prediction Scoring System probability on every CVE finding
- **CISA KEV** — Known Exploited Vulnerabilities catalog flag
- **Risk scoring** — composite A-F grades from EPSS + KEV + CVSS + reachability + Scorecard
- **SBOM** — CycloneDX 1.5 and SPDX 2.3

</details>

---

## Fabricated-pin verification

Most pinning linters check that a SHA string exists in an action reference. `resolve_existence` verifies the SHA references a real commit by querying the GitHub API.

| HTTP status | Interpretation |
|---|---|
| 200 | Valid commit — no finding |
| 422 | Commit does not exist — `CRITICAL fabricated_reference` |
| 404 | Repo unreachable — `HIGH fabricated_reference` |
| 401/403/429 | Auth/rate-limit — `INFO unverified_reference` (never false CRITICAL) |

When a fabricated pin has a `# vX.Y.Z` comment, the scanner resolves the real tag to characterize the fault: a long prefix match = "conflation" (real prefix + hallucinated tail). Valid commits whose tags moved are NOT flagged.

`version_existence` applies the same principle to package versions: `requests==99.99.99` resolves to nothing on PyPI.

**False positive discipline**: yanked-but-real versions are never flagged. Network failures degrade to INFO. Both scanners gate on `fetch_enabled()` and respect `--no-fetch`.

---

## Installation

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
pip install -e .                      # core
pip install -e ".[ml]"                # with scikit-learn behavioral scoring
```

Once published to PyPI: `pip install depfence` / `pipx install depfence`.

Python 3.10+. Tested on 3.10, 3.11, 3.12, 3.13. No native dependencies.

### AI coding assistants

**Claude Code** — add the MCP server for inline security checks:
```bash
claude mcp add depfence -- depfence-mcp serve
```
Or add to your project's `.claude/settings.json`:
```json
{ "mcpServers": { "depfence": { "command": "depfence-mcp", "args": ["serve"] } } }
```
Slash commands (`/depfence`, `/depfence-check`) are available in projects that include depfence's `.claude/commands/` directory.

**Codex** — copy `docs/AGENTS.md` to `.codex/AGENTS.md` in your project for automatic pre-install checks.

### Docker

```bash
docker build -t depfence .
docker run --rm -v "$(pwd):/project" depfence scan /project
```

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

<details>
<summary><strong>Targeted scans</strong></summary>

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

</details>

<details>
<summary><strong>SBOM and compliance</strong></summary>

```bash
depfence sbom . -o sbom.json                       # CycloneDX 1.5
depfence sbom . --format spdx -o sbom.spdx.json    # SPDX 2.3
depfence sbom-diff before.json after.json           # compare SBOMs
depfence license-scan .                             # license compliance
depfence compliance . -o compliance.html            # full compliance report
```

</details>

<details>
<summary><strong>Analysis and triage</strong></summary>

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
depfence stats .                 # scan statistics summary
depfence summary .               # findings summary
depfence info lodash npm         # package metadata
```

</details>

<details>
<summary><strong>Operations</strong></summary>

```bash
depfence watch . --interval 30   # auto-scan on lockfile change
depfence monorepo-scan .         # multi-workspace scanning
depfence baseline . --create     # snapshot current findings (suppress known issues)
depfence red-team .              # security assessment
depfence remediate .             # remediation suggestions
depfence outdated .              # outdated dependencies
depfence policy .                # policy evaluation
depfence firewall .              # dependency firewall check
depfence health .                # project health assessment
depfence ignore CVE-2021-23337   # add to ignore list
depfence cache clear             # clear metadata cache
depfence doctor                  # diagnostics
depfence plugins                 # list loaded scanners
```

</details>

---

## Output formats

```bash
depfence scan . --format json | jq '.findings[] | select(.severity == "CRITICAL")'
depfence scan . --format sarif -o results.sarif
depfence scan . --format html -o report.html
depfence scan . --top 10                       # show only the 10 most severe findings
```

| Format | Use case |
|---|---|
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

A composite GitHub Action is defined in [`action.yml`](action.yml). Once a release tag is published: `uses: ericrihm/depfence@v1`.

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

<details>
<summary>Pre-commit hook</summary>

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ericrihm/depfence
    rev: main  # pin to a specific commit SHA for reproducibility
    hooks:
      - id: depfence
```

</details>

<details>
<summary>GitLab CI</summary>

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

</details>

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

<details>
<summary>Inline suppression and baselines</summary>

```python
import lodash  # depfence:ignore[CVE-2021-23337] -- not reachable via our import path
```

```bash
depfence baseline . --create     # snapshot current findings
depfence baseline . --show       # list baselined findings
depfence scan .                  # automatically filters baselined findings
```

</details>

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings above threshold |
| `1` | Findings at or above `--fail-on` severity |
| `2` | Scan error |

---

## Network behavior

All source code and lockfiles are processed locally. No source code is transmitted. Scanners that make network calls:

| Scanner | Endpoint | Data sent | Disable |
|---|---|---|---|
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
|---|---|
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

Project-level scanners use `async def scan_project(self, project_dir: Path) -> list[Finding]` instead.

---

## Limitations

- `resolve_existence` and `version_existence` require network access. Without `GITHUB_TOKEN`, GitHub API is rate-limited to 60/hour.
- Slopsquatting uses curated popular-package lists, not a complete registry mirror.
- Prompt injection patterns are regex-based. Novel obfuscation techniques may evade detection.
- EPSS and KEV enrichment require network access to FIRST.org and CISA APIs.
- `reachability` performs static import tracing only. Dynamic imports (`importlib`, `__import__`) are not resolved.
- Heuristic scanners (`behavioral`, `reputation`, `obfuscation`, `payload_behavior`) produce false positives. Use `depfence:ignore` or baselines to suppress known-good patterns.
- All detection is static. No dynamic analysis, sandboxed execution, or runtime monitoring.
- Not yet published on PyPI. Install from source until the first release is published.
- The GitHub Action (`action.yml`) will be available as `uses: ericrihm/depfence@v1` after the first release tag.

<details>
<summary>False positive expectations</summary>

Authoritative-source scanners (`resolve_existence`, `version_existence`, `osv`, `npm_advisory`, `pypi_advisory`) have zero expected false positives.

| Scanner | Common false positive | Suppression |
|---|---|---|
| `behavioral` | Legitimate `eval` in template engines, `child_process` in build tools | `depfence:ignore` |
| `obfuscation` | Base64 data URIs, high-entropy generated code | `depfence:ignore` |
| `reputation` | New but legitimate packages from established maintainers | baseline |
| `slopsquat` | Legitimate packages with names similar to popular ones | `depfence:ignore` |
| `prompt_injection` | Security comments discussing injection attacks | `depfence:ignore` |
| `agent_skill` | Legitimate tools referencing external documentation or lesser-known domains | `depfence:ignore` |
| `payload_behavior` | Build scripts with legitimate credential-store access patterns | `depfence:ignore` |

</details>

---

## When to use something else

- **CVE/advisory scanning only**: Dependabot, Snyk, or Grype have larger advisory databases.
- **Runtime behavioral analysis** (sandboxed execution): depfence is purely static.
- **Container image scanning** (not just Dockerfile linting): Trivy or Grype.
- **SAST** (vulnerabilities in your own code): Semgrep or CodeQL.

depfence covers the gap between these tools: AI-specific supply chain threats, fabricated pins, prompt injection in dependencies, agent skill manipulation, and CI/CD workflow security that no other scanner detects.

---

## Contributing

```bash
git clone https://github.com/ericrihm/depfence
cd depfence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

3843 test functions across 150 test files (parametrized cases push the badge higher; this number is what a dependency-free count can assert). Run `ruff check` before opening a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Project structure

```
depfence/          ~46K LOC
  cli/             CLI commands (click)
  core/            Engine, lockfile parsing, policy, caching, enrichment
  scanners/        57 scanner modules (54 entry-point, 33 project)
  reporters/       SARIF, CycloneDX, SPDX, HTML, JSON formatters
  analyzers/       AST analysis, install script analysis
  integrations/    Pre-commit hook, Claude Code PreToolUse hook
  mcp/             MCP server (JSON-RPC over stdio)
```

---

## Community

- [Contributing guide](CONTRIBUTING.md) — how to add scanners, run tests, submit PRs
- [Security policy](SECURITY.md) — report vulnerabilities via [GitHub security advisory](https://github.com/ericrihm/depfence/security/advisories/new)
- [Issue templates](https://github.com/ericrihm/depfence/issues/new/choose) — bug reports, false positives, feature requests
- [Changelog](https://github.com/ericrihm/depfence/releases) — release history

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
