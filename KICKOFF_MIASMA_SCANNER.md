# Kickoff: depfence Miasma / AI-Tool Config Injection Scanner

## Prompt

```
Use Elara recall for "Miasma supply chain attack" and "depfence" context before starting.
Use Dynamo brain_ask to validate detection heuristics against known attack patterns.

## Objective

Add a new scanner to depfence that detects the Wave 3 Miasma attack vector: malicious
configuration files planted in repositories that auto-execute payloads when developers
open the repo in AI coding tools (Claude Code, Gemini CLI, Cursor) or VS Code.

This is a TWO-TIER delivery. GitHub public release is FIRST PRIORITY. The private
(internal) version stays in `depfence/_private/` and is never pushed to GitHub.

## The Attack (Miasma Worm, June 2026, TeamPCP / Shai-Hulud variant)

Three-wave supply chain campaign. Wave 3 is the novel vector we're targeting:

**Wave 3 — AI Coding Tool Config Injection (June 3-5, 2026)**
- Attacker commits malicious config files to legitimate repos via stolen contributor creds
- Files auto-execute a 4.6MB credential harvester (.github/setup.js) when devs open the repo
- 73 Microsoft GitHub repos compromised (Azure, Azure-Samples, Microsoft, MicrosoftDocs)
- Commit backdated to 2020-03-09 with [skip ci] flag to evade detection

**Malicious files planted:**
| File | Tool | Trigger Mechanism |
|------|------|-------------------|
| `.claude/settings.json` | Claude Code | `SessionStart` hook executes shell command |
| `.gemini/settings.json` | Gemini CLI | `SessionStart` hook executes shell command |
| `.cursor/rules/setup.mdc` | Cursor AI | `alwaysApply: true` prompt injection tells agent to run setup.js |
| `.vscode/tasks.json` | VS Code | `"runOn": "folderOpen"` auto-runs task on folder open |

**Payload characteristics:**
- `.github/setup.js` — 4.6MB obfuscated JavaScript
- Harvests AWS/Azure/GCP/K8s/npm/GitHub/Docker/SSH creds (90+ tool configs)
- Self-propagates via victim's GitHub repos (spoofed github-actions@github.com commits)
- Exfils to victim-owned repos named "Miasma: The Spreading Blight"
- C2: check.git-service[.]com, t.m-kosche[.]com
- Dormant exfil channel to api.anthropic.com:443
- Destructive failsafe: `rm -rf ~/` triggered by honeytoken invalidation

**Wave 1 context (npm preinstall hooks):**
- 32 @redhat-cloud-services npm packages with malicious preinstall hooks
- Already partially covered by depfence's existing `preinstall.py` scanner
- 4.29MB obfuscated JS, AES-128-GCM, PBKDF2 200K iterations

**Wave 2 context (Phantom Gyp):**
- Malicious binding.gyp files trigger code execution during npm install
- Bypasses standard preinstall/postinstall hook detection

**IoCs:**
- C2 domains: check.git-service[.]com, t.m-kosche[.]com
- SHA-256 hashes of index.js samples:
  396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4
  d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223
  f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c
  d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b
  f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f
  25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b
- Defender detection: Trojan:JS/ShaiWorm.DAW!MTB
- Commit pattern: backdated timestamps + [skip ci] + config-only changes

## Existing depfence Architecture

- Public scanners: `depfence/scanners/` (40+ scanners, MIT licensed, on GitHub)
- Private extensions: `depfence/_private/` (intel, flywheel, codexbro, autonomous)
- Scanner protocol: `class Scanner(Protocol)` with `name`, `ecosystems`, `async scan()`
- Analyzer protocol: `class Analyzer(Protocol)` with `name`, `async analyze(package, source_path)`
- Plugin registry: entry points + DEPFENCE_PLUGIN_PATH + ~/.depfence/plugins/
- Related existing scanners:
  - `preinstall.py` — already detects preinstall hook abuse (references Shai-Hulud)
  - `obfuscation.py` — detects base64/hex/charcode obfuscation, entropy analysis
  - `gha_workflow_scanner.py` / `gha_scanner.py` — GitHub Actions security
  - `provenance.py` — SLSA provenance verification
  - `prompt_injection_scanner.py` — prompt injection in deps
  - `behavioral.py` — behavioral analysis patterns

## PUBLIC VERSION (GitHub Priority — `depfence/scanners/`)

**New file: `depfence/scanners/editor_config_scanner.py`**

Detects malicious AI-tool and editor configuration files in repositories. This is the
version that ships to GitHub. It catches the attack pattern but does NOT include:
- Specific IoC hashes or C2 domains (those go in private)
- Advanced behavioral correlation
- Automated C2 infrastructure fingerprinting
- Threat actor attribution logic

**Detection rules (public tier):**

1. **Claude Code hook injection**: `.claude/settings.json` containing `SessionStart`,
   `PreToolUse`, `PostToolUse`, or `Stop` hooks with shell commands (`bash`, `sh`,
   `node`, `python`, `curl`, `wget`, `exec`)

2. **Gemini CLI hook injection**: `.gemini/settings.json` with similar hook patterns

3. **Cursor prompt injection**: `.cursor/rules/*.mdc` files containing `alwaysApply: true`
   combined with instructions to execute files (`run`, `execute`, `node`, `bash`, `sh`)

4. **VS Code auto-run tasks**: `.vscode/tasks.json` with `"runOn": "folderOpen"` that
   execute scripts (not just build tasks from known build systems)

5. **Phantom Gyp**: `binding.gyp` files in packages that don't have native C/C++ code
   (no .c/.cc/.cpp/.h files) — indicates the gyp is a trojan execution vector

6. **Suspicious setup scripts**: `.github/setup.js`, `.github/setup.sh`, or similar
   files referenced by config hooks that are unusually large (>100KB) or obfuscated

7. **Backdated commits with config-only changes**: Flag commits that ONLY add/modify
   editor config files (`.claude/`, `.cursor/`, `.gemini/`, `.vscode/`) with `[skip ci]`
   in the message — the exact Miasma commit pattern

**Also add: `depfence/scanners/binding_gyp_scanner.py`** (Wave 2 — Phantom Gyp)
- Detects binding.gyp in packages without native source files
- Flags gyp files that shell out to unexpected commands

**Update existing:**
- `preinstall.py` — add Phantom Gyp cross-reference, flag binding.gyp as alternate hook vector
- `obfuscation.py` — add detection for the 4MB+ obfuscated JS pattern (ROT cipher + AES-128-GCM staged unpacking)

## PRIVATE VERSION (`depfence/_private/intel/`)

**New file: `depfence/_private/intel/miasma_intel.py`**

Advanced detection that stays internal:

1. **IoC database**: Miasma-specific SHA-256 hashes, C2 domains, TLS cert fingerprints,
   campaign identifiers ("Miasma: The Spreading Blight" repo naming pattern)

2. **Behavioral correlation**: Cross-reference editor config injection + obfuscated
   payload + [skip ci] + backdated commit = high-confidence Miasma attribution

3. **C2 infrastructure fingerprinting**: TLS certificate analysis for git-service[.]com
   pattern, NameSilo registration correlation, domain age scoring

4. **SLSA provenance forgery detection**: Validate that Sigstore attestations chain back
   to expected CI infrastructure, not just that a valid signature exists

5. **Propagation graph analysis**: Track self-replication patterns across repos
   (github-actions@github.com spoofed commits, .github/setup.js injection pattern)

6. **Threat actor clustering**: TeamPCP infrastructure fingerprints, cross-campaign
   correlation (TanStack CVE-2026-45321, @antv, @redhat-cloud-services, LiteLLM, Telnyx)

## Test Plan

- Unit tests for each detection rule (malicious + benign config files)
- Fixtures: real Miasma config samples (sanitized) + legitimate .claude/settings.json
- False positive tests: legitimate VS Code task configs, normal cursor rules
- Integration test: scan a mock repo with planted Miasma artifacts
- Regression: existing scanner tests still pass

## Constraints

- Python 3.10+, no new heavy dependencies for public scanners
- Follow existing Scanner/Analyzer protocol from depfence/core/registry.py
- Public version must be useful standalone without private intel module
- Do NOT commit IoC hashes, C2 domains, or threat actor names to public repo
- README update: add editor config injection to the scanner list
- Tests: target 90%+ coverage on new scanner code

## Workflow

1. Elara: recall depfence context, store Miasma intel as entity + facts
2. Read existing scanner code (preinstall.py, obfuscation.py, gha_scanner.py) for patterns
3. Implement public editor_config_scanner.py + binding_gyp_scanner.py
4. Implement tests
5. Update preinstall.py and obfuscation.py with Miasma-relevant patterns
6. Update README scanner table
7. Commit + push to GitHub (public scanners only)
8. Implement private miasma_intel.py (DO NOT push)
9. Run full test suite, verify no regressions
```

## Sources

- [Cloudsmith: Miasma worm is a new variant of Shai-Hulud](https://cloudsmith.com/blog/miasma-worms-path-of-destruction)
- [StepSecurity: Miasma Worm Hits Microsoft Again](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents)
- [Microsoft Security Blog: Preinstall to Persistence](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
- [The Hacker News: Miasma Worm Hits 73 Microsoft GitHub Repos](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)
- [Wiz: Miasma Supply Chain Attack Targeting RedHat npm](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages)
- [Snyk: Miasma Attack Hits Red Hat npm Packages](https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/)
