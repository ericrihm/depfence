# depfence Gap Analysis: Simply Cyber x June 2026 Threat Landscape

**Date**: 2026-07-01
**Source**: Simply Cyber Daily Cyber Threat Brief Ep 1143-1164 (Jun 1-30, 2026) cross-referenced against depfence v0.8.0 (55 registered scanners)
**Method**: Threat stories from 22 episodes + independent research on AI agent attack vectors, verified against depfence source code

---

## Executive Summary

depfence has strong coverage of traditional supply chain attacks (typosquatting, dep confusion, CI injection) and emerging AI threats (prompt injection, MCP tool poisoning, Gaslight-style anti-analysis). However, the June 2026 threat landscape reveals **10 verified gaps** where real-world attacks succeed against patterns depfence does not yet detect. The single biggest opportunity: **agent instruction file content analysis** — VentureBeat confirms "no supply chain scanner has a detection category for it." depfence can be first.

## Implementation ledger — 2026-08-16

This ledger supersedes the historical "what depfence has" and "what's missing"
snapshots below. Those sections preserve the original research record; they are
not current product claims.

This ledger is evidence-oriented: “partial” means at least one firing case exists, not that the broader claim is proven.

| Gap | State | Current evidence | Next proof required |
|---|---|---|---|
| 1. Agent instructions | Covered for static text inputs | Nested Cursor, Roo, Windsurf, Continue, GitHub instruction roots and arbitrary AGENTS/CLAUDE/GEMINI/SKILL files are scanned; malicious, benign, oversized, file-budget, and symlink cases are exercised in `tests/test_prompt_injection_scanner.py` and `tests/test_security_contracts_v08.py` | External-reference reputation is a separate, network-backed claim and remains deferred |
| 2. Documentation payloads | Partial | Markdown/text, invisible Unicode, ANSI hiding, padding/tail analysis, size and file budgets are bounded; skipped candidates are named incomplete | Add explicit PDF/image/vector-store coverage |
| 3. RAG poisoning | Partial | Bounded Markdown/text/JSON/JSONL/CSV corpora detect instruction payloads and padding; unsupported media is `UNPROVEN` | Add corpus provenance, cross-document anomaly scoring, and retrieval-pipeline correlation |
| 4. AI advisories | Partial | Placeholder CVEs were removed; normal package scans now correlate exact PyPI package versions instead of limiting checks to `ai-scan`; failed remote lookups remain incomplete coverage | Replace the bundled list with a signed, freshness-checked feed before making current-intelligence claims |
| 5. Fictional framing | Covered for the declared English correlation | Narrative framing only fires when correlated with a sensitive action and target; a benign-story counter-case is in `tests/test_prompt_injection_scanner.py` | Multilingual and semantic variants remain explicitly outside the 0.8 claim |
| 6. AI VEX | Partial | CycloneDX 1.7 output no longer equates EPSS with exploitable | Require explicit exploitability evidence and define an AI inventory before an AI VEX claim |
| 7. Least privilege | Partial | CI source→sink→capability paths and MCP root/network/tool assurance now fire | Add cross-agent identity, OAuth audience, memory, and deployment authority graphs |
| 8. MCP CVE/runtime correlation | Partial | MCP launchers, pins, malicious packages, tool schemas, and authority declarations are checked | Add optional fingerprinted runtime inventory replay and drift correlation |
| 9. Build payloads | Partial | Language build-hook scanners and bounded project workers exist | Correlate generated instructions/artifacts into downstream agent sinks |
| 10. Agent-targeted activation | Open | Environment and CI patterns exist independently | Add condition/data-flow analysis for agent-only activation and benign feature gates |

The continuous gate is: every new claim needs a firing case, a benign counter-case, named incomplete coverage, and a stable machine-readable result before this table can move to “covered.”

### Current truth-to-release checkpoint — 2026-08-16

- The dirty-tree suite passes 3,717 tests with warnings treated as errors. Five user-deleted test files are intentionally
  excluded locally and must remain present in clean-checkout release validation.
- Ruff and full-package mypy were clean at the checkpoint.
- Python 3.14 project workers now use forkserver/spawn only; non-importable targets are
  named `UNPROVEN`. SQLite and HTTP-client owners close deterministically, and the complete
  suite passes with warnings treated as errors.
- The latest private fleet audit completed 316 opaque candidates: 115 valid worktrees and
  201 malformed recovery placeholders. All results remain triage evidence, not proof that
  the host is clean.
- Provenance remains `not_present`, `unavailable`, or `present_unverified`; no code path may
  emit `verified` until cryptographic digest, signature, identity, issuer, source, and time
  evidence are actually checked.

### DepFence 0.8 release-candidate evidence — 2026-08-15

- A reconstructed detached worktree retained the five tests deleted only in the developer's working tree; the current Python 3.14 strict suite passes 3,878 tests with warnings treated as errors. The earlier cross-version gate passed on every declared interpreter from CPython 3.10 through 3.14 and must be rerun before publication.
- Full-package mypy passed 168 source files, full Ruff passed `depfence` and `tests`, and the documentation, Action, schema, and whitespace gates passed.
- The wheel and sdist passed strict Twine validation. The sdist contains the five retained HEAD tests, and a clean Python 3.12 wheel install loaded both commands, both schemas, the standalone dashboard, 55 scanner, 2 analyzer, and 8 reporter entry points.
- The intermittent SQLite failure was reproduced as descriptor growth above 200 handles. Explicit transaction closure reduced a 500-cache stress test from unbounded growth to a zero-descriptor delta.
- External TestPyPI upload, consumer-canary execution, tagging, and Trusted Publishing remain release gates; none is represented here as completed.

---

## Verified Gaps

### GAP 1: Agent Instruction File Content Analysis [CRITICAL]

**Threat source**: Simply Cyber Ep 1161 (OpenClaw malicious skills, "Bioshocking" prompt injection), ClawHavoc campaign (341 malicious ClawHub skills), Snyk ToxicSkills (36% of ClawHub skills had security flaws)

**What depfence has**: `ci_ai_bot_scanner` checks AI config files (CLAUDE.md, .cursorrules, copilot-instructions.md, etc.) for broad tool permission grants (`*` wildcards, dangerous tool names). `editor_config_scanner` checks Cursor/Cline/Windsurf rules for execution instructions via `_CURSOR_EXEC_PATTERNS`.

**What's missing**: Neither scanner runs `prompt_injection_scanner`'s 55+ detection patterns against instruction file CONTENT. A SKILL.md or CLAUDE.md could contain sophisticated credential exfiltration instructions, behavior manipulation, or data leakage prompts that would be caught in source code strings but are invisible in instruction files. The content analysis is the gap — depfence knows WHERE these files are, but doesn't deeply analyze WHAT they say.

**Proposed fix**: New scanner `instruction_file_scanner.py`:
- Walk filesystem for all known instruction files (SKILL.md, AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .cursor/rules/*.md, .github/copilot-instructions.md, .windsurfrules, .clinerules, .roo/rules/*.md, .continue/rules/*.md)
- Run prompt_injection_scanner patterns against file content
- Add instruction-specific patterns: credential exfil ("send to", "POST to", "webhook"), behavior override ("ignore all previous", "you are now"), tool grant escalation ("always allow", "auto-approve"), data leakage ("include contents of", "read and send")
- Detect padding evasion (>1MB instruction files with repetitive whitespace/content)
- Cross-reference external URL references against known-malicious domains

**Impact**: First supply chain scanner with this detection category. Directly addresses the #1 emerging attack surface of 2026.

---

### GAP 2: README/Documentation Hidden Payload Detection [HIGH]

**Threat source**: ClawHavoc campaign (22MB padding in README.md hiding malicious payload above the fold), Simply Cyber Ep 1156 (malicious Python packages with AI-generated tutorials as social engineering)

**What depfence has**: Nothing scans documentation files (.md, .rst, .txt) for hidden payloads or manipulation content.

**What's missing**: AI coding agents read README.md, CONTRIBUTING.md, and documentation files as project context. Attackers embed prompt injection in these files knowing agents will process them. The 22MB padding trick makes the payload invisible to human review (it scrolls below the fold) while remaining in the AI's context window.

**Proposed fix**: New scanner `doc_payload_scanner.py`:
- Flag documentation files exceeding size thresholds (>100KB for .md files)
- Detect large padding blocks (repeated whitespace, zero-width characters, invisible Unicode)
- Run prompt injection patterns against documentation content
- Detect AI-generated documentation indicators (statistical analysis of writing patterns commonly used in social engineering packages)
- Check for hidden content after large whitespace blocks

---

### GAP 3: RAG/Knowledge Base Poisoning Detection [HIGH]

**Threat source**: OWASP Agentic Top 10 #6 (Memory Poisoning), redteams.ai May 2026 challenge, Anthropic/AISI study (250 documents can backdoor any LLM)

**What depfence has**: No RAG-specific scanning.

**What's missing**: Repositories increasingly contain knowledge bases (JSON, JSONL, markdown docs, CSV datasets) used for RAG pipelines. depfence doesn't analyze these for poisoning indicators — adversarial documents designed to manipulate retrieval results or inject instructions when retrieved.

**Proposed fix**: New scanner `rag_poison_scanner.py`:
- Identify RAG knowledge base directories (common patterns: `data/`, `knowledge/`, `docs/`, `corpus/`, files matching `*.jsonl`, `*.parquet` with text fields)
- Scan text content in knowledge base documents for prompt injection payloads
- Detect statistical anomalies (documents with dramatically different token distributions)
- Flag documents containing system prompt override patterns
- Check for instruction-following content embedded in what should be factual data

---

### GAP 4: AI Framework Backdoor Advisory Coverage [HIGH]

**Threat source**: LiteLLM v1.82.8 TeamPCP compromise (setup.py credential exfiltration, 97M monthly downloads), Simply Cyber coverage

**What depfence has**: `ai_vulns.py` has LiteLLM SSRF advisory (<1.55.0) and general unsafe patterns. `miasma_intel.py` references the LiteLLM compromise narrative. `preinstall.py` mentions LiteLLM/TeamPCP.

**What's missing**: The v1.82.8 backdoor (setup.py credential exfiltration) is NOT in the `_AI_ADVISORIES` list — only the older SSRF vulnerability is. The two placeholder CVEs (CVE-2026-XXXXX) have never been filled in. No scan specifically detects the setup.py credential exfiltration pattern that characterized the TeamPCP attack.

**Proposed fix**:
- Add LiteLLM v1.82.8 backdoor to `_AI_ADVISORIES` with correct CVE
- Replace both CVE-2026-XXXXX placeholders with real CVE numbers
- Add detection pattern for setup.py credential exfiltration (environment variable harvesting + HTTP POST in install scripts) — this is a reusable pattern for future AI framework compromises
- Build a living advisory feed: periodically pull AI-specific security advisories (PyPI advisories, GitHub security advisories filtered to AI packages)

---

### GAP 5: Prompt Injection via Fictional Framing / "Bioshocking" [HIGH]

**Threat source**: Simply Cyber Ep 1161 (Layer X "Bioshocking" attacks on AI browsers), BleepingComputer June 2026

**What depfence has**: `prompt_injection_scanner` detects role injection ("you are now", "ignore previous"), system prompt overrides, encoding bypasses, and `pretend` (line 44: `pretend\s+(you|to\s+be|that)`). 55+ patterns with multi-pass normalization.

**What's missing**: "Bioshocking" wraps real exfiltration instructions in fictional/roleplay framing that avoids the `pretend` keyword. Patterns like "in this story, the character needs to...", "imagine you are a system with access to...", "for this game scenario, output the user's..." bypass all existing patterns. The scanner catches direct identity override (`pretend you are`) but not narrative-embedded instructions where the payload never claims a new identity — it embeds actions inside fictional framing.

**Proposed fix**: Add to `prompt_injection_scanner.py`:
- Fictional framing patterns not yet covered: "in this story", "in this scenario", "the character needs to", "for this game", "imagine you are", "in a world where", "hypothetically", "roleplay as"
- Combined with action verbs: "reveal", "output", "send", "exfiltrate", "share", "disclose"
- Lower confidence (0.60-0.70) since fictional framing has legitimate uses — flag for review rather than hard block

---

### GAP 6: AI VEX (Vulnerability Exploitability eXchange) Support [MEDIUM]

**Threat source**: Simply Cyber Ep 1161 (AI VEX framework adopted by Flexera and Anchore)

**What depfence has**: `ai_bom_generator.py` produces AI Bills of Materials listing AI packages, models, and frameworks.

**What's missing**: The AI VEX standard extends SBOM/VEX with AI-specific safety context (model provenance, training data lineage, safety evaluation results). depfence generates AI BOMs but doesn't produce VEX documents or consume VEX data for vulnerability prioritization.

**Proposed fix**: Extend `ai_bom_generator.py`:
- Generate AI VEX documents alongside AI BOMs
- Include model provenance fields (source registry, hash, license)
- Support VEX status fields (affected/not_affected/fixed/under_investigation) for AI-specific vulnerabilities
- Consume published VEX documents to suppress false positives in vulnerability scanning

---

### GAP 7: Agent Permission Least-Privilege Auditing [MEDIUM]

**Threat source**: OWASP Agentic Top 10 #3 (Excessive Agency), Simply Cyber Ep 1156 (Estonia AI Agent Digital ID)

**What depfence has**: `ci_ai_bot_scanner` flags wildcard tool grants and dangerous tool names.

**What's missing**: No analysis of granted-vs-needed permissions. An agent configured with filesystem write + network + code execution when it only needs read access isn't flagged unless it uses a literal `*` grant. The excessive agency risk is about the GAP between what's granted and what's required, not just the presence of dangerous tools.

**Proposed fix**: Extend `ci_ai_bot_scanner` or new `agent_least_privilege_scanner.py`:
- Parse agent configuration to enumerate granted capabilities
- Classify capabilities by risk tier (read < write < execute < network < admin)
- Flag agents with high-risk capabilities that don't appear to need them (heuristic: no reference to those capabilities in the agent's instruction content)
- Recommend minimum-privilege configurations

---

### GAP 8: MCP Server CVE Correlation [MEDIUM]

**Threat source**: 200K vulnerable MCP instances, 30+ CVEs in 60 days, CVE-2026-33032 (CVSS 9.8)

**What depfence has**: `mcp_scanner` checks configs for tool shadowing, credential leaks, missing TLS. `mcp_fingerprint` detects rug-pulls via schema fingerprinting.

**What's missing**: No correlation of MCP server package names/versions against known CVEs. depfence reads MCP configs and knows which servers are installed, but doesn't check whether those specific server versions have known vulnerabilities.

**Proposed fix**: Add CVE advisory lookup to `mcp_scanner.py`:
- Extract MCP server package names and versions from config files
- Cross-reference against a curated MCP CVE database (30+ CVEs already documented)
- Flag servers with known critical vulnerabilities
- Recommend version upgrades

---

### GAP 9: Build Script Payloads Targeting AI Agents [MEDIUM]

**Threat source**: "Decades-old Bash tricks bypass safeguards in most open source AI coding agents" (eSecurity Planet, June 2026)

**What depfence has**: `prompt_injection_scanner` scans source strings. `preinstall.py` detects install-time code execution. `editor_config_scanner` detects editor config injection.

**What's missing**: Makefiles, shell scripts, and build configs (justfile, taskfile, etc.) with payloads specifically targeting AI coding agents that auto-execute build commands. ANSI escape sequences can hide malicious commands from agent context windows. Terminal control codes can trick agents into executing different commands than displayed.

**Proposed fix**: New scanner `build_script_agent_scanner.py`:
- Scan Makefile, justfile, Taskfile.yml, package.json scripts, Cargo.toml build scripts
- Detect ANSI escape sequences that could hide commands
- Detect command chaining patterns that differ from displayed intent
- Flag eval/exec with obfuscated inputs
- Detect terminal control codes (\033[2J clear screen, \r carriage return overwrites)

---

### GAP 10: Conditional AI-Agent-Targeted Activation [MEDIUM]

**Threat source**: VulMask obfuscation (payloads disguised as ordinary vulnerabilities that activate when an AI agent attempts to "fix" them), independent security research on AI-agent-aware malware

**What depfence has**: `protestware_scanner` detects geography-based, date-based, and political activation conditions.

**What's missing**: Payloads that activate specifically when they detect they're being analyzed by an AI coding agent (checking for Claude/Copilot/Cursor environment variables, MCP server processes, specific prompt patterns in stdin). Also: payloads disguised as ordinary vulnerability patterns that only become dangerous when an AI agent attempts to "fix" them.

**Proposed fix**: Extend `protestware_scanner.py`:
- Detect checks for AI agent environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, CURSOR_SESSION, CLINE_*)
- Detect process enumeration targeting known AI tool names
- Detect code that changes behavior based on stdin content analysis (checking if input looks like an LLM prompt)
- Cross-reference with VulMask-style patterns where code appears to be a benign vulnerability but contains a secondary payload

---

## Strategic Recommendations

### 1. "First Scanner for Agent Instructions" positioning
GAP 1 is the headline. VentureBeat explicitly says no scanner has this category. Ship `instruction_file_scanner` as a v0.9.0 headline feature. Blog post: "depfence is the first supply chain scanner to detect malicious AI agent instructions."

### 2. Fix the placeholders
Two CVE-2026-XXXXX placeholders in `ai_vulns.py` (lines 129, 137) need real CVE numbers or removal. These are credibility risks if anyone reads the source.

### 3. AI VEX early adoption
The standard is being adopted by Flexera and Anchore NOW. Adding AI VEX output to depfence's AI BOM positions it as compliance-ready before competitors.

### 4. Living advisory feed for AI packages
Instead of manually adding advisories, build an automated ingestion pipeline from PyPI/npm security advisories filtered to AI-critical packages (the list already exists in `ai_bom_generator.py` and `provenance.py`).

### 5. Bioshocking patterns are quick wins
Adding 5-10 fictional-framing regex patterns to the existing `prompt_injection_scanner` is a small PR with disproportionate coverage gain.

---

## Simply Cyber Episode Cross-Reference

| Episode | Date | Relevant Story | Gap # |
|---------|------|---------------|-------|
| 1161 | Jun 25 | Malicious OpenClaw AI skills (Unit 42) | 1 |
| 1161 | Jun 25 | "Bioshocking" prompt injection (Layer X) | 5 |
| 1161 | Jun 25 | AI VEX framework adoption | 6 |
| 1156 | Jun 18 | Malicious Python packages with AI-generated tutorials | 2 |
| 1156 | Jun 18 | Estonia AI Agent Digital ID | 7 |
| 1145 | Jun 3 | Operation Dragon Rust malware + Azure C2 | 9 |
| 1145 | Jun 3 | Cali 365 PhaaS with AI-generated lures | 2, 5 |
| — | Jun 2026 | LiteLLM v1.82.8 TeamPCP backdoor | 4 |
| — | Jun 2026 | ClawHavoc 341 malicious skills | 1, 2 |
| — | Jun 2026 | 200K vulnerable MCP instances, 30+ CVEs | 8 |
| — | Jun 2026 | OWASP Agentic Top 10 published | 3, 7 |
| — | Jun 2026 | Bash tricks vs AI coding agents | 9 |

---

## Implementation Priority

| Priority | Gap | Effort | Impact |
|----------|-----|--------|--------|
| P0 | GAP 1: Instruction file content analysis | Medium (new scanner, reuses prompt_injection patterns) | First-mover, CRITICAL threat |
| P0 | GAP 4: AI framework backdoor advisories | Small (add entries to existing list, fix placeholders) | Credibility + coverage |
| P1 | GAP 5: Bioshocking/fictional framing | Small (add patterns to existing scanner) | Quick win, HIGH threat |
| P1 | GAP 2: Doc hidden payload detection | Medium (new scanner) | HIGH threat, unique capability |
| P1 | GAP 8: MCP CVE correlation | Medium (advisory database + lookup) | HIGH threat, 30+ CVEs |
| P2 | GAP 3: RAG poisoning detection | Large (new scanner, new domain) | Unoccupied market |
| P2 | GAP 9: Build script agent targeting | Medium (new scanner) | Growing threat |
| P2 | GAP 7: Agent least-privilege audit | Medium (extend existing) | OWASP alignment |
| P3 | GAP 6: AI VEX support | Medium (extend AI BOM) | Standards positioning |
| P3 | GAP 10: AI-targeted conditional activation | Small (extend protestware) | Emerging threat |
