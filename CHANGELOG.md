# Changelog

All notable changes to depfence are documented here.

## [0.8.0] - 2026-08-16

### Added

- Schema-validated artifact runtime diagnostics and artifact intake contracts,
  plus distinct SARIF identities for visual-text-deception subrules.
- Canonical AI-profile routing for `ai-scan` and CI path triggers for font,
  web, DOCX, and PDF inputs.
- Canonical 56-scanner catalog with named execution coverage and scanner errors.
- Versioned `depfence.snapshot/v1` contract and product-native project dashboard.
- Optional adapter for the separately versioned shared artifact runtime.
- Network-denial, symlink-containment, archive-budget, redaction, and scanner-timeout contracts.
- Official MCP SDK v2 server with modern/legacy client compatibility, structured tool results, and root containment.
- Packaged `depfence.scan/v1` and `depfence.snapshot/v1` JSON Schemas.
- Named scanner profiles: `full`, `advisory`, `ai`, `mcp`, `ci`, and `model`.
- Provenance-aware CI agent flows for event files and downloaded artifacts.
- Bounded RAG corpus poisoning scanner for text, JSON, JSONL, and CSV ingestion roots.
- Quarantine-first visual-text deception inspection for OpenType/WOFF, HTML/CSS,
  DOCX, and PDF, with an explicit digest-pinned OCI boundary for optional rendering.
- Purpose-scoped signed OCI workers, runtime doctors, allowlisting-proxy sealed
  acquisition, and offline exact-commit font/document blob analysis with
  redacted evidence and delete-by-default artifact retention.
- Project-scoped MCP and external-instruction fingerprint state with separate
  observed and explicitly approved digests, exact-digest CLI approval, and
  persistent drift reporting.
- Privacy-preserving repository fleet inventory/audit, quarantine-first Git
  intake, manifest-only sealed OCI Git intake, and dry-run-first private-state
  migration and retention commands.
- Versioned evidence and advisory envelopes for provider-neutral private model
  routing; advisory output cannot alter deterministic scan assurance.
- One canonical finding identity shared by JSON, snapshots, SARIF, regression
  ledgers, and the versioned fail-closed knowledge-graph reporter.

### Changed

- Incomplete scans are `INDETERMINATE` and fail closed by default; `--allow-incomplete` is explicit.
- Offline mode now blocks registry, advisory, provenance, EPSS, KEV, and scorecard clients.
- User-global MCP configuration and host build caches require explicit opt-in.
- CI and publishing validate distributions, version parity, action pins, wheel entry points, and least privilege.
- Scanner documentation now reflects 56 registered and 44 project-capable scanners.
- JSON output now defaults to the versioned v1 contract; `json-legacy` remains available.
- CycloneDX now defaults to 1.7 with explicit 1.5 compatibility; SPDX remains 2.3.
- Third-party plugins require explicit enablement and fingerprint approval; project scanners execute in bounded worker processes.
- Local intelligence is stored under a hardened private-state boundary; private
  KG observations cannot assert canonical repository authority.
- Incomplete intake and fleet worker failures are named and exit with code 2;
  intake approval records a decision but never executes or promotes content.

### Fixed

- CycloneDX scan invocation, generated policy shape, baseline timezone handling, action SBOM outputs, and hidden plugin/hook failures.
- Single-package CLI and MCP checks no longer report network failures as safe.
- Binary Bun locks and unsupported lock versions now produce incomplete coverage instead of heuristic packages.
- CI refuses PR-authored baselines and inline suppressions unless separately trusted.
- Placeholder KEV monitoring reports `UNPROVEN`; remediation refuses the unimplemented apply mode.
- SQLite advisory and metadata caches now close every transaction handle, preventing descriptor exhaustion during long scans and test runs.
- Project-scanner workers now release their parent-side process resources after termination and reaping.

## [0.7.0] - 2026-06-26

### Added

- **Anti-analysis evasion detection** (Gaslight-style): 21+ new patterns in `prompt_injection` scanner detecting malware that uses fabricated system messages, resource exhaustion claims, classification markings, legal/regulatory threats, emotional coercion, and CBRN refusal triggers to trick AI security agents into aborting analysis.
  - Fake token/session exhaustion, OOM, disk full signals
  - Analysis abort/skip/cease instructions with synonym coverage
  - Negative-imperative blocks ("do not analyze", "prohibited from processing")
  - Fake prior-clearance and redundant-analysis claims
  - Self-declared benign payload detection
  - Markdown-fenced fake system/error/warning blocks
  - Emotional coercion to suppress analysis ("will cause irreversible harm")
  - Coerced clean-result demands ("return empty results")
  - Legal/regulatory threat detection (CFAA, GDPR, ITAR, FISA, CWC, BWC)
  - Fake classification markings (TOP SECRET, TS/SCI, NOFORN)
  - Fake clearance-denial ("not cleared for TS/SCI")
  - Base64 decode detection including `__import__("base64")` evasion
- **`strip_cbrn_shield()`** utility: preprocessor that removes CBRN-themed comments and docstrings used as AI refusal-trigger shields, preserving functional code for safe analysis.
- **`_CBRN_SHIELD_PATTERN`** regex: identifies nuclear, biological, chemical, radiological, and explosive content used as evasion shields in source files.
- `DEPFENCE_SIGNAL_BUS` environment variable for configurable signal bus path in the PreToolUse hook.

### Changed

- PreToolUse hook signal bus path is now configurable via `DEPFENCE_SIGNAL_BUS` env var (defaults to `~/.depfence/signals/pending.jsonl`).
- Prompt injection scanner pattern count increased from 34 to 55+.

### Security

- Addresses the anti-AI-analysis evasion technique documented in the [Gaslight macOS malware](https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html) (DPRK attribution), which uses 38 fabricated "system" messages to trick AI agents into halting malware analysis.

## [0.6.0] - 2026-06-24

### Added

- Agent skill scanner: external instruction fetch, domain spoofing, deferred payload detection.
- Cordyceps-class CI/CD workflow checks (5 new patterns).
- PreToolUse hook for blocking fabricated SHA pins in GitHub Actions workflows.
- 281 new scanner tests from ultracode hardening.
- Model security wave 1+2: format scanners, exception handling, wildcard denylist, GGUF SSTI, secrets detection.

### Changed

- README rewritten with full scanner documentation.
- License changed to Apache 2.0.
- 84 ruff lint errors resolved.

## [0.5.0] - 2026-06-03

### Added

- Initial public release.
- 42 entry-point scanners + 21 project scanners.
- Prompt injection, slopsquatting, MCP auditing, fabricated-pin resolution.
- AI model security (pickle, GGUF, ONNX, TFLite).
- SBOM generation (CycloneDX 1.5, SPDX 2.3, SARIF).
- GitHub Actions, GitLab CI, pre-commit hook integration.
- MCP server for AI coding assistant integration.
- Plugin system via pip entry points.
