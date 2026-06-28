# Changelog

All notable changes to depfence are documented here.

## [0.8.0] - 2026-06-28

### Added

- `CITATION.cff` for standardized software citation (GitHub "Cite this repository" support).
- `.zenodo.json` metadata for Zenodo DOI archival.

### Changed

- Author attribution updated to Eric Rihm (was "depfence contributors").
- Scanner count updated to 56 across project metadata.

### Removed

- `.mcp.json` removed from version control (internal MCP configuration).

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
