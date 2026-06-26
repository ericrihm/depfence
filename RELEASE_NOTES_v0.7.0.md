# depfence v0.7.0

AI-aware dependency security scanner — 45 scanners covering attack classes that CVE-based tools miss.

## Highlights

### Anti-analysis evasion detection (Gaslight-style)

21+ new patterns in the `prompt_injection` scanner detect malware that tricks AI security agents into aborting analysis. Covers the techniques documented in the [Gaslight macOS malware](https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html) (DPRK attribution):

- Fake resource exhaustion (token budget, OOM, disk full)
- Analysis abort/skip/cease instructions with synonym coverage
- Negative-imperative blocks ("do not analyze", "prohibited from processing")
- Fake prior-clearance and safe-to-ignore claims
- Emotional coercion and clean-result demands
- Legal/regulatory threats (CFAA, GDPR, ITAR, FISA)
- Fake classification markings (TOP SECRET, TS/SCI, NOFORN)
- Markdown-fenced fake system/error/warning blocks

### CBRN refusal-trigger shield stripping

New `strip_cbrn_shield()` preprocessor removes CBRN-themed content (nuclear, biological, chemical, radiological, explosive) used as AI refusal-trigger shields in malware, preserving functional code for safe analysis.

### Adversarial test suite

153 new tests covering every anti-analysis evasion pattern, CBRN shield stripping, ANSI escape hiding, encoding bypass attempts, real-world attack reproductions (Gaslight, jqwik), and false positive resistance.

## What's new

- 21+ anti-analysis evasion detection patterns
- `strip_cbrn_shield()` preprocessor for safe malware analysis
- `_CBRN_SHIELD_PATTERN` regex for refusal-trigger identification
- 153-test adversarial evasion test suite
- Configurable signal bus path via `DEPFENCE_SIGNAL_BUS` env var
- Prompt injection pattern count increased from 34 to 55+
- Benchmark comparison vs Snyk, Trivy, Grype, Semgrep, Socket.dev
- GitHub issue templates (bug report, false positive, feature request)
- PR template with scanner checklist
- CONTRIBUTING.md contributor guide
- Documentation site with benchmark page

## Stats

- **45** scanner modules (42 entry-point + 33 project)
- **3,331** tests across 121 test files
- **55+** prompt injection detection patterns
- **13** ecosystems supported
- **6** output formats (table, JSON, SARIF, HTML, CycloneDX, SPDX)

## Install

```bash
git clone https://github.com/ericrihm/depfence && cd depfence
pip install -e .
depfence scan .
```

## Full changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed changes across all versions.
