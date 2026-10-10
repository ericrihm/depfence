# depfence Gap Analysis: Simply Cyber x June 2026 Threat Landscape

**Date**: 2026-07-01
**Source**: Simply Cyber Daily Cyber Threat Brief Ep 1143-1164 (Jun 1-30, 2026) cross-referenced against depfence v0.8.0 (56 scanners)
**Method**: Threat stories from 22 episodes + independent research on AI agent attack vectors, verified against depfence source code

## W1 advisory truth repair — 2026-10-09

**Status**: LOCAL_VERIFIED for the bounded source-selected catalogue/API/offline CLI; observed parent proof below. This section supersedes
the unqualified catalogue/placeholder claims in GAP 4 and recommendation 2 below,
not the rest of this historical audit.

**Plan / scope**: Adjudicate all 18 original `ai_vulns.py` rows against published
CNA records and upstream security advisories. Remove unsupported claims from
runtime findings; correct evidenced package mappings, intervals, titles and
severity. Use existing `Finding.references`, explicit optional `fix_version`,
and the already-required `packaging` dependency for interval matching. Preserve
the public `check_package_version` interface, inert behavioral scanning and
benign-file behavior. Update its actual CLI allowlist and semantic tests.
No advisory feed, scanner redesign, exploit execution or network scan is in scope.

**Frozen consumer expectations before implementation** (primary records read):
`langchain` 0.0.246 is affected by CVE-2023-36188, 0.0.247 is patched;
`transformers` 4.35.2 is affected by CVE-2023-7018, 4.36.0 is patched;
`mlflow` 2.9.1 is affected by CVE-2023-6831, 2.9.2 is patched;
`gradio` 5.5.0 is affected by CVE-2025-23042, 5.6.0 is patched;
`torch` 1.13.0 must not promote rejected CVE-2024-5480;
`pytorch-lightning` 2.4.0 and `litellm` 1.54.0 must not promote placeholders;
Ray 2.8.0 has a disputed published report but no evidenced patched version.
An empty result is catalogue non-coverage, not an assurance of safety.

**Evidence / checks**: Before repair, `.venv/bin/python .trip-w1-advisory-before.py`
exited 0 under Python 3.14.8 and wrote `.trip-w1-advisory-before.json`. Both
placeholder packages became `known_vulnerability` with invented patch versions;
rejected torch CVE-2024-5480 was promoted; MLflow 2.9.1 and Gradio 5.5.0 were
missed; Ray 2.8.0 was assigned the unsupported fix 2.8.1. These are API receipts,
not exploitation. Retain both scratch files until parent durable capture.
Parent owns subsequent focused pytest, actual API and offline `scan_project`
consumers. No worker test/build/lint/formatter execution or after-proof.
Portable TRIP research/plan/implement/test/review skills
were read; no project specialization exists. LSP reference request via
`xd://lsp` returned “No such tool”; targeted references found the CLI and
`tests/test_ai_vulns.py`.

### Complete original catalogue disposition (18/18)

Sources below were retrieved on 2026-10-09. A CNA `PUBLISHED` status is not a
claim that the scanner proved exploitability in a particular deployment. Prefer
upstream patch/severity statements when the CNA copy is stale; explicit conflicts
and missing mappings remain visible. The original catalogue had 18 rows; 11 now
have corrected supported entries and 7 are quarantined only in this document.
No quarantine row emits `KNOWN_VULN`, even without a CVE. This denominator is
research evidence, not a runtime/test count invariant.

| Original row / rejected assertion | Authoritative adjudication (identity, affected interval, patch, issue, severity, status) | Runtime disposition |
| --- | --- | --- |
| 1. `langchain <0.0.325`, CVE-2023-44467, critical “Arbitrary code execution via LCEL” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-44467) says Experimental PALChain `__import__` bypass in LangChain before 0.0.306, not LCEL. [Reviewed package record](https://github.com/advisories/GHSA-gjjr-63x4-v8cq) maps PyPI `langchain-experimental <=0.0.14`, critical 9.8, patched **None**. Published; monorepo version is not the Experimental distribution version. | Correct to `langchain-experimental <=0.0.14`, PALChain code execution, critical, `fix_version=None`. Reject the original main-package range, LCEL title and inferred 0.0.325 fix. |
| 2. `langchain <0.0.312`, CVE-2023-36188, critical “Prompt injection via PALChain” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-36188) identifies PALChain exec arbitrary code execution in 0.0.64. [Reviewed package record](https://github.com/advisories/GHSA-57fc-8q82-gfp3), updated 2026-07-06, maps `langchain <0.0.247`, patched 0.0.247, critical 9.8. Published. | Correct range/fix to 0.0.247 and title to arbitrary code execution via PALChain. |
| 3. `transformers <4.36.0`, CVE-2023-7018, high “Unsafe pickle deserialization in model loading” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-7018): Hugging Face Transformers `<4.36`, untrusted-data deserialization, critical 9.6, published; references upstream fix commit. | Retain boundary 4.36.0, correct severity to critical and scope title to untrusted-data deserialization. |
| 4. `torch <2.1.0`, CVE-2024-5480, high “Arbitrary code execution via torch.load” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2024-5480): **REJECTED**, 2024-10-02; withdrawn by its CNA. No supported interval, severity or patched version survives rejection. | Quarantine entire claim, including 2.1.0 fix. Existing behavioral `torch.load` pattern remains, without this CVE. |
| 5. `llama-index <0.9.0`, CVE-2024-1455, high “Server-side request forgery in data connectors” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2024-1455): LangChain XML entity expansion/Billion Laughs DoS, `<0.1.35`, medium 5.9, published. [Reviewed distribution mapping](https://github.com/advisories/GHSA-q84m-rmw3-4382) is **langchain-core**, patched 0.1.35; applies to exposed XMLOutputParser usage, not LlamaIndex SSRF. | Correct to `langchain-core <0.1.35`, fix 0.1.35, medium XML entity expansion. Reject every part of the LlamaIndex mapping. |
| 6. `gradio <4.0`, CVE-2023-51449, high “Path traversal allows arbitrary file read” | [GitHub CNA](https://cveawg.mitre.org/api/cve/CVE-2023-51449) and linked upstream advisory: Gradio `/file` traversal `<4.11.0`, patched 4.11.0, medium 5.6, published; public application access and known file paths matter. | Correct threshold/fix to 4.11.0 and severity to medium; scoped `/file` title. |
| 7. `tensorflow <2.14.0`, CVE-2023-25668, high “Multiple memory corruption vulnerabilities” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-25668) lists `<2.11.1`, critical 9.8; [upstream](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-gw97-ff7c-9v96) identifies a **single** QuantizeAndDequantize heap out-of-bounds read, lists `<2.12.0` with 2.11.1 backport and 2.12.0 patches, and rates moderate. Published; severity disagreement retained here. | Use `<2.11.1`, explicit earliest backport 2.11.1, upstream moderate/`MEDIUM`, specific operation title. Do not flag patched 2.11.1/2.12/2.13 or infer 2.14 fix. |
| 8. `onnx <1.14.0`, CVE-2023-32577, medium “Directory traversal in model path handling” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-32577): WordPress **DevBuddy Twitter Feed** plugin `<=4.0.0`, administrator stored XSS, medium 5.9, published. No ONNX identity/range/patch established. | Quarantine wrong-product claim; no replacement ONNX CVE invented. |
| 9. `mlflow <2.9.0`, CVE-2023-6831, critical “Remote code execution via crafted model artifact” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-6831): MLflow path traversal `<2.9.2`, high 8.1, published, upstream fix referenced. | Correct threshold/fix to 2.9.2, title to path traversal and severity to high. |
| 10. `ray <2.8.1`, CVE-2023-48022, critical “Unauthenticated RCE on Ray dashboard” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2023-48022), updated 2025-12-17: named **2.6.3 and 2.8.0**, job submission API arbitrary code execution; published **disputed**. CISA ADP critical 9.8. No patched release asserted. [Upstream security model](https://docs.ray.io/en/latest/ray-security/index.html): controlled network/trusted clients required; token auth from 2.52.0 is defense in depth, not replacement for isolation. | Only named versions (`==2.6.3` OR `==2.8.0`) emit an explicitly disputed report, no fix. Reject invented 2.8.1 patch and broad `<2.8.1` interval. Other versions are unqualified, not safe. |
| 11. `auto-gpt <0.6.0`, CVE-2026-33233, critical “Arbitrary code execution in AutoGPT plugin system” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2026-33233) and [upstream](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-rfg2-37xq-w4m9): **AutoGPT Platform backend** Redis cache pickle deserialization `>=0.6.34,<0.6.52`, patched 0.6.52, high 7.6, published. Upstream names `autogpt-platform-backend` without a PyPI ecosystem mapping. | Quarantine `pypi:auto-gpt` claim; platform deployment version cannot be assigned to that distribution. Reject plugin title, severity, range/fix. Missing PyPI identity is unresolved; actual platform report is not denied. |
| 12. `lerobot <0.4.0`, CVE-2026-25874, high “Unsafe pickle deserialization in LeRobot model loading” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2026-25874), updated 2026-07-14: LeRobot `>=0,<=0.5.1`, unsafe deserialization over unauthenticated, non-TLS gRPC async inference, critical 9.3, published. [Distribution metadata](https://pypi.org/pypi/lerobot/0.5.1/json) links PyPI `lerobot` to that repository. No patched version in CNA; upstream 0.6.0 roadmap alone is not patch proof. | Correct to bounded inclusive interval, critical gRPC title, no fix. Versions beyond 0.5.1 are unqualified rather than patched/safe. |
| 13. `onnx <1.17.0`, CVE-2026-28500, high “Hub.load bypass allows loading from arbitrary URLs” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2026-28500): `<=1.20.1`, `silent=True` suppresses repo trust warnings, high 8.6, no patch at publication. [Current upstream advisory](https://github.com/onnx/onnx/security/advisories/GHSA-hqmj-h5c6-369m) explicitly identifies patch **1.21.0** (feature removed) and moderate 4.8. Published; stale CNA patch/severity conflict remains recorded. | Use upstream `<=1.20.1`, explicit fix 1.21.0, medium trust-check bypass title. Reject 1.17.0 “fix” and generic arbitrary-URL formulation. |
| 14. `sglang <0.4.0`, CVE-2026-5760, critical “GGUF Jinja2 SSTI enables full RCE via chat templates” | [CNA](https://cveawg.mitre.org/api/cve/CVE-2026-5760): unsandboxed rerank Jinja environment RCE, affected commit **8f3097e**, published, CISA ADP critical 9.8. [CERT](https://www.kb.cert.org/vuls/id/915947) reported no patch during coordination; [upstream PR 23660](https://github.com/sgl-project/sglang/pull/23660) adds sandboxing. No authoritative released-version interval or patched release was established by those records. | Quarantine original version assertion; cannot convert a commit or researcher 0.5.9 report into `<0.4.0`/0.4.0 release bounds. Genuine CVE exists; release mapping remains unresolved, not package-safe. |
| 15. `transformers <4.48.0`, CVE-2025-47250, critical “RCE via from_pretrained with crafted model repos” | [CVE API](https://cveawg.mitre.org/api/cve/CVE-2025-47250) returned HTTP 404; [CVEProject record path](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/47xxx/CVE-2025-47250.json) also 404; exact-ID public search returned no matching primary record. Publication/reservation state is **unresolved**, not proven nonexistent. No identity, interval, patch, title or severity established. | Quarantine entire unsupported assertion; do not rename to a similar Transformers CVE. |
| 16. `pytorch-lightning <2.5.0`, literal CVE-2026-XXXXX, critical “Supply chain compromise via malicious checkpoint loading” | Placeholder is not a CVE identifier and supplies no record/range. [Actual upstream compromise advisory](https://github.com/Lightning-AI/pytorch-lightning/security/advisories/GHSA-w37p-236h-pfx3), CVE-2026-44484, critical, describes malicious PyPI **2.6.2/2.6.3** credential harvesting and rollback to 2.6.1, not checkpoint loading `<2.5`. Header says `>=2.6.2`; exact set investigation ongoing. | Quarantine original placeholder/range/fix/title. Do not relabel it as the distinct package compromise, or claim 2.4.0 is safe. New-compromise feed coverage is out of this row repair's scope. |
| 17. `litellm <1.55.0`, literal CVE-2026-XXXXX, high “SSRF and credential exposure in proxy endpoint” | Placeholder supplies no published record or 1.55.0 patch. [Related current upstream routing advisory](https://github.com/BerriAI/litellm/security/advisories/GHSA-3cv6-jpf6-8222), CVE-2026-84377, moderate 6.5, has `<1.94.0` header and multiple listed patched branches (1.88.6 through 1.96.2), authenticated SSRF/credential exfiltration; not evidence for original `<1.55`/1.55 fix. Other LiteLLM advisories exist. | Quarantine original placeholder assertion. Do not assign a superficially related ID/range or treat catalogue omission as LiteLLM safety. Resolving that advisory's branch/header inconsistencies would be separate ingestion scope. |
| 18. `gradio <5.0.0`, CVE-2025-23042, high “Multiple path traversal and SSRF vulnerabilities” | [GitHub CNA](https://cveawg.mitre.org/api/cve/CVE-2025-23042): **blocked path ACL case-normalization bypass**, `<5.6.0`, patched 5.6.0, high 8.7, published. [Upstream page](https://github.com/gradio-app/gradio/security/advisories/GHSA-j2jg-fq62-7c3h) has inconsistent prose `<=5.6.0` and patched “None” despite header `<5.6.0`; conflict retained. | Follow explicit published CNA fix/interval 5.6.0, not inferred `<5.0` fix; scoped case-insensitive ACL title, high. The upstream-page discrepancy remains unresolved; this is source-selected catalogue evidence, not independent exploit proof. |

### Implementation and parent proof contract

- Changed `depfence/scanners/ai_vulns.py`, CLI `ai-scan` package mapping,
  `tests/test_ai_vulns.py`, `tests/test_cli_integration.py`, this native audit and
  `CHANGELOG.md`. Public method signatures and the behavioral pattern catalogue
  are unchanged. Findings now carry source references and explicit optional
  patch versions; an upper endpoint is never automatically a patch.
- Version intervals use the existing required `packaging` dependency:
  commas intersect bounds, separate entries are alternatives, inclusive bounds
  remain inclusive, names follow PyPI normalization, and PEP 440 prerelease/local
  version semantics apply. Invalid/non-release versions do not produce a version
  finding. No unknown version is thereby marked safe.
- Parent focused check: `.venv/bin/python -m pytest -q tests/test_ai_vulns.py tests/test_cli_integration.py::test_ai_scan_adjudicated_package_mappings`.
  Prepared but **not executed** by the worker:
  `.venv/bin/python .trip-w1-advisory-after.py` writes a separate after receipt
  `.trip-w1-advisory-after.json`, exercises real API and offline `scan_project`,
  and creates inert `.trip-w1-fixtures/{behavioral,benign,cli}` consumers.
  Then `.venv/bin/python -m depfence.cli.main ai-scan .trip-w1-fixtures/cli --format json --fail-on none`
  provides actual CLI evidence. Parent should capture receipts durably and
  remove only `.trip-w1-advisory-before.py`, `.trip-w1-advisory-before.json`,
  `.trip-w1-advisory-after.py`, its generated JSON, and `.trip-w1-fixtures`.
  Do not rerun the before script after repair: it would overwrite before evidence.
  Actual API proof must cover the frozen positives/patches above, the corrected
  Experimental/Core mappings, inclusive LeRobot/ONNX endpoints, exact Ray
  alternatives with `fix_version=None`, and placeholder/rejected/unresolved
  non-promotion. Assert findings by CVE, not total row counts.
- Offline real `scan_project` proof: disposable source containing inert
  `torch.load("model.bin")` should yield `BEHAVIORAL`, no CVE/patch; another
  disposable file using `weights_only=True` and ordinary pretrained loading
  should have no matching behavior. Do not execute either fixture's contents.
  CLI proof may use synthetic `requirements.txt` with `langchain_core==0.1.34`,
  `langchain-experimental==0.0.14`, `lerobot==0.5.1`, and the two placeholder
  versions; `ai-scan --format json --fail-on none` must expose corrected mappings
  without promoting placeholders.
- This is an offline, manually adjudicated local catalogue, **not** a complete
  AI vulnerability inventory, dynamically updated feed, package-safety verdict,
  deployment applicability proof, novel discovery, or scanner-wide accuracy
  claim. Unresolved/rejected assertions are recorded rather than silently
  reassigned. Parent alone promotes IMPLEMENTED_UNVERIFIED after actual checks.

### Observed parent acceptance and associated accounting repair

Parent exercised all28 prepared package API controls (11 matching reports,17 excluded/unqualified), real behavioral-only `torch.load` inspection and the benign weights-only/ordinary loader control; fixture code was never executed. Actual offline CLI exposed the corrected Core/Experimental/LeRobot mappings with no placeholder promotion. Read-only AI review found no actionable owned-delta defects; it is not independent human or exploitation qualification.

The actual CLI also exposed a preexisting associated truth bug: `packages_scanned` was derived from packages with findings, reporting3 for four recognized/versioned inputs in five parsed fixture rows. Parent repaired that field to count distinct canonical eligible name/version pairs in the actual catalogue loop, separately from findings. Permanent real-CLI regressions cover the mixed case and two eligible inputs with zero findings. After repair, actual mixed CLI returned4 eligible/3 findings and no-finding CLI returned2 eligible/0 findings; input hashes were unchanged. This is not a full parsed-dependency or source-file coverage field.

Initial native pytest command could not run because the project environment lacks pytest; the GRC interpreter alternative lacked Click and failed collection. Neither failure is a pass, and no dependency was installed. Parent then ran the actual tests under the native Python3.14.8 interpreter, keeping its production dependencies first and appending the already-installed pure-Python pytest9.0.3/pytest-asyncio1.4.0 cache from GRC, with plugin autoload disabled. All40 selected API/behavior/base CLI tests passed; after the accounting repair, the two affected CLI tests passed. Each run emitted the cached-runner plugin assertion-rewrite warning; no product test failed. Other unchanged checks were not repeated.

The standalone repository retains the complete 18-row disposition above, the
[implementation and proof contract](#implementation-and-parent-proof-contract),
and the [bounded observed acceptance summary](#observed-parent-acceptance-and-associated-accounting-repair).
Exact historical commands, cache runner/source method, raw before/after receipts
and accepted source fingerprints are separately retained in the unshipped estate
archive: `security-work/2026-10-09-trip-estate-wave3.md` and
`security-work/2026-10-09-trip-estate-wave3-evidence.json`. Those archive files are
not part of this Git tree or required to resolve the native summary; no raw
archive is imported into this repository. Before observations have no
worker-captured cryptographic pre-edit source hash; final accepted source SHA256
is recorded, not retroactively assigned to before execution. Owned scratch was
removed after durable capture; the scratch commands above are historical proof
instructions, not available standalone verification tools. No real
corpus/account/state or public release was touched.


---

## Executive Summary

depfence has strong coverage of traditional supply chain attacks (typosquatting, dep confusion, CI injection) and emerging AI threats (prompt injection, MCP tool poisoning, Gaslight-style anti-analysis). However, the June 2026 threat landscape reveals **10 verified gaps** where real-world attacks succeed against patterns depfence does not yet detect. The single biggest opportunity: **agent instruction file content analysis** — VentureBeat confirms "no supply chain scanner has a detection category for it." depfence can be first.

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

**Historical claim, superseded by W1 above**: The July audit described LiteLLM
SSRF `<1.55.0` and placeholder CVEs as if they were established advisory coverage.
Those entries were unsupported, not verified older SSRF coverage. W1 quarantines
them and adjudicates the complete original catalogue; unrelated compromise/feed
coverage and reusable install-script patterns are outside this repair.

**Proposed fix**:
- Any future compromise advisory addition must establish distribution identity,
  exact affected versions and remediation from primary sources.
- Do not replace placeholders with superficially related real CVE numbers.
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
The historical placeholders were symptoms of an unadjudicated catalogue. W1 above removes unsupported runtime claims and records the full 18-row disposition; source-selected findings still require deployment applicability review.

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
