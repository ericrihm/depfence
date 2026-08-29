# Visual-text deception defense methodology

DepFence treats an “evil font” as one instance of a broader representation-disagreement
problem. Rendered pixels, stored Unicode, PDF extraction, DOCX stories, browser selection,
accessibility output, clipboard serialization, OCR, and AI-ingested text may disagree.

## Evidence and policy

Every conclusion is classified independently from the ingestion decision:

- `proven`: a bounded rendered region disagrees with its machine-readable representation
  at the declared OCR/confidence thresholds.
- `heuristic`: structural evidence such as a sparse companion-font cluster, conflicting
  Unicode cmap subtables, per-character font switching, or hidden PDF text topology.
- `unproven`: a required member, story, page, presentation mechanism, browser channel, or
  object could not be processed within policy.
- `out_of_scope`: a mechanism the declared worker version does not inspect.

The corresponding ingestion policy is `allow`, `quarantine`, `confirm`, or `unproven`.
Suspicious or confirmed disagreement is quarantined. Incomplete analysis fails closed as
`unproven`. Document content never receives network, secret, write, or tool authority.

## Current coverage

Font inspection decodes OpenType, WOFF, WOFF2, and TTC members through FontTools; enumerates
Unicode cmap subtables; reports conflicts; and records GSUB, variation, CFF/CFF2, SVG,
color, and bitmap presentation mechanisms. Sparse clusters remain heuristic. A font name is
not treated as identity, and semantic outline claims require trusted rendered references.

DOCX inspection bounds ZIP/XML expansion and walks document, header, footer, footnote,
endnote, comment, glossary, field, revision, hidden-text, and text-box structures. It records
all four `rFonts` classes. DF-DOCX-002 independently flags documents with 3+ hidden runs
(`w:vanish`/`w:webHidden`/white text color) or 5+ revision-tracking nodes, even without
font-switching. White/near-white text (`w:color` values FFFFFF, FEFEFE, FDFDFD, FCFCFC)
counts as a hidden run because it is invisible on a white background.
PDF inspection uses decoded objects and content operations,
including recursive form XObjects, Type 3 fonts, `ToUnicode`, rendering mode, clipping,
transforms, optional layers, `ActualText`, and white-on-white fill color. DF-PDF-001 now
detects both invisible rendering mode (Tr 3) and white fill color (`1 1 1 rg` or `1 g`
with values ≥ 0.98). DF-PDF-002 detects active content (JavaScript, `/OpenAction`, `/AA`
auto-actions). DF-PDF-003 flags incremental saves (multiple `%%EOF` markers) that can
shadow earlier content. Render comparison aligns PDF evidence per page so a mismatch late
in a document is not averaged away.

Local HTML can be rendered in the separate Chromium worker with JavaScript and networking
disabled. Accessibility, selection, and clipboard collection are not yet implemented, so
HTML rendered analysis remains explicitly `unproven`; static web-font correlation is only
a heuristic.

## Detection rules

| Rule | Description | Tier | Confidence | Severity | Evidence Class |
|------|-------------|------|------------|----------|----------------|
| DF-FONT-001 | Sparse companion-font cluster | 1 | 0.76 | MEDIUM | `sparse_font_cluster` |
| DF-FONT-002 | Conflicting Unicode glyph mappings | 1 | 0.82 | MEDIUM | `cmap_subtable_conflict` |
| DF-FONT-003 | Degenerate glyph-to-codepoint mapping (>20:1) | 1 | 0.92 | HIGH | `degenerate_cmap` |
| DF-FONT-004 | Stealth font zero-width glyphs (≥8) | 1 | 0.90 | HIGH | `zero_width_stealth` |
| DF-FONT-005 | Missing layout tables (26+ codepoints) | 1 | 0.55 | LOW | `missing_layout_tables` |
| DF-WEB-001 | Per-character web-font construction | 1 | 0.78 | MEDIUM | `structural_correlation` |
| DF-DOCX-001 | Embedded-font run switching | 1 | 0.84-0.90 | MEDIUM | `structural_correlation` |
| DF-DOCX-002 | DOCX hidden/revision-tracked content | 1 | 0.65 | MEDIUM | `hidden_document_content` |
| DF-PDF-001 | PDF invisible text topology | 1 | 0.62 | MEDIUM | `hidden_text_topology` |
| DF-PDF-002 | PDF active content (JS/auto-actions) | 1 | 0.90 | HIGH | `active_content` |
| DF-PDF-003 | PDF incremental saves (multiple `%%EOF`) | 1 | 0.70 | MEDIUM | `incremental_save` |
| DF-VIS-001 | Rendered vs machine text disagreement | 2 | 0.75-0.99 | HIGH/CRIT | `rendered_text_comparison` |

The sealed intake validator accepts these ten evidence classes:
`sparse_font_cluster`, `cmap_subtable_conflict`, `structural_correlation`,
`degenerate_cmap`, `zero_width_stealth`, `missing_layout_tables`, `active_content`,
`incremental_save`, `hidden_document_content`, and `hidden_text_topology`.

DF-FONT-002, DF-FONT-003, DF-FONT-004, and DF-FONT-005 are distinct rule IDs even when
their findings are summarized together as font-structure evidence.

## Containment

Resolution uses `ls-remote HEAD` and fetches no objects. After explicit exact-commit
approval, acquisition requests protocol v2 with `blob:none`, streams a bounded tree, and
materializes only supported blobs inside a quota-backed tmpfs OCI volume. Every resolution,
acquisition, inventory, static-analysis, and render worker receives a reviewed hash-pinned,
default-deny seccomp profile, a non-root identity, resource limits, and either the constrained
proxy network or no network. Cleanup failure is indeterminate.

Worker publication is separate from PyPI and releases. A manual workflow on reviewed
`main` builds multi-architecture `sha-<commit>` images, publishes SBOM/provenance evidence,
and signs exact manifest digests. VM readiness verifies the three image roles, signatures,
attestations, source/toolchain hashes, runtime, canaries, and orphan cleanup before emitting
`READY_FOR_URL`.

## Limitations

Structural font counts are not semantic proof. Legitimate OCR PDFs, accessibility tagging,
web-font subsetting, icon fonts, ligatures, math fonts, and multilingual layouts are
confounders. OCR is evidence, not sanitization. Parser containment does not establish that
content is trustworthy. Precision, recall, and false-positive claims require a versioned,
consented calibration corpus and are not currently made.

The independent article, neutral live demo, and any sample publication remain gated on a
completed exact-commit review, licensing review, claim audit, and independent technical and
editorial sign-off.

## Resolved contract and packaging findings

Identified by cross-family review on 2026-08-29 and resolved in the same pass.

- **Optional extra was never installed** *(resolved)*: `fontTools`, `pypdf`, and
  `jsonschema` live in the `[evilfont]` extra, but CI installed `.[dev]` and both
  container images installed the bare package. The artifact modules import those
  libraries at module scope, so ~243 tests failed to collect and the `static`
  worker could not perform semantic font or PDF inspection at all. `[dev]` now
  depends on `depfence[evilfont]`, CI names the extra explicitly, and both
  Dockerfiles build and install `.[evilfont]`.
- **Missing `pypdf` raised `NameError`** *(resolved)*: `_scan_pdf` imported
  `PdfReader` and `PdfReadError` inside the same `try` whose handler referenced
  `PdfReadError`. Without `pypdf`, the import raised `ImportError` and evaluating
  the handler tuple then raised `NameError`, which escaped `scan_artifact_bytes`
  and caused the caller to discard every finding from the scanner. The import is
  now separate and raises `ScanIncompleteError`, matching `inspect_font_semantics`.
- **Sealed-intake schema contradicted its emitters** *(resolved)*: the JSON Schema
  admitted 5 rule IDs, pinned `severity` to the constant `medium`, and listed five
  evidence classes that no producer emits — omitting `cmap_subtable_conflict`, the
  exact value DF-FONT-002 emits. Any DF-FONT-002 finding therefore failed schema
  validation. The schema now carries all 11 rule IDs, the 10 real evidence classes,
  and a `low`/`medium`/`high` severity enum, matching the Python validator.
- **Worker flattened severity** *(resolved)*: `sealed_git_worker` hard-coded
  `"severity": "medium"` for every finding, silently downgrading DF-FONT-003,
  DF-FONT-004, and DF-PDF-002 (HIGH) and upgrading DF-FONT-005 (LOW), which
  contradicted the severity column above. The worker now carries each rule's real
  severity, clamped to the sealed-intake vocabulary.
- **Tier-2 allowlist implied unreachable capability** *(resolved)*: the host
  accepted five rule IDs and then rejected everything that was not `DF-VIS-001`,
  leaving four unreachable entries and four unreachable title strings. Both now
  state the real contract: Tier 2 confirms `DF-VIS-001` only.

## Resolved architectural findings

These were identified by cross-family code review and resolved in commit `f7532ee`.

- **Platform isolation** *(resolved)*: Runtime attestation replaces `platform.system()`.
  All four values — `runsc`, `kata`, `kata-runtime`, and `vm` — are always required. `vm` is
  an operator attestation that the engine runs containers inside a hardware-isolated VM
  (Docker Desktop, Podman Machine) and is not passed as a `--runtime` flag.
- **TTC pre-validation** *(resolved)*: The TTC header `numFonts` field is validated via
  `struct.unpack` before `TTCollection` construction, so FontTools cannot be triggered by a
  hostile member count.
- **PDF form recursion** *(resolved)*: `MAX_FORM_DEPTH=16` and `MAX_PDF_OBJECTS=10000`
  limits are enforced before recursive form XObject and content stream inspection, in
  addition to the existing 500,000-operation budget.
- **Container stderr boundary** *(resolved)*: `_run_bounded_subprocess` accepts
  `discard_stderr=True`, which routes stderr to `DEVNULL`. Sandbox analysis uses this mode
  so worker tracebacks cannot cross the IPC boundary.
- **Network validation** *(resolved)*: `_verify_network_exists()` runs
  `docker network inspect --format {{.Internal}}` at execution time. Both
  `resolve_source_sealed` and `inspect_source_sealed` call it after image signature
  verification and before any container operation.
- **Inventory/coverage cross-correlation** *(resolved)*: After sealed inspection, the host
  verifies that `analysis["candidate_count"]` is consistent with inventory `suffix_counts`
  for supported file types, and that per-suffix coverage does not exceed inventory counts.
- **`git ls-tree -l` with `blob:none`** *(resolved)*: `GIT_NO_LAZY_FETCH=1` prevents
  `ls-tree -l` from silently fetching all blobs. `_batch_check_sizes()` resolves sizes for
  supported-suffix candidates only, with explicit `GIT_ALLOW_LAZY_FETCH=1` override per
  call. Both `-` (non-blob) and `BAD` (unresolved promisor blob) are handled as unresolved
  size markers.
