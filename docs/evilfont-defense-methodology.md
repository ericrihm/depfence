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
