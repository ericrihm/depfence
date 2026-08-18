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
all four `rFonts` classes. PDF inspection uses decoded objects and content operations,
including recursive form XObjects, Type 3 fonts, `ToUnicode`, rendering mode, clipping,
transforms, optional layers, and `ActualText`. Render comparison aligns PDF evidence per
page so a mismatch late in a document is not averaged away.

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
