# Resolve-never-predict: defeating AI-fabricated supply-chain pins

**Threat.** AI coding agents (and humans) increasingly *write* version identifiers from
memory — a GitHub Action commit SHA, a `==X.Y.Z`, an `@sha256:` digest. A model emits a
syntactically perfect but **non-existent** identifier: a 40-hex SHA with a plausible
`# v4` comment that points to no commit (GitHub returns HTTP 422), or a package version
that was never published. This is the same failure family as *slopsquatting* (LLMs
recommending non-existent packages), generalized to pinned references.

**Why nothing catches it.** The ecosystem splits into two camps and the fabricated-pin
gap falls between them:

| Camp | Tools | What they do | Catch a fabricated pin already in the tree? |
|---|---|---|---|
| **Write** pins | ratchet, pinact, frizbee, StepSecurity, Renovate, Dependabot | resolve tag→SHA at *authoring* time | No — they never re-validate a hand/AI-written SHA |
| **Lint** pinned-ness | zizmor `unpinned-uses`, OpenSSF Scorecard `Pinned-Dependencies` | check 40-hex *format* only | No — a workflow full of fabricated SHAs scores **perfect** |

`pinact --verify-comment` is the nearest analog (checks a `# vX` comment's tag resolves
to the SHA) but only when a comment exists and only in pin-aware CLI mode.

**depfence's niche: verify-existing.** depfence treats a pinned ref as a *claim to be
resolved*, auditing pins **already in the repo** as real, generalizing one
"resolve-never-predict" primitive across action SHAs, package versions, and container
digests — the cross-ecosystem "does this AI-emitted identifier resolve upstream?" oracle
no incumbent owns.

## Shipped (v0 — the `resolve_existence` scanner)

`depfence/scanners/resolve_existence_scanner.py`. On a normal online `depfence scan`:

- For every `uses: owner/repo@<40hex>`, `GET /repos/{owner}/{repo}/commits/{sha}`:
  **422/404 = CRITICAL `fabricated_reference`** (disambiguates a missing *commit* from a
  missing *repo*). This definitively catches the triggering incident.
- A fabricated pin carrying a `# vX.Y.Z` comment is fault-classed (`conflation` when the
  fake SHA shares a long prefix with the real tag — the "real prefix + hallucinated tail"
  case; else `pure_fabrication_or_typo`).
- **No silent pass:** no token / 403 / 429 / network error → a single INFO
  `unverified_reference`, never an implied "clean".
- Reversible kill-switch `DEPFENCE_RESOLVE_EXISTENCE=0`; immutable results so repeat
  scans are cheap. Independent of `scripts/verify-action-pins.sh` (kept as a CI cross-check).

**Deliberately *not* in v0** (false-positive discipline): flagging that a `# v4` tag has
moved past a pinned commit — that is the normal, correct pinning case. Same for
`branches-where-head` canonicality (false-positives on fresh/tag-only/squash-merged
commits). Both are `--pedantic`/fast-follow material, not defaults.

## Roadmap (fast-follows, in priority order)

1. **Lying-comment detection (done right):** flag a `# vX.Y.Z` comment only when the SHA
   is *not in that tag's ancestry* (tj-actions CVE-2025-30066 class) — needs tag-ancestry
   resolution, not naive equality. `FindingType.MUTABLE_TAG` is reserved for it.
2. **Package-version existence:** ✅ shipped as the `version_existence` entry-point
   scanner (`depfence/scanners/version_existence_scanner.py`) — resolves exact npm/PyPI
   pins against the registry and flags versions/packages that were never published
   (CRITICAL `fabricated_reference`). Exact-pins-only, yanked-is-real, canonical version
   compare, `--no-fetch`-gated. Next: Cargo/Go/OCI resolvers behind one `Resolver` protocol.
3. **Container digests:** OCI manifest existence for `image@sha256:…`.
4. **`--pedantic` canonicality:** `branches-where-head` empty-list = orphaned/fork commit,
   opt-in with an allowlist.
5. **Persistent cache:** store positive results in `DownloadCache` (10y TTL; existence is
   immutable) so first-scan primes and later scans are offline-capable.

## Fleet "resolve-never-predict" process (5 gates)

The rule: **no agent or human writes a SHA / `==version` / `@sha256` from memory.**
Identifiers are produced only by a network-resolving tool; agents emit a *tag*
(`uses: owner/repo@v4`) and let `ratchet`/`pinact` resolve it, so a fabricated SHA is
structurally impossible to author.

| Layer | Gate | Status |
|---|---|---|
| 1. Author | Claude Code `PreToolUse` hook (`depfence/integrations/pretooluse_hook.py`) resolves any newly-written `uses:@<sha>` in a workflow and warns on fabricated pins; `DEPFENCE_PRETOOLUSE_BLOCK=1` escalates to deny | **shipped** (warn-only default, reversible) |
| 2. Commit | `.pre-commit-hooks.yaml` now triggers on `.github/workflows/*` and the hook drops `--no-fetch` so project scanners (incl. resolve_existence) run; `depfence scan --fail-on high` blocks on FABRICATED_REF | **shipped** |
| 3. CI | `action-pins` job (`verify-action-pins.sh`) + the depfence action + `zizmor` + `ratchet --check` — independent resolvers, fail-closed | **shipped** in depfence CI |
| 4. Merge | Renovate `pinGitHubActionDigestsToSemver` + org "require SHA-pinned actions" policy; credit GitHub Immutable Releases | designed |
| 5. Runtime | StepSecurity Harden-Runner egress monitoring — backstop for an existing-but-malicious commit | designed |

Rollout: ship behind `DEPFENCE_RESOLVE_EXISTENCE` in warn-only shadow fleet-wide, confirm
zero false positives against cached results, then flip CI to `--fail-on`.

> Provenance vs existence are complementary layers. Existence (this work) proves the ref
> is *real*; Sigstore/SLSA/npm-provenance/PyPI-attestations prove it is *trustworthy*.
> Verify existence first (cheap, catches hallucination), then provenance where available.
