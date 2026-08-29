# Suppression authority — design v2

**Date:** 2026-08-29
**Status:** draft, supersedes the containment-based v1
**Scope:** five confirmed defects where the audited artifact controls its own verdict.

## Why v1 was withdrawn

v1 decided provenance by **containment** — is the suppression source inside the audited tree? An adversarial critique broke it in three ways, one fatally:

**Monorepo root inversion.** CI runs `depfence scan ./services/payment`. A `.depfence-policy.yml` at `/repo/` is *outside* that tree, so containment classifies it as operator-supplied and **trusts** it. The attacker moves their suppression one directory up and gets it blessed. v1 would have been worse than the status quo in exactly the layout most likely to be running CI.

**Symlinks break it in both directions.** Resolve them, and `.depfence-baseline.json -> /tmp/x` escapes into "trusted". Don't resolve them, and `..` traversal reads arbitrary paths. There is no safe setting.

**Case-insensitive and Unicode-normalising filesystems** make the comparison itself unreliable on macOS and Windows.

Containment is not a provenance test. v2 abandons it entirely.

## Principle: trust is granted, never inferred

No path heuristic decides authority. During `depfence scan`, **every** suppression source is parsed, counted, and reported — and **none is applied** unless the operator explicitly grants it on the command line. The absence of a flag is a deny, not a fallback to a heuristic.

This is deliberately blunt. A heuristic is a thing an attacker reasons about; an explicit flag is a thing only the operator can supply.

## Command-aware threat models

v1's second error was collapsing two different situations into one rule.

| Invocation | Who runs it | Audited artifact | Default posture |
|---|---|---|---|
| `depfence scan <untrusted PR>` | CI, on contributor code | The repo under test | Suppressions **not applied**, reported |
| `depfence policy .` | The repo owner, on their own repo | Their own policy | Suppressions **applied** — this is the command's entire purpose |

Making `depfence policy .` ignore `depfence.yml` by default would render the documented command meaningless and silently pass builds that violate policy. It keeps today's behaviour and gains `--untrusted` for auditing a foreign repo.

## Per-source grants

One flag cannot express the real policy: *allow developers inline suppressions for vetted false positives, forbid PRs from editing the policy file.*

```
--trust-inline      honour  # depfence:ignore  comments in manifests
--trust-baseline    honour  .depfence-baseline.json
--trust-policy      honour  .depfence-policy.yml / depfence.yml
--trust-project     all three (convenience, documented as broad)
```

Composable, and each names exactly what it opens.

## Visibility is the fix; failing is opt-in

The critique's strongest availability objection: making any scanner crash exit 2 turns a parser bug into an org-wide merge block that any unprivileged PR can trigger.

That objection is right, and it exposes a better framing. **The defect is not that scan errors fail to break the build — it is that scan errors are invisible.** `ScanResult.errors`, `scanner_coverage` and `scanner_errors` are populated today and read by nothing: not `_should_fail()`, not any of the five reporters.

So:

- **Always report.** Every reporter (table, json, sarif, cyclonedx, html) emits scanner coverage and errors. A crashed scanner becomes visible in all output formats. This alone kills "indistinguishable from a clean scan".
- **Failing is opt-in.** `--fail-on-error {none,any}` defaults to `none`, preserving availability. CI that wants strictness sets `any`.
- **Exit 2 outranks exit 1.** When `--fail-on-error=any` is set and a scanner errored, the process exits 2 even if findings also exist. Otherwise an attacker triggers a crash *and* leaves one dummy finding, so exit 1 masks the failure and CI treats it as routine triage.

This satisfies the documented contract at `README.md:515-521` (`2` = "Scan error") without weaponising it.

## Suppression parsing must not become the new crash

Parsing an attacker-authored suppression file is itself attacker-controlled input. A malformed `.depfence-policy.yml` must not raise into the scanner-error path, or a single bad comment becomes a CI DoS.

Suppression parsing failures are recorded as a **distinct** category — `suppression_unparseable` — reported like any other coverage gap, never fatal, and never silently ignored.

## What this design does NOT fix

Stated plainly, because the residual attacks are cheaper than the ones being closed.

- **Parser evasion.** Suppression is post-finding. An attacker who prevents the finding never engages this machinery — dynamic imports in `setup.py`, polyglot `package.json`, non-standard encodings. This is the cheaper attack and remains open.
- **ReDoS / hangs.** A scanner that hangs raises no exception, so `scanner_errors` stays empty and no error is reported. Needs per-scanner timeouts, which this design does not add.
- **The fingerprint remains unsalted.** `sha256(finding_type + package + title)[:16]` is still offline-computable. Irrelevant once baselines are deny-by-default, but it re-arms the moment `--trust-baseline` is passed.
- **Four suppression mechanisms still exist.** This gates them; it does not consolidate them. Each remains a maintenance surface.

## Open questions for the owner

1. `--fail-on-error` default. `none` preserves availability and is the safe migration; `any` is the stronger security posture and will break some pipelines on first run.
2. Should `--trust-project` exist at all, or does a convenience alias undermine the point of per-source grants?
3. Migration: teams using baselines today will see suppressions stop applying under `depfence scan`. Is that a major-version change, or acceptable in a minor with a loud warning?
