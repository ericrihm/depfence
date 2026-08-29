# Autonomous roadmap loop — design

**Date:** 2026-08-29
**Status:** approved (approach C)
**Scope:** work the depfence EvilFont roadmap unattended, feeding discovered gaps back into its own queue.

## Problem

The roadmap in `tech-notebooks/40-security/reference/depfence-evilfont-roadmap.md` holds 11 gaps across phases 3–7. Most are mechanical and individually verifiable; they stall because each needs a human to start it. The work is well-specified enough to run unattended, but three properties of this repo make a naive loop unsafe:

- The full test suite takes **56 minutes**, so it cannot gate every task.
- The repo is **public** with a Zenodo DOI, so pushes are externally visible.
- This estate has **lost work to concurrent writers before** — 45 dirty entries across lanes, three paths staged by a lane that did not own them.

## Architecture — one writer, many readers

The outer loop is `ralph-loop`: a Stop hook re-feeds the same prompt on exit, so the prompt is stateless and **all progress lives in files and git**. Exit occurs on a completion promise or `--max-iterations`.

Inside each iteration:

```
main session (SINGLE WRITER)
  ├── read .turbo/loop-queue.md, take next unblocked task
  ├── implement it TDD, run the fast gate, commit, push
  └── fan out READ-ONLY lanes in parallel:
        ├── blindspot hunt        -> research      -> sol (codex)
        ├── adversarial review    -> vuln_prioritization -> terra (codex)
        └── inventory / grunt     -> data_analysis -> gemini-flash (agy)
              (agy cannot take --workspace; context must be inlined)
```

Exactly one process writes to the index. Every parallel lane is read-only and returns findings, which are appended to the queue as new tasks. This is the invariant the whole design rests on; violating it is how this estate has previously lost work.

## The queue

`.turbo/loop-queue.md`, committed, append-only for discovered work.
`.turbo/` does not yet exist and is not in `.gitignore`, so the loop creates it
and the queue is tracked — the audit trail is worth the tracked file.

```
| id | task | phase | state | route | attempts | evidence |
```

`state ∈ pending | in_progress | done | skipped:<reason> | blocked:<reason>`

Rules:
- A task is *unblocked* when its listed dependencies are `done`.
- Findings from read-only lanes append new `pending` rows with `evidence` populated. They never modify existing rows.
- `in_progress` is written before work starts and cleared after, so a crashed iteration is visible to the next one.
- The queue is the only source of truth for progress. Nothing is inferred from git.

## Gates

Two tiers, because a 56-minute suite cannot run per task.

**Fast gate — every task, before every commit (~5s):**
```
ruff check depfence/ tests/
mypy <the five artifact modules>
bash tools/docs-check.sh
pytest <test files named for the changed modules, plus any test file
       whose name appears in the task's `evidence` column>
```

**Full gate — checkpoints only:**
```
pytest -n auto          # ~1 min parallel, 56 min serial
```
Runs every 5 completed tasks, and always before opening or updating a PR. A red full gate halts the loop and writes a handoff.

`docs-check` is in the fast gate deliberately: three times today a change altered the test count and would have shipped a stale README claim.

## Task routing

| Task kind | Regulus task_type | Model |
|---|---|---|
| Mechanical implementation | `codex_implementation` | terra |
| Escalated retry | `research` / `deep_reasoning` | sol |
| Adversarial review | `vuln_prioritization` | terra |
| Inventory, enumeration | `data_analysis` | gemini-flash |
| Final arbitration | native | opus |

`bin/resolve` is invoked with an **absolute path** — resolving from the target repo fails with exit 127, which cost two dispatches today. Every dispatch records `model_id` and `was_fallback`; a silent Anthropic fallback is never reported as cross-provider work.

Budget: `bin/resolve` may return `budget_throttled:<model>`. That is the governor working, not a failure. The loop honours it by taking the fallback rather than overriding.

## Failure handling

Per the approved policy — retry with escalation, then skip:

1. Task fails → retry once on a stronger route.
2. Still failing → `skipped:<reason>` with evidence, continue.
3. **Full gate red → halt.** Not skippable; a red suite invalidates every subsequent task's baseline.
4. Two consecutive halts → stop the loop entirely and write a handoff.

## Push policy

Narrowest defensible reading of "full autonomy" for a public repo:

- Push only to `agent/evilfont-defense-p0`. Never `main`.
- **Never force-push.** A non-fast-forward push aborts the iteration.
- PRs opened as **drafts**, never marked ready.
- Never touch the `backup/*` namespace, and never re-push the branches deleted on request today.
- **Never author or modify `.depfence-baseline.json`, `.depfence-policy.*`, or any inline
  `depfence:ignore` comment.** These are suppression authority. G-L establishes that
  target-owned suppression is already a defect; a loop that can silence its own findings
  would make the scanner's output meaningless. Any task implying such an edit is
  `blocked:` for human decision, never `skipped:`.
- Secret scan before every push, using tooling verified present on this machine:
  `gitleaks` (at `/opt/homebrew/bin/gitleaks`) over the staged diff, plus
  `depfence scan depfence/ --fail-on critical --no-fetch`, which is the same
  self-scan CI runs (`ci.yml:56`). Any hit halts rather than skips.

## Termination

`--max-iterations` is the real terminator, not queue emptiness — the queue grows as the read-only lanes discover work, so it may never empty by design.

Completion promise, output only when unequivocally true:

> `QUEUE DRAINED — every task is done or skipped, the full gate is green, and no lane has appended new work in the last two iterations.`

Additional hard stops: budget exhaustion, two consecutive halts, any non-fast-forward push, any secret-scan hit.

## Scope

**In:** G-C (deepen emitter tests), G-D (port the KG emitter from v08 — depfence is a registered atlas producer emitting nothing), G-E items 4/5 (CVE placeholders, fictional-framing patterns), G-J (doc/claim drift), G-G (revive Tier 2 by splitting `channel_unavailable` from `analysis_incomplete`), Phase 3 (open the draft PR), Phase 5 (TrapDoor coverage).

**Out:** G-F (outline-hash detector) and G-H (calibration corpus). Both need design judgment and real malicious samples; an unattended loop would produce plausible-looking but unvalidated detection logic. G-I (confidence calibration) is out because it depends on G-H.

## What this design does not solve

- **`tests/test_cli_integration.py` takes 143–300s and is timing-variable.** The full gate's cost is dominated by one file. Not fixed here; recorded as G-K.
- **Every detection input is synthetic.** The loop can add tests but cannot manufacture ground truth, so it cannot raise confidence in detection *accuracy* — only in contract correctness.
- **Findings come from AI lanes.** The loop replicates today's method, including its weakness: findings are not independently reproduced by a second method unless the adversarial lane happens to catch them. Today that lane did catch a real regression I introduced, which is evidence for the method but not proof.
