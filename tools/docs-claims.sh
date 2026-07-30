# shellcheck shell=bash
# depfence's claims about itself, as data. Sourced by tools/docs-check.sh.
#
# THE RULE: no fix lands without its claim in the same commit. Every stale number in this
# fleet was true when it was typed; correcting one by hand without attaching a derivation
# reproduces the same failure within about a week.

# --- counts -----------------------------------------------------------------

# README.md said "3,456 tests across 133 test files". Measured 2026-07-30: 3537 test
# functions across 136 files. Both numbers moved and nothing derived either.
#
# The derivation is a dependency-free grep, NOT `pytest --collect-only`, and that choice
# is the load-bearing one. Collection needs httpx, yaml and click; none are installed in
# this repo's own .venv, so pytest reports 3055 with 24 collection ERRORS here and a
# different number in CI. A derivation whose answer depends on which machine runs it is
# the exact host-scoped defect this checker exists to catch — it would go green in CI and
# red on every laptop, and the laptop is where anyone would first meet it.
#
# The claim was therefore rewritten to say "test functions", which is what a static count
# can honestly assert. Parametrized cases are NOT counted; that is why this number is
# lower than the badge. Making the claim checkable is the fix — not making the checker
# pretend it can count what it cannot.
claim_count README.md \
  '([0-9]+) test functions' \
  "grep -rhoE '^[[:space:]]*(async )?def test_[A-Za-z0-9_]+' tests/ | wc -l"

claim_count README.md \
  'across ([0-9]+) test files' \
  "find tests -name 'test_*.py' | wc -l"

# README.md:54 — "All 56 scanners run ...". Correct as measured on 2026-07-30, pinned so
# it stays that way. This is also the number OTHER repos cite: vibeaudit's ARCHI.md and
# CLAUDE.md both said 57 for months.
claim_count README.md \
  'All ([0-9]+) scanners' \
  "ls depfence/scanners/*.py | grep -vc __init__"

# --- paths ------------------------------------------------------------------

claim_path README.md CONTRIBUTING.md docs/AGENTS.md

# --- deliberately NOT claimed ------------------------------------------------
#
# The `Tests: 3631` badge at README.md:9 is the full parametrized total, produced by a
# clean CI run. It is NOT claimed here, and the honest reason is that nothing available
# to this checker can derive it: pytest cannot collect in this repo without network
# installs, and asserting a number from a command that only works in one environment is
# the defect, not the check.
#
# What would make it claimable: have the CI job that runs the suite write the collected
# count to a tracked file, and claim THAT. Until then the badge is an unchecked claim,
# recorded here as one rather than left to look verified.
