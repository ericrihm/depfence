# shellcheck shell=bash
# depfence's claims about itself, as data. Sourced by tools/docs-check.sh.
#
# THE RULE: no fix lands without its claim in the same commit. Every stale number in this
# fleet was true when it was typed; correcting one by hand without attaching a derivation
# reproduces the same failure within about a week.

# --- counts -----------------------------------------------------------------

# Test totals are deliberately not marketed: static function counts omit
# parametrization, while collection depends on the active environment.  Scanner
# capability counts are derived from the two executable declarations instead.
claim_count README.md \
  'canonical catalog contains ([0-9]+) scanners' \
  "awk '/\\[project.entry-points\\.\"depfence.scanners\"\\]/{on=1;next}/^\\[/{on=0} on && /=/{n++} END{print n+0}' pyproject.toml"

claim_count README.md \
  'including ([0-9]+) project-capable scanners' \
  "grep -c 'project=True' depfence/core/registry.py"

# --- paths ------------------------------------------------------------------

claim_path README.md CONTRIBUTING.md docs/AGENTS.md

# --- deliberately NOT claimed ------------------------------------------------
#
# The badge names the test runner rather than asserting a volatile count.
