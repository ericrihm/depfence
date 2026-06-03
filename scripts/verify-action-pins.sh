#!/usr/bin/env bash
#
# verify-action-pins.sh — prove every pinned GitHub Action SHA is a REAL commit.
#
# Why this exists
# ---------------
# SHA-pinning an action to a 40-hex commit is the right supply-chain hygiene, BUT a
# pin is only as good as the hash. A hash that was *typed from memory* (or generated
# by an LLM) can be syntactically perfect — 40 hex chars, plausible `# v4` comment —
# yet point to no commit that ever existed. GitHub then fails the run at dispatch
# time ("unable to resolve action"), which is the *good* case; the dangerous case is
# a typo that happens to collide with a real-but-wrong commit.
#
# The only safe way to know a pin is valid is to ASK GITHUB, not to trust the text.
# This script does exactly that: for every `uses: owner/repo@<sha>` it calls the
# GitHub API and fails if the commit does not exist in that repo.
#
#   RULE: never hand-write an action SHA. Resolve it with `ratchet pin`, then run
#         this script (and `zizmor`) in CI. Run code; do not predict hashes.
#
# Usage
# -----
#   scripts/verify-action-pins.sh [path ...]      # default: .github/workflows
#   GH_REPO_DIR=/path/to/repo scripts/verify-action-pins.sh
#
# Requires: gh (authenticated), grep, awk. Exit 0 = all pins real; 1 = fabricated
# pin(s) found; 2 = prerequisite/tooling error.
set -euo pipefail

command -v gh >/dev/null 2>&1 || { echo "error: gh CLI not found" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "error: gh not authenticated (run 'gh auth login')" >&2; exit 2; }

# Collect target files.
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  if [ -d .github/workflows ]; then
    targets=(.github/workflows)
  else
    echo "error: no .github/workflows directory and no paths given" >&2
    exit 2
  fi
fi

# Gather unique owner/repo@sha pairs from `uses:` lines (40-hex pins only).
# Sub-path actions (github/codeql-action/upload-sarif@sha) collapse to owner/repo.
mapfile -t refs < <(
  grep -rhoE 'uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}' "${targets[@]}" 2>/dev/null \
    | sed -E 's/^uses:[[:space:]]*//' \
    | awk -F@ '{n=split($1,p,"/"); print p[1]"/"p[2]"@"$2}' \
    | sort -u
)

if [ ${#refs[@]} -eq 0 ]; then
  echo "No SHA-pinned actions found under: ${targets[*]}"
  exit 0
fi

echo "Verifying ${#refs[@]} unique SHA-pinned action(s) against GitHub..."
fail=0
declare -A seen_repo_404
for ref in "${refs[@]}"; do
  repo="${ref%@*}"
  sha="${ref#*@}"
  # repos/<owner>/<repo>/commits/<sha> -> 200 if the commit exists, 422/404 if not.
  if gh api "repos/${repo}/commits/${sha}" --jq '.sha' >/dev/null 2>&1; then
    printf '  ✓ %s\n' "$ref"
  else
    # Distinguish a fabricated SHA from a missing/renamed repo for a clearer message.
    if [ -n "${seen_repo_404[$repo]:-}" ] || ! gh api "repos/${repo}" --jq '.full_name' >/dev/null 2>&1; then
      seen_repo_404[$repo]=1
      printf '  ✗ %s  -> repo not found or inaccessible\n' "$ref"
    else
      printf '  ✗ %s  -> NO SUCH COMMIT (fabricated/typo pin)\n' "$ref"
    fi
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "FAILED: one or more action pins do not resolve to a real commit."
  echo "Fix with:  ratchet unpin <file> && ratchet pin <file>   (re-resolves from the # vX comment)"
  exit 1
fi

echo ""
echo "OK: every pinned action SHA is a real commit."
