#!/usr/bin/env bash
# docs-check.sh — assert that this repo's documents agree with this repo.
#
# A document lies when it asserts something untrue and nothing checks it. That is the
# dominant defect class across all 15 repos under ~/dev, and it is not a discipline
# problem: every one of these claims was TRUE when it was typed.
#
# THE RULE: a number a human must hand-sync is a defect generator. Every claim is either
# DERIVED BY COMMAND or it is not a claim this file can defend.
#
# THIS FILE IS VENDORED, NOT SHARED. It is byte-identical in every repo that carries it.
# It deliberately does NOT source anything from ~/dev: a CI checkout contains only its own
# repo, so a shared include would work on this laptop and nowhere else — which is the same
# host-scoped defect the checker exists to catch. Update by copying, and let the fleet
# sweep report version skew.
#
# WHAT IT CAN AND CANNOT CHECK, stated because the boundary is the design:
#   CAN — numbers with a derivation command; paths that must resolve; banned phrases;
#         whether a claimed guard is actually wired.
#   CANNOT — semantic truth. "49 controls implemented" is not a count problem: the count
#         is checkable, "implemented" is not. Do not pretend otherwise.
#
# Claims live in tools/docs-claims.sh, which is the only file anyone edits.
#
# Dependency-free (bash/awk/sed/grep/git) and bash-3.2 clean: no mapfile, no `declare -A`,
# no ${var,,}. macOS ships bash 3.2, and a checker that aborts before checking anything is
# indistinguishable from a clean run.
set -uo pipefail

DOCS_CHECK_VERSION=1

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1

fail=0
note_fail() { printf 'FAIL %s\n' "$*" >&2; fail=1; }
note_unchk() { printf 'UNCHECKABLE %s\n' "$*" >&2; fail=1; }

# --- exemptions -------------------------------------------------------------
# Two visible escapes, both rendered in the document so nothing is silently excused:
#   [UNVERIFIED YYYY-MM-DD]  an operator asserting what the tool cannot verify
#   ~~strikethrough~~        a claim quoted in order to retire it
# The UNVERIFIED marker DECAYS: older than 90 days and it fails. A permanent escape hatch
# is just a slower lie.
_exempt_line() {
  case "$1" in
    *'~~'*) return 0 ;;
  esac
  local d today
  d=$(printf '%s' "$1" | sed -nE 's/.*\[UNVERIFIED ([0-9]{4}-[0-9]{2}-[0-9]{2})\].*/\1/p')
  [ -n "$d" ] || return 1
  today=$(date -u +%Y-%m-%d)
  # String comparison is valid on ISO dates and needs no date arithmetic.
  if [ "$(printf '%s\n%s\n' "$d" "$today" | sort | head -1)" = "$d" ]; then
    local cutoff
    cutoff=$(_days_ago 90)
    if [ "$(printf '%s\n%s\n' "$d" "$cutoff" | sort | head -1)" = "$d" ] && [ "$d" != "$cutoff" ]; then
      note_fail "an [UNVERIFIED $d] marker is more than 90 days old — re-verify it or delete the claim"
      return 1
    fi
  fi
  return 0
}

_days_ago() {
  # BSD and GNU date disagree on relative dates; try both rather than assume a platform.
  date -u -v-"$1"d +%Y-%m-%d 2>/dev/null || date -u -d "$1 days ago" +%Y-%m-%d 2>/dev/null || echo "0000-00-00"
}

# --- paragraph-joined view --------------------------------------------------
# ONE RECORD PER PARAGRAPH, prefixed with the line it starts on.
#
# A line-scoped grep is systematically blind here: these repos hard-wrap prose, so a claim
# broken by a newline is invisible. Measured in atlas on 2026-07-30 — two stale claims
# survived a gate shipped that same morning because the phrase wrapped. The blank line is
# the join boundary, deliberately: flattening a whole file fuses unrelated paragraphs into
# phrases nobody wrote, and a false positive is how a checker becomes noise.
#
# GENERATED REGIONS ARE SKIPPED. Any block delimited by `<!-- <name>:begin -->` /
# `<!-- <name>:end -->` is excluded, because its content is derived by a tool and is
# therefore already true by construction — checking it re-reports the tool's own correct
# output as a defect. Measured: atlas's `atlas:state` block legitimately lists every
# REGISTERED host's dev_root, including an unreachable one, and claim_path flagged it as a
# nonexistent path. The convention is generic (any name), not one repo's, so this file
# stays byte-identical across repos.
_paragraphs() {
  [ -f "$1" ] || return 1
  awk '
    /<!--[[:space:]]*[A-Za-z0-9_.:-]+:begin[[:space:]]*-->/ { gen=1; next }
    /<!--[[:space:]]*[A-Za-z0-9_.:-]+:end[[:space:]]*-->/   { gen=0; next }
    gen { next }
    { if ($0 ~ /^[[:space:]]*$/) { if (buf != "") { print start": "buf; buf="" }; next }
      if (buf == "") { start=NR; buf=$0 } else { buf = buf " " $0 } }
    END { if (buf != "") print start": "buf }
  ' "$1"
}

_mktemp() { mktemp "${TMPDIR:-/tmp}/docs-check.XXXXXX"; }

# A DECLARED CLAIM THAT MATCHES NOTHING IS NOT A PASSING CLAIM.
# Measured 2026-07-30: docs-claims.sh asserted CLAUDE.md claimed three .claude hooks were
# wired. CLAUDE.md never said it, so the primitive returned clean — and the mutation test
# that deleted the hook from settings.json stayed green. A guard whose subject has been
# edited away reports success forever, which is the exact defect this file exists to catch,
# reproduced inside the checker itself.
_assert_matched() {
  local seen="$1" file="$2" pat="$3"
  if [ ! -s "$seen" ]; then
    note_unchk "$file: no text matches /$pat/, but $CLAIMS asserts a claim there. Vacuous claims are not clean — fix the claim or restore the sentence."
  fi
  rm -f "$seen"
}

# ---------------------------------------------------------------------------
# claim primitives — each is one assertion with a named derivation
# ---------------------------------------------------------------------------

# claim_count <file> <extended-regex with ONE capture group> <derivation command>
# The claimed number must equal what the command prints. No derivation, no claim.
claim_count() {
  local file="$1" pat="$2" cmd="$3" line claimed actual seen
  [ -f "$file" ] || { note_unchk "$file: in scope but missing — not clean"; return; }
  actual=$(eval "$cmd" 2>/dev/null | tr -d '[:space:]')
  [ -n "$actual" ] || { note_unchk "$file: derivation produced nothing: $cmd"; return; }
  seen="$(_mktemp)"
  _paragraphs "$file" | while IFS= read -r rec; do
    # Extract by matching the pattern ALONE, then anchoring the capture to that match.
    # The obvious `sed -nE "s/.*$pat.*/\1/p"` is wrong whenever the pattern has no literal
    # prefix: the leading greedy `.*` eats as much as it can, so /([0-9]+) tests/ against
    # "97 tests" captures "7". Measured in vibeaudit 2026-07-30 — it reported a CORRECT
    # number as a defect, which is how a checker gets routed around.
    match=$(printf '%s' "$rec" | grep -oE "$pat" | head -1)
    [ -n "$match" ] || continue
    claimed=$(printf '%s' "$match" | sed -nE "s/^$pat\$/\1/p" | head -1)
    [ -n "$claimed" ] || continue
    # Mark BEFORE the exemption check: an exempted line still makes the claim, it is only
    # excused from the comparison. Marking after reported every exempted claim as vacuous,
    # which would have made [UNVERIFIED] and ~~strikethrough~~ fail instead of exempt.
    printf 'x' >> "$seen"
    _exempt_line "$rec" && continue
    [ "$claimed" = "$actual" ] && continue
    line=${rec%%:*}
    printf 'FAIL %s:%s: claims %s, but `%s` says %s\n' "$file" "$line" "$claimed" "$cmd" "$actual" >&2
    printf 'x' >> "$_FAILMARK"
  done
  _assert_matched "$seen" "$file" "$pat"
}

# claim_path <file>... — every absolute path token cited must resolve on THIS host.
# Catches the whole foreign-host class: /var/home on a Mac, /Users/ops for a user that
# does not exist, a plugin path from another machine.
claim_path() {
  local file p line
  for file in "$@"; do
    [ -f "$file" ] || continue
    _paragraphs "$file" | while IFS= read -r rec; do
      _exempt_line "$rec" && continue
      line=${rec%%:*}
      for p in $(printf '%s' "$rec" | grep -oE '(/Users|/var/home|/home|/opt)/[A-Za-z0-9._/-]+' | sort -u); do
        case "$p" in */) p=${p%/} ;; esac
        [ -e "$p" ] && continue
        printf 'FAIL %s:%s: cites %s, which does not exist on this host\n' "$file" "$line" "$p" >&2
        printf 'x' >> "$_FAILMARK"
      done
    done
  done
}

# claim_absent <file> <regex> — a phrase that must not appear, e.g. a retired claim.
claim_absent() {
  local file="$1" pat="$2" line
  [ -f "$file" ] || return 0
  _paragraphs "$file" | while IFS= read -r rec; do
    _exempt_line "$rec" && continue
    printf '%s' "$rec" | grep -qiE "$pat" || continue
    line=${rec%%:*}
    printf 'FAIL %s:%s: contains a claim that must not be made: /%s/\n' "$file" "$line" "$pat" >&2
    printf 'x' >> "$_FAILMARK"
  done
}

# claim_enforced <file> <regex describing the claimed guard> <proof command>
# A document may not claim a guard is ACTIVE; the guard must actually be wired.
# This is the primitive for regulus/docs/START-HERE.md's "a repo hook blocks" — which was
# false, with core.hooksPath empty — and for atlas's three hooks that passed 17 tests
# while .claude/settings.json had no hooks key at all. A guard nothing invokes is not a
# guard, and a doc that says otherwise is how a session relies on protection it lacks.
claim_enforced() {
  local file="$1" pat="$2" proof="$3"
  [ -f "$file" ] || { note_unchk "$file: in scope but missing — not clean"; return; }
  # Paragraph-joined, like every other primitive. Grepping line-by-line here was a real
  # inconsistency: regulus's "wired as a `PreToolUse`/`Bash` hook" wraps mid-phrase, so a
  # line-scoped grep declared the claim absent and reported a correctly-wired guard as a
  # vacuous claim. Measured 2026-07-30. The blindness _paragraphs exists to fix was left
  # in the one primitive whose whole job is detecting a false claim about a guard.
  # NOT `_paragraphs "$file" | grep -qiE`. Under `set -o pipefail`, grep -q exits on the
  # first match, awk takes SIGPIPE, and the PIPELINE reports failure — so a claim that IS
  # present reads as absent, and only in files big enough for awk to still be writing.
  # The selftest fixture below is 5000 lines precisely because a small one cannot
  # reproduce it. Measured 2026-07-30 in atlas: this made a correctly wired guard report
  # as a vacuous claim, and it would have gone unnoticed in every small repo.
  local joined; joined="$(_mktemp)"
  _paragraphs "$file" > "$joined"
  if ! grep -qiE "$pat" "$joined"; then
    rm -f "$joined"
    note_unchk "$file: declares a claim matching /$pat/ in $CLAIMS, but the document no longer says it. Vacuous claims are not clean — update the claim or restore the sentence."
    return
  fi
  rm -f "$joined"
  # Run the proof in the REAL repo, never in the exported index tree. The document is
  # content and is read from staged bytes; the guard is a property of the environment.
  # Under --staged the cwd is a bare export with no .git, so `git config` found no repo
  # and reported every wired guard as unwired — a checker inventing the exact failure it
  # exists to report. Measured 2026-07-30.
  if ! ( cd "$REPO_ROOT" && eval "$proof" ) >/dev/null 2>&1; then
    note_fail "$file: claims a guard matching /$pat/, but it is NOT active — \`$proof\` fails. Wire it, or delete the claim."
  fi
}

# --- selftest ---------------------------------------------------------------
# A CHECK NEVER SEEN FAILING IS NOT KNOWN TO WORK. This file is vendored into repos with
# no CI at all, where the fleet sweep is the only enforcement — so it carries its own
# proof rather than depending on a test suite that may not exist. Each case builds a
# fixture, runs THIS script against it in a subprocess, and asserts the exact message.
# Fixtures live outside any git repo, so the toplevel probe falls back to `.` by design.
_SELFDIR=""
_selftest() {
  local dir rc out n=0 bad=0
  dir="$(mktemp -d "${TMPDIR:-/tmp}/docs-check-selftest.XXXXXX")"
  _SELFDIR="$dir"
  trap 'rm -rf "$_SELFDIR"' EXIT

  _case() { # _case <name> <expect-rc> <expect-substring>
    local name="$1" want_rc="$2" want="$3"
    n=$((n + 1))
    out="$(cd "$dir" && bash "$SELF" 2>&1)"; rc=$?
    if [ "$rc" != "$want_rc" ] || ! printf '%s' "$out" | grep -qF "$want"; then
      bad=$((bad + 1))
      printf 'SELFTEST FAIL %s: rc=%s (want %s), output:\n%s\n' "$name" "$rc" "$want_rc" "$out" >&2
    fi
  }

  mkdir -p "$dir/tools"

  : > "$dir/tools/docs-claims.sh"
  _case "empty claims file is UNCHECKABLE, not clean" 1 "declares no claims"

  rm -f "$dir/tools/docs-claims.sh"
  _case "missing claims file is UNCHECKABLE, not clean" 1 "is missing"

  printf 'we ship 7 widgets today\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "claim_count catches a stale number" 1 "claims 7"

  printf 'we ship widgets today\n' > "$dir/D.md"
  _case "claim_count on absent text is UNCHECKABLE" 1 "no text matches"

  printf 'we ship 9 widgets today\n' > "$dir/D.md"
  _case "claim_count agrees" 0 "documents agree"

  # A pattern with NO literal prefix must not lose its leading digits to a greedy `.*`.
  # The first implementation captured "7" from "97 tests" and reported a correct number
  # as a defect. Measured in vibeaudit 2026-07-30.
  printf 'we ship 97 widgets today\n' > "$dir/D.md"
  printf "claim_count D.md '([0-9]+) widgets' 'echo 97'\n" > "$dir/tools/docs-claims.sh"
  _case "an unprefixed pattern keeps all its digits" 0 "documents agree"

  printf 'we ship 96 widgets today\n' > "$dir/D.md"
  _case "an unprefixed pattern still catches a real mismatch" 1 "claims 96"

  printf 'we ship 9 widgets today\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"

  # The reason paragraph joining exists: the claim survives a hard wrap.
  printf 'we ship\n7 widgets today\n' > "$dir/D.md"
  _case "claim_count sees across a hard wrap" 1 "claims 7"

  printf 'we ship 7 widgets today [UNVERIFIED %s]\n' "$(date -u +%Y-%m-%d)" > "$dir/D.md"
  _case "a fresh UNVERIFIED marker exempts" 0 "documents agree"

  printf 'we ship 7 widgets today [UNVERIFIED 2019-01-01]\n' > "$dir/D.md"
  _case "an UNVERIFIED marker over 90 days old fails" 1 "more than 90 days old"

  printf 'we ~~ship 7 widgets~~ today\n' > "$dir/D.md"
  _case "strikethrough retires a claim" 0 "documents agree"

  printf 'see /var/home/nobody/nowhere for details\n' > "$dir/D.md"
  printf 'claim_path D.md\n' > "$dir/tools/docs-claims.sh"
  _case "claim_path catches a foreign-host path" 1 "does not exist on this host"

  printf '<!-- x:begin -->\nsee /var/home/nobody/nowhere\n<!-- x:end -->\n' > "$dir/D.md"
  _case "a generated block is skipped" 0 "documents agree"

  printf 'a repo hook blocks it\n' > "$dir/D.md"
  printf "claim_absent D.md 'a repo hook blocks'\n" > "$dir/tools/docs-claims.sh"
  _case "claim_absent catches a retired phrase" 1 "must not be made"

  printf 'the guard is wired\n' > "$dir/D.md"
  printf "claim_enforced D.md 'the guard is wired' 'false'\n" > "$dir/tools/docs-claims.sh"
  _case "claim_enforced catches an unwired guard" 1 "NOT active"

  # claim_enforced must be paragraph-joined too. Line-scoped, it declared a correctly
  # wired guard's claim absent because the phrase wrapped. Measured in regulus 2026-07-30.
  printf 'the guard\nis wired\n' > "$dir/D.md"
  _case "claim_enforced sees across a hard wrap" 1 "NOT active"

  # A LARGE file with the claim near the top. This is the SIGPIPE case: `_paragraphs |
  # grep -q` returns failure under pipefail once the file is big enough that awk is still
  # writing when grep exits, so the claim reads as absent. A small fixture cannot
  # reproduce it, which is why this one is 5000 lines.
  { printf 'the guard is wired\n\n'; awk 'BEGIN{for(i=0;i<5000;i++) print "filler line", i}'; } > "$dir/D.md"
  _case "claim_enforced survives a large file (pipefail/SIGPIPE)" 1 "NOT active"

  printf 'nothing here\n' > "$dir/D.md"
  _case "claim_enforced on a deleted sentence is UNCHECKABLE" 1 "no longer says it"

  printf 'the guard is wired\n' > "$dir/D.md"
  printf "claim_enforced D.md 'the guard is wired' 'true'\n" > "$dir/tools/docs-claims.sh"
  _case "claim_enforced passes when the guard is real" 0 "documents agree"

  if [ "$bad" -ne 0 ]; then
    printf 'selftest: %s of %s cases FAILED\n' "$bad" "$n" >&2
    return 1
  fi
  printf 'selftest: %s cases, every primitive observed red for its stated reason.\n' "$n"
}

if [ "${1:-}" = "--selftest" ]; then _selftest; exit $?; fi

# --staged — judge the bytes being COMMITTED, not the working tree.
# A hook that reads the working tree passes while CI fails on the committed tree, and
# then teaches you the hook is the authority. Atlas shipped that exact defect once
# (gaps/2026-07-29-019): a regenerated-but-unstaged block was green locally and red in
# CI. Exporting the index to a scratch tree makes every claim -- including its derivation
# command -- read staged content, with no per-claim awareness required.
# LIMIT, stated because it is load-bearing: only TRACKED files are exported. A claim whose
# derivation reads an untracked file cannot be checked this way; CI is the backstop.
if [ "${1:-}" = "--staged" ]; then
  _staged_dir="$(mktemp -d "${TMPDIR:-/tmp}/docs-check-staged.XXXXXX")"
  trap 'rm -rf "$_staged_dir"' EXIT
  git checkout-index -a --prefix="$_staged_dir/" 2>/dev/null || {
    printf 'UNCHECKABLE could not export the index — not clean.\n' >&2; exit 1
  }
  cd "$_staged_dir" || exit 1
fi

# ---------------------------------------------------------------------------
_FAILMARK="$(mktemp)"; : > "$_FAILMARK"
trap 'rm -f "$_FAILMARK"' EXIT

CLAIMS="tools/docs-claims.sh"
if [ ! -f "$CLAIMS" ]; then
  printf 'UNCHECKABLE %s is missing — a repo with no declared claims is not a clean repo.\n' "$CLAIMS" >&2
  exit 1
fi
if ! grep -qE '^[[:space:]]*claim_' "$CLAIMS"; then
  printf 'UNCHECKABLE %s declares no claims — UNCHECKABLE is not clean.\n' "$CLAIMS" >&2
  exit 1
fi

# shellcheck source=/dev/null
. "$CLAIMS"

[ -s "$_FAILMARK" ] && fail=1
if [ "$fail" -ne 0 ]; then exit 1; fi
printf 'docs-check(v%s): documents agree with the repo.\n' "$DOCS_CHECK_VERSION"
