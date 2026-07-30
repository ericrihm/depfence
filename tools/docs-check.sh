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
#   CAN — numbers with a derivation command; absolute paths that must resolve on this
#         host; relative markdown links that must resolve beside their file; banned
#         phrases; whether a claimed guard is actually wired.
#   CANNOT — semantic truth. "49 controls implemented" is not a count problem: the count
#         is checkable, "implemented" is not. Do not pretend otherwise.
#   CANNOT — judge whether a PROOF is meaningful. `claim_enforced X "true"` passes, and
#         nothing here can tell a real proof from a tautology. The primitive verifies that
#         a named command succeeds, not that the command was worth naming. This is the
#         largest remaining hole and it is a human review problem, not a parser problem.
#   CANNOT — see a claim it was never pointed at. Coverage is exactly the file list in
#         docs-claims.sh; a document nobody added is unchecked and reports nothing. The
#         checker cannot tell "clean" from "never looked", which is why SCOPE is the
#         decision to argue about, not the primitives.
#
# Its own failure modes are the ones it reports about others, so it is probed adversarially
# rather than trusted: --selftest is that probe, and every case in it is a run where this
# file once said "documents agree" while the fixture was lying.
#
# Claims live in tools/docs-claims.sh, which is the only file anyone edits.
#
# Dependency-free (bash/awk/sed/grep/git) and bash-3.2 clean: no mapfile, no `declare -A`,
# no ${var,,}. macOS ships bash 3.2, and a checker that aborts before checking anything is
# indistinguishable from a clean run.
set -uo pipefail

DOCS_CHECK_VERSION=2
_SD=$(printf '\001')  # sed delimiter; a pattern may legitimately contain '/'

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" || exit 1

# ONE FAILURE CHANNEL, AND IT IS A FILE.
# There used to be two: a `fail` shell variable and the $_FAILMARK file. Every primitive
# reads its documents through `_paragraphs "$f" | while ...`, and the right-hand side of a
# pipe is a SUBSHELL — so `fail=1` set there was discarded when the loop ended. Measured
# 2026-07-30: an [UNVERIFIED] marker more than 90 days old printed its FAIL line and the
# script exited 0, because the only thing recording it was a variable in a dead subshell.
# A file survives the subshell. Nothing may record a failure any other way.
# ONE SCRATCH DIRECTORY, removed by one trap. The first version kept a list in a shell
# variable and appended to it from _mktemp — but _mktemp is always invoked as `$(_mktemp)`,
# and a command substitution is a SUBSHELL, so every append mutated a copy that died
# immediately. Measured 2026-07-30: five orphaned temp files per run. Anything under this
# directory is cleaned no matter which subshell created it.
_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/docs-check.XXXXXX")"
_FAILMARK="$_SCRATCH/failmark"; : > "$_FAILMARK"
# Counts primitives that actually EXECUTED. The static prescan proves the claims file
# mentions known primitives; it cannot prove any of them ran. A claims file whose calls
# all sit inside a function that is never invoked passed the prescan, executed nothing,
# and reported "documents agree". Measured 2026-07-30. A file, not a variable, because
# primitives may be called from anywhere.
_RANMARK="$_SCRATCH/ranmark"; : > "$_RANMARK"
# Installed the moment the directory exists, so --selftest and every early exit clean up
# too. _verdict replaces this later with a trap that also removes $_SCRATCH.
trap 'rm -rf "$_SCRATCH"' EXIT
_track() { :; }  # retained so callers read declaratively; the directory does the work
note_fail()  { printf 'FAIL %s\n' "$*" >&2; printf 'x' >> "$_FAILMARK"; }
note_unchk() { printf 'UNCHECKABLE %s\n' "$*" >&2; printf 'x' >> "$_FAILMARK"; }

# --- exemptions -------------------------------------------------------------
# Two visible escapes, both rendered in the document so nothing is silently excused:
#   [UNVERIFIED YYYY-MM-DD]  an operator asserting what the tool cannot verify
#   ~~strikethrough~~        a claim quoted in order to retire it
# The UNVERIFIED marker DECAYS: older than 90 days and it fails. A permanent escape hatch
# is just a slower lie.
# _exempt_line <record> — true when the WHOLE record is excused.
# Callers that can be precise about WHICH match was struck should use _strip_struck
# instead; this remains for claim_path and claim_absent, whose subject is the record.
# _exempt_unverified <record> — the [UNVERIFIED] rule ONLY, with no strikethrough rule.
# claim_count uses this and handles ~~ per MATCH, because the coarse whole-paragraph rule
# below cannot tell a retired note from a live stale number sharing its paragraph.
_exempt_unverified() {
  local d today cutoff
  # A FUTURE DATE IS NOT A FRESH VERIFICATION. The decay test used to run only when the
  # marker date was <= today, so `[UNVERIFIED 2099-01-01]` skipped it entirely and became
  # a permanent, silent off switch for any claim — typed in seconds, never expiring.
  # Measured 2026-07-30. A dated marker asserts when someone LOOKED, and nobody has
  # looked in 2099.
  d=$(printf '%s' "$1" | sed -nE 's/.*\[UNVERIFIED ([0-9]{4}-[0-9]{2}-[0-9]{2})\].*/\1/p' | head -1)
  if [ -n "$d" ]; then
    today=$(date -u +%Y-%m-%d)
    if [ "$d" \> "$today" ]; then
      note_fail "an [UNVERIFIED $d] marker is dated in the future — a marker records when someone looked, so this excuses nothing"
      return 1
    fi
    cutoff=$(_days_ago 90)
    # FAIL CLOSED when the date could not be computed. _days_ago falls back to
    # 0000-00-00 if neither BSD nor GNU date works; comparing against that silently
    # granted every marker a permanent exemption on such a platform.
    if [ "$cutoff" = "0000-00-00" ]; then
      note_unchk "cannot compute a 90-day cutoff on this platform — [UNVERIFIED] markers cannot be aged, so none are honoured"
      return 1
    fi
    if [ "$d" \< "$cutoff" ]; then
      note_fail "an [UNVERIFIED $d] marker is more than 90 days old — re-verify it or delete the claim"
      return 1
    fi
    return 0
  fi
  return 1
}

# _exempt_line — the record-scoped rule: [UNVERIFIED], or any strikethrough at all.
# Used where the SUBJECT is the whole record (a cited path, a banned phrase) rather than
# one extracted value.
_exempt_line() {
  _exempt_unverified "$1" && return 0
  case "$1" in
    (*'~~'*) return 0 ;;
  esac
  return 1
}

# _strip_struck — remove ~~…~~ spans so a caller can tell WHICH match was retired.
# `case $rec in *'~~'*` exempts the entire paragraph, which is far too coarse for a
# count: a retired note anywhere in the same paragraph silently excused a live, stale
# number sitting beside it. Measured 2026-07-30.
_strip_struck() { printf '%s' "$1" | sed 's/~~[^~]*~~//g'; }

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
# Record format is `<line>:<fenced>: <text>`, where <fenced> is 1 when the paragraph
# began inside a ``` code fence. Only the LINK check consults it: a markdown link inside a
# fence is an example or a TEMPLATE, not a citation — atlas's TRIP-init skill emits
# `[ARCHI.md](ARCHI.md)` into the project it initialises, and reporting that as a broken
# link would be reporting the skill's output as the skill's defect. Absolute paths inside
# a fence are still checked, because `cd /var/home/eric/dev/atlas` in a runnable block is
# exactly the defect worth catching — and hub/NEXT.md had precisely that.
_paragraphs() {
  [ -f "$1" ] || return 1
  awk '
    /<!--[[:space:]]*[A-Za-z0-9_.:-]+:begin[[:space:]]*-->/ { gen=1; next }
    /<!--[[:space:]]*[A-Za-z0-9_.:-]+:end[[:space:]]*-->/   { gen=0; next }
    gen { next }
    /^[[:space:]]*```/ { fence = !fence; next }
    { if ($0 ~ /^[[:space:]]*$/) { if (buf != "") { print start":"fstart": "buf; buf="" }; next }
      if (buf == "") { start=NR; fstart=(fence?1:0); buf=$0 } else { buf = buf " " $0 } }
    END { if (buf != "") print start":"fstart": "buf }
  ' "$1"
}

_mktemp() { mktemp "$_SCRATCH/t.XXXXXX"; }

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
  printf 'x' >> "$_RANMARK"
  local file="$1" pat="$2" cmd="$3" line claimed actual seen recs st
  [ -f "$file" ] || { note_unchk "$file: in scope but missing — not clean"; return; }
  # A pattern with no capture group cannot yield a claimed value: sed reports "\1 not
  # defined in the RE" on stderr and the claim silently checks nothing, exit 0. Measured
  # 2026-07-30 — noisy on the terminal and green in CI, which is the worst combination.
  case "$pat" in
    (*'('*) ;;
    (*) note_unchk "$file: claim_count pattern /$pat/ has no capture group, so it can never yield a number"; return ;;
  esac

  # THE DERIVATION IS VALIDATED BEFORE IT IS BELIEVED. Three ways it used to lie quietly:
  #   - multi-line output was concatenated by `tr -d`, so 9 and 5 became "95";
  #   - non-numeric output was compared as a string, producing a nonsense FAIL message;
  #   - a command that FAILED still had its output used, so `ls missing/ | wc -l` printed
  #     0 and a document claiming 0 passed. Zero because it could not look is not zero —
  #     that is the empty-corpus lie, and it is the one this whole file exists to refuse.
  # A nonzero status with a positive count is allowed, because `grep -c` legitimately
  # exits 1 when it counts nothing; that case is caught by the zero rule instead.
  local raw nlines
  raw=$(eval "$cmd" 2>/dev/null); st=$?
  # Multi-line is detected BEFORE whitespace is stripped. Stripping first turns "9\n5"
  # into "95", which then passes an all-digits test as a plausible number — the selftest
  # caught this after the probe had wrongly scored the case as fixed, because it went red
  # for a different reason (a mismatch against the concatenation). Red for the wrong
  # reason is not a passing check.
  nlines=$(printf '%s\n' "$raw" | grep -c '[^[:space:]]')
  if [ "$nlines" -gt 1 ]; then
    note_unchk "$file: derivation printed $nlines lines, not a single number: $cmd"
    return
  fi
  actual=$(printf '%s' "$raw" | tr -d '[:space:]')
  case "$actual" in
    (''|*[!0-9]*)
      note_unchk "$file: derivation is not a single number (got '"'"'$actual'"'"', status $st): $cmd"
      return ;;
  esac
  if [ "$st" -ne 0 ] && [ "$actual" = "0" ]; then
    note_unchk "$file: derivation FAILED (status $st) and produced 0: $cmd
  Zero because it could not look is not zero. Fix the command or the claim."
    return
  fi

  seen="$(_mktemp)"; recs="$(_mktemp)"
  _paragraphs "$file" > "$recs"
  while IFS= read -r rec; do
    # EVERY match in the paragraph, not just the first. `grep -oE ... | head -1` checked
    # only the leading occurrence, so "we ship 9 widgets and also 5 widgets" passed on the
    # 9 and never looked at the 5. Measured 2026-07-30.
    printf '%s' "$rec" | grep -oE "$pat" > "$seen.m" || true
    [ -s "$seen.m" ] || continue
    # Mark BEFORE the exemption check: an exempted line still makes the claim, it is only
    # excused from the comparison. Marking after reported every exempted claim as vacuous,
    # which would have made [UNVERIFIED] and ~~strikethrough~~ fail instead of exempt.
    printf 'x' >> "$seen"
    _exempt_unverified "$rec" && continue
    line=${rec%%:*}
    # Struck spans are removed per MATCH, not per paragraph: a retired note elsewhere in
    # the same paragraph must not excuse a live stale number beside it.
    local unstruck; unstruck=$(_strip_struck "$rec")
    while IFS= read -r match; do
      case "$unstruck" in (*"$match"*) ;; (*) continue ;; esac
      # Anchor the capture to the isolated match. The obvious `sed -nE "s/.*$pat.*/\1/p"`
      # is wrong whenever the pattern has no literal prefix: the leading greedy `.*` eats
      # as much as it can, so /([0-9]+) tests/ against "97 tests" captured "7" and called
      # a CORRECT number a defect. The delimiter is \001, not `/`, because a pattern may
      # legitimately contain a slash — /is ([0-9]+)\/100/ used to abort sed and be
      # misreported as "no text matches".
      claimed=$(printf '%s' "$match" | sed -nE "s${_SD}^${pat}\$${_SD}\1${_SD}p" | head -1)
      [ -n "$claimed" ] || continue
      [ "$claimed" = "$actual" ] && continue
      printf 'FAIL %s:%s: claims %s, but `%s` says %s\n' "$file" "$line" "$claimed" "$cmd" "$actual" >&2
      printf 'x' >> "$_FAILMARK"
    done < "$seen.m"
  done < "$recs"
  rm -f "$seen.m"
  _assert_matched "$seen" "$file" "$pat"
}

# claim_path <file>... — every absolute path token cited must resolve on THIS host.
# Catches the whole foreign-host class: /var/home on a Mac, /Users/ops for a user that
# does not exist, a plugin path from another machine.
claim_path() {
  printf 'x' >> "$_RANMARK"
  local file p q line recs
  # `claim_path` with no arguments looks like a declared claim, satisfies the prescan,
  # marks itself as having run, and checks nothing. Measured 2026-07-30.
  [ "$#" -gt 0 ] || { note_unchk "claim_path was called with no files — it checked nothing"; return; }
  for file in "$@"; do
    # A MISSING FILE IS NOT A PASSING FILE. This used to `continue`, so `claim_path
    # NOSUCH.md` reported clean — a claim about a document that had been deleted or
    # renamed simply stopped checking anything, quietly. Measured 2026-07-30.
    [ -f "$file" ] || { note_unchk "$file: in scope for claim_path but missing — not clean"; continue; }
    recs="$(_mktemp)"
    _paragraphs "$file" > "$recs"
    while IFS= read -r rec; do
      _exempt_line "$rec" && continue
      # A GUARDED PROBE IS NOT A CITATION. A record containing a POSIX existence test is
      # checking whether a path is there, which is the CORRECT portable idiom — e.g.
      # `for b in /home/linuxbrew/.linuxbrew/bin /opt/homebrew/bin; do [ -d "$b" ] && ...`.
      # Flagging it would penalise the very pattern that fixes the foreign-host defect and
      # push authors back to hardcoding one machine's layout.
      # THE COST, stated because it is real: this exempts every path in that record, so a
      # genuine bad citation sharing a paragraph with an existence test is missed. That is
      # the deliberate trade — a checker that fires on its own remedy gets routed around.
      case "$rec" in
        (*'[ -d '*|*'[ -e '*|*'[ -f '*|*'[ -x '*|*'[ -L '*) continue ;;
      esac
      line=${rec%%:*}

      # (1) ABSOLUTE paths, which are the foreign-host class.
      for p in $(printf '%s' "$rec" | grep -oE '(/Users|/var/home|/home|/opt)/[A-Za-z0-9._/-]+' | sort -u); do
        [ -e "$p" ] && continue
        # Trailing sentence punctuation belongs to the prose, not the path. `.` is a legal
        # filename character so it cannot simply be excluded from the pattern; instead the
        # path is retried with it stripped, and only reported if BOTH forms are absent.
        # Without this, "the config lives at /Users/eric/dev/atlas/README.md." — a real
        # file at the end of a sentence — was reported as nonexistent. A checker that
        # fires on correct prose is how it becomes noise. Measured 2026-07-30.
        # Only '.' needs stripping: the capture charclass is [A-Za-z0-9._/-], so a comma,
        # semicolon or paren already terminates the match and can never be captured.
        q=$p
        while :; do
          case "$q" in (*.) q=${q%.} ;; (*) break ;; esac
        done
        [ "$q" != "$p" ] && [ -e "$q" ] && continue
        printf 'FAIL %s:%s: cites %s, which does not exist on this host\n' "$file" "$line" "$p" >&2
        printf 'x' >> "$_FAILMARK"
      done

      # (2) RELATIVE markdown link targets — the commonest doc rot of all, and previously
      # unchecked in every repo: only absolute paths were examined, so `[design](docs/
      # NOSUCHFILE.md)` was invisible. Scope is deliberately narrow — a markdown link
      # target only, never a backticked word in prose, because prose is full of things
      # that look like paths and are not. URLs, anchors, mail links and anything holding a
      # shell/template expansion are skipped.
      # Fenced paragraphs are skipped for links only — see _paragraphs.
      case "$rec" in ([0-9]*:1:*) continue ;; esac
      for p in $(printf '%s' "$rec" | grep -oE '\]\([^)[:space:]]+\)' | sed -e 's/^](//' -e 's/)$//' | sort -u); do
        case "$p" in
          (http*|\#*|mailto:*|ftp*|//*|/*|*'$'*|*'{'*|*'<'*|*'*'*) continue ;;
        esac
        p=${p%%#*}
        [ -n "$p" ] || continue
        # RESOLVED AGAINST THE FILE'S OWN DIRECTORY, which is how markdown links work.
        # Resolving against the repo root instead reported all 50 rows of grc-eng's
        # controls/INDEX.md as broken — every one of them correct. Measured 2026-07-30 on
        # the first fleet run after this check was added: a new check's first output is
        # the one most likely to be wrong, and 50 confident false positives would have
        # retired the whole gate.
        [ -e "$(dirname "$file")/$p" ] && continue
        printf 'FAIL %s:%s: links to %s, which does not exist relative to %s\n' "$file" "$line" "$p" "$(dirname "$file")" >&2
        printf 'x' >> "$_FAILMARK"
      done
    done < "$recs"
  done
}

# claim_absent <file> <regex> — a phrase that must not appear, e.g. a retired claim.
claim_absent() {
  printf 'x' >> "$_RANMARK"
  local file="$1" pat="$2" line
  # A banned phrase cannot be absent from a document that is not there. Returning 0 meant
  # a renamed or deleted file silently satisfied every claim_absent about it.
  [ -f "$file" ] || { note_unchk "$file: in scope for claim_absent but missing — not clean"; return; }
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
  printf 'x' >> "$_RANMARK"
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
  # Inside $_SCRATCH so the trap installed at startup removes it; a second EXIT trap here
  # would REPLACE that one rather than add to it, and bash keeps exactly one.
  dir="$(mktemp -d "$_SCRATCH/selftest.XXXXXX")"
  _SELFDIR="$dir"

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

  # A guarded probe is the correct portable idiom, not a bad citation.
  printf 'for b in /var/home/nobody/nowhere /opt/x; do [ -d "$b" ] && use "$b"; done\n' > "$dir/D.md"
  _case "a path guarded by an existence test is a probe" 0 "documents agree"

  printf 'the tool lives at /var/home/nobody/nowhere and is required\n' > "$dir/D.md"
  _case "an unguarded path is still a citation" 1 "does not exist on this host"

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

  # ---- gaps found by adversarially probing this file on 2026-07-30 --------------
  # Every case below reproduced a run where the checker reported "documents agree" (or
  # fired on correct prose) while the fixture was lying. They are kept as fixtures because
  # a fix without a failing case is a claim about the code, not a check on it.

  printf 'we ship 7 widgets today\n' > "$dir/D.md"
  printf 'claim_count D.md ((( unbalanced\n' > "$dir/tools/docs-claims.sh"
  _case "a claims file that does not parse is UNCHECKABLE" 1 "does not parse"

  printf "claim_cont D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "a mistyped primitive is UNCHECKABLE, not clean" 1 "primitives this checker does not define"

  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\nexit 0\n" > "$dir/tools/docs-claims.sh"
  _case "a bare exit in the claims file cannot force a pass" 1 "claims 7"

  # The failure channel must survive a subshell: this FAIL is raised by _exempt_line from
  # inside a `... | while` loop, and the count itself AGREES, so nothing else can fail.
  printf 'we ship 9 widgets today [UNVERIFIED 2019-01-01]\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "an expired marker fails even when the count agrees" 1 "more than 90 days old"

  printf 'claim_path NOSUCH.md\n' > "$dir/tools/docs-claims.sh"
  _case "claim_path on a missing file is UNCHECKABLE" 1 "missing — not clean"

  printf "claim_absent NOSUCH.md 'forbidden'\n" > "$dir/tools/docs-claims.sh"
  _case "claim_absent on a missing file is UNCHECKABLE" 1 "missing — not clean"

  printf 'we ship 9 widgets and also 5 widgets\n' > "$dir/D.md"
  printf "claim_count D.md '([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "a second wrong match in one paragraph is caught" 1 "claims 5"

  printf 'we ship 0 widgets today\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'ls /no/such/dir 2>/dev/null | wc -l'\n" > "$dir/tools/docs-claims.sh"
  _case "a failed derivation printing 0 is not evidence of 0" 1 "could not look"

  printf "claim_count D.md 'ship ([0-9]+) widgets' 'printf \"9\\n5\\n\"'\n" > "$dir/tools/docs-claims.sh"
  _case "a multi-line derivation is UNCHECKABLE, not concatenated" 1 "printed 2 lines"

  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo not-a-number'\n" > "$dir/tools/docs-claims.sh"
  _case "a non-numeric derivation is UNCHECKABLE" 1 "not a single number"

  printf 'coverage is 87/100 today\n' > "$dir/D.md"
  printf "claim_count D.md 'is ([0-9]+)/100' 'echo 87'\n" > "$dir/tools/docs-claims.sh"
  _case "a pattern containing a slash still works" 0 "documents agree"

  # A REAL path at the end of a sentence must not be reported. $dir is guaranteed to
  # exist, and '.' is the only punctuation the capture charclass can absorb.
  printf 'the fixture lives at %s/D.md.\n' "$dir" > "$dir/D.md"
  printf 'claim_path D.md\n' > "$dir/tools/docs-claims.sh"
  _case "a real path followed by a period does not fire" 0 "documents agree"

  printf 'read [the design](docs/NOSUCHFILE.md) for detail\n' > "$dir/D.md"
  _case "a broken relative markdown link is caught" 1 "does not exist relative to"

  # Links resolve against the FILE's directory, not the repo root. Getting this wrong
  # reported 50 correct rows of grc-eng's controls/INDEX.md as broken.
  mkdir -p "$dir/sub/target"
  printf 'see [it](target/) and [also](target)\n' > "$dir/sub/N.md"
  printf 'claim_path sub/N.md\n' > "$dir/tools/docs-claims.sh"
  _case "a link resolves against its own file's directory" 0 "documents agree"

  printf 'read [the spec](https://example.com/x) and [top](#anchor)\n' > "$dir/D.md"
  _case "urls and anchors are not treated as paths" 0 "documents agree"

  # A link inside a fence is an example or a template the document EMITS, not a citation.
  # atlas's TRIP-init skill writes `[ARCHI.md](ARCHI.md)` into the project it initialises;
  # reporting that is reporting the skill's output as the skill's defect.
  printf 'the template is:\n\n```markdown\nsee [ARCHI.md](ARCHI.md) for rules\n```\n' > "$dir/D.md"
  printf 'claim_path D.md\n' > "$dir/tools/docs-claims.sh"
  _case "a link inside a code fence is a template, not a citation" 0 "documents agree"

  # An absolute path inside a fence is still checked: a runnable block that cds somewhere
  # nonexistent is the defect, not an example. hub/NEXT.md had exactly this.
  printf 'run it:\n\n```bash\ncd /var/home/nobody/nowhere\n```\n' > "$dir/D.md"
  _case "an absolute path inside a fence is still a citation" 1 "does not exist on this host"

  # ---- second adversarial round, 2026-07-30 -------------------------------------

  printf 'we ship 7 widgets today [UNVERIFIED 2099-01-01]\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "a future-dated marker is not a permanent off switch" 1 "dated in the future"

  printf 'f() {\n  claim_count D.md "ship ([0-9]+) widgets" "echo 9"\n}\n' > "$dir/tools/docs-claims.sh"
  printf 'we ship 7 widgets today\n' > "$dir/D.md"
  _case "a claims file that executes nothing is UNCHECKABLE" 1 "executed no claim at all"

  # Strikethrough retires the claim it WRAPS, not everything in the paragraph.
  printf 'we ship 7 widgets today.\nSeparately ~~an old note~~ is retired.\n' > "$dir/D.md"
  printf "claim_count D.md 'ship ([0-9]+) widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "an unrelated strikethrough does not excuse a stale number" 1 "claims 7"

  printf 'we ~~ship 7 widgets~~ today\n' > "$dir/D.md"
  _case "strikethrough around the claim itself still exempts" 0 "documents agree"

  printf 'we ship 7 widgets today\n' > "$dir/D.md"
  printf "claim_count D.md 'ship [0-9]+ widgets' 'echo 9'\n" > "$dir/tools/docs-claims.sh"
  _case "a pattern with no capture group is UNCHECKABLE" 1 "no capture group"

  printf 'claim_path\n' > "$dir/tools/docs-claims.sh"
  printf 'anything\n' > "$dir/D.md"
  _case "claim_path with no files is UNCHECKABLE" 1 "checked nothing"

  if [ "$bad" -ne 0 ]; then
    printf 'selftest: %s of %s cases FAILED\n' "$bad" "$n" >&2
    return 1
  fi
  printf 'selftest: %s cases, every primitive observed red for its stated reason.\n' "$n"
}

case "${1:-}" in
  ''|--selftest|--staged) ;;
  *)
    # A TYPO IN THE FLAG MUST NOT REPORT ON SOMETHING ELSE. `--stagd` used to fall through
    # and check the WORKING TREE, then print "documents agree" — a green verdict for a
    # check the operator did not ask for and did not get. Measured 2026-07-30.
    printf 'usage: docs-check.sh [--staged|--selftest]\n' >&2
    printf 'unknown argument: %s\n' "$1" >&2
    exit 2 ;;
esac

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
  # Registered with _track rather than given its own trap. It HAD its own, and the
  # _verdict trap installed further down replaced it — bash keeps one EXIT trap, not a
  # stack — so every --staged run leaked a full copy of the index into TMPDIR. Measured
  # 2026-07-30: 18 orphaned export trees on this machine. One trap, one cleanup list.
  _staged_dir="$(mktemp -d "$_SCRATCH/staged.XXXXXX")"
  git checkout-index -a --prefix="$_staged_dir/" 2>/dev/null || {
    printf 'UNCHECKABLE could not export the index — not clean.\n' >&2; exit 1
  }
  cd "$_staged_dir" || exit 1
fi

# ---------------------------------------------------------------------------
CLAIMS="tools/docs-claims.sh"

# THE VERDICT IS AN EXIT TRAP, because any line placed after `. "$CLAIMS"` can be skipped.
# The claims file is SOURCED, so a bare `exit 0` in it terminates this script outright —
# measured 2026-07-30, a fixture printed a real FAIL line and exited 0. A syntax error
# aborts the source at that point and every claim below it silently never runs. Only an
# EXIT trap is guaranteed to execute in both cases, so the pass/fail decision lives there
# and nowhere else.
_CLAIMS_DONE=0
_verdict() {
  local rc=$? bad=0
  [ -s "$_FAILMARK" ] && bad=1
  if [ "$_CLAIMS_DONE" -eq 1 ] && [ ! -s "$_RANMARK" ]; then
    printf 'UNCHECKABLE %s ran to completion but executed no claim at all.\n' "$CLAIMS" >&2
    printf '  Claims nested inside a function that is never called, or behind a condition\n' >&2
    printf '  that never held, are declared and unenforced. Nothing was checked.\n' >&2
    bad=1
  fi
  if [ "$_CLAIMS_DONE" -ne 1 ]; then
    printf 'UNCHECKABLE %s did not run to completion — a syntax error, a bare `exit`, or a\n' "$CLAIMS" >&2
    printf '  crashed derivation stopped it partway, so an unknown number of claims never ran.\n' >&2
    printf '  Partial coverage reported as clean is the defect this file exists to catch.\n' >&2
    bad=1
  fi
  rm -rf "$_SCRATCH" 2>/dev/null
  [ "$bad" -eq 0 ] || exit 1
  [ "$rc" -eq 0 ] || exit "$rc"
  printf 'docs-check(v%s): documents agree with the repo.\n' "$DOCS_CHECK_VERSION"
  exit 0
}
trap _verdict EXIT

if [ ! -f "$CLAIMS" ]; then
  printf 'UNCHECKABLE %s is missing — a repo with no declared claims is not a clean repo.\n' "$CLAIMS" >&2
  _CLAIMS_DONE=1; exit 1
fi
if ! grep -qE '^[[:space:]]*claim_' "$CLAIMS"; then
  printf 'UNCHECKABLE %s declares no claims — UNCHECKABLE is not clean.\n' "$CLAIMS" >&2
  _CLAIMS_DONE=1; exit 1
fi

# SYNTAX IS CHECKED BEFORE THE FILE IS SOURCED. A syntax error in a sourced file does NOT
# abort the parent script — `.` merely returns nonzero and execution carries on — so the
# _CLAIMS_DONE guard below cannot see it, and every claim after the bad line silently
# never runs. Measured 2026-07-30: a malformed claims file produced "documents agree".
# `bash -n` is the only thing that catches this before the damage, and its status cannot
# be confused with a claim's own result.
if ! bash -n "$CLAIMS" 2>/dev/null; then
  printf 'UNCHECKABLE %s does not parse — every claim in it is unenforced:\n' "$CLAIMS" >&2
  bash -n "$CLAIMS" 2>&1 | sed 's/^/  /' >&2
  _CLAIMS_DONE=1; exit 1
fi

# EVERY claim_* CALLED MUST BE A PRIMITIVE THAT EXISTS. A mistyped name is not a syntax
# error: bash prints "command not found", carries on, and the claim simply never runs —
# measured 2026-07-30, `claim_cont` produced a green "documents agree". This also catches
# a claims file written against a newer vendored copy than the one installed here.
_KNOWN=" claim_count claim_path claim_absent claim_enforced "
_unknown=$(grep -oE '^[[:space:]]*claim_[A-Za-z0-9_]+' "$CLAIMS" | tr -d '[:blank:]' | sort -u \
  | while IFS= read -r c; do case "$_KNOWN" in (*" $c "*) ;; (*) printf '%s ' "$c" ;; esac; done)
if [ -n "$_unknown" ]; then
  printf 'UNCHECKABLE %s calls primitives this checker does not define: %s\n' "$CLAIMS" "$_unknown" >&2
  printf '  A mistyped claim never runs and reports nothing, which reads as clean.\n' >&2
  printf '  Known primitives:%s\n' "$_KNOWN" >&2
  _CLAIMS_DONE=1; exit 1
fi

# shellcheck source=/dev/null
. "$CLAIMS"
_CLAIMS_DONE=1
