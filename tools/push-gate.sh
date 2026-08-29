#!/usr/bin/env bash
# Secret-scan gate for pushes.
#
# Scans ONLY what is about to be pushed, not the working directory.
# Measured 2026-08-29: `gitleaks detect --no-git --source .` returned 159
# findings, 113 of which lived in .claude/worktrees/ and build/ -- paths that
# are excluded from git and can never be pushed. A gate that is ~70% noise
# gets ignored, which is how a real hit slips through.
#
# Exits non-zero on any finding. Callers MUST check the exit status; chaining
# this with `;` before a push defeats the entire point.
set -euo pipefail

REMOTE="${1:-origin}"
BRANCH="${2:-$(git rev-parse --abbrev-ref HEAD)}"
RANGE="${REMOTE}/${BRANCH}..HEAD"

if ! git rev-parse --verify --quiet "${REMOTE}/${BRANCH}" >/dev/null; then
  echo "push-gate: ${REMOTE}/${BRANCH} does not exist; scanning all of HEAD" >&2
  RANGE="HEAD"
fi

COUNT=$(git rev-list --count "${RANGE}" 2>/dev/null || echo 0)
if [ "${COUNT}" = "0" ]; then
  echo "push-gate: nothing to push."
  exit 0
fi

echo "push-gate: scanning ${COUNT} commit(s) in ${RANGE}"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "push-gate: REFUSING -- gitleaks is not installed." >&2
  echo "push-gate: an unavailable scanner is not a passing scan." >&2
  exit 2
fi

REPORT=$(mktemp -t push-gate-XXXXXX.json)
trap 'rm -f "${REPORT}"' EXIT

# --log-opts scopes the scan to the outgoing commits only.
set +e
gitleaks detect --log-opts="${RANGE}" \
  --report-format json --report-path "${REPORT}" --redact >/dev/null 2>&1
RC=$?
set -e

FOUND=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "${REPORT}" 2>/dev/null || echo "?")

if [ "${RC}" -ne 0 ] || { [ "${FOUND}" != "0" ] && [ "${FOUND}" != "?" ]; }; then
  echo "push-gate: BLOCKED -- ${FOUND} finding(s) in the outgoing commits." >&2
  python3 - "${REPORT}" <<'PY' >&2 || true
import json, sys
for f in json.load(open(sys.argv[1]))[:20]:
    print(f"  {f['File']}:{f['StartLine']}  {f['RuleID']}")
PY
  exit 1
fi

echo "push-gate: clean (${FOUND} findings in outgoing commits)."
