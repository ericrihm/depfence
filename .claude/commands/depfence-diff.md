# /depfence-diff — Dependency Changes Since Last Commit

Show what changed in your dependency tree and whether it's safe to merge.

## Arguments

`$ARGUMENTS` can be:
- empty — diff against last git commit
- `ci` — lockfile drift detection mode
- two paths — SBOM-to-SBOM diff: `<before.json> <after.json>`

## Instructions

1. Dispatch based on `$ARGUMENTS`:

   **Two paths** (SBOM diff):
   ```bash
   depfence sbom-diff <before> <after> --format json 2>/dev/null
   ```

   **`ci` keyword**:
   ```bash
   depfence diff . --git --ci --format json 2>/dev/null
   ```

   **Empty or single path** (default):
   ```bash
   depfence diff . --git --format json 2>/dev/null
   ```

2. Categorize and present changes:

   - **NEW** packages — run a risk check on each:
     ```bash
     depfence check <package> -e <ecosystem> 2>/dev/null
     ```
     Flag any with risk_score ≥ 50 or known CVEs.

   - **UPGRADED** — show old version → new version, net CVE delta (fixed vs. introduced).

   - **REMOVED** — list with no action needed unless they were load-bearing security packages (e.g., cryptography libraries).

   - **DOWNGRADED** — flag as suspicious. Downgrades can reintroduce known CVEs. Show which CVEs return.

3. Render a summary table:
   | Change | Package | From | To | Risk |
   |--------|---------|------|----|------|

4. Deliver a merge verdict:
   - **safe to merge** — no new critical/high issues, no suspicious downgrades
   - **review needed** — new packages with moderate risk or CVE delta is non-zero
   - **block — critical issues** — new critical CVEs introduced, active typosquat, or unexplained downgrade

5. If blockers exist, suggest `/depfence-fix` or `/depfence-check <package>` for the specific offenders.

If depfence is not installed, tell the user: `pip install depfence`
