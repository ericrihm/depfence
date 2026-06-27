# /depfence-fix — Auto-Remediate Security Findings

Generate and apply a remediation plan for vulnerable dependencies.

## Instructions

1. Run the remediation dry-run to get the plan:
```bash
depfence fix . --format json 2>/dev/null
```

2. Parse the JSON and present as a table:
   | Package | Current | Target | CVEs Fixed | Breaking Risk |
   |---------|---------|--------|------------|---------------|

   Mark breaking risk as LOW (patch/minor bump), MEDIUM (major bump), or HIGH (API changes flagged).

3. Ask the user which fixes to apply:
   - **"all safe"** — apply only patch/minor bumps (no breaking risk)
   - **"all"** — apply every fix in the plan
   - **specific packages** — comma-separated list

4. If approved, apply the selected fixes:
```bash
depfence fix . --apply --fail-on none 2>/dev/null
```
   If the user chose specific packages, pass `--packages <pkg1,pkg2>` if the CLI supports it; otherwise apply all and note what was changed.

5. Confirm changes landed:
```bash
depfence diff . --git --format json 2>/dev/null
```
   Show which lockfiles were modified and summarize before/after CVE counts.

6. Remind the user to run their test suite before committing: "Run your tests to verify nothing broke, then commit the lockfile changes."

If no findings require remediation, say so and suggest `/depfence` for a fresh scan.

If depfence is not installed, tell the user: `pip install depfence`
