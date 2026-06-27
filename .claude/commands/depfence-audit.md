# /depfence-audit — Full 7-Dimension Security Audit

Run all depfence scanners in parallel and produce a graded security report.

## Instructions

1. Run all 7 scans in parallel via a single Bash call:
```bash
depfence scan . --format json 2>/dev/null > /tmp/df_deps.json &
depfence license-scan . --format json 2>/dev/null > /tmp/df_license.json &
depfence secrets scan . --format json 2>/dev/null > /tmp/df_secrets.json &
depfence scan-workflows . --format json 2>/dev/null > /tmp/df_workflows.json &
depfence scan-docker . --format json 2>/dev/null > /tmp/df_docker.json &
depfence mcp-scan . --format json 2>/dev/null > /tmp/df_mcp.json &
depfence ai-scan . --format json 2>/dev/null > /tmp/df_ai.json &
wait
```

2. Parse all seven output files. For each dimension, extract critical/high/medium/low counts.

3. Calculate the overall letter grade from the **worst** dimension:
   - **A** — 0 critical, 0 high across all dimensions
   - **B** — 0 critical, ≤ 3 high total
   - **C** — 0 critical, ≤ 10 high total
   - **D** — 1+ critical findings
   - **F** — 5+ critical findings

4. Present per-dimension grades in a table:
   | Dimension | Tool | Critical | High | Medium | Grade |
   |-----------|------|----------|------|--------|-------|
   | Dependencies | depfence scan | | | | |
   | Licenses | depfence license-scan | | | | |
   | Secrets | depfence secrets scan | | | | |
   | CI/Workflows | depfence scan-workflows | | | | |
   | Docker | depfence scan-docker | | | | |
   | MCP Tools | depfence mcp-scan | | | | |
   | AI/LLM | depfence ai-scan | | | | |

   Apply the same A/B/C/D/F scale to each dimension individually.

5. Prioritized remediation roadmap — ordered by severity then ease of fix:
   - P0 (fix now): all critical findings
   - P1 (fix this sprint): high findings in deps and secrets
   - P2 (schedule): high findings in other dimensions, medium findings in deps
   - P3 (track): medium findings elsewhere, license policy gaps

6. Suggest next steps:
   - `/depfence-fix` for P0/P1 dependency findings
   - `/depfence-check <package>` for the highest-risk individual package
   - `depfence secrets rotate <file>` for any exposed secrets

If a scan produces no output (tool not applicable, e.g. no Docker files), mark that dimension as N/A rather than A.

If depfence is not installed, tell the user: `pip install depfence`
