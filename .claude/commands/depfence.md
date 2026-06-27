# /depfence — AI-Aware Dependency Security Scanner

Scan the current project for supply chain risks, vulnerabilities, and AI safety issues.

## Instructions

1. If `$ARGUMENTS` is a single word with no slashes or dots, treat it as a package name and run:
```bash
depfence check $ARGUMENTS -e $(depfence scan . --format json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ecosystems',['pypi'])[0])" 2>/dev/null || echo pypi)
```

2. If `$ARGUMENTS` is empty or a path, run a full project scan:
```bash
depfence scan ${ARGUMENTS:-.} --format json --top 20 2>/dev/null
```

3. If `$ARGUMENTS` is a mode keyword, dispatch to the appropriate subcommand:
   - `quick` → `depfence audit .`
   - `deep` → `depfence scan . --format json`
   - `ai` → `depfence ai-scan . --format json`
   - `docker` → `depfence scan-docker . --format json`
   - `secrets` → `depfence secrets scan . --format json`
   - `mcp` → `depfence mcp-scan . --format json`
   - `actions` → `depfence gha-scan . --format json`
   - `licenses` → `depfence license-scan . --format json`

4. Parse the JSON output and present results as:
   - **Summary line**: "X findings across Y packages (Z critical, W high, V medium)"
   - **Top findings**: severity | package | title | fix action
   - **Verdict**: CLEAN (0 findings), CAUTION (low/medium only), or UNSAFE (critical/high present)

5. If findings exist, suggest next steps:
   - `/depfence-check <package>` for deep-dive on a specific package
   - `/depfence-fix` to generate a remediation plan
   - `depfence diff --git` to see what changed since last commit

If depfence is not installed, tell the user: `pip install depfence` or `uvx depfence scan .`
