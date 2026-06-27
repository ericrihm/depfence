# /depfence-check — Single Package Security Deep-Dive

Check whether a package is safe before adding it as a dependency.

## Arguments

`$ARGUMENTS` should be `<package_name> [ecosystem]`. If ecosystem is omitted, auto-detect from the project's lockfiles.

## Instructions

1. Parse the package name and ecosystem from `$ARGUMENTS`:
```bash
# Auto-detect ecosystem if not provided
if [ -f package-lock.json ] || [ -f yarn.lock ] || [ -f pnpm-lock.yaml ]; then
  ECO="npm"
elif [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f Pipfile.lock ]; then
  ECO="pypi"
elif [ -f Cargo.lock ]; then
  ECO="cargo"
elif [ -f go.sum ]; then
  ECO="go"
elif [ -f Gemfile.lock ]; then
  ECO="rubygems"
elif [ -f composer.lock ]; then
  ECO="composer"
else
  ECO="pypi"
fi
```

2. Run these three checks in parallel via Bash:
```bash
depfence check <package> -e <ecosystem> 2>/dev/null
```
```bash
depfence trust <package> -e <ecosystem> 2>/dev/null
```

3. Synthesize results into a verdict:
   - **SAFE** (risk_score < 30, no typosquat, no CVEs): "Safe to use. No known issues."
   - **CAUTION** (risk_score 30-49 OR minor CVEs): "Usable with caution. Pin to version X.Y.Z."
   - **UNSAFE** (risk_score >= 50 OR typosquat OR malicious): "Do NOT install. Consider <alternative> instead."

4. Always include:
   - Risk score (0-100) with letter grade
   - Trust score breakdown (downloads, age, maintainers)
   - Any CVEs with EPSS exploitation probability
   - License compatibility
   - Safer alternatives if the package is risky

If depfence is not installed, tell the user: `pip install depfence`
