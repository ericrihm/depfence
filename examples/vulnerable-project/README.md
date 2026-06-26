# Vulnerable Project — depfence Demo

This project contains intentional security vulnerabilities for testing depfence.
**Do not use any of these files in production.**

## Attack payloads included

| File | Attack Class | Severity |
|------|-------------|----------|
| `.github/workflows/ci.yml` | Fabricated SHA pin (hallucinated commit) | CRITICAL |
| `node_modules/jqwik-react/lib/index.js` | ANSI-hidden prompt injection | CRITICAL |
| `node_modules/jqwik-react/package.json` | Package description injection | CRITICAL |
| `src/analytics.py` | Anti-analysis evasion + base64 payload | CRITICAL |
| `package-lock.json` | Slopsquatting + scope typosquatting | HIGH |

## Run the demo

```bash
pip install depfence   # or: pip install -e . from the repo root
depfence scan examples/vulnerable-project --no-fetch
```

Expected output: 70+ findings, 11 critical, 17 high — including attack classes
that Snyk, Trivy, and Grype do not detect.
