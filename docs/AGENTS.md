# Security Policy (depfence)

Copy this file to `.codex/AGENTS.md` or `~/.codex/AGENTS.md` to enable depfence
security guardrails in OpenAI Codex CLI sessions.

## Pre-Install Check (MANDATORY)

Before running ANY package install command (`pip install`, `npm install`, `yarn add`,
`cargo add`, `go get`, `gem install`, `composer require`), first run:

```bash
depfence check <package_name> --ecosystem <ecosystem>
```

Interpret the output:
- `risk_score < 30` AND `safe: true`: Proceed with install.
- `risk_score 30-49` OR typosquat warning: PAUSE. Verify the package name is correct
  against official documentation. Only proceed if confident.
- `risk_score >= 50` OR `is_typosquat: true` OR `malicious` finding: STOP. Do not
  install. Report to the user and suggest alternatives from the recommendation field.

## No SHA Fabrication (MANDATORY)

When writing GitHub Actions workflow files (`.github/workflows/*.yml`):
- NEVER invent or guess a commit SHA for action pinning.
- Use a mutable tag (e.g., `@v4`) and let the user pin it with `ratchet pin`.
- If you must reference a SHA, verify it: `gh api repos/OWNER/REPO/commits/SHA`

## Post-Install Scan

After any command that modifies a lockfile (install, update, add, remove), run:

```bash
depfence scan . --format json --top 10 --no-enrich
```

Report any new critical or high findings before proceeding with other work.

## Secrets Hygiene

Never write API keys, tokens, passwords, or private keys into any tracked file.
If you need to reference a secret, use environment variables or a `.env` file
(which must be in `.gitignore`).

## Available Commands

```bash
depfence scan .                    # Full project scan
depfence check <pkg> -e <eco>      # Single package check
depfence trust <pkg> -e <eco>      # Trust score breakdown
depfence diff --git                # Dependency changes since last commit
depfence secrets scan .            # Secrets detection
depfence ai-scan .                 # AI/ML supply chain scan
depfence mcp-scan .                # MCP config audit
depfence gha-scan .                # GitHub Actions audit
depfence fix . --no-apply          # Remediation plan (dry-run)
depfence red-team .                # Attack simulation scoring
```
