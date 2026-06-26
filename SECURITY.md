# Security Policy

depfence is a supply-chain security scanner, so we hold its own security to a high
bar. Thank you for helping keep depfence and its users safe.

## Supported Versions

Security fixes are applied to the latest released `0.x` version. depfence has not yet
reached `1.0`; pin a known-good version in production and upgrade promptly when a
security release is published.

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| 0.6.x   | :white_check_mark: |
| < 0.6   | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

1. **GitHub Security Advisories (preferred):** open a draft advisory at
   <https://github.com/ericrihm/depfence/security/advisories/new>. This keeps the
   report private and lets us collaborate on a fix and CVE if warranted.
2. **Email:** `security@cobaltsystems.io` with subject `depfence security`. PGP
   available on request.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal project tree or workflow, the exact `depfence`
  command, and the observed vs. expected output).
- The depfence version (`depfence --version`), Python version, and OS.
- Any proof-of-concept, logs, or suggested remediation you have.

## Scope

In scope:

- The `depfence` Python package and CLI (`depfence/`).
- The scanner, analyzer, and reporter plugins shipped in this repository.
- The MCP server (`depfence-mcp`).
- The published GitHub Action (`action.yml`) and the workflows in
  `.github/workflows/`.
- Issues where depfence itself introduces risk: arbitrary code execution while
  scanning an untrusted project, command/SARIF injection in output, SSRF in
  advisory lookups, or secret leakage in logs/reports.

Out of scope:

- Vulnerabilities in third-party dependencies that depfence merely *reports on*
  (report those to the upstream project).
- False positives / false negatives in detections. These are correctness bugs, not
  vulnerabilities — please file a regular issue with a reproducer.
- Findings that require a malicious local plugin already installed with the user's
  consent (`DEPFENCE_PLUGIN_PATH`, `~/.depfence/plugins/`, or an installed entry
  point), since plugins run as trusted code by design.

## Our Commitment

- We will acknowledge your report within **3 business days**.
- We will provide an initial assessment within **7 business days**.
- We aim to ship a fix or mitigation for confirmed high/critical issues within
  **30 days**, coordinating a disclosure timeline with you.
- We will credit reporters in the release notes and any advisory unless you prefer
  to remain anonymous.

## Safe Harbor

We will not pursue or support legal action against researchers who act in good
faith, avoid privacy violations and service disruption, and give us a reasonable
opportunity to remediate before any public disclosure.
