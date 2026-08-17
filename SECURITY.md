# Security Policy

depfence is a supply-chain security scanner, so we hold its own security to a high
bar. Thank you for helping keep depfence and its users safe.

## Supported Versions

Security fixes are applied to the latest released `0.x` version. depfence has not yet
reached `1.0`; pin a known-good version in production and upgrade promptly when a
security release is published.

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
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

## Untrusted Fonts and Documents

Treat fonts, HTML, DOCX, and PDF files as hostile parser inputs. Normal
`depfence scan` analysis is structural and never renders a document, registers a
font, launches an office suite, performs OCR, or fetches linked resources.

Use `depfence artifact inspect PATH` to process one bounded regular file in
private state without previewing it. Raw bytes are removed after analysis by
default; retained records are redacted and logical deletion is not represented
as secure erasure. Sandboxed comparison is explicit and requires a
digest-pinned, Sigstore-verified OCI image. Run `depfence artifact doctor`
first. On native Linux,
depfence also requires gVisor or Kata rather than an ordinary shared-kernel
runtime.

For a remote repository that may contain parser-hostile artifacts, use
`depfence intake inspect-sealed` with an exact commit. It performs offline
static analysis of supported Git blobs and retains only a redacted manifest; it
does not materialize repository files on the host. Acquisition must traverse a
dedicated internal network and allowlisting proxy. The older `intake inspect`
command is suitable only when host-side private quarantine is acceptable.

For AI/RAG pipelines:

- Treat extracted text and OCR text as separate untrusted channels.
- Preserve and block on meaningful discrepancies; never silently prefer one.
- Do not turn document text into agent instructions or executable commands.
- OCR is evidence, not content sanitization or CDR.
- Do not use desktop previews, host font APIs, Word, LibreOffice, or browsers to
  inspect an untrusted artifact outside an appropriate isolation boundary.

## Safe Harbor

We will not pursue or support legal action against researchers who act in good
faith, avoid privacy violations and service disruption, and give us a reasonable
opportunity to remediate before any public disclosure.
