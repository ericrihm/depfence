# Contributing to depfence

## Quick start

```bash
git clone https://github.com/ericrihm/depfence && cd depfence
pip install -e ".[dev]"
pytest tests/ -v
ruff check depfence/ tests/
```

## Adding a scanner

depfence loads scanners via pip entry points. To add one:

1. Create `depfence/scanners/your_scanner.py`:

```python
from depfence.core.models import Finding, FindingType, PackageMeta, Severity

class YourScanner:
    name = "your_scanner"
    ecosystems = ["pypi", "npm"]  # which ecosystems this applies to

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        """Scan package metadata. Return findings."""
        findings = []
        for meta in packages:
            # your detection logic here
            pass
        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Optional: scan files in the project directory."""
        return []
```

2. Register it in `pyproject.toml` under `[project.entry-points."depfence.scanners"]`:

```toml
your_scanner = "depfence.scanners.your_scanner:YourScanner"
```

3. Add tests in `tests/test_your_scanner.py`. Every scanner needs tests.

4. Reinstall: `pip install -e ".[dev]"` to pick up the new entry point.

**Two scanner types:**
- **Entry-point scanners** implement `scan(packages)` — they operate on fetched package metadata (name, version, maintainers, install scripts).
- **Project scanners** implement `scan_project(project_dir)` — they walk files (workflows, Dockerfiles, model files, configs).

A scanner can implement both.

## Architecture

```
lockfile detection → metadata fetch → scanner execution → enrichment → output
                                           │
                               ┌───────────┴───────────┐
                      entry-point scanners      project scanners
                      (42 via pip registry)     (21 filesystem-based)
                               │                       │
                      operate on PackageMeta    operate on project dir
```

Enrichment adds EPSS scores, CISA KEV status, OpenSSF Scorecard, and reachability data.
Output formats: table, JSON, SARIF, HTML, CycloneDX, SPDX.

## Code style

- **Linter**: ruff (config in `pyproject.toml`)
- **Line length**: 100
- **Target**: Python 3.10+
- **Tests**: pytest with pytest-asyncio
- **Type hints**: use them, but full mypy strictness is not required

Run before submitting:

```bash
ruff check depfence/ tests/
pytest tests/ -v
```

## Testing

- Every scanner needs a corresponding `tests/test_<scanner_name>.py`
- Target >95% coverage per scanner file
- Test both detection (malicious input triggers finding) and false-positive avoidance (benign input produces no findings)
- Use `pytest-asyncio` for async scanner methods
- CI runs tests on Python 3.10, 3.11, 3.12, and 3.13

## Pull requests

- Branch from `main`. Name branches `feat/<thing>`, `fix/<thing>`, or `docs/<thing>`.
- Keep PRs focused — one scanner or one feature per PR.
- Include tests. PRs without tests for new detection logic will be asked to add them.
- CI must pass (lint + tests + self-scan + action pin verification).
- Write a clear description: what the scanner detects, a real-world example of the attack, and how you tested it.

## Reporting false positives

Open an issue with:
- The `finding_type` and `matched_pattern` from the finding metadata
- The package name and version (or file path) that triggered it
- Why you believe it's a false positive

We take false positives seriously — every one erodes trust in the tool.

## Security vulnerabilities

See [SECURITY.md](SECURITY.md) for reporting security issues. Do not open public issues for vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
