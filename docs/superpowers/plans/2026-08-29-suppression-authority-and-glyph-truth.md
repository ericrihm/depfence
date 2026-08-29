# Suppression Authority and Glyph-Truth Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop an audited repository from waiving its own findings, and detect PDFs whose drawn glyphs disagree with their declared Unicode.

**Architecture:** Two independent changes. First, suppression authority moves outside the scanned tree: an in-repo `.depfence-baseline.json` is ignored by default and its use is reported, while an explicitly-passed `--baseline PATH` is always honoured. Second, a new `pdf_glyph_truth` module resolves content-stream codes through `/CIDToGIDMap` to the embedded font program's own character map, and compares that ground truth against the PDF's `/ToUnicode` claim.

**Tech Stack:** Python 3.10+, `pypdf` (BSD-3), `fontTools` (MIT), `click`, `pytest`. No new dependencies — both libraries are already in the `[evilfont]` extra.

**Spec:** `docs/superpowers/specs/2026-08-29-autonomous-loop-design.md` (loop driver, separate plan) and the gap register at `~/dev/tech-notebooks/40-security/reference/depfence-evilfont-roadmap.md` §G-L and §G-M.

## Global Constraints

- Licence: Apache-2.0. No AGPL dependency may be added — this rules out PyMuPDF, iText and doc-sherlock.
- Python floor: 3.10 (`pyproject.toml` `requires-python`).
- Every new rule ID must be added to all four registers or the sealed pipeline rejects it: `depfence/schemas/depfence.sealed-intake.v1.schema.json`, `depfence/core/sealed_intake.py` (`allowed_rules`, `allowed_evidence_classes`, `_RULE_CONTRACT`), and `depfence/sealed_git_worker.py`.
- `tools/docs-check.sh` must exit 0 before every commit. Adding tests changes the README counts; update `README.md:9` (badge) and `README.md:648` (function/file counts) in the same commit.
- Run tests with `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest` — the repo `.venv` has no pytest.
- Never author or modify `.depfence-baseline.json` outside a test fixture.

## File Structure

| File | Responsibility |
|---|---|
| `depfence/core/baseline.py` (modify) | Gains `trusted` flag; `from_project` no longer implies authority |
| `depfence/cli/main.py` (modify, ~line 154) | Honours the new flag; reports ignored suppressions |
| `depfence/core/pdf_glyph_truth.py` (create) | Resolves code→GID→ground-truth character from the embedded font |
| `depfence/core/artifact_analysis.py` (modify) | Emits `DF-PDF-004` from the new module |
| `tests/test_baseline_authority.py` (create) | Authority tests |
| `tests/test_pdf_glyph_truth.py` (create) | Detector tests |
| `tests/fixtures/pdf/` (create) | Four committed PDF fixtures |

---

### Task 1: Baseline requires explicit trust

**Files:**
- Modify: `depfence/core/baseline.py:32-35`
- Test: `tests/test_baseline_authority.py`

**Interfaces:**
- Consumes: `Finding` from `depfence.core.models`, `finding_fingerprint` from this module.
- Produces: `Baseline.from_project(project_dir: Path, trusted: bool = False) -> Baseline` and `Baseline.ignored_count: int`. Task 2 consumes both.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_baseline_authority.py
import json
from pathlib import Path

from depfence.core.baseline import Baseline, finding_fingerprint
from depfence.core.models import Finding, FindingType, Severity


def _finding() -> Finding:
    return Finding(
        finding_type=FindingType.VISUAL_TEXT_DECEPTION,
        severity=Severity.CRITICAL,
        package="artifact:evil.pdf",
        title="Rendered text differs from machine-readable text",
        detail="",
        confidence=0.99,
    )


def _write_baseline(project_dir: Path, finding: Finding) -> None:
    (project_dir / ".depfence-baseline.json").write_text(
        json.dumps({finding_fingerprint(finding): {"reason": "attacker supplied"}})
    )


def test_project_baseline_is_ignored_by_default(tmp_path: Path) -> None:
    """An in-repo baseline is attacker-controlled and must not suppress."""
    finding = _finding()
    _write_baseline(tmp_path, finding)

    baseline = Baseline.from_project(tmp_path)

    assert baseline.is_suppressed(finding) is False
    assert baseline.count == 0
    assert baseline.ignored_count == 1


def test_project_baseline_applies_when_explicitly_trusted(tmp_path: Path) -> None:
    """A human opting in locally keeps the existing workflow."""
    finding = _finding()
    _write_baseline(tmp_path, finding)

    baseline = Baseline.from_project(tmp_path, trusted=True)

    assert baseline.is_suppressed(finding) is True
    assert baseline.count == 1
    assert baseline.ignored_count == 0


def test_explicit_path_outside_the_tree_is_always_trusted(tmp_path: Path) -> None:
    """--baseline PATH is supplied by the operator, not the audited repo."""
    finding = _finding()
    external = tmp_path / "external.json"
    external.write_text(
        json.dumps({finding_fingerprint(finding): {"reason": "reviewed"}})
    )

    baseline = Baseline(external)

    assert baseline.is_suppressed(finding) is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_baseline_authority.py -v`

Expected: FAIL — `test_project_baseline_is_ignored_by_default` asserts `is_suppressed is False` but current code returns `True`; `ignored_count` raises `AttributeError`.

- [ ] **Step 3: Write minimal implementation**

Replace `depfence/core/baseline.py:26-35` with:

```python
    def __init__(self, path: Path | None = None, *, trusted: bool = True) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        self._ignored_count = 0
        if path and path.exists():
            self._load()
            if not trusted:
                # The baseline came from the scanned tree, so a malicious PR can
                # add an entry suppressing its own finding: the fingerprint is
                # sha256 over finding_type + package + title, all of which the
                # attacker controls or can read from this source.
                self._ignored_count = len(self._entries)
                self._entries = {}

    @property
    def ignored_count(self) -> int:
        """Entries found in an untrusted baseline and deliberately not applied."""
        return self._ignored_count

    @classmethod
    def from_project(cls, project_dir: Path, *, trusted: bool = False) -> Baseline:
        path = project_dir / ".depfence-baseline.json"
        return cls(path, trusted=trusted)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_baseline_authority.py -v`

Expected: 3 passed.

- [ ] **Step 5: Run the existing baseline tests**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/ -k baseline -v`

Expected: all pass. `Baseline(path)` still defaults to `trusted=True`, so direct construction is unchanged.

- [ ] **Step 6: Commit**

```bash
git add depfence/core/baseline.py tests/test_baseline_authority.py
git commit -m "fix(baseline): require explicit trust for in-repo suppressions"
```

---

### Task 2: CLI reports ignored suppressions and adds the opt-in flag

**Files:**
- Modify: `depfence/cli/main.py:154-161`
- Test: `tests/test_baseline_authority.py`

**Interfaces:**
- Consumes: `Baseline.from_project(project_dir, trusted=...)` and `Baseline.ignored_count` from Task 1.
- Produces: the `--trust-project-baseline` CLI flag.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_baseline_authority.py`:

```python
from click.testing import CliRunner

from depfence.cli.main import cli


def test_scan_warns_when_a_project_baseline_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".depfence-baseline.json").write_text(
        json.dumps({"0123456789abcdef": {"reason": "attacker supplied"}})
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-fetch"])

    assert "1 suppression" in result.output or "1 suppression" in (result.stderr or "")


def test_scan_accepts_the_trust_flag(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    result = CliRunner().invoke(
        cli, ["scan", str(tmp_path), "--no-fetch", "--trust-project-baseline"]
    )

    assert result.exit_code == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_baseline_authority.py -k "warns or trust_flag" -v`

Expected: FAIL — `--trust-project-baseline` is not a known option (exit code 2).

- [ ] **Step 3: Add the flag**

Add to the `scan` command's decorators in `depfence/cli/main.py`, beside the other scan options:

```python
@click.option(
    "--trust-project-baseline",
    is_flag=True,
    default=False,
    help="Apply .depfence-baseline.json from the scanned project. Off by default: "
         "a scanned repository must not be able to suppress its own findings.",
)
```

Add `trust_project_baseline: bool` to the `scan` function signature.

- [ ] **Step 4: Use it at the filtering site**

Replace `depfence/cli/main.py:154-161` with:

```python
    # Filter out baselined findings
    from depfence.core.baseline import Baseline
    bl = Baseline.from_project(project_dir, trusted=trust_project_baseline)
    if bl.ignored_count:
        click.echo(
            f"({bl.ignored_count} suppression(s) in the project baseline were ignored; "
            "pass --trust-project-baseline to apply them)",
            err=True,
        )
    if bl.count > 0:
        active, suppressed = bl.filter_findings(result.findings)
        if suppressed:
            click.echo(f"({len(suppressed)} baselined finding(s) suppressed)", err=True)
        result.findings = active
```

- [ ] **Step 5: Run tests**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_baseline_authority.py tests/test_cli_integration.py -v`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add depfence/cli/main.py tests/test_baseline_authority.py
git commit -m "fix(cli): report ignored project suppressions, add --trust-project-baseline"
```

---

### Task 3: Glyph-truth resolution module

**Files:**
- Create: `depfence/core/pdf_glyph_truth.py`
- Test: `tests/test_pdf_glyph_truth.py`
- Create: `tests/fixtures/pdf/{orig,evil,stealth,fpdf}.pdf` — copy from `~/dev/_backups/evilfont-detector-2026-08-29/`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `glyph_truth_mismatches(data: bytes) -> list[GlyphMismatch]` where `GlyphMismatch` is a frozen dataclass with fields `page: int`, `font: str`, `code: int`, `drawn: str`, `claimed: str`. Task 4 consumes both.

- [ ] **Step 1: Copy the fixtures**

```bash
mkdir -p tests/fixtures/pdf
cp ~/dev/_backups/evilfont-detector-2026-08-29/{orig,evil,stealth,fpdf}.pdf tests/fixtures/pdf/
git add -f tests/fixtures/pdf/
```

`orig.pdf` is benign; `evil.pdf` hijacks `ABC`→`XYZ`; `stealth.pdf` renders "1000" and extracts "9000"; `fpdf.pdf` is benign and carries a **non-identity** `/CIDToGIDMap`, which is the false-positive trap.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_pdf_glyph_truth.py
from pathlib import Path

import pytest

from depfence.core.pdf_glyph_truth import glyph_truth_mismatches

FIXTURES = Path(__file__).parent / "fixtures" / "pdf"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_benign_pdf_has_no_mismatches() -> None:
    assert glyph_truth_mismatches(_read("orig.pdf")) == []


def test_non_identity_cid_to_gid_map_is_not_a_false_positive() -> None:
    """fpdf2 emits Identity-H with a non-identity CIDToGIDMap. Ignoring the map
    produced 9 false positives on this entirely benign document."""
    assert glyph_truth_mismatches(_read("fpdf.pdf")) == []


def test_detects_tounicode_hijack() -> None:
    mismatches = glyph_truth_mismatches(_read("evil.pdf"))

    assert len(mismatches) == 3
    assert {(m.drawn, m.claimed) for m in mismatches} == {("A", "X"), ("B", "Y"), ("C", "Z")}


def test_detects_stealth_digit_substitution() -> None:
    """Renders 1000, extracts 9000 -- a financial substitution."""
    mismatches = glyph_truth_mismatches(_read("stealth.pdf"))

    assert len(mismatches) == 1
    assert (mismatches[0].drawn, mismatches[0].claimed) == ("1", "9")


def test_malformed_pdf_returns_empty_rather_than_raising() -> None:
    assert glyph_truth_mismatches(b"%PDF-1.4\nnot a real pdf\n%%EOF\n") == []
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_pdf_glyph_truth.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'depfence.core.pdf_glyph_truth'`.

- [ ] **Step 4: Write the implementation**

Create `depfence/core/pdf_glyph_truth.py` using the verified reference implementation at `~/dev/_backups/evilfont-detector-2026-08-29/dualview.py`. Port it with these changes, keeping every comment that explains a trap:

1. Replace the `check(path)` signature with `glyph_truth_mismatches(data: bytes) -> list[GlyphMismatch]`, reading via `PdfReader(io.BytesIO(data))`.
2. Return a frozen dataclass rather than tuples:

```python
@dataclass(frozen=True)
class GlyphMismatch:
    page: int
    font: str
    code: int
    drawn: str
    claimed: str
```

3. Wrap the whole body in `try/except Exception: return []` so a malformed PDF yields no finding rather than raising — `scan_artifact_bytes` callers only catch `ScanIncompleteError`.
4. Import `pypdf` and `fontTools` **outside** any `try` whose handler names an exception from them, and raise `ScanIncompleteError` on `ImportError`. Folding them together caused a `NameError` that discarded every finding (see `artifact_analysis.py:821-828` for the corrected pattern).

- [ ] **Step 5: Run tests to verify they pass**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_pdf_glyph_truth.py -v`

Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add depfence/core/pdf_glyph_truth.py tests/test_pdf_glyph_truth.py tests/fixtures/pdf/
git commit -m "feat(detection): glyph-truth resolution for PDF text"
```

---

### Task 4: Wire DF-PDF-004 into artifact analysis

**Files:**
- Modify: `depfence/core/artifact_analysis.py` (inside `_scan_pdf`, after the DF-PDF-003 block)
- Modify: `depfence/core/sealed_intake.py` (`allowed_rules`, `allowed_evidence_classes`, `_RULE_CONTRACT`)
- Modify: `depfence/schemas/depfence.sealed-intake.v1.schema.json`
- Modify: `depfence/sealed_git_worker.py` (worker allowlist)
- Modify: `docs/evilfont-defense-methodology.md` (rules table)
- Test: `tests/test_pdf_glyph_truth.py`, `tests/test_schemas.py`

**Interfaces:**
- Consumes: `glyph_truth_mismatches` and `GlyphMismatch` from Task 3.
- Produces: rule `DF-PDF-004`, evidence class `glyph_unicode_mismatch`, severity `high`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_pdf_glyph_truth.py`:

```python
from depfence.core.artifact_analysis import scan_artifact_bytes


def test_scan_artifact_bytes_emits_df_pdf_004() -> None:
    findings, limitations = scan_artifact_bytes(Path("stealth.pdf"), _read("stealth.pdf"))

    rule_ids = [f.metadata.get("rule_id") for f in findings]
    assert "DF-PDF-004" in rule_ids
    hit = next(f for f in findings if f.metadata.get("rule_id") == "DF-PDF-004")
    assert hit.metadata["evidence_class"] == "glyph_unicode_mismatch"


def test_benign_pdf_emits_no_df_pdf_004() -> None:
    findings, _ = scan_artifact_bytes(Path("orig.pdf"), _read("orig.pdf"))

    assert "DF-PDF-004" not in [f.metadata.get("rule_id") for f in findings]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_pdf_glyph_truth.py -k df_pdf_004 -v`

Expected: FAIL — `StopIteration`, no `DF-PDF-004` is emitted.

- [ ] **Step 3: Emit the finding**

In `_scan_pdf`, after the DF-PDF-003 block, add:

```python
    mismatches = glyph_truth_mismatches(data)
    if mismatches:
        sample = ", ".join(
            f"glyph draws {m.drawn!r} but the document claims {m.claimed!r}"
            for m in mismatches[:3]
        )
        findings.append(_finding(
            path,
            "DF-PDF-004",
            "PDF glyphs disagree with their declared Unicode",
            "The embedded font program states that a drawn glyph renders one character "
            "while the document's /ToUnicode map claims another, so extracted text "
            f"differs from what a reader sees. {sample}.",
            Severity.HIGH,
            0.95,
            mismatch_count=len(mismatches),
            evidence_class="glyph_unicode_mismatch",
        ))
```

- [ ] **Step 4: Register the rule in all four registers**

`sealed_intake.py`: add `"DF-PDF-004"` to `allowed_rules`, `"glyph_unicode_mismatch"` to `allowed_evidence_classes`, and to `_RULE_CONTRACT`:

```python
    "DF-PDF-004": ("glyph_unicode_mismatch", "high", _PDF_SUFFIXES),
```

`depfence.sealed-intake.v1.schema.json`: add `"DF-PDF-004"` to the `rule_id` enum and `"glyph_unicode_mismatch"` to the `evidence_class` enum.

`sealed_git_worker.py`: add `"DF-PDF-004"` to the worker allowlist set.

`docs/evilfont-defense-methodology.md`: add the row

```
| DF-PDF-004 | Glyph/Unicode disagreement | 1 | 0.95 | HIGH | `glyph_unicode_mismatch` |
```

- [ ] **Step 5: Run the full affected set**

Run: `uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest tests/test_pdf_glyph_truth.py tests/test_schemas.py tests/test_sealed_intake.py tests/test_artifact_analysis.py -v`

Expected: all pass. `test_sealed_intake_schema_enums_match_the_python_validator` proves the four registers agree.

- [ ] **Step 6: Update the README counts and run docs-check**

```bash
echo "fns: $(grep -rhoE '^[[:space:]]*(async )?def test_[A-Za-z0-9_]+' tests/ | wc -l | tr -d ' ')"
echo "files: $(find tests -name 'test_*.py' | wc -l | tr -d ' ')"
uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio --with-editable . --from pytest pytest --collect-only -q | tail -2
```

Update `README.md:9` (badge = collected count) and `README.md:648` (function and file counts), then:

```bash
bash tools/docs-check.sh
```

Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add depfence/ tests/ docs/ README.md
git commit -m "feat(detection): DF-PDF-004 glyph/Unicode disagreement"
```

---

### Task 5: Full gate and draft PR

- [ ] **Step 1: Run every gate**

```bash
.venv/bin/ruff check depfence/ tests/
.venv/bin/mypy depfence/core/artifact_analysis.py depfence/core/pdf_glyph_truth.py \
  depfence/artifact_worker.py depfence/core/sealed_intake.py \
  depfence/sealed_git_worker.py depfence/scanners/visual_text_deception_scanner.py
bash tools/docs-check.sh
uvx --with "fonttools[woff]" --with pypdf --with jsonschema --with pytest-asyncio \
  --with pytest-xdist --with-editable . --from pytest pytest -p no:cacheprovider -q -n auto
```

Expected: ruff clean, mypy clean, docs-check exit 0, suite green.

- [ ] **Step 2: Secret scan before pushing**

```bash
gitleaks detect --no-git --source . --redact
depfence scan depfence/ --format json --fail-on critical --no-fetch
```

Expected: no findings. Any hit halts — do not push.

- [ ] **Step 3: Push and open a draft PR**

```bash
git push origin agent/evilfont-defense-p0
gh pr create --draft --base main --head agent/evilfont-defense-p0 \
  --title "EvilFont defense: build gate, sealed-intake contract, suppression authority, glyph truth"
```

---

## Self-Review

**Spec coverage.** G-L is covered by Tasks 1–2; G-M by Tasks 3–4. The related G-L items — the `~/.m2` and `~/.gradle` reads at `prompt_injection_scanner.py:533`, and the `<` size-cap boundary — are **not** covered here and need their own tasks; they are separate defects in a different module and would make this plan two subsystems wide. Recorded as a gap, not silently dropped.

**Placeholder scan.** No TBD/TODO. Task 3 Step 4 describes a port rather than inlining ~90 lines already committed at a named path; the four required changes are enumerated exactly.

**Type consistency.** `glyph_truth_mismatches` and `GlyphMismatch` are named identically in Tasks 3 and 4. `Baseline.from_project(project_dir, *, trusted=...)` and `ignored_count` match between Tasks 1 and 2. `DF-PDF-004` and `glyph_unicode_mismatch` are spelled identically in all five files Task 4 touches.

**One risk to flag.** Task 1 changes a default: teams relying on an in-repo baseline will see suppressions stop applying until they pass `--trust-project-baseline`. That is the point of the fix, but it is a breaking change for a published tool and belongs in `CHANGELOG.md` under a BREAKING heading.
