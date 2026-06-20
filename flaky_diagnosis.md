# Flaky Test Diagnosis: test_large_7b_model_no_size_anomaly

## Summary

The test fails intermittently (~1.7% of runs in isolation, higher in CI) due to
`_detect_arch_hint` doing a raw substring match on the **full absolute path**,
including the randomly-generated system temp directory prefix.

---

## Root Cause

### Where the bug lives

`depfence/scanners/model_integrity.py`, function `_detect_arch_hint` (line 233):

```python
def _detect_arch_hint(path: Path) -> int | None:
    path_lower = str(path).lower()          # ← converts the FULL absolute path
    for pattern, min_bytes in _ARCH_MIN_BYTES:
        if pattern in path_lower:           # ← matches anywhere in the string
            return min_bytes
    return None
```

The function converts the entire absolute path to lowercase and checks whether
any arch pattern substring (`"7b"`, `"6b"`, `"3b"`, …) appears anywhere in it.

### Why the test uses a temp directory

`test_large_7b_model_no_size_anomaly` creates its model directory inside a
`tempfile.TemporaryDirectory()`:

```
/tmp/tmpXXXXXXXX/llama-1b/pytorch_model.bin
         ^^^^^^^^
         8 random characters (letters + digits)
```

### The collision

When the random suffix happens to contain a pattern that appears **before** `"1b"`
in the `_ARCH_MIN_BYTES` list, the wrong (higher) minimum byte threshold is
selected:

| Pattern | Min threshold | Test file (60 MB) | Outcome |
|---------|--------------|-------------------|---------|
| `"1b"`  | 50 MB        | 60 MB ≥ 50 MB     | PASS    |
| `"7b"`  | 500 MB       | 60 MB < 500 MB    | **FAIL** |
| `"6b"`  | 400 MB       | 60 MB < 400 MB    | **FAIL** |
| `"3b"`  | 200 MB       | 60 MB < 200 MB    | **FAIL** |

Concrete example of a poisoned path:
```
/tmp/tmp7bXXXXX/llama-1b/pytorch_model.bin
         ^^
         "7b" matches before "1b" → min = 500 MB
         60 MB < 500 MB → size anomaly finding raised → assertion fails
```

### Empirical failure rate

Measured over 1000 random `tempfile.TemporaryDirectory()` calls on macOS:

- Wrong match ("7b" / "6b" / "3b" in temp prefix): **17 / 1000 = 1.7%**
- Breakdown: `"7b"` 0.5%, `"6b"` 0.9%, `"3b"` 0.3%

In the full test suite the effective rate is higher because more tests run,
increasing the chance of at least one collision per session.

---

## Why It Passes in Isolation Most of the Time

Most randomly-generated temp path suffixes (e.g., `tmpl_teomh5`, `tmpABCDEFG`)
do not contain an arch pattern that fires before `"1b"`, so the function
correctly returns 50 MB and the 60 MB file clears the threshold.

---

## Secondary Issue: Misleading Test Name

The test is named `test_large_7b_model_no_size_anomaly` but the model directory
it creates is `llama-1b` (a 1B architecture, not 7B). A genuine 7B test would
require a file ≥ 500 MB. This naming confusion does not cause the flakiness but
obscures intent.

---

## Fix (not yet applied)

Scope the arch hint search to only the **project-relative path components**
(filename + parent directory names), not the full system-rooted absolute path.
The relevant context is always the repository structure supplied by the user, not
the system temp directory prefix.

```python
# Proposed fix: search only the parts under (and including) the project root,
# or at minimum restrict to path.name and path.parent.name rather than str(path)
def _detect_arch_hint(path: Path) -> int | None:
    # Only look at the filename and its immediate parent directory — the portion
    # the user controls — not the absolute path that may include system temp dirs.
    searchable = (path.parent.name + "/" + path.name).lower()
    for pattern, min_bytes in _ARCH_MIN_BYTES:
        if pattern in searchable:
            return min_bytes
    return None
```
