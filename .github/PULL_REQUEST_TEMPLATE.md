## What

<!-- One sentence: what this PR does -->

## Why

<!-- What problem does it solve? Link issue if applicable -->

## Testing

- [ ] New/updated tests cover the change
- [ ] `pytest tests/ -v` passes locally
- [ ] `ruff check depfence/ tests/` clean
- [ ] Self-scan passes: `depfence scan . --no-fetch`

## Scanner changes (if applicable)

- [ ] Entry point registered in `pyproject.toml`
- [ ] Scanner has `name` and `ecosystems` attributes
- [ ] Findings use appropriate `FindingType` and `Severity`
- [ ] False positive rate considered (document known FP scenarios)
