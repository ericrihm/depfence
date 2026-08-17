from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from depfence.core.engine import _run_project_scanners, _run_scanners
from depfence.core.models import (
    PackageId,
    PackageMeta,
    ScannerErrorCode,
    ScannerOutcome,
    ScannerReasonCode,
    ScanResult,
    ScanState,
)
from depfence.core.parallel import LockfileEntry, _merge_results
from depfence.core.registry import ProjectScannerResult
from depfence.core.scanner_outcome import error_code, from_legacy
from depfence.reporters.json_out import JsonReporter, LegacyJsonReporter
from depfence.schemas import validate_document


def test_json_v1_materializes_typed_outcome_without_changing_legacy_shape() -> None:
    result = ScanResult(target=".", ecosystem="npm", packages_scanned=1)
    result.scanner_coverage["slow"] = ScanState.INDETERMINATE
    result.scanner_errors["slow"] = "TimeoutError: attacker/path timed out"

    document = json.loads(JsonReporter().render(result))
    legacy = json.loads(LegacyJsonReporter().render(result))

    validate_document(document)
    assert document["coverage"]["outcomes"]["slow"] == {
        "state": "INDETERMINATE",
        "reason_code": "timeout",
        "error_code": "scanner.timeout",
        "findings_preserved": 0,
        "evaluated": False,
        "skipped": False,
        "duration_ms": None,
    }
    assert "scanner_outcomes" not in legacy
    assert legacy["scanner_errors"] == result.scanner_errors


def test_scope_and_runtime_failures_map_to_stable_fail_closed_codes() -> None:
    assert error_code("ScopeEscapeError: /private/escape") == ScannerErrorCode.SCOPE_ESCAPE
    assert error_code("InputLimitError: oversized") == ScannerErrorCode.INPUT_LIMIT
    assert error_code("MalformedInputError: hostile yaml") == ScannerErrorCode.MALFORMED_INPUT
    assert error_code("worker exited with code 9") == ScannerErrorCode.WORKER_FAILURE
    expected_reasons = {
        "unsupported archive": ScannerReasonCode.UNSUPPORTED,
        "MalformedInputError: yaml": ScannerReasonCode.MALFORMED_INPUT,
        "ScanIncompleteError: cannot read file": ScannerReasonCode.UNREADABLE,
        "InputLimitError: too large": ScannerReasonCode.INPUT_LIMIT,
        "ScopeEscapeError: symlink": ScannerReasonCode.SCOPE_ESCAPE,
        "TimeoutError: deadline": ScannerReasonCode.TIMEOUT,
        "worker exited with code 9": ScannerReasonCode.WORKER_CRASH,
        "HTTP 503 service unavailable": ScannerReasonCode.DEPENDENCY_UNAVAILABLE,
        "signature verification failed": ScannerReasonCode.VERIFICATION_FAILED,
    }
    for message, expected in expected_reasons.items():
        assert from_legacy(ScanState.INDETERMINATE, message).reason_code == expected
    outcome = from_legacy(
        ScanState.UNPROVEN,
        "PartialScanError: incomplete coverage",
        findings_preserved=3,
    )
    assert outcome.state == ScanState.UNPROVEN
    assert outcome.reason_code == ScannerReasonCode.PARTIAL_COVERAGE
    assert outcome.findings_preserved == 3
    assert outcome.evaluated is True


def test_native_or_stale_typed_outcome_cannot_turn_incomplete_coverage_into_pass() -> None:
    native = ScanResult(target=".", ecosystem="npm", packages_scanned=1)
    native.scanner_outcomes["native"] = ScannerOutcome(
        state=ScanState.INDETERMINATE,
        reason_code=ScannerReasonCode.RUNTIME_FAILURE,
        error_code=ScannerErrorCode.RUNTIME_FAILURE,
    )
    stale = ScanResult(target=".", ecosystem="npm", packages_scanned=1)
    stale.scanner_coverage["scanner"] = ScanState.INDETERMINATE
    stale.scanner_outcomes["scanner"] = ScannerOutcome(
        state=ScanState.PASS,
        reason_code=ScannerReasonCode.EVALUATED,
        evaluated=True,
    )

    native_document = json.loads(JsonReporter().render(native))
    stale_document = json.loads(JsonReporter().render(stale))

    assert native_document["status"] == "INDETERMINATE"
    assert native_document["coverage"]["scanners"]["native"] == "INDETERMINATE"
    assert stale_document["status"] == "INDETERMINATE"
    assert stale_document["coverage"]["outcomes"]["scanner"]["state"] == "INDETERMINATE"


def test_parallel_outcome_merge_is_order_independent_and_preserves_evidence() -> None:
    first = ScanResult(target="one", ecosystem="npm")
    first.scanner_coverage["shared"] = ScanState.PASS
    first.scanner_outcomes["shared"] = ScannerOutcome(
        state=ScanState.PASS,
        reason_code=ScannerReasonCode.EVALUATED,
        findings_preserved=2,
        evaluated=True,
        duration_ms=2.5,
    )
    second = ScanResult(target="two", ecosystem="npm")
    second.scanner_coverage["shared"] = ScanState.INDETERMINATE
    second.scanner_errors["shared"] = "worker failure"
    second.scanner_outcomes["shared"] = ScannerOutcome(
        state=ScanState.INDETERMINATE,
        reason_code=ScannerReasonCode.WORKER_CRASH,
        error_code=ScannerErrorCode.WORKER_FAILURE,
        findings_preserved=1,
        evaluated=False,
        duration_ms=4.0,
    )
    entries = [
        (LockfileEntry("npm", Path("one/package-lock.json")), first),
        (LockfileEntry("npm", Path("two/package-lock.json")), second),
    ]

    forward = _merge_results(".", entries)
    reverse = _merge_results(".", list(reversed(entries)))

    assert forward.scanner_outcomes == reverse.scanner_outcomes
    assert forward.scanner_outcomes["shared"] == ScannerOutcome(
        state=ScanState.INDETERMINATE,
        reason_code=ScannerReasonCode.WORKER_CRASH,
        error_code=ScannerErrorCode.WORKER_FAILURE,
        findings_preserved=3,
        evaluated=True,
        skipped=False,
        duration_ms=6.5,
    )


def test_mixed_evaluated_and_skipped_shards_do_not_become_globally_skipped() -> None:
    evaluated = ScannerOutcome(
        state=ScanState.PASS,
        reason_code=ScannerReasonCode.EVALUATED,
        evaluated=True,
        skipped=False,
    )
    skipped = ScannerOutcome(
        state=ScanState.PASS,
        reason_code=ScannerReasonCode.NOT_APPLICABLE,
        evaluated=False,
        skipped=True,
    )
    first = ScanResult(target="one", ecosystem="npm", scanner_outcomes={"scanner": evaluated})
    first.scanner_coverage["scanner"] = ScanState.PASS
    second = ScanResult(target="two", ecosystem="npm", scanner_outcomes={"scanner": skipped})
    second.scanner_coverage["scanner"] = ScanState.PASS

    merged = _merge_results(
        ".",
        [
            (LockfileEntry("npm", Path("one/package-lock.json")), first),
            (LockfileEntry("npm", Path("two/package-lock.json")), second),
        ],
    )

    assert merged.scanner_outcomes["scanner"].evaluated is True
    assert merged.scanner_outcomes["scanner"].skipped is False


@pytest.mark.asyncio
async def test_project_scope_error_and_partial_findings_are_typed_and_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = [
        ProjectScannerResult(
            "scope",
            ScanState.INDETERMINATE,
            [],
            1.25,
            "ScopeEscapeError: private path",
        ),
        ProjectScannerResult(
            "partial",
            ScanState.UNPROVEN,
            [],
            2.5,
            "InputLimitError: oversized input",
        ),
    ]
    monkeypatch.setattr(
        "depfence.core.engine.run_shipped_project_scanners",
        AsyncMock(return_value=runs),
    )
    outcomes: dict[str, ScannerOutcome] = {}

    _findings, _errors, coverage, _scanner_errors = await _run_project_scanners(
        tmp_path,
        outcomes=outcomes,
    )

    assert coverage == {
        "scope": ScanState.INDETERMINATE,
        "partial": ScanState.UNPROVEN,
    }
    assert outcomes["scope"].error_code == ScannerErrorCode.SCOPE_ESCAPE
    assert outcomes["scope"].reason_code == ScannerReasonCode.SCOPE_ESCAPE
    assert outcomes["scope"].evaluated is False
    assert outcomes["partial"].error_code == ScannerErrorCode.INPUT_LIMIT
    assert outcomes["partial"].reason_code == ScannerReasonCode.INPUT_LIMIT
    assert outcomes["partial"].duration_ms == 2.5


@pytest.mark.asyncio
async def test_package_scanner_records_duration_and_non_applicable_skip() -> None:
    class Scanner:
        ecosystems = ["npm"]

        async def scan(self, _packages):
            return []

    registry = SimpleNamespace(scanners={"package": Scanner()})
    evaluated: dict[str, ScannerOutcome] = {}
    await _run_scanners(
        registry,
        [PackageMeta(PackageId("npm", "example", "1"))],
        False,
        False,
        False,
        outcomes=evaluated,
    )
    skipped: dict[str, ScannerOutcome] = {}
    await _run_scanners(
        registry,
        [PackageMeta(PackageId("pypi", "example", "1"))],
        False,
        False,
        False,
        outcomes=skipped,
    )

    assert evaluated["package"].evaluated is True
    assert evaluated["package"].duration_ms is not None
    assert evaluated["package"].duration_ms >= 0
    assert skipped["package"].reason_code == ScannerReasonCode.NOT_APPLICABLE
    assert skipped["package"].skipped is True
    assert skipped["package"].duration_ms == 0.0
