"""Compatibility helpers for typed scanner execution outcomes."""

from __future__ import annotations

from depfence.core.models import (
    ScannerErrorCode,
    ScannerOutcome,
    ScannerReasonCode,
    ScanState,
    merge_scan_state,
)


def error_code(message: str | None) -> ScannerErrorCode | None:
    """Map attacker-influenced error text to a stable, non-sensitive code."""

    if not message:
        return None
    lowered = message.lower()
    if "offline policy" in lowered or "network-required" in lowered:
        return ScannerErrorCode.NETWORK_DISABLED
    if "unsupported" in lowered:
        return ScannerErrorCode.UNSUPPORTED
    if "timeout" in lowered or "timed out" in lowered or "deadline" in lowered:
        return ScannerErrorCode.TIMEOUT
    if "scopeescapeerror" in lowered or "escapes project root" in lowered or "symlink" in lowered:
        return ScannerErrorCode.SCOPE_ESCAPE
    if "inputlimiterror" in lowered or "exceeds" in lowered and "limit" in lowered:
        return ScannerErrorCode.INPUT_LIMIT
    if "malformedinputerror" in lowered or "malformed" in lowered:
        return ScannerErrorCode.MALFORMED_INPUT
    if "scanincompleteerror" in lowered or "cannot read" in lowered or "unreadable" in lowered:
        return ScannerErrorCode.INPUT_UNAVAILABLE
    if "worker" in lowered or "process" in lowered or "exit code" in lowered:
        return ScannerErrorCode.WORKER_FAILURE
    if any(
        token in lowered
        for token in ("dependency unavailable", "connectionerror", "http 429", "http 5", "service unavailable")
    ):
        return ScannerErrorCode.DEPENDENCY_UNAVAILABLE
    if any(token in lowered for token in ("verification failed", "wrong digest", "signature", "untrusted issuer")):
        return ScannerErrorCode.VERIFICATION_FAILED
    return ScannerErrorCode.RUNTIME_FAILURE


def _reason_for_error(code: ScannerErrorCode | None) -> ScannerReasonCode | None:
    if code is None:
        return None
    return {
        ScannerErrorCode.NETWORK_DISABLED: ScannerReasonCode.DISABLED_BY_POLICY,
        ScannerErrorCode.TIMEOUT: ScannerReasonCode.TIMEOUT,
        ScannerErrorCode.SCOPE_ESCAPE: ScannerReasonCode.SCOPE_ESCAPE,
        ScannerErrorCode.INPUT_LIMIT: ScannerReasonCode.INPUT_LIMIT,
        ScannerErrorCode.MALFORMED_INPUT: ScannerReasonCode.MALFORMED_INPUT,
        ScannerErrorCode.INPUT_UNAVAILABLE: ScannerReasonCode.UNREADABLE,
        ScannerErrorCode.WORKER_FAILURE: ScannerReasonCode.WORKER_CRASH,
        ScannerErrorCode.UNSUPPORTED: ScannerReasonCode.UNSUPPORTED,
        ScannerErrorCode.DEPENDENCY_UNAVAILABLE: ScannerReasonCode.DEPENDENCY_UNAVAILABLE,
        ScannerErrorCode.VERIFICATION_FAILED: ScannerReasonCode.VERIFICATION_FAILED,
        ScannerErrorCode.RUNTIME_FAILURE: ScannerReasonCode.RUNTIME_FAILURE,
    }[code]


def from_legacy(
    state: ScanState,
    message: str | None = None,
    *,
    findings_preserved: int = 0,
    duration_ms: float | None = None,
) -> ScannerOutcome:
    """Create honest typed accounting for an existing coverage/error pair."""

    code = error_code(message)
    specific_reason = _reason_for_error(code)
    if state in {ScanState.PASS, ScanState.FAIL} and not message:
        reason = ScannerReasonCode.EVALUATED
        evaluated = True
    elif state == ScanState.UNPROVEN:
        if specific_reason is None or specific_reason == ScannerReasonCode.RUNTIME_FAILURE:
            reason = ScannerReasonCode.PARTIAL_COVERAGE
        else:
            reason = specific_reason
        evaluated = True
    elif state == ScanState.INDETERMINATE:
        reason = specific_reason or ScannerReasonCode.RUNTIME_FAILURE
        evaluated = False
    else:
        reason = ScannerReasonCode.NO_EVIDENCE
        evaluated = False
    return ScannerOutcome(
        state=state,
        reason_code=reason,
        error_code=code,
        findings_preserved=findings_preserved,
        evaluated=evaluated,
        skipped=False,
        duration_ms=duration_ms,
    )


def materialize(
    coverage: dict[str, ScanState],
    errors: dict[str, str],
    outcomes: dict[str, ScannerOutcome],
) -> dict[str, ScannerOutcome]:
    """Return typed outcomes for every legacy or native named scanner."""

    merged = dict(outcomes)
    for name, state in coverage.items():
        legacy = from_legacy(state, errors.get(name))
        if name not in merged:
            merged[name] = legacy
        elif merged[name].state != state:
            merged[name] = merge_outcome(merged[name], legacy)
    return merged


def merge_outcome(
    current: ScannerOutcome | None,
    incoming: ScannerOutcome,
) -> ScannerOutcome:
    """Merge repeated scanner runs deterministically across project shards."""

    if current is None:
        return incoming
    state = merge_scan_state(current.state, incoming.state)
    candidates = [item for item in (current, incoming) if item.state == state]
    selected = min(
        candidates,
        key=lambda item: (
            item.error_code is None,
            item.error_code.value if item.error_code else "",
            item.reason_code.value,
        ),
    )
    durations = [value for value in (current.duration_ms, incoming.duration_ms) if value is not None]
    return ScannerOutcome(
        state=state,
        reason_code=selected.reason_code,
        error_code=selected.error_code,
        findings_preserved=current.findings_preserved + incoming.findings_preserved,
        evaluated=current.evaluated or incoming.evaluated,
        skipped=current.skipped and incoming.skipped,
        duration_ms=sum(durations) if durations else None,
    )


__all__ = ["error_code", "from_legacy", "materialize", "merge_outcome"]
