"""Core data models for scan results, packages, and findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanState(str, enum.Enum):
    """Assurance state for scanner execution and coverage."""

    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    UNPROVEN = "UNPROVEN"


class ScannerReasonCode(str, enum.Enum):
    """Stable, non-sensitive explanation for a scanner outcome."""

    EVALUATED = "evaluated"
    NOT_APPLICABLE = "not_applicable"
    DISABLED_BY_POLICY = "disabled_by_policy"
    PARTIAL_COVERAGE = "partial_coverage"
    UNSUPPORTED = "unsupported"
    MALFORMED_INPUT = "malformed_input"
    UNREADABLE = "unreadable"
    INPUT_LIMIT = "input_limit"
    SCOPE_ESCAPE = "scope_escape"
    TIMEOUT = "timeout"
    WORKER_CRASH = "worker_crash"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    VERIFICATION_FAILED = "verification_failed"
    RUNTIME_FAILURE = "runtime_failure"
    NO_EVIDENCE = "no_evidence"


class ScannerErrorCode(str, enum.Enum):
    """Stable machine error codes; messages remain in legacy scanner_errors."""

    NETWORK_DISABLED = "network.disabled"
    TIMEOUT = "scanner.timeout"
    SCOPE_ESCAPE = "scope.escape"
    INPUT_LIMIT = "input.limit"
    MALFORMED_INPUT = "input.malformed"
    INPUT_UNAVAILABLE = "input.unavailable"
    WORKER_FAILURE = "worker.failure"
    UNSUPPORTED = "input.unsupported"
    DEPENDENCY_UNAVAILABLE = "dependency.unavailable"
    VERIFICATION_FAILED = "verification.failed"
    RUNTIME_FAILURE = "scanner.runtime"


@dataclass(frozen=True)
class ScannerOutcome:
    """Typed scanner accounting that complements the legacy coverage maps."""

    state: ScanState
    reason_code: ScannerReasonCode
    error_code: ScannerErrorCode | None = None
    findings_preserved: int = 0
    evaluated: bool = False
    skipped: bool = False
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "reason_code": self.reason_code.value,
            "error_code": self.error_code.value if self.error_code else None,
            "findings_preserved": self.findings_preserved,
            "evaluated": self.evaluated,
            "skipped": self.skipped,
            "duration_ms": self.duration_ms,
        }


_SCAN_STATE_PRECEDENCE = {
    ScanState.PASS: 0,
    ScanState.UNPROVEN: 1,
    ScanState.FAIL: 2,
    ScanState.INDETERMINATE: 3,
}


def merge_scan_state(current: ScanState | None, incoming: ScanState) -> ScanState:
    """Return the least-assured state using the canonical roll-up order."""
    if current is None:
        return incoming
    return max((current, incoming), key=_SCAN_STATE_PRECEDENCE.__getitem__)


class FindingType(str, enum.Enum):
    KNOWN_VULN = "known_vulnerability"
    MALICIOUS = "malicious_package"
    TYPOSQUAT = "typosquat"
    BEHAVIORAL = "behavioral_anomaly"
    INSTALL_SCRIPT = "suspicious_install_script"
    MAINTAINER = "maintainer_risk"
    REPUTATION = "low_reputation"
    LICENSE = "license_risk"
    PROVENANCE = "provenance_missing"
    DEPRECATED = "deprecated"
    SLOPSQUAT = "slopsquat_candidate"
    SECRET_EXPOSED = "secret_exposed"
    UNPINNED = "unpinned_dependency"
    DOCKERFILE = "dockerfile_issue"
    WORKFLOW = "workflow_issue"
    TERRAFORM = "terraform_issue"
    OBFUSCATION = "obfuscation_detected"
    NETWORK = "suspicious_network"
    PHANTOM_DEP = "phantom_dependency"
    SCOPE_SQUAT = "scope_squatting"
    DEP_CONFUSION = "dependency_confusion"
    PROMPT_INJECTION = "prompt_injection"
    ANSI_HIDING = "ansi_content_hiding"
    VISUAL_TEXT_DECEPTION = "visual_text_deception"
    FABRICATED_REF = "fabricated_reference"  # pinned SHA/version that resolves to no real upstream object
    MUTABLE_TAG = "mutable_tag_masquerade"  # # vX comment disagrees with the SHA it labels
    UNVERIFIED_REF = "unverified_reference"  # could not resolve (no token / rate-limited) — never a silent pass
    EXTERNAL_INSTRUCTION_FETCH = "external_instruction_fetch"  # skill/tool fetches instructions from external URL
    DOMAIN_SPOOF = "domain_spoof"  # referenced domain is a lookalike of a well-known service
    DEFERRED_PAYLOAD = "deferred_payload"  # content at a referenced URL changed since last scan (bait-and-switch)
    PROTESTWARE = "protestware"  # date-gated, locale-gated, or geofenced malicious logic


@dataclass(frozen=True)
class PackageId:
    ecosystem: str  # npm, pypi, cargo, go
    name: str
    version: str | None = None

    def __str__(self) -> str:
        v = f"@{self.version}" if self.version else ""
        return f"{self.ecosystem}:{self.name}{v}"


@dataclass
class MaintainerInfo:
    username: str
    email: str | None = None
    account_age_days: int | None = None
    has_2fa: bool | None = None
    package_count: int | None = None
    recent_ownership_change: bool = False


@dataclass
class PackageMeta:
    pkg: PackageId
    description: str = ""
    homepage: str = ""
    repository: str = ""
    license: str = ""
    download_count: int | None = None
    first_published: datetime | None = None
    latest_publish: datetime | None = None
    maintainers: list[MaintainerInfo] = field(default_factory=list)
    has_install_scripts: bool = False
    has_native_code: bool = False
    has_provenance: bool = False
    dependency_count: int = 0
    transitive_count: int = 0


@dataclass
class Finding:
    finding_type: FindingType
    severity: Severity
    # Project scanners historically identify files/resources with strings,
    # while package scanners use a structured PackageId. Both are public,
    # serialized behavior and the worker boundary must preserve either form.
    package: PackageId | str
    title: str
    detail: str
    cve: str | None = None
    cwe: str | None = None
    fix_version: str | None = None
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0 - 1.0
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    ecosystem: str
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    completed_at: datetime | None = None
    packages_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Named scanner accounting distinguishes a clean scan from an incomplete
    # one.  Absence from this map means the scanner was not applicable/enabled;
    # INDETERMINATE means it was expected but could not establish coverage.
    scanner_coverage: dict[str, ScanState] = field(default_factory=dict)
    scanner_errors: dict[str, str] = field(default_factory=dict)
    scanner_outcomes: dict[str, ScannerOutcome] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_blockers(self) -> bool:
        return self.critical_count > 0 or any(
            f.finding_type == FindingType.MALICIOUS for f in self.findings
        )
