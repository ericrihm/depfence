"""Core data models for scan results, packages, and findings."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
    package: PackageId
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
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    packages_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

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
