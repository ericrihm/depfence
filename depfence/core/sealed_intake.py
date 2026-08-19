"""Manifest-only Git intake inside a disposable OCI volume.

This path is intended for repositories whose files must never be materialized
on the host.  A trusted, digest-pinned image performs acquisition and offline
inventory.  DepFence retains only a bounded manifest in private state.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

from depfence.core.artifact_analysis import _run_bounded_subprocess, verify_image_signature
from depfence.core.local_state import PrivateState
from depfence.core.models import ScanState
from depfence.core.scan_scope import InputLimitError, ScanIncompleteError

MAX_INTAKE_MANIFEST_BYTES = 1024 * 1024
MAX_ANALYSIS_MANIFEST_BYTES = 1024 * 1024
MAX_RESOLUTION_MANIFEST_BYTES = 16 * 1024
DEFAULT_FILE_BUDGET = 100_000
DEFAULT_BYTE_BUDGET = 512 * 1024 * 1024
_WARNING_CODES = frozenset({
    "submodule_present",
    "symlink_present",
    "non_regular_entry",
    "oversized_blob",
    "unknown_mode",
})
INTAKE_SECCOMP_SHA256 = "75f87909de0adeb58a327fc3cb1bebd21712594e3a58ebaaa36c7cc48f3c00a5"
ANALYSIS_SECCOMP_SHA256 = "f6d4aafd4d37b8d9efe83da8b9660e633c4e63d24de05a62e83292c6ac8e5bf6"


def _validated_seccomp(path: str, expected_sha256: str) -> str:
    raw_profile = Path(path).expanduser()
    if raw_profile.is_symlink():
        raise ValueError("seccomp profile must be a regular non-symlink file")
    profile = raw_profile.resolve(strict=True)
    if not profile.is_file():
        raise ValueError("seccomp profile must be a regular non-symlink file")
    raw = profile.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("seccomp profile hash does not match the reviewed policy")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("seccomp profile is malformed") from exc
    if not isinstance(document, dict) or document.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise ValueError("seccomp profile must default deny")
    return str(profile)


def _validated_source_host(source: str, allowed_hosts: frozenset[str]) -> str:
    if any(ord(character) < 33 or ord(character) == 127 for character in source):
        raise ValueError("sealed intake source contains whitespace or control characters")
    parsed = urlparse(source)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("sealed intake source must be credential-free HTTPS")
    host = parsed.hostname.casefold().rstrip(".")
    normalized_hosts = {value.casefold().rstrip(".") for value in allowed_hosts}
    if host not in normalized_hosts:
        raise ValueError(f"sealed intake source host is not allowlisted: {host}")
    return host


def _run_command(
    command: list[str],
    environment: dict[str, str],
    timeout: float,
) -> tuple[int, bytes, bytes]:
    try:
        return _run_bounded_subprocess(command, b"", environment, timeout)
    except ScanIncompleteError:
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanIncompleteError(
            f"sealed intake helper unavailable ({type(exc).__name__})"
        ) from exc


@dataclass(frozen=True)
class SealedResolutionConfig:
    engine: str
    image: str
    allowed_hosts: frozenset[str]
    acquisition_network: str
    https_proxy: str
    certificate_identity: str
    certificate_oidc_issuer: str
    runtime: str | None = None
    timeout_seconds: float = 90.0
    seccomp_profile: str = "containers/seccomp-intake.json"
    seccomp_sha256: str = INTAKE_SECCOMP_SHA256

    def validate(self, source: str) -> str:
        if self.engine not in {"docker", "podman"}:
            raise ValueError("sealed resolution engine must be docker or podman")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", self.image):
            raise ValueError("sealed resolution image must be pinned by an @sha256: digest")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.acquisition_network):
            raise ValueError("sealed resolution requires a dedicated acquisition network")
        proxy = urlparse(self.https_proxy)
        if proxy.scheme not in {"http", "https"} or not proxy.hostname or proxy.username or proxy.password:
            raise ValueError("sealed resolution requires a credential-free HTTPS proxy URL")
        if not self.certificate_identity or len(self.certificate_identity) > 512:
            raise ValueError("sealed resolution certificate identity is invalid")
        if not self.certificate_oidc_issuer.startswith("https://"):
            raise ValueError("sealed resolution certificate issuer is invalid")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise ValueError("sealed resolution timeout must be between 0 and 300 seconds")
        if self.runtime is not None and self.runtime not in {"runsc", "kata", "kata-runtime"}:
            raise ValueError("sealed resolution runtime must be runsc or Kata")
        if platform.system() == "Linux" and self.runtime is None:
            raise ValueError("native Linux sealed resolution requires gVisor (runsc) or Kata")
        _validated_seccomp(self.seccomp_profile, self.seccomp_sha256)
        return _validated_source_host(source, self.allowed_hosts)


@dataclass(frozen=True)
class SealedIntakeConfig:
    engine: str
    image: str
    analyzer_image: str
    allowed_hosts: frozenset[str]
    acquisition_network: str
    https_proxy: str
    certificate_identity: str
    certificate_oidc_issuer: str
    runtime: str | None = None
    timeout_seconds: float = 180.0
    intake_seccomp_profile: str = "containers/seccomp-intake.json"
    intake_seccomp_sha256: str = INTAKE_SECCOMP_SHA256
    analysis_seccomp_profile: str = "containers/seccomp-analysis.json"
    analysis_seccomp_sha256: str = ANALYSIS_SECCOMP_SHA256

    def validate(self, source: str, commit: str) -> str:
        if self.engine not in {"docker", "podman"}:
            raise ValueError("sealed intake engine must be docker or podman")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", self.image):
            raise ValueError("sealed intake image must be pinned by an @sha256: digest")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-fA-F]{64}", self.analyzer_image):
            raise ValueError("sealed analyzer image must be pinned by an @sha256: digest")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.acquisition_network):
            raise ValueError("sealed intake requires a dedicated acquisition network")
        proxy = urlparse(self.https_proxy)
        if proxy.scheme not in {"http", "https"} or not proxy.hostname or proxy.username or proxy.password:
            raise ValueError("sealed intake requires a credential-free HTTPS proxy URL")
        if not self.certificate_identity or len(self.certificate_identity) > 512:
            raise ValueError("sealed intake certificate identity is invalid")
        if not self.certificate_oidc_issuer.startswith("https://"):
            raise ValueError("sealed intake certificate issuer is invalid")
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit):
            raise ValueError("sealed intake requires an exact 40- or 64-hex commit")
        host = _validated_source_host(source, self.allowed_hosts)
        if self.timeout_seconds <= 0 or self.timeout_seconds > 1800:
            raise ValueError("sealed intake timeout must be between 0 and 1800 seconds")
        if self.runtime is not None and self.runtime not in {"runsc", "kata", "kata-runtime"}:
            raise ValueError("sealed intake runtime must be runsc or Kata")
        if platform.system() == "Linux" and self.runtime is None:
            raise ValueError("native Linux sealed intake requires gVisor (runsc) or Kata")
        _validated_seccomp(self.intake_seccomp_profile, self.intake_seccomp_sha256)
        _validated_seccomp(self.analysis_seccomp_profile, self.analysis_seccomp_sha256)
        return host


def _base_run(
    config: SealedIntakeConfig,
    *,
    network: str,
    read_only_volume: bool,
    container_name: str,
    seccomp_profile: str,
) -> list[str]:
    volume_mode = ",readonly" if read_only_volume else ""
    command = [
        config.engine,
        "run",
        "--rm",
        "--name",
        container_name,
        "--label",
        "dev.depfence.purpose=sealed-intake",
        "--pull",
        "never",
        "--network",
        network,
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={seccomp_profile}",
        "--pids-limit",
        "64",
        "--memory",
        "768m",
        "--cpus",
        "1",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "core=0:0",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=268435456",  # noqa: S108 - container tmpfs
        "--mount",
        f"type=volume,src={{volume}},dst=/quarantine{volume_mode}",
    ]
    if config.runtime:
        command.extend(["--runtime", config.runtime])
    return command


def _resolution_run(
    config: SealedResolutionConfig,
    *,
    container_name: str,
) -> list[str]:
    command = [
        config.engine,
        "run",
        "--rm",
        "--name",
        container_name,
        "--label",
        "dev.depfence.purpose=sealed-resolution",
        "--pull",
        "never",
        "--network",
        config.acquisition_network,
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={_validated_seccomp(config.seccomp_profile, config.seccomp_sha256)}",
        "--pids-limit",
        "32",
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--ulimit",
        "nofile=128:128",
        "--ulimit",
        "core=0:0",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16777216",  # noqa: S108 - container tmpfs
    ]
    if config.runtime:
        command.extend(["--runtime", config.runtime])
    return command


def _validated_resolution(raw: bytes, expected_host: str) -> dict[str, object]:
    if len(raw) > MAX_RESOLUTION_MANIFEST_BYTES:
        raise InputLimitError("sealed resolution manifest exceeded its byte budget")
    try:
        document = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ScanIncompleteError("sealed resolution returned malformed JSON") from exc
    expected_fields = {
        "schema_version", "source_host", "symbolic_ref", "exact_commit",
        "complete", "limitations",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise ScanIncompleteError("sealed resolution envelope is invalid")
    if document.get("schema_version") != "depfence.sealed-resolution-worker/v1":
        raise ScanIncompleteError("sealed resolution protocol is unsupported")
    if document.get("source_host") != expected_host:
        raise ScanIncompleteError("sealed resolution host does not match the request")
    commit = document.get("exact_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ScanIncompleteError("sealed resolution commit is invalid")
    symbolic_ref = document.get("symbolic_ref")
    if not isinstance(symbolic_ref, str) or (
        symbolic_ref
        and (
            len(symbolic_ref) > 256
            or not re.fullmatch(r"refs/heads/[A-Za-z0-9._/+\-]{1,244}", symbolic_ref)
            or ".." in symbolic_ref
            or "@{" in symbolic_ref
            or symbolic_ref.endswith((".", "/"))
        )
    ):
        raise ScanIncompleteError("sealed resolution symbolic ref is invalid")
    if document.get("complete") is not True or document.get("limitations") != []:
        raise ScanIncompleteError("sealed resolution was incomplete")
    return cast(dict[str, object], document)


def resolve_source_sealed(
    source: str,
    *,
    state: PrivateState,
    config: SealedResolutionConfig,
) -> dict[str, object]:
    """Resolve remote HEAD through the sealed proxy without fetching objects."""

    host = config.validate(source)
    resolution_id = str(uuid.uuid4())
    container_name = "depfence-resolve-" + resolution_id
    environment = {"PATH": os.environ.get("PATH", "")}
    verify_image_signature(
        config.image,
        config.certificate_identity,
        config.certificate_oidc_issuer,
    )
    command = _resolution_run(config, container_name=container_name)
    command.extend([
        "--env",
        f"HTTPS_PROXY={config.https_proxy}",
        "--env",
        "NO_PROXY=",
        config.image,
        "depfence-sealed-git-resolve",
        "--source",
        source,
        "--allowed-host",
        host,
        "--no-redirects",
        "--format",
        "json",
    ])
    try:
        return_code, stdout, _stderr = _run_command(
            command, environment, config.timeout_seconds
        )
        if return_code:
            raise ScanIncompleteError(
                f"sealed HEAD resolution failed with exit {return_code}"
            )
        worker = _validated_resolution(stdout, host)
    except ScanIncompleteError as exc:
        state.write_text(
            Path("intake") / "sealed-resolutions" / f"{resolution_id}.failure.json",
            json.dumps(
                {
                    "schema_version": "depfence.sealed-resolution-failure/v1",
                    "resolution_id": resolution_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "source_id": state.opaque_id("source", source),
                    "source_host": host,
                    "status": ScanState.INDETERMINATE.value,
                    "reason_code": "sealed_resolution_failed",
                    "materialized_on_host": False,
                    "objects_fetched": False,
                },
                sort_keys=True,
                indent=2,
            ) + "\n",
        )
        raise exc
    finally:
        try:
            _run_command(
                [config.engine, "rm", "--force", container_name],
                environment,
                30.0,
            )
            # Verify the container is actually gone.
            inspect_result = subprocess.run(
                [config.engine, "inspect", container_name],
                capture_output=True, timeout=10,
            )
            if inspect_result.returncode == 0:
                raise ScanIncompleteError("sealed resolution cleanup was indeterminate")
        except ScanIncompleteError:
            raise
        except (OSError, subprocess.TimeoutExpired):
            raise ScanIncompleteError("sealed resolution cleanup was indeterminate") from None
    result = {
        "schema_version": "depfence.sealed-resolution/v1",
        "resolution_id": resolution_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_id": state.opaque_id("source", source),
        "source_host": host,
        "symbolic_ref": worker["symbolic_ref"],
        "exact_commit": worker["exact_commit"],
        "status": ScanState.PASS.value,
        "complete": True,
        "limitations": [],
        "materialized_on_host": False,
        "objects_fetched": False,
        "approved": False,
    }
    state.write_text(
        Path("intake") / "sealed-resolutions" / f"{resolution_id}.json",
        json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return result


def _strict_json_object(raw: bytes) -> dict[str, object]:
    """Parse JSON rejecting duplicate keys (last-key-wins is unsafe for IPC)."""
    def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        seen: dict[str, object] = {}
        for key, value in pairs:
            if key in seen:
                raise ScanIncompleteError(f"sealed intake JSON contains duplicate key: {key}")
            seen[key] = value
        return seen
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ScanIncompleteError("sealed intake returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise ScanIncompleteError("sealed intake manifest must be an object")
    return document


def _validated_inventory(raw: bytes, expected_commit: str) -> dict[str, object]:
    if len(raw) > MAX_INTAKE_MANIFEST_BYTES:
        raise InputLimitError("sealed intake manifest exceeded its byte budget")
    document = _strict_json_object(raw)
    allowed = {
        "commit", "tree_sha256", "file_count", "byte_count", "regular_files",
        "symlink_count", "submodule_count", "non_regular_count", "suffix_counts",
        "warning_codes",
    }
    if not set(document) <= allowed:
        raise ScanIncompleteError("sealed intake manifest contains unsupported fields")
    if str(document.get("commit", "")).casefold() != expected_commit.casefold():
        raise ScanIncompleteError("sealed intake commit does not match the requested commit")
    tree_digest = str(document.get("tree_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", tree_digest):
        raise ScanIncompleteError("sealed intake tree digest is invalid")
    integer_fields = (
        "file_count", "byte_count", "regular_files", "symlink_count",
        "submodule_count", "non_regular_count",
    )
    for field in integer_fields:
        value = document.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ScanIncompleteError(f"sealed intake field is invalid: {field}")
    accounted = sum(
        int(document[field])
        for field in ("regular_files", "symlink_count", "submodule_count", "non_regular_count")
    )
    if accounted != document["file_count"]:
        raise ScanIncompleteError("sealed intake file counts do not reconcile")
    suffixes = document.get("suffix_counts", {})
    if not isinstance(suffixes, dict) or len(suffixes) > 256:
        raise ScanIncompleteError("sealed intake suffix inventory is invalid")
    for suffix, count in suffixes.items():
        if not isinstance(suffix, str) or not re.fullmatch(r"\.[a-z0-9]{1,16}|<none>", suffix):
            raise ScanIncompleteError("sealed intake suffix key is invalid")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ScanIncompleteError("sealed intake suffix count is invalid")
    if sum(cast(int, count) for count in suffixes.values()) != document["file_count"]:
        raise ScanIncompleteError("sealed intake suffix counts do not reconcile")
    warnings = document.get("warning_codes", [])
    if not isinstance(warnings, list) or any(value not in _WARNING_CODES for value in warnings):
        raise ScanIncompleteError("sealed intake warning codes are invalid")
    return document


def _validated_analysis(raw: bytes, expected_commit: str) -> dict[str, object]:
    if len(raw) > MAX_ANALYSIS_MANIFEST_BYTES:
        raise InputLimitError("sealed analysis manifest exceeded its byte budget")
    document = _strict_json_object(raw)
    allowed = {
        "schema_version", "commit", "complete", "candidate_count", "analyzed_count",
        "analyzed_bytes", "coverage_by_suffix", "findings", "limitations", "toolchain",
    }
    if set(document) != allowed or document.get("schema_version") != "depfence.sealed-analysis/v1":
        raise ScanIncompleteError("sealed analysis envelope is unsupported")
    if str(document.get("commit", "")).casefold() != expected_commit.casefold():
        raise ScanIncompleteError("sealed analysis commit does not match the requested commit")
    if not isinstance(document.get("complete"), bool):
        raise ScanIncompleteError("sealed analysis completeness is invalid")
    for field in ("candidate_count", "analyzed_count", "analyzed_bytes"):
        value = document.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ScanIncompleteError(f"sealed analysis field is invalid: {field}")
    if cast(int, document["analyzed_count"]) > cast(int, document["candidate_count"]):
        raise ScanIncompleteError("sealed analysis counts do not reconcile")
    coverage = document.get("coverage_by_suffix")
    if not isinstance(coverage, dict) or len(coverage) > 32:
        raise ScanIncompleteError("sealed analysis coverage is invalid")
    for suffix, raw_counts in coverage.items():
        if not isinstance(suffix, str) or not re.fullmatch(r"\.[a-z0-9]{1,16}", suffix):
            raise ScanIncompleteError("sealed analysis coverage suffix is invalid")
        if not isinstance(raw_counts, dict) or set(raw_counts) != {"total", "analyzed", "incomplete"}:
            raise ScanIncompleteError("sealed analysis coverage counters are invalid")
        values = list(raw_counts.values())
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
            raise ScanIncompleteError("sealed analysis coverage count is invalid")
        if cast(int, raw_counts["analyzed"]) > cast(int, raw_counts["total"]):
            raise ScanIncompleteError("sealed analysis suffix counts do not reconcile")
    findings = document.get("findings")
    limitations = document.get("limitations")
    if not isinstance(findings, list) or len(findings) > 2_000:
        raise ScanIncompleteError("sealed analysis findings are invalid")
    if not isinstance(limitations, list) or len(limitations) > 2_000:
        raise ScanIncompleteError("sealed analysis limitations are invalid")
    artifact_pattern = re.compile(r"sealed-artifact-sha256:[0-9a-f]{64}")
    allowed_rules = {"DF-FONT-001", "DF-FONT-002", "DF-WEB-001", "DF-DOCX-001", "DF-PDF-001"}
    allowed_evidence_classes = {
        "sparse_font_cluster", "conflicting_cmap", "per_character_webfont",
        "embedded_font_switching", "structural_correlation",
    }
    suffix_pattern = re.compile(r"^\.[a-z0-9]{1,16}$")
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {
            "artifact_id", "suffix", "rule_id", "severity", "confidence", "evidence_class"
        }:
            raise ScanIncompleteError("sealed analysis finding shape is invalid")
        confidence = finding.get("confidence")
        suffix_val = str(finding.get("suffix", ""))
        evidence_val = str(finding.get("evidence_class", ""))
        if (
            not artifact_pattern.fullmatch(str(finding.get("artifact_id", "")))
            or finding.get("rule_id") not in allowed_rules
            or finding.get("severity") != "medium"
            or not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0 <= float(confidence) <= 1
            or not suffix_pattern.fullmatch(suffix_val)
            or evidence_val not in allowed_evidence_classes
        ):
            raise ScanIncompleteError("sealed analysis finding value is invalid")
    allowed_limitations = {
        "artifact_budget_exceeded", "artifact_size_exceeded", "analysis_byte_budget_exceeded",
        "blob_read_failed", "deep_analysis_required", "font_sanitizer_unavailable",
        "font_sanitization_failed", "font_collection_limit", "font_collection_unsupported",
        "font_collection_decompression_failed",
    }
    for limitation in limitations:
        if not isinstance(limitation, dict) or set(limitation) != {"artifact_id", "suffix", "code"}:
            raise ScanIncompleteError("sealed analysis limitation shape is invalid")
        if (
            not artifact_pattern.fullmatch(str(limitation.get("artifact_id", "")))
            or not suffix_pattern.fullmatch(str(limitation.get("suffix", "")))
            or limitation.get("code") not in allowed_limitations
        ):
            raise ScanIncompleteError("sealed analysis limitation is invalid")
    toolchain = document.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {"depfence"} or not isinstance(toolchain["depfence"], str):
        raise ScanIncompleteError("sealed analysis toolchain is invalid")
    version = str(toolchain["depfence"])
    if not re.fullmatch(r"[0-9a-zA-Z._\-+]{1,64}", version):
        raise ScanIncompleteError("sealed analysis toolchain version is invalid")
    if bool(limitations) == bool(document["complete"]):
        raise ScanIncompleteError("sealed analysis completeness contradicts limitations")
    return document


def inspect_source_sealed(
    source: str,
    commit: str,
    *,
    approved_commit: str,
    state: PrivateState,
    config: SealedIntakeConfig,
    file_budget: int = DEFAULT_FILE_BUDGET,
    byte_budget: int = DEFAULT_BYTE_BUDGET,
) -> dict[str, object]:
    """Acquire and inventory an exact Git commit without host materialization."""

    if approved_commit.casefold() != commit.casefold() or not re.fullmatch(
        r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", approved_commit
    ):
        raise ValueError("sealed intake requires approval of the exact commit")
    host = config.validate(source, commit)
    if file_budget <= 0 or byte_budget <= 0:
        raise ValueError("sealed intake budgets must be positive")
    intake_id = str(uuid.uuid4())
    volume = "depfence-intake-" + intake_id
    acquire_name = "depfence-acquire-" + intake_id
    inventory_name = "depfence-inventory-" + intake_id
    analysis_name = "depfence-analysis-" + intake_id
    environment = {"PATH": os.environ.get("PATH", "")}

    verify_image_signature(
        config.image,
        config.certificate_identity,
        config.certificate_oidc_issuer,
    )
    verify_image_signature(
        config.analyzer_image,
        config.certificate_identity,
        config.certificate_oidc_issuer,
    )

    create = [
        config.engine,
        "volume",
        "create",
        "--label",
        "dev.depfence.purpose=sealed-intake",
        "--label",
        f"dev.depfence.intake-id={intake_id}",
        "--opt", "type=tmpfs",
        "--opt", "device=tmpfs",
        "--opt", f"o=size={min(byte_budget + 67108864, 805306368)},nodev,nosuid,noexec",
        volume,
    ]
    return_code, _stdout, _stderr = _run_command(
        create, environment, min(config.timeout_seconds, 30.0)
    )
    if return_code:
        raise ScanIncompleteError(f"sealed intake volume creation failed with exit {return_code}")

    inventory: dict[str, object] | None = None
    analysis: dict[str, object] | None = None
    cleanup_failed = False
    failure: ScanIncompleteError | None = None
    try:
        acquire = [value.replace("{volume}", volume) for value in _base_run(
            config,
            network=config.acquisition_network,
            read_only_volume=False,
            container_name=acquire_name,
            seccomp_profile=_validated_seccomp(config.intake_seccomp_profile, config.intake_seccomp_sha256),
        )]
        acquire.extend([
            "--env",
            f"HTTPS_PROXY={config.https_proxy}",
            "--env",
            "NO_PROXY=",
            config.image,
            "depfence-sealed-git-acquire",
            "--source",
            source,
            "--commit",
            commit,
            "--allowed-host",
            host,
            "--no-redirects",
            "--no-checkout",
            "--no-submodules",
            "--no-lfs",
            "--destination",
            "/quarantine/repository",
            "--artifact-budget",
            "2000",
            "--byte-budget",
            str(min(byte_budget, 256 * 1024 * 1024)),
        ])
        return_code, _stdout, _stderr = _run_command(
            acquire, environment, config.timeout_seconds
        )
        if return_code:
            raise ScanIncompleteError(f"sealed Git acquisition failed with exit {return_code}")

        analyze = [value.replace("{volume}", volume) for value in _base_run(
            config,
            network="none",
            read_only_volume=True,
            container_name=inventory_name,
            seccomp_profile=_validated_seccomp(config.intake_seccomp_profile, config.intake_seccomp_sha256),
        )]
        analyze.extend([
            config.image,
            "depfence-sealed-git-inventory",
            "--repository",
            "/quarantine/repository",
            "--commit",
            commit,
            "--format",
            "json",
        ])
        return_code, stdout, _stderr = _run_command(
            analyze, environment, config.timeout_seconds
        )
        if return_code:
            raise ScanIncompleteError(f"sealed Git inventory failed with exit {return_code}")
        inventory = _validated_inventory(stdout, commit)

        static_analysis = [value.replace("{volume}", volume) for value in _base_run(
            config,
            network="none",
            read_only_volume=True,
            container_name=analysis_name,
            seccomp_profile=_validated_seccomp(config.analysis_seccomp_profile, config.analysis_seccomp_sha256),
        )]
        static_analysis.extend([
            config.analyzer_image,
            "depfence-sealed-git-analyze",
            "--repository",
            "/quarantine/repository",
            "--commit",
            commit,
            "--format",
            "json",
            "--artifact-budget",
            "2000",
            "--byte-budget",
            str(min(byte_budget, 256 * 1024 * 1024)),
        ])
        return_code, stdout, _stderr = _run_command(
            static_analysis, environment, config.timeout_seconds
        )
        if return_code:
            raise ScanIncompleteError(f"sealed artifact analysis failed with exit {return_code}")
        analysis = _validated_analysis(stdout, commit)
    except ScanIncompleteError as exc:
        failure = exc
    finally:
        for container_name in (acquire_name, inventory_name, analysis_name):
            try:
                _run_command(
                    [config.engine, "rm", "--force", container_name],
                    environment,
                    30.0,
                )
            except (OSError, ScanIncompleteError):
                cleanup_failed = True
        remove = [config.engine, "volume", "rm", volume]
        try:
            remove_code, _stdout, _stderr = _run_command(
                remove, environment, 30.0
            )
            if remove_code:
                cleanup_failed = True
        except (OSError, ScanIncompleteError):
            # The generated volume name is returned below as a cleanup error;
            # never broaden deletion to a prefix or workspace path.
            cleanup_failed = True

    if failure is not None:
        failure_record = {
            "schema_version": "depfence.sealed-intake-failure/v1",
            "intake_id": intake_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_id": state.opaque_id("source", source),
            "source_host": host,
            "commit": commit.casefold(),
            "status": ScanState.INDETERMINATE.value,
            "reason_code": "sealed_worker_failed",
            "cleanup_failed": cleanup_failed,
            "cleanup_resource": (
                {"engine": config.engine, "kind": "volume", "name": volume}
                if cleanup_failed
                else None
            ),
            "materialized_on_host": False,
        }
        state.write_text(
            Path("intake") / "sealed-records" / f"{intake_id}.failure.json",
            json.dumps(failure_record, sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        raise failure

    assert inventory is not None
    assert analysis is not None
    for finding in cast(list[dict[str, object]], analysis["findings"]):
        finding["rule_version"] = "2026-08-17"
        finding["artifact_type"] = str(finding.get("suffix", "")).lstrip(".")
        finding["carrier_type"] = "git_blob"
    warnings = list(cast(list[str], inventory.get("warning_codes", [])))
    if inventory["symlink_count"]:
        warnings.append("symlink_present")
    if inventory["submodule_count"]:
        warnings.append("submodule_present")
    if inventory["non_regular_count"]:
        warnings.append("non_regular_entry")
    if cast(int, inventory["file_count"]) > file_budget:
        warnings.append("file_budget_exceeded")
    if cast(int, inventory["byte_count"]) > byte_budget:
        warnings.append("byte_budget_exceeded")
    if cleanup_failed:
        warnings.append("volume_cleanup_failed")
        state.write_text(
            Path("intake") / "cleanup" / f"{intake_id}.json",
            json.dumps(
                {
                    "schema_version": "depfence.oci-cleanup/v1",
                    "intake_id": intake_id,
                    "engine": config.engine,
                    "resources": [{"kind": "volume", "name": volume}],
                    "apply_required": True,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
        )
    if not cast(bool, analysis["complete"]):
        warnings.append("artifact_analysis_incomplete")
    status = (
        ScanState.UNPROVEN
        if warnings
        else ScanState.FAIL
        if cast(list[object], analysis["findings"])
        else ScanState.PASS
    )
    ingestion_policy = (
        "unproven" if status in {ScanState.UNPROVEN, ScanState.INDETERMINATE}
        else "quarantine" if cast(list[object], analysis["findings"])
        else "allow"
    )
    result = {
        "schema_version": "depfence.sealed-intake/v1",
        "intake_id": intake_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_id": state.opaque_id("source", source),
        "source_host": host,
        "commit": commit.casefold(),
        "tree_sha256": inventory["tree_sha256"],
        "status": status.value,
        "ingestion_policy": ingestion_policy,
        "counts": {
            "files": inventory["file_count"],
            "bytes": inventory["byte_count"],
            "regular_files": inventory["regular_files"],
            "symlinks": inventory["symlink_count"],
            "submodules": inventory["submodule_count"],
            "non_regular": inventory["non_regular_count"],
        },
        "suffix_counts": inventory["suffix_counts"],
        "analysis": {
            "complete": analysis["complete"],
            "candidate_count": analysis["candidate_count"],
            "analyzed_count": analysis["analyzed_count"],
            "analyzed_bytes": analysis["analyzed_bytes"],
            "coverage_by_suffix": analysis["coverage_by_suffix"],
            "findings": analysis["findings"],
            "limitations": analysis["limitations"],
            "toolchain": analysis["toolchain"],
            "rule_version": "2026-08-17",
            "coverage_units": {"artifacts": analysis["analyzed_count"]},
            "presentation_mechanisms_inspected": ["cmap", "gsub", "document_structure", "decoded_pdf_objects"],
        },
        "warning_codes": sorted(set(warnings)),
        "approved": False,
        "materialized_on_host": False,
    }
    state.write_text(
        Path("intake") / "sealed-records" / f"{intake_id}.json",
        json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n",
    )
    return result


__all__ = [
    "SealedIntakeConfig",
    "SealedResolutionConfig",
    "inspect_source_sealed",
    "resolve_source_sealed",
]
