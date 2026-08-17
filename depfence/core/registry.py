"""Fail-closed scanner/analyzer/reporter registry.

Shipped extensions are loaded from the in-tree catalog. Third-party entry
points and path plugins are ignored by default; embedding applications must set
``enable_third_party=True`` and approve the exact entry-point identity or file
contents with :func:`plugin_fingerprint` before any third-party code is loaded.
Normal CLI execution uses the default, shipped-only registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import logging
import multiprocessing
import os
import signal
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

from depfence.core.models import (
    Finding,
    FindingType,
    PackageId,
    PackageMeta,
    ScanResult,
    ScanState,
    Severity,
)
from depfence.core.scan_scope import PartialScanError, ScanIncompleteError, ScanScope

log = logging.getLogger(__name__)

MAX_SCANNER_FINDINGS = 10_000
MAX_SCANNER_RESULT_BYTES = 8 * 1024 * 1024


SHIPPED_ANALYZERS: dict[str, str] = {
    "ast_analyzer": "depfence.analyzers.ast_analysis:AstAnalyzer",
    "install_script": "depfence.analyzers.install_script:InstallScriptAnalyzer",
}

SHIPPED_REPORTERS: dict[str, str] = {
    "json_reporter": "depfence.reporters.json_out:JsonReporter",
    "json_legacy_reporter": "depfence.reporters.json_out:LegacyJsonReporter",
    "table_reporter": "depfence.reporters.table_out:TableReporter",
    "sarif_reporter": "depfence.reporters.sarif_out:SarifReporter",
    "cyclonedx_reporter": "depfence.reporters.cyclonedx:generate_sbom",
    "spdx_reporter": "depfence.reporters.spdx_out:generate_spdx",
    "compliance_reporter": "depfence.reporters.compliance_report:generate_compliance_report",
    "html_reporter": "depfence.core.html_report:generate_html_report",
}


def plugin_fingerprint(source: str | Path) -> str:
    """Return the approval fingerprint for an entry-point identity or plugin file."""
    if isinstance(source, Path):
        content = source.resolve(strict=True).read_bytes()
    else:
        content = source.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _load_target(target: str) -> object:
    module_name, attribute = target.split(":", 1)
    loaded = getattr(importlib.import_module(module_name), attribute)
    return loaded() if isinstance(loaded, type) else loaded


@dataclass(frozen=True)
class ShippedScannerSpec:
    """One scanner shipped by DepFence and the interfaces it supports."""

    name: str
    target: str
    package: bool = True
    project: bool = False
    requires_network: bool = False
    advisory: bool = False
    timeout_seconds: float = 60.0
    applicable_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("scanner timeout must be positive")

    def load(self) -> object:
        module_name, class_name = self.target.split(":", 1)
        return getattr(importlib.import_module(module_name), class_name)()


# Runtime source of truth for shipped scanners.  Packaging entry points expose
# the same classes to third-party hosts, but production execution must not
# depend on installed distribution metadata (source checkouts are supported).
SHIPPED_SCANNERS: tuple[ShippedScannerSpec, ...] = (
    ShippedScannerSpec("npm_advisory", "depfence.scanners.npm_advisory:NpmAdvisoryScanner", requires_network=True, advisory=True),
    ShippedScannerSpec("pypi_advisory", "depfence.scanners.pypi_advisory:PypiAdvisoryScanner", requires_network=True, advisory=True),
    ShippedScannerSpec("behavioral", "depfence.scanners.behavioral:BehavioralScanner"),
    ShippedScannerSpec("reputation", "depfence.scanners.reputation:ReputationScanner"),
    ShippedScannerSpec("slopsquat", "depfence.scanners.slopsquat:SlopsquatScanner"),
    ShippedScannerSpec("mcp_scanner", "depfence.scanners.mcp_scanner:McpScanner", project=True),
    ShippedScannerSpec("gha_scanner", "depfence.scanners.gha_scanner:GhaScanner", project=True),
    ShippedScannerSpec("mcp_fingerprint", "depfence.scanners.mcp_fingerprint:McpFingerprintScanner", project=True),
    ShippedScannerSpec("dep_confusion", "depfence.scanners.depconfusion:DepConfusionScanner"),
    ShippedScannerSpec("preinstall", "depfence.scanners.preinstall:PreinstallScanner", project=True),
    ShippedScannerSpec("provenance", "depfence.scanners.provenance:ProvenanceScanner"),
    ShippedScannerSpec("model_scanner", "depfence.scanners.model_scanner:ModelScanner", project=True),
    ShippedScannerSpec("ci_secrets", "depfence.scanners.ci_secrets:CiSecretsScanner"),
    ShippedScannerSpec("license_scanner", "depfence.scanners.license_scanner:LicenseScanner"),
    ShippedScannerSpec("reachability", "depfence.scanners.reachability:ReachabilityScanner", package=False, project=True),
    ShippedScannerSpec("ownership", "depfence.scanners.ownership_scanner:OwnershipScanner"),
    ShippedScannerSpec("scope_squatting", "depfence.scanners.scope_scanner:ScopeScanner"),
    ShippedScannerSpec("dockerfile", "depfence.scanners.dockerfile_scanner:DockerfileScanner", project=True),
    ShippedScannerSpec("gha_workflow", "depfence.scanners.gha_workflow_scanner:GhaWorkflowScanner", project=True),
    ShippedScannerSpec("freshness", "depfence.scanners.freshness_scanner:FreshnessScanner", project=True),
    ShippedScannerSpec("secrets", "depfence.scanners.secrets_scanner:SecretsScanner", project=True),
    ShippedScannerSpec("terraform", "depfence.scanners.terraform_scanner:TerraformScanner", project=True),
    ShippedScannerSpec("pinning", "depfence.scanners.pinning_scanner:PinningScanner", project=True),
    ShippedScannerSpec("osv", "depfence.scanners.osv_scanner:OsvScanner", project=True, requires_network=True, advisory=True),
    ShippedScannerSpec("obfuscation", "depfence.scanners.obfuscation:ObfuscationScanner", project=True),
    ShippedScannerSpec("network", "depfence.scanners.network_scanner:NetworkScanner", project=True),
    ShippedScannerSpec("phantom_deps", "depfence.scanners.phantom_deps:PhantomDepsScanner", package=False, project=True),
    ShippedScannerSpec("ai_vulns", "depfence.scanners.ai_vulns:AiVulnScanner", project=True),
    ShippedScannerSpec("model_integrity", "depfence.scanners.model_integrity:ModelIntegrityScanner", project=True),
    ShippedScannerSpec("provenance_checker", "depfence.scanners.provenance_checker:ProvenanceChecker", project=True),
    ShippedScannerSpec("prompt_injection", "depfence.scanners.prompt_injection_scanner:PromptInjectionScanner", project=True),
    ShippedScannerSpec("git_message", "depfence.scanners.git_message_scanner:GitMessageScanner", project=True),
    ShippedScannerSpec("ci_ai_bot", "depfence.scanners.ci_ai_bot_scanner:CiAiBotScanner", project=True),
    ShippedScannerSpec("docker_layer", "depfence.scanners.docker_layer_scanner:DockerLayerScanner", project=True),
    ShippedScannerSpec("ai_bom", "depfence.scanners.ai_bom_generator:AiBomGenerator", project=True),
    ShippedScannerSpec(
        "version_existence",
        "depfence.scanners.version_existence_scanner:VersionExistenceScanner",
        requires_network=True,
    ),
    ShippedScannerSpec("editor_config", "depfence.scanners.editor_config_scanner:EditorConfigScanner", project=True),
    ShippedScannerSpec("binding_gyp", "depfence.scanners.binding_gyp_scanner:BindingGypScanner", project=True),
    ShippedScannerSpec("model_format", "depfence.scanners.model_format_scanner:ModelFormatScanner", project=True),
    ShippedScannerSpec("payload_behavior", "depfence.scanners.payload_behavior_scanner:PayloadBehaviorScanner", project=True),
    ShippedScannerSpec(
        "resolve_existence",
        "depfence.scanners.resolve_existence_scanner:ResolveExistenceScanner",
        project=True,
        requires_network=True,
    ),
    ShippedScannerSpec("ruby_lifecycle", "depfence.scanners.ruby_lifecycle_scanner:RubyLifecycleScanner", project=True),
    ShippedScannerSpec("protestware", "depfence.scanners.protestware_scanner:ProtestwareScanner", package=False, project=True),
    ShippedScannerSpec("android_manifest", "depfence.scanners.android_manifest_scanner:AndroidManifestScanner", package=False, project=True),
    ShippedScannerSpec("gradle_plugin", "depfence.scanners.gradle_plugin_scanner:GradlePluginScanner", package=False, project=True),
    ShippedScannerSpec("cocoapods_hook", "depfence.scanners.cocoapods_hook_scanner:CocoaPodsHookScanner", package=False, project=True),
    ShippedScannerSpec("flutter_pubspec", "depfence.scanners.flutter_pubspec_scanner:FlutterPubspecScanner", package=False, project=True),
    ShippedScannerSpec("spm_plugin", "depfence.scanners.spm_plugin_scanner:SpmPluginScanner", package=False, project=True),
    ShippedScannerSpec("rust_build", "depfence.scanners.rust_build_scanner:RustBuildScanner", package=False, project=True),
    ShippedScannerSpec("go_generate", "depfence.scanners.go_generate_scanner:GoGenerateScanner", package=False, project=True),
    ShippedScannerSpec("composer_script", "depfence.scanners.composer_script_scanner:ComposerScriptScanner", package=False, project=True),
    ShippedScannerSpec("python_build", "depfence.scanners.python_build_scanner:PythonBuildScanner", package=False, project=True),
    ShippedScannerSpec("maven_plugin", "depfence.scanners.maven_plugin_scanner:MavenPluginScanner", package=False, project=True),
    # AgentSkillScanner was historically hard-coded in both engines but absent
    # from the package entry points.  Keeping it here makes it genuinely shipped.
    ShippedScannerSpec(
        "agent_skill",
        "depfence.scanners.agent_skill_scanner:AgentSkillScanner",
        project=True,
    ),
    ShippedScannerSpec(
        "rag_poison",
        "depfence.scanners.rag_poison_scanner:RagPoisonScanner",
        package=False,
        project=True,
    ),
    ShippedScannerSpec(
        "visual_text_deception",
        "depfence.scanners.visual_text_deception_scanner:VisualTextDeceptionScanner",
        package=False,
        project=True,
    ),
)

# Stable product-facing views over the scanner catalog.  Profiles select
# capabilities; they do not create a second execution path.
SCANNER_PROFILES: dict[str, frozenset[str]] = {
    "full": frozenset(spec.name for spec in SHIPPED_SCANNERS),
    "advisory": frozenset(spec.name for spec in SHIPPED_SCANNERS if spec.advisory),
    "ai": frozenset({
        "agent_skill", "ai_bom", "ai_vulns", "ci_ai_bot", "mcp_fingerprint",
        "mcp_scanner", "model_format", "model_integrity", "model_scanner",
        "prompt_injection",
        "rag_poison",
        "visual_text_deception",
    }),
    "mcp": frozenset({"agent_skill", "mcp_fingerprint", "mcp_scanner"}),
    "ci": frozenset({
        "ci_ai_bot", "ci_secrets", "gha_scanner", "gha_workflow", "pinning",
        "secrets",
    }),
    "model": frozenset({
        "ai_bom", "ai_vulns", "model_format", "model_integrity", "model_scanner",
    }),
}


@dataclass(frozen=True)
class RegistryIssue:
    source: str
    name: str
    error: str

    def __str__(self) -> str:
        return f"{self.source} {self.name}: {self.error}"


@dataclass
class ProjectScannerResult:
    name: str
    status: ScanState
    findings: list[Finding]
    duration_ms: float
    error: str | None = None
    evaluated: bool = True
    skipped: bool = False

    @property
    def success(self) -> bool:
        return bool(self.status == ScanState.PASS)


@runtime_checkable
class Scanner(Protocol):
    name: str
    ecosystems: list[str]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]: ...


@runtime_checkable
class Analyzer(Protocol):
    name: str

    async def analyze(self, package: PackageMeta, source_path: Path | None) -> list[Finding]: ...


@runtime_checkable
class Reporter(Protocol):
    name: str
    format: str

    def render(self, result: ScanResult) -> str: ...


class PluginRegistry:
    def __init__(
        self,
        *,
        enable_third_party: bool = False,
        trusted_plugin_fingerprints: set[str] | frozenset[str] = frozenset(),
        plugin_paths: tuple[Path, ...] | list[Path] = (),
    ) -> None:
        self._scanners: dict[str, Scanner] = {}
        self._analyzers: dict[str, Analyzer] = {}
        self._reporters: dict[str, Reporter] = {}
        self._hooks: dict[str, list[Any]] = {}
        self._issues: list[RegistryIssue] = []
        self._enable_third_party = enable_third_party
        self._trusted_plugin_fingerprints = frozenset(trusted_plugin_fingerprints)
        self._plugin_paths = tuple(Path(path) for path in plugin_paths)

    def discover(self) -> None:
        self._load_shipped_scanners()
        self._load_shipped_extensions()
        if self._enable_third_party:
            self._load_entry_points()
            self._load_path_plugins()

    def _record_issue(self, source: str, name: str, exc: BaseException) -> None:
        issue = RegistryIssue(source=source, name=name, error=f"{type(exc).__name__}: {exc}")
        self._issues.append(issue)
        log.warning("Plugin registry issue: %s", issue)

    def _load_shipped_scanners(self) -> None:
        for spec in SHIPPED_SCANNERS:
            try:
                instance = spec.load()
                self._scanners[spec.name] = instance  # type: ignore[assignment]
            except Exception as exc:  # noqa: BLE001
                self._record_issue("shipped scanner", spec.name, exc)

    def _load_shipped_extensions(self) -> None:
        for name, target in SHIPPED_ANALYZERS.items():
            try:
                self._analyzers[name] = _load_target(target)  # type: ignore[assignment]
            except Exception as exc:  # noqa: BLE001
                self._record_issue("shipped analyzer", name, exc)
        for name, target in SHIPPED_REPORTERS.items():
            try:
                self._reporters[name] = _load_target(target)  # type: ignore[assignment]
            except Exception as exc:  # noqa: BLE001
                self._record_issue("shipped reporter", name, exc)

    def _load_entry_points(self) -> None:
        for group, store in [
            ("depfence.scanners", self._scanners),
            ("depfence.analyzers", self._analyzers),
            ("depfence.reporters", self._reporters),
        ]:
            try:
                eps = importlib.metadata.entry_points(group=group)
            except TypeError:
                eps = importlib.metadata.entry_points().get(group, [])  # type: ignore[arg-type]
            for ep in eps:
                identity = f"{group}:{ep.name}:{ep.value}"
                if plugin_fingerprint(identity) not in self._trusted_plugin_fingerprints:
                    self._issues.append(
                        RegistryIssue(group, ep.name, "plugin fingerprint is not approved")
                    )
                    continue
                try:
                    loaded = ep.load()
                    # Scanner/analyzer entry points are classes; several
                    # built-in reporters are renderer functions and must not
                    # be called as zero-argument constructors during discovery.
                    instance = loaded() if isinstance(loaded, type) else loaded
                    # Installed metadata repeats shipped scanner entry points.
                    # The in-tree catalog wins so source and installed runs agree.
                    cast(Any, store).setdefault(ep.name, instance)
                except Exception as exc:  # noqa: BLE001
                    self._record_issue(f"entry point {group}", ep.name, exc)

    def _load_path_plugins(self) -> None:
        directories = list(self._plugin_paths)
        configured = os.environ.get("DEPFENCE_PLUGIN_PATH", "")
        directories.extend(
            Path(value) for value in configured.split(os.pathsep) if value
        )
        user_directory = Path.home() / ".depfence" / "plugins"
        if user_directory.exists():
            directories.append(user_directory)
        for directory in dict.fromkeys(directories):
            self._load_plugins_from_dir(directory)

    def _load_plugins_from_dir(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        for py_file in directory.glob("*.py"):
            try:
                approved = plugin_fingerprint(py_file) in self._trusted_plugin_fingerprints
            except OSError as exc:
                self._record_issue("path plugin", str(py_file), exc)
                continue
            if not approved:
                self._issues.append(
                    RegistryIssue("path plugin", str(py_file), "plugin fingerprint is not approved")
                )
                continue
            if str(directory) not in sys.path:
                sys.path.insert(0, str(directory))
            module_name = f"depfence_plugin_{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    self._register_from_module(mod)
            except Exception as exc:  # noqa: BLE001
                self._record_issue("path plugin", str(py_file), exc)

    def _register_from_module(self, mod: Any) -> None:
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, type):
                try:
                    instance = obj()
                except Exception:
                    continue
                if isinstance(instance, Scanner):
                    self._scanners[instance.name] = instance
                elif isinstance(instance, Analyzer):
                    self._analyzers[instance.name] = instance
                elif isinstance(instance, Reporter):
                    self._reporters[instance.name] = instance

    def register_hook(self, event: str, callback: Any) -> None:
        self._hooks.setdefault(event, []).append(callback)

    async def fire_hook(self, event: str, **kwargs: Any) -> list[str]:
        errors: list[str] = []
        for cb in self._hooks.get(event, []):
            try:
                result = cb(**kwargs)
                if hasattr(result, "__await__"):
                    await result
            except Exception as exc:  # noqa: BLE001
                callback_name = getattr(cb, "__qualname__", repr(cb))
                message = f"Hook {event} ({callback_name}) failed: {exc}"
                errors.append(message)
                log.warning(message)
        return errors

    @property
    def scanners(self) -> dict[str, Scanner]:
        return dict(self._scanners)

    @property
    def analyzers(self) -> dict[str, Analyzer]:
        return dict(self._analyzers)

    @property
    def reporters(self) -> dict[str, Reporter]:
        return dict(self._reporters)

    @property
    def issues(self) -> tuple[RegistryIssue, ...]:
        return tuple(self._issues)


def _project_scanner_worker(
    connection: Any,
    scanner_source: object,
    scope: ScanScope,
    max_findings: int,
    max_result_bytes: int,
) -> None:
    """Child-process entry point.  Only bounded serialized data crosses back."""
    try:
        if hasattr(os, "setsid") and os.getpgrp() != os.getpid():
            try:
                os.setsid()
            except PermissionError:
                # Some sandboxed macOS workers cannot create a session. The
                # parent detects whether a private process group exists before
                # attempting group termination and otherwise kills the worker.
                pass
        scanner = _load_target(scanner_source) if isinstance(scanner_source, str) else scanner_source
        scan_project = scanner.scan_project  # type: ignore[attr-defined]
        findings = asyncio.run(scan_project(scope))
        if not isinstance(findings, list):
            raise TypeError(f"scan_project() returned {type(findings).__name__}, expected list")
        if len(findings) > max_findings:
            raise ValueError(
                f"scanner result exceeds finding limit ({len(findings)} > {max_findings})"
            )
        for finding in findings:
            if not isinstance(finding, Finding):
                raise TypeError(
                    f"scanner result contains {type(finding).__name__}, expected Finding"
                )
        assurance_unproven = any(
            finding.metadata.get("assurance") == "unproven" for finding in findings
        )
        payload = json.dumps(
            {
                "state": "partial" if assurance_unproven else "ok",
                "error": (
                    "scanner evidence contains an unproven authority boundary"
                    if assurance_unproven else None
                ),
                "findings": [asdict(finding) for finding in findings],
            },
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > max_result_bytes:
            raise ValueError(
                f"scanner result exceeds serialized size limit ({len(payload)} > {max_result_bytes})"
            )
        connection.send_bytes(payload)
    except PartialScanError as exc:
        try:
            findings = exc.findings[:max_findings]
            payload = json.dumps(
                {
                    "state": "partial",
                    "error": str(exc),
                    "findings": [asdict(cast(Finding, finding)) for finding in findings],
                },
                default=str,
                separators=(",", ":"),
            ).encode("utf-8")
            if len(payload) > max_result_bytes:
                raise ValueError("partial scanner result exceeded serialized size limit")
            connection.send_bytes(payload)
        except BaseException:
            pass
    except BaseException as exc:  # child must report scanner crashes as coverage failures
        try:
            payload = json.dumps(
                {"state": "error", "error": f"{type(exc).__name__}: {exc}"},
                separators=(",", ":"),
            ).encode("utf-8")
            connection.send_bytes(payload[:max_result_bytes])
        except BaseException:
            pass
    finally:
        connection.close()


def _stop_worker(process: multiprocessing.Process) -> None:
    """Terminate a scanner and its descendants, then reap it."""
    try:
        pid = process.pid
    except ValueError:
        # ``multiprocessing.Process.close`` intentionally makes every later
        # attribute access fail. Cleanup can be reached through cancellation
        # and receive-error paths, so stopping an already-closed worker must be
        # harmless rather than obscuring the original coverage failure.
        return
    if pid is None:
        try:
            process.close()
        except ValueError:
            pass
        return
    owns_group = False
    if hasattr(os, "getpgid"):
        try:
            owns_group = os.getpgid(pid) == pid
        except ProcessLookupError:
            pass
    if process.is_alive():
        if owns_group and hasattr(os, "killpg"):
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        else:
            process.terminate()
        process.join(timeout=0.2)
    if process.is_alive():
        if owns_group and hasattr(os, "killpg"):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
    process.join(timeout=0.5)
    if not process.is_alive():
        # ``join`` reaps the child, while ``close`` releases the Process
        # object's sentinel and other parent-side resources.  Project scans
        # can create many short-lived workers, so relying on GC here can
        # exhaust file descriptors during a long test or scan run.
        process.close()


async def _receive_worker_result(
    process: multiprocessing.Process,
    connection: Any,
    timeout: float,
) -> tuple[str, object]:
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if connection.poll():
                try:
                    payload = connection.recv_bytes(MAX_SCANNER_RESULT_BYTES + 1)
                except OSError as exc:
                    return "error", f"scanner result exceeded size limit: {exc}"
                if len(payload) > MAX_SCANNER_RESULT_BYTES:
                    return "error", "scanner result exceeded serialized size limit"
                message = json.loads(payload)
                if not isinstance(message, dict):
                    return "error", "scanner worker returned an invalid envelope"
                message_state = message.get("state")
                if message_state not in {"ok", "partial"}:
                    return "error", str(message.get("error", "scanner worker failed"))
                raw_findings = message.get("findings")
                if not isinstance(raw_findings, list):
                    return "error", "scanner worker returned invalid findings"
                findings: list[Finding] = []
                for raw in raw_findings:
                    if not isinstance(raw, dict):
                        return "error", "scanner worker returned an invalid finding"
                    package = raw["package"]
                    if isinstance(package, dict):
                        package_value: PackageId | str = PackageId(**package)
                    elif isinstance(package, str):
                        package_value = package
                    else:
                        return "error", "scanner worker returned an invalid package identity"
                    findings.append(
                        Finding(
                            finding_type=FindingType(raw["finding_type"]),
                            severity=Severity(raw["severity"]),
                            package=package_value,
                            title=str(raw["title"]),
                            detail=str(raw["detail"]),
                            cve=raw.get("cve"),
                            cwe=raw.get("cwe"),
                            fix_version=raw.get("fix_version"),
                            references=list(raw.get("references", [])),
                            confidence=float(raw.get("confidence", 1.0)),
                            metadata=dict(raw.get("metadata", {})),
                        )
                    )
                if message_state == "partial":
                    return "partial", (findings, str(message.get("error", "incomplete scan")))
                return "ok", findings
            if not process.is_alive():
                if connection.poll():
                    continue
                return "error", f"scanner worker exited with code {process.exitcode}"
            await asyncio.sleep(min(0.01, max(0.001, timeout / 10)))
        return "timeout", f"TimeoutError: timed out after {timeout:.3f}s"
    finally:
        connection.close()
        _stop_worker(process)


def _project_scanner_is_applicable(
    spec: ShippedScannerSpec,
    scanner: object,
    scope: ScanScope,
) -> bool:
    """Determine applicability without creating a scanner process.

    Catalog paths cover scanners whose candidate inputs are known statically.
    A scanner may additionally expose a synchronous ``is_applicable(scope)``
    method for rules that require richer checks.  Applicability failures are
    coverage failures; they are never interpreted as a clean skip.
    """
    if spec.applicable_paths:
        for relative in spec.applicable_paths:
            candidate = scope.root / relative
            try:
                candidate.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ScanIncompleteError(
                    f"cannot inspect project scanner candidate {candidate}: {exc}"
                ) from exc
            else:
                scope.resolve(candidate)
                return True
        return False

    predicate = getattr(scanner, "is_applicable", None)
    if predicate is None:
        return True
    applicable = predicate(scope)
    if hasattr(applicable, "__await__"):
        raise TypeError("project scanner is_applicable() must be synchronous")
    if not isinstance(applicable, bool):
        raise TypeError(
            f"project scanner is_applicable() returned {type(applicable).__name__}, expected bool"
        )
    return applicable


def _safe_process_context() -> Any:
    """Return an import-based multiprocessing context, never ``fork``.

    Forking a multithreaded scanner process can inherit inconsistent locks and
    network-library state.  Spawn and forkserver both reconstruct the worker
    from importable code, which is the required authority boundary here.
    """
    methods = multiprocessing.get_all_start_methods()
    for method in ("forkserver", "spawn"):
        if method in methods:
            return multiprocessing.get_context(method)
    raise RuntimeError("no safe multiprocessing start method is available")


def _importable_scanner_target(spec: ShippedScannerSpec, scanner: object) -> str:
    """Prove that a scanner can be reconstructed in a clean interpreter."""
    try:
        module_name, attribute = spec.target.split(":", 1)
        if not module_name or not attribute or "." in attribute:
            raise ValueError("scanner target must identify one module-level attribute")
        module = importlib.import_module(module_name)
        scanner_type = getattr(module, attribute)
    except (ImportError, AttributeError, ValueError) as exc:
        raise RuntimeError("scanner target is not importable in an isolated worker") from exc
    if not isinstance(scanner_type, type) or type(scanner) is not scanner_type:
        raise RuntimeError("scanner instance does not match its importable catalog target")
    scan_project = getattr(scanner, "scan_project", None)
    if getattr(scan_project, "__module__", None) != module_name:
        raise RuntimeError("scanner method is patched or is not module-level importable code")
    if "<locals>" in getattr(scanner_type, "__qualname__", ""):
        raise RuntimeError("scanner class is local and cannot be reconstructed safely")
    return spec.target


async def run_shipped_project_scanners(
    registry: PluginRegistry,
    project_dir: Path,
    *,
    skip_advisory: bool = False,
    scanner_names: frozenset[str] | set[str] | None = None,
    max_workers: int = 4,
    deadline_seconds: float | None = None,
) -> list[ProjectScannerResult]:
    """Execute shipped project scanners within one bounded process budget."""

    if max_workers <= 0:
        raise ValueError("project scanner worker budget must be positive")

    specs = [
        spec for spec in SHIPPED_SCANNERS
        if spec.project
        and not (skip_advisory and spec.advisory)
        and (scanner_names is None or spec.name in scanner_names)
    ]
    if not specs:
        return []
    if deadline_seconds is None:
        deadline_seconds = max(spec.timeout_seconds for spec in specs)
    if deadline_seconds <= 0:
        raise ValueError("project scanner deadline must be positive")

    try:
        scope = ScanScope(project_dir)
    except (OSError, ScanIncompleteError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        return [
            ProjectScannerResult(spec.name, ScanState.INDETERMINATE, [], 0.0, error)
            for spec in specs
        ]

    semaphore = asyncio.Semaphore(min(max_workers, len(specs)))
    aggregate_deadline = time.monotonic() + deadline_seconds

    async def run_one(spec: ShippedScannerSpec) -> ProjectScannerResult:
        from depfence.core.fetcher import fetch_enabled

        if spec.requires_network and not fetch_enabled():
            return ProjectScannerResult(
                spec.name,
                ScanState.INDETERMINATE,
                [],
                0.0,
                "network-required scanner disabled by offline policy",
            )
        scanner = registry.scanners.get(spec.name)
        if scanner is None:
            # Minimal registries are commonly supplied by embedders to control
            # package scanners.  Shipped project execution remains catalog-
            # driven and does not disappear just because that registry omitted
            # the pre-instantiated object.
            try:
                scanner = cast(Scanner, spec.load())
            except Exception as exc:  # noqa: BLE001
                issue = next(
                    (
                        issue
                        for issue in getattr(registry, "issues", ())
                        if issue.name == spec.name
                    ),
                    None,
                )
                error = str(issue) if issue else f"{type(exc).__name__}: {exc}"
                return ProjectScannerResult(
                    spec.name, ScanState.INDETERMINATE, [], 0.0, error
                )
        if getattr(scanner, "scan_project", None) is None:
            return ProjectScannerResult(
                spec.name,
                ScanState.INDETERMINATE,
                [],
                0.0,
                "declared project scanner has no scan_project()",
            )
        started = time.monotonic()
        try:
            if not _project_scanner_is_applicable(spec, scanner, scope):
                return ProjectScannerResult(
                    spec.name,
                    ScanState.PASS,
                    [],
                    (time.monotonic() - started) * 1000.0,
                    evaluated=False,
                    skipped=True,
                )

            remaining = aggregate_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"aggregate project scanner deadline exceeded after {deadline_seconds:.3f}s"
                )
            try:
                await asyncio.wait_for(semaphore.acquire(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise TimeoutError(
                    f"aggregate project scanner deadline exceeded after {deadline_seconds:.3f}s"
                ) from exc
            process: multiprocessing.Process | None = None
            parent_connection: Any | None = None
            child_connection: Any | None = None
            try:
                remaining = aggregate_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"aggregate project scanner deadline exceeded after {deadline_seconds:.3f}s"
                    )
                try:
                    scanner_target = _importable_scanner_target(spec, scanner)
                    context = _safe_process_context()
                except RuntimeError as exc:
                    return ProjectScannerResult(
                        spec.name,
                        ScanState.UNPROVEN,
                        [],
                        (time.monotonic() - started) * 1000.0,
                        f"safe process isolation unavailable: {exc}",
                    )
                parent_connection, child_connection = context.Pipe(duplex=False)
                process = context.Process(  # type: ignore[attr-defined]
                    target=_project_scanner_worker,
                    args=(
                        child_connection,
                        scanner_target,
                        scope,
                        MAX_SCANNER_FINDINGS,
                        MAX_SCANNER_RESULT_BYTES,
                    ),
                )
                process.start()
                child_connection.close()
                child_connection = None
                # Receipt owns and closes both handles on every outcome. Clear
                # the outer cleanup references before awaiting so an exception
                # cannot stop an already-closed Process a second time.
                receiving_process = process
                receiving_connection = parent_connection
                process = None
                parent_connection = None
                state, value = await _receive_worker_result(
                    receiving_process,
                    receiving_connection,
                    min(spec.timeout_seconds, remaining),
                )
            finally:
                if child_connection is not None:
                    child_connection.close()
                if parent_connection is not None:
                    parent_connection.close()
                if process is not None:
                    _stop_worker(process)
                semaphore.release()
            if state == "partial":
                findings, error = cast(tuple[list[Finding], str], value)
                return ProjectScannerResult(
                    spec.name,
                    ScanState.UNPROVEN,
                    findings,
                    (time.monotonic() - started) * 1000.0,
                    error,
                )
            if state != "ok":
                raise RuntimeError(str(value))
            findings = cast(list[Finding], value)
            if not isinstance(findings, list):
                raise TypeError("scanner worker returned an invalid result")
            return ProjectScannerResult(
                spec.name,
                ScanState.PASS,
                findings,
                (time.monotonic() - started) * 1000.0,
            )
        except Exception as exc:  # noqa: BLE001
            # Exception messages can contain repository paths or snippets from
            # attacker-controlled inputs. Structured results retain the named
            # incomplete cause; routine logs expose only its type.
            log.warning("Project scanner '%s' failed (%s)", spec.name, type(exc).__name__)
            return ProjectScannerResult(
                spec.name,
                ScanState.INDETERMINATE,
                [],
                (time.monotonic() - started) * 1000.0,
                str(exc) if str(exc).startswith("TimeoutError:") else f"{type(exc).__name__}: {exc}",
            )
    return await asyncio.gather(*(run_one(spec) for spec in specs))


_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        _registry.discover()
    return _registry
