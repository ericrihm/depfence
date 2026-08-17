"""Fleet, quarantine-intake, and redacted-evidence CLI surfaces."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import click

from depfence.cli.artifact_commands import _run_doctor_probe
from depfence.core.fleet import audit_fleet, inventory_fleet
from depfence.core.intake import approve_intake, inspect_source
from depfence.core.local_state import PrivateState, PrivateStateError
from depfence.core.models import ScanState
from depfence.core.scan_scope import ScanIncompleteError
from depfence.core.sealed_intake import (
    SealedIntakeConfig,
    SealedResolutionConfig,
    inspect_source_sealed,
    resolve_source_sealed,
)
from depfence.core.triage import (
    append_triage,
    finding_evidence,
    review_triage,
    triage_plan,
    triage_queue,
)
from depfence.schemas import validate_document


def _emit(document: dict[str, object], output: str | None) -> None:
    validate_document(document)
    rendered = json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if output:
        requested = Path(output).expanduser()
        parent = requested.parent.resolve(strict=True)
        destination = parent / requested.name
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=parent,
        )
        temporary_path = Path(temporary)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), stat.S_IRUSR | stat.S_IWUSR)
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, destination)
            os.chmod(destination, 0o600)
        except BaseException:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise
    else:
        click.echo(rendered, nl=False)


def _exit_for_status(status: object) -> None:
    if status in {ScanState.INDETERMINATE.value, ScanState.UNPROVEN.value}:
        raise click.exceptions.Exit(2)
    if status == ScanState.FAIL.value:
        raise click.exceptions.Exit(1)


@click.group("fleet")
def fleet() -> None:
    """Inventory or audit independent Git worktrees without executing them."""


@fleet.command("inventory")
@click.argument("root", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def fleet_inventory(root: str, output: str | None) -> None:
    """Create a privacy-preserving repository-fleet inventory."""

    document = inventory_fleet(Path(root)).to_dict()
    _emit(document, output)
    _exit_for_status(document["status"])


@fleet.command("audit")
@click.argument("root", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--workers", "-j", default=4, show_default=True, type=click.IntRange(1, 64))
@click.option("--project-deadline", default=300.0, show_default=True, type=click.FloatRange(min=0.1))
@click.option(
    "--fleet-deadline",
    default=1800.0,
    show_default=True,
    type=click.FloatRange(min=0.1),
    help="Maximum wall-clock seconds for the entire audit.",
)
@click.option("--online/--offline", default=False, help="Enable registry/advisory network access.")
@click.option(
    "--resume",
    is_flag=True,
    help="Resume the latest validated private checkpoint and skip completed projects.",
)
@click.option(
    "--project-id",
    "project_ids",
    multiple=True,
    help="Audit only an opaque project ID from fleet inventory (repeatable).",
)
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def fleet_audit(
    root: str,
    workers: int,
    project_deadline: float,
    fleet_deadline: float,
    online: bool,
    resume: bool,
    project_ids: tuple[str, ...],
    output: str | None,
) -> None:
    """Scan every worktree independently under one global budget."""

    document = asyncio.run(
        audit_fleet(
            Path(root),
            workers=workers,
            project_deadline=project_deadline,
            fleet_deadline=fleet_deadline,
            online=online,
            resume=resume,
            project_ids=frozenset(project_ids) if project_ids else None,
        )
    ).to_dict()
    _emit(document, output)
    _exit_for_status(document["status"])


def _fleet_state(root: str, state_root: Path | None, *, apply: bool) -> PrivateState:
    project = Path(root).expanduser().resolve(strict=True)
    requested = (state_root or (Path.home() / ".depfence" / "private" / "v1")).expanduser()
    if apply:
        try:
            return PrivateState.open(project_root=project, root=requested)
        except (OSError, PrivateStateError):
            raise click.ClickException("private state is unavailable") from None
    if not requested.exists():
        raise click.ClickException("private state is unavailable; dry-run made no changes")
    # PrivateState.path() still enforces containment and rejects symlink
    # components. Avoid PrivateState.open() in read-only/dry-run mode because
    # open intentionally creates and chmods the private root.
    return PrivateState(requested.absolute())


@fleet.command("evidence")
@click.argument("finding_id")
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option("--show-snippet", is_flag=True, help="Include the bounded redacted snippet.")
def fleet_evidence_command(
    finding_id: str, state_root: Path | None, show_snippet: bool
) -> None:
    """Look up private evidence for one opaque finding ID."""

    try:
        document = finding_evidence(
            _fleet_state(".", state_root, apply=False),
            finding_id,
            show_snippet=show_snippet,
        )
    except (OSError, PrivateStateError, ValueError):
        raise click.ClickException("private fleet evidence is unavailable") from None
    _emit(document, None)
    _exit_for_status(document["status"])


@fleet.command("triage")
@click.argument("root", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
)
@click.option("--rule", help="Limit the queue to one rule when checkpoint detail supports it.")
def fleet_triage_command(
    root: str,
    state_root: Path | None,
    severity: str | None,
    rule: str | None,
) -> None:
    """Build a redacted finding queue from private fleet evidence."""

    try:
        document = triage_queue(
            _fleet_state(root, state_root, apply=False), severity=severity, rule=rule
        )
    except (OSError, PrivateStateError, ValueError):
        raise click.ClickException("private triage queue is unavailable") from None
    _emit(document, None)
    _exit_for_status(document["status"])


@fleet.command("review")
@click.argument("finding_id")
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--decision",
    required=True,
    type=click.Choice(
        ["unreviewed", "confirmed", "likely", "false_positive", "accepted_risk", "needs_context"]
    ),
)
@click.option("--reason", default="operator review", show_default=True)
@click.option("--apply", is_flag=True, help="Append the review (default: dry-run).")
def fleet_review_command(
    finding_id: str,
    state_root: Path | None,
    decision: str,
    reason: str,
    apply: bool,
) -> None:
    """Plan or append a decision for one finding."""

    try:
        read_state = _fleet_state(".", state_root, apply=False)
        evidence = finding_evidence(read_state, finding_id)
        if evidence["status"] != "PASS":
            _emit(evidence, None)
            _exit_for_status(evidence["status"])
            return
        project_id = str(evidence["project_id"])
        evidence_id = str(evidence["evidence_id"])
        if apply:
            document = append_triage(
                _fleet_state(".", state_root, apply=True),
                project_id=project_id,
                finding_id=finding_id,
                decision=decision,
                reason=reason,
                evidence_ids=(evidence_id,),
            )
        else:
            document = triage_plan(
                project_id=project_id,
                finding_id=finding_id,
                decision=decision,
                reason=reason,
                evidence_ids=(evidence_id,),
            )
    except (OSError, PrivateStateError, ValueError):
        raise click.ClickException("private finding review was refused") from None
    _emit(document, None)


@fleet.command("journal")
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
def fleet_journal_command(state_root: Path | None) -> None:
    """Verify and summarize the append-only private triage journal."""

    document = review_triage(_fleet_state(".", state_root, apply=False))
    _emit(document, None)
    _exit_for_status(document["status"])


@click.group("intake")
def intake() -> None:
    """Inspect repository sources in a private no-checkout quarantine."""


@intake.command("doctor")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("--intake-image", required=True, help="Digest-pinned acquisition image.")
@click.option("--analyzer-image", required=True, help="Digest-pinned static analyzer image.")
@click.option("--runtime", required=True, type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--acquisition-network", required=True, help="Pre-created internal OCI network.")
@click.option("--https-proxy", required=True, help="Credential-free proxy URL on that network.")
def intake_doctor(
    engine: str,
    intake_image: str,
    analyzer_image: str,
    runtime: str,
    acquisition_network: str,
    https_proxy: str,
) -> None:
    """Verify sealed-intake containment prerequisites without fetching a source."""

    engine_path = shutil.which(engine)
    digest_pattern = re.compile(r"[^\s]+@sha256:[0-9a-fA-F]{64}")
    proxy = urlparse(https_proxy)
    checks: dict[str, bool] = {
        "native_linux": platform.system() == "Linux",
        "engine_available": engine_path is not None,
        "intake_image_available": False,
        "analyzer_image_available": False,
        "runtime_configured": False,
        "acquisition_network_internal": False,
        "proxy_configuration_valid": bool(
            proxy.scheme in {"http", "https"}
            and proxy.hostname
            and not proxy.username
            and not proxy.password
        ),
        "images_digest_pinned": bool(
            digest_pattern.fullmatch(intake_image)
            and digest_pattern.fullmatch(analyzer_image)
        ),
    }
    if engine_path:
        for key, image in (
            ("intake_image_available", intake_image),
            ("analyzer_image_available", analyzer_image),
        ):
            ok, digests = _run_doctor_probe(
                [engine_path, "image", "inspect", image, "--format", "{{json .RepoDigests}}"]
            )
            checks[key] = bool(ok and isinstance(digests, list) and image in digests)
        if engine == "docker":
            ok, runtimes = _run_doctor_probe(
                [engine_path, "info", "--format", "{{json .Runtimes}}"]
            )
            checks["runtime_configured"] = bool(
                ok and isinstance(runtimes, dict) and runtime in runtimes
            )
            ok, internal = _run_doctor_probe([
                engine_path,
                "network",
                "inspect",
                acquisition_network,
                "--format",
                "{{json .Internal}}",
            ])
            checks["acquisition_network_internal"] = bool(ok and internal is True)
        else:
            ok, info = _run_doctor_probe([engine_path, "info", "--format", "json"])
            if ok and isinstance(info, dict):
                host_info = info.get("host") or info.get("Host")
                if isinstance(host_info, dict):
                    oci = host_info.get("ociRuntime") or host_info.get("OCIRuntime")
                    checks["runtime_configured"] = bool(
                        isinstance(oci, dict) and oci.get("name") == runtime
                    )
            ok, network = _run_doctor_probe(
                [engine_path, "network", "inspect", acquisition_network]
            )
            checks["acquisition_network_internal"] = bool(
                ok
                and isinstance(network, list)
                and network
                and isinstance(network[0], dict)
                and network[0].get("internal") is True
            )
    limitation_codes = [
        name.upper() for name, passed in checks.items() if not passed
    ]
    document: dict[str, object] = {
        "schema_version": "depfence.intake-doctor/v1",
        "status": "PASS" if all(checks.values()) else "UNPROVEN",
        "engine": engine,
        "runtime": runtime,
        "intake_image": intake_image,
        "analyzer_image": analyzer_image,
        "acquisition_network": acquisition_network,
        "proxy_host": proxy.hostname or "",
        "checks": checks,
        "limitation_codes": limitation_codes,
    }
    _emit(document, None)
    _exit_for_status(document["status"])


@intake.command("inspect")
@click.argument("source")
@click.option("--timeout", default=120.0, show_default=True, type=click.FloatRange(min=1.0))
@click.option("--file-budget", default=100_000, show_default=True, type=click.IntRange(min=1))
@click.option("--byte-budget", default=512 * 1024 * 1024, show_default=True, type=click.IntRange(min=1))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def intake_inspect(
    source: str,
    timeout: float,
    file_budget: int,
    byte_budget: int,
    output: str | None,
) -> None:
    """Clone and inspect SOURCE without checkout, hooks, or lifecycle scripts."""

    state = PrivateState.open(project_root=Path.cwd())
    result = inspect_source(
        source,
        state=state,
        timeout=timeout,
        file_budget=file_budget,
        byte_budget=byte_budget,
    )
    document = result.to_dict()
    _emit(document, output)
    _exit_for_status(document["status"])


@intake.command("inspect-sealed")
@click.argument("source")
@click.option("--commit", required=True, help="Exact 40- or 64-hex Git commit.")
@click.option("--image", required=True, help="Preloaded intake image pinned by @sha256 digest.")
@click.option("--analyzer-image", required=True, help="Preloaded static analyzer image pinned by @sha256 digest.")
@click.option("--allow-host", "allowed_hosts", multiple=True, required=True, help="Exact HTTPS host allowed for acquisition.")
@click.option("--acquisition-network", required=True, help="Pre-created internal OCI network shared only with the allowlisting proxy.")
@click.option("--https-proxy", required=True, help="Credential-free proxy URL reachable on the acquisition network.")
@click.option("--certificate-identity", required=True, help="Exact Sigstore identity authorized to sign both worker images.")
@click.option("--certificate-oidc-issuer", default="https://token.actions.githubusercontent.com", show_default=True)
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("--runtime", type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--timeout", default=180.0, show_default=True, type=click.FloatRange(min=1.0, max=1800.0))
@click.option("--file-budget", default=100_000, show_default=True, type=click.IntRange(min=1))
@click.option("--byte-budget", default=512 * 1024 * 1024, show_default=True, type=click.IntRange(min=1))
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def intake_inspect_sealed(
    source: str,
    commit: str,
    image: str,
    analyzer_image: str,
    allowed_hosts: tuple[str, ...],
    acquisition_network: str,
    https_proxy: str,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    engine: str,
    runtime: str | None,
    timeout: float,
    file_budget: int,
    byte_budget: int,
    state_root: Path | None,
    output: str | None,
) -> None:
    """Inventory an exact remote commit without host file materialization."""

    try:
        state = PrivateState.open(project_root=Path.cwd(), root=state_root)
        document = inspect_source_sealed(
            source,
            commit,
            state=state,
            config=SealedIntakeConfig(
                engine=engine,
                image=image,
                analyzer_image=analyzer_image,
                allowed_hosts=frozenset(allowed_hosts),
                acquisition_network=acquisition_network,
                https_proxy=https_proxy,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
                runtime=runtime,
                timeout_seconds=timeout,
            ),
            file_budget=file_budget,
            byte_budget=byte_budget,
        )
    except (OSError, PrivateStateError, ScanIncompleteError, ValueError):
        raise click.ClickException("sealed repository intake was refused") from None
    _emit(document, output)
    _exit_for_status(document["status"])


@intake.command("resolve-sealed")
@click.argument("source")
@click.option("--image", required=True, help="Preloaded intake image pinned by @sha256 digest.")
@click.option("--allow-host", "allowed_hosts", multiple=True, required=True, help="Exact HTTPS host allowed for metadata resolution.")
@click.option("--acquisition-network", required=True, help="Pre-created internal OCI network shared only with the allowlisting proxy.")
@click.option("--https-proxy", required=True, help="Credential-free proxy URL reachable on the acquisition network.")
@click.option("--certificate-identity", required=True, help="Exact Sigstore identity authorized to sign the intake image.")
@click.option("--certificate-oidc-issuer", default="https://token.actions.githubusercontent.com", show_default=True)
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("--runtime", required=True, type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--timeout", default=90.0, show_default=True, type=click.FloatRange(min=1.0, max=300.0))
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def intake_resolve_sealed(
    source: str,
    image: str,
    allowed_hosts: tuple[str, ...],
    acquisition_network: str,
    https_proxy: str,
    certificate_identity: str,
    certificate_oidc_issuer: str,
    engine: str,
    runtime: str,
    timeout: float,
    state_root: Path | None,
    output: str | None,
) -> None:
    """Resolve remote HEAD metadata without fetching repository objects."""

    try:
        state = PrivateState.open(project_root=Path.cwd(), root=state_root)
        document = resolve_source_sealed(
            source,
            state=state,
            config=SealedResolutionConfig(
                engine=engine,
                image=image,
                allowed_hosts=frozenset(allowed_hosts),
                acquisition_network=acquisition_network,
                https_proxy=https_proxy,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
                runtime=runtime,
                timeout_seconds=timeout,
            ),
        )
    except (OSError, PrivateStateError, ScanIncompleteError, ValueError):
        raise click.ClickException("sealed repository resolution was refused") from None
    _emit(document, output)
    _exit_for_status(document["status"])


@intake.command("approve")
@click.argument("intake_id")
@click.option("--reason", required=True, help="Bounded operator justification.")
@click.option("--approved-by", default=lambda: os.environ.get("USER", "operator"), show_default="current user")
@click.option("--yes", is_flag=True, help="Confirm the approval record. Does not promote files.")
def intake_approve(intake_id: str, reason: str, approved_by: str, yes: bool) -> None:
    """Record approval for a complete intake; never promote automatically."""

    if not yes:
        raise click.UsageError("intake approval requires --yes")
    state = PrivateState.open(project_root=Path.cwd())
    approve_intake(
        intake_id,
        state=state,
        approved_by=approved_by,
        reason=reason,
    )
    click.echo(json.dumps({"intake_id": intake_id, "approved": True, "promoted": False}))


def register_fleet_commands(root: click.Group) -> None:
    root.add_command(fleet)
    root.add_command(intake)


__all__ = ["fleet", "intake", "register_fleet_commands"]
