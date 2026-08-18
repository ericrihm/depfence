"""Focused exact-commit sealed-intake CLI commands."""

from __future__ import annotations

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
from depfence.core.local_state import PrivateState, PrivateStateError
from depfence.core.models import ScanState
from depfence.core.scan_scope import ScanIncompleteError
from depfence.core.sealed_intake import (
    SealedIntakeConfig,
    SealedResolutionConfig,
    inspect_source_sealed,
    resolve_source_sealed,
)
from depfence.schemas import validate_document


def _emit(document: dict[str, object], output: str | None) -> None:
    validate_document(document)
    rendered = json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if not output:
        click.echo(rendered, nl=False)
        return
    destination = Path(output).expanduser().resolve(strict=False)
    parent = destination.parent.resolve(strict=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
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
        temporary_path.unlink(missing_ok=True)
        raise


def _exit_for_status(status: object) -> None:
    if status in {ScanState.INDETERMINATE.value, ScanState.UNPROVEN.value}:
        raise click.exceptions.Exit(2)
    if status == ScanState.FAIL.value:
        raise click.exceptions.Exit(1)


@click.group("intake")
def intake() -> None:
    """Resolve and inspect exact commits in sealed workers."""


@intake.command("doctor")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker")
@click.option("--intake-image", required=True)
@click.option("--analyzer-image", required=True)
@click.option("--runtime", required=True, type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--acquisition-network", required=True)
@click.option("--https-proxy", required=True)
def intake_doctor(engine: str, intake_image: str, analyzer_image: str, runtime: str,
                  acquisition_network: str, https_proxy: str) -> None:
    """Verify immutable images, an isolated network, and hardened runtime."""
    executable = shutil.which(engine)
    digest = re.compile(r"[^\s]+@sha256:[0-9a-fA-F]{64}")
    proxy = urlparse(https_proxy)
    checks = {
        "native_linux": platform.system() == "Linux",
        "engine_available": executable is not None,
        "intake_image_available": False,
        "analyzer_image_available": False,
        "runtime_configured": False,
        "acquisition_network_internal": False,
        "proxy_configuration_valid": bool(proxy.scheme in {"http", "https"} and proxy.hostname and not proxy.username and not proxy.password),
        "images_digest_pinned": bool(digest.fullmatch(intake_image) and digest.fullmatch(analyzer_image)),
    }
    if executable:
        for key, image in (("intake_image_available", intake_image), ("analyzer_image_available", analyzer_image)):
            ok, values = _run_doctor_probe([executable, "image", "inspect", image, "--format", "{{json .RepoDigests}}"])
            checks[key] = bool(ok and isinstance(values, list) and image in values)
        ok, runtimes = _run_doctor_probe([executable, "info", "--format", "{{json .Runtimes}}"])
        checks["runtime_configured"] = bool(ok and isinstance(runtimes, dict) and runtime in runtimes)
        ok, internal = _run_doctor_probe([executable, "network", "inspect", acquisition_network, "--format", "{{json .Internal}}"])
        checks["acquisition_network_internal"] = bool(ok and internal is True)
    document: dict[str, object] = {
        "schema_version": "depfence.intake-doctor/v1",
        "status": "PASS" if all(checks.values()) else "UNPROVEN",
        "engine": engine, "runtime": runtime, "intake_image": intake_image,
        "analyzer_image": analyzer_image, "acquisition_network": acquisition_network,
        "proxy_host": proxy.hostname or "", "checks": checks,
        "limitation_codes": [name.upper() for name, value in checks.items() if not value],
    }
    _emit(document, None)
    _exit_for_status(document["status"])


def _intake_config(engine: str, image: str, analyzer_image: str, allowed_hosts: tuple[str, ...],
                   acquisition_network: str, https_proxy: str, certificate_identity: str,
                   certificate_oidc_issuer: str, runtime: str | None, timeout: float) -> SealedIntakeConfig:
    return SealedIntakeConfig(engine=engine, image=image, analyzer_image=analyzer_image,
        allowed_hosts=frozenset(allowed_hosts), acquisition_network=acquisition_network,
        https_proxy=https_proxy, certificate_identity=certificate_identity,
        certificate_oidc_issuer=certificate_oidc_issuer, runtime=runtime, timeout_seconds=timeout)


@intake.command("inspect-sealed")
@click.argument("source")
@click.option("--commit", required=True)
@click.option("--approved-commit", required=True, help="Repeat the exact resolved commit to record explicit approval.")
@click.option("--image", required=True)
@click.option("--analyzer-image", required=True)
@click.option("--allow-host", "allowed_hosts", multiple=True, required=True)
@click.option("--acquisition-network", required=True)
@click.option("--https-proxy", required=True)
@click.option("--certificate-identity", required=True)
@click.option("--certificate-oidc-issuer", default="https://token.actions.githubusercontent.com")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker")
@click.option("--runtime", type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--timeout", default=180.0, type=click.FloatRange(min=1.0, max=1800.0))
@click.option("--file-budget", default=100_000, type=click.IntRange(min=1))
@click.option("--byte-budget", default=512 * 1024 * 1024, type=click.IntRange(min=1))
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def intake_inspect_sealed(source: str, commit: str, approved_commit: str, image: str, analyzer_image: str,
        allowed_hosts: tuple[str, ...], acquisition_network: str, https_proxy: str,
        certificate_identity: str, certificate_oidc_issuer: str, engine: str,
        runtime: str | None, timeout: float, file_budget: int, byte_budget: int,
        state_root: Path | None, output: str | None) -> None:
    try:
        state = PrivateState.open(project_root=Path.cwd(), root=state_root)
        document = inspect_source_sealed(source, commit, approved_commit=approved_commit, state=state,
            config=_intake_config(engine, image, analyzer_image, allowed_hosts,
                acquisition_network, https_proxy, certificate_identity,
                certificate_oidc_issuer, runtime, timeout),
            file_budget=file_budget, byte_budget=byte_budget)
    except (OSError, PrivateStateError, ScanIncompleteError, ValueError):
        raise click.ClickException("sealed repository intake was refused") from None
    _emit(document, output)
    _exit_for_status(document["status"])


@intake.command("resolve-sealed")
@click.argument("source")
@click.option("--image", required=True)
@click.option("--allow-host", "allowed_hosts", multiple=True, required=True)
@click.option("--acquisition-network", required=True)
@click.option("--https-proxy", required=True)
@click.option("--certificate-identity", required=True)
@click.option("--certificate-oidc-issuer", default="https://token.actions.githubusercontent.com")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker")
@click.option("--runtime", required=True, type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option("--timeout", default=90.0, type=click.FloatRange(min=1.0, max=300.0))
@click.option("--state-root", type=click.Path(path_type=Path, file_okay=False))
@click.option("--output", "-o", type=click.Path(dir_okay=False))
def intake_resolve_sealed(source: str, image: str, allowed_hosts: tuple[str, ...],
        acquisition_network: str, https_proxy: str, certificate_identity: str,
        certificate_oidc_issuer: str, engine: str, runtime: str, timeout: float,
        state_root: Path | None, output: str | None) -> None:
    try:
        state = PrivateState.open(project_root=Path.cwd(), root=state_root)
        document = resolve_source_sealed(source, state=state, config=SealedResolutionConfig(
            engine=engine, image=image, allowed_hosts=frozenset(allowed_hosts),
            acquisition_network=acquisition_network, https_proxy=https_proxy,
            certificate_identity=certificate_identity,
            certificate_oidc_issuer=certificate_oidc_issuer, runtime=runtime,
            timeout_seconds=timeout))
    except (OSError, PrivateStateError, ScanIncompleteError, ValueError):
        raise click.ClickException("sealed repository resolution was refused") from None
    _emit(document, output)
    _exit_for_status(document["status"])


def register_intake_commands(root: click.Group) -> None:
    root.add_command(intake)


__all__ = ["intake", "register_intake_commands"]
