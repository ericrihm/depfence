"""Focused quarantine and inspection commands for hostile document artifacts."""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import click
from jsonschema import ValidationError

from depfence.core.artifact_analysis import (
    SandboxConfig,
    inspect_artifact,
    verify_image_signature,
)
from depfence.core.local_state import PrivateState, PrivateStateError
from depfence.core.models import ScanState, Severity
from depfence.core.scan_scope import ScanIncompleteError
from depfence.reporters.json_out import JsonReporter


@click.group("artifact")
def artifact() -> None:
    """Quarantine and inspect untrusted fonts and documents."""


def _run_doctor_probe(command: list[str]) -> tuple[bool, object | None]:
    """Run one read-only engine probe and return bounded, parsed JSON."""
    try:
        completed = subprocess.run(  # noqa: S603 - executable is resolved by shutil.which
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
        return False, None
    try:
        return True, json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, None


def _artifact_doctor_document(
    *, engine: str, image: str, runtime: str
) -> dict[str, object]:
    native_linux = platform.system() == "Linux"
    engine_path = shutil.which(engine)
    engine_available = engine_path is not None
    image_available = False
    image_contract = False
    runtime_configured = False
    self_test = False
    limitation_codes: list[str] = []

    try:
        SandboxConfig(engine, image, runtime).validate()
    except ValueError:
        limitation_codes.append("SANDBOX_CONFIGURATION_INVALID")

    if not native_linux:
        limitation_codes.append("NATIVE_LINUX_REQUIRED")
    if not engine_available:
        limitation_codes.append("ENGINE_UNAVAILABLE")
    else:
        assert engine_path is not None
        image_available, inspected = _run_doctor_probe(
            [engine_path, "image", "inspect", image]
        )
        if not image_available:
            limitation_codes.append("IMAGE_UNAVAILABLE")
        elif isinstance(inspected, list) and len(inspected) == 1 and isinstance(inspected[0], dict):
            descriptor = inspected[0]
            config = descriptor.get("Config") or descriptor.get("config")
            repo_digests = descriptor.get("RepoDigests") or descriptor.get("repoDigests")
            requested_digest = image.rsplit("@", 1)[-1]
            if isinstance(config, dict):
                labels = config.get("Labels") or config.get("labels")
                entrypoint = config.get("Entrypoint") or config.get("entrypoint")
                user = config.get("User") or config.get("user")
                image_contract = bool(
                    isinstance(repo_digests, list)
                    and any(
                        isinstance(value, str) and value.endswith("@" + requested_digest)
                        for value in repo_digests
                    )
                    and user == "65532:65532"
                    and entrypoint == ["/usr/local/bin/depfence-worker-entrypoint"]
                    and isinstance(labels, dict)
                    and labels.get("dev.depfence.worker.protocol") == "1"
                    and labels.get("dev.depfence.worker.role") == "render"
                    and "depfence-artifact-analyzer"
                    in str(labels.get("dev.depfence.worker.commands", "")).split(",")
                )
            if not image_contract:
                limitation_codes.append("IMAGE_CONTRACT_INVALID")
        elif image_available:
            limitation_codes.append("IMAGE_CONTRACT_INVALID")

        if engine == "docker":
            ok, runtimes = _run_doctor_probe(
                [engine_path, "info", "--format", "{{json .Runtimes}}"]
            )
            runtime_configured = bool(
                ok and isinstance(runtimes, dict) and runtime in runtimes
            )
        else:
            ok, info = _run_doctor_probe([engine_path, "info", "--format", "json"])
            if ok and isinstance(info, dict):
                host = info.get("host") or info.get("Host")
                if isinstance(host, dict):
                    oci = host.get("ociRuntime") or host.get("OCIRuntime")
                    if isinstance(oci, dict):
                        runtime_configured = oci.get("name") == runtime
        if not runtime_configured:
            limitation_codes.append("RUNTIME_UNVERIFIED")

        if image_contract and runtime_configured:
            self_test, response = _run_doctor_probe(
                [
                    engine_path,
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    "none",
                    "--read-only",
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "32",
                    "--memory",
                    "128m",
                    "--cpus",
                    "0.5",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=33554432",  # noqa: S108 - container tmpfs
                    "--runtime",
                    runtime,
                    image,
                    "--self-test",
                ]
            )
            self_test = bool(
                self_test
                and isinstance(response, dict)
                and response.get("protocol") == 1
                and response.get("role") == "render"
                and response.get("uid") == 65532
            )
        if not self_test:
            limitation_codes.append("WORKER_SELF_TEST_FAILED")

    checks = {
        "native_linux": native_linux,
        "engine_available": engine_available,
        "image_available": image_available,
        "image_contract": image_contract,
        "runtime_configured": runtime_configured,
        "self_test": self_test,
    }
    return {
        "schema_version": "depfence.artifact-doctor/v1",
        "status": "PASS" if all(checks.values()) and not limitation_codes else "UNPROVEN",
        "engine": engine,
        "image": image,
        "runtime": runtime,
        "checks": checks,
        "limitation_codes": sorted(set(limitation_codes)),
    }


@artifact.command("doctor")
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("--image", required=True, help="Analyzer image pinned as NAME@sha256:DIGEST.")
@click.option(
    "--runtime",
    required=True,
    type=click.Choice(["runsc", "kata", "kata-runtime"]),
)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def artifact_doctor(engine: str, image: str, runtime: str, fmt: str) -> None:
    """Verify the local runtime prerequisites without processing an artifact."""
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image):
        raise click.UsageError("--image must be pinned as NAME@sha256:DIGEST")
    document = _artifact_doctor_document(engine=engine, image=image, runtime=runtime)
    from depfence.schemas import validate_document

    validate_document(document)
    if fmt == "json":
        click.echo(json.dumps(document, sort_keys=True, indent=2, allow_nan=False))
    else:
        click.echo(f"Artifact sandbox readiness: {document['status']}")
        checks = document["checks"]
        assert isinstance(checks, dict)
        for name, passed in checks.items():
            click.echo(f"  {name}: {'PASS' if passed else 'UNPROVEN'}")
        for code in cast(list[str], document["limitation_codes"]):
            click.echo(f"  limitation: {code}")
    if document["status"] != "PASS":
        raise click.exceptions.Exit(2)


@artifact.command("inspect")
@click.argument(
    "path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--analysis",
    type=click.Choice(["static", "sandboxed"]),
    default="static",
    show_default=True,
    help="Static never renders. Sandboxed requires an immutable OCI image.",
)
@click.option("--engine", type=click.Choice(["docker", "podman"]), default="docker", show_default=True)
@click.option("--image", help="Analyzer image pinned as NAME@sha256:DIGEST.")
@click.option("--runtime", type=click.Choice(["runsc", "kata", "kata-runtime"]))
@click.option(
    "--certificate-identity",
    help="Exact Sigstore certificate identity authorized to sign the analyzer image.",
)
@click.option(
    "--certificate-oidc-issuer",
    default="https://token.actions.githubusercontent.com",
    show_default=True,
)
@click.option("--timeout", default=120.0, show_default=True, type=click.FloatRange(min=0.1, max=900.0))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "any", "none"]),
    default="high",
    show_default=True,
)
@click.option("--state-root", type=click.Path(file_okay=False, path_type=Path))
@click.option(
    "--retain-for",
    type=click.IntRange(1, 30),
    help="Retain raw bytes in private state for 1-30 days (default: delete immediately).",
)
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path))
def artifact_inspect(
    path: Path,
    analysis: str,
    engine: str,
    image: str | None,
    runtime: str | None,
    certificate_identity: str | None,
    certificate_oidc_issuer: str,
    timeout: float,
    fmt: str,
    fail_on: str,
    state_root: Path | None,
    retain_for: int | None,
    output: Path | None,
) -> None:
    """Inspect PATH without opening, previewing, or registering its fonts."""

    sandbox = None
    if analysis == "sandboxed":
        if not image:
            raise click.UsageError("--analysis sandboxed requires --image NAME@sha256:DIGEST")
        sandbox = SandboxConfig(engine, image, runtime, timeout)
        try:
            sandbox.validate()
            if not certificate_identity:
                raise click.UsageError(
                    "--analysis sandboxed requires --certificate-identity for Sigstore verification"
                )
            verify_image_signature(image, certificate_identity, certificate_oidc_issuer)
        except click.UsageError:
            raise
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        except ScanIncompleteError as exc:
            raise click.ClickException(f"artifact inspection refused: {exc}") from None

    try:
        state = PrivateState.open(project_root=Path.cwd(), root=state_root)
        result = inspect_artifact(
            path,
            state=state,
            analysis_mode=analysis,
            sandbox=sandbox,
            retain_payload=retain_for is not None,
        )
    except (OSError, PrivateStateError, ScanIncompleteError, ValueError) as exc:
        raise click.ClickException(f"artifact inspection refused: {exc}") from None

    storage_id = result.target.split(":", 1)[-1]
    record_path = Path("artifacts") / storage_id / "record.json"
    try:
        record = json.loads(state.path(record_path).read_text(encoding="utf-8"))
        record["secure_erasure"] = False
        if retain_for is not None:
            record["retention_days"] = retain_for
            record["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(days=retain_for)
            ).isoformat()
        state.write_text(
            record_path,
            json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n",
        )
        from depfence.schemas import validate_document

        validate_document(record)
    except (
        OSError,
        PrivateStateError,
        ValidationError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        result.errors.append("artifact retention record could not be finalized")
        result.scanner_coverage["artifact_retention"] = ScanState.INDETERMINATE
        result.scanner_errors["artifact_retention"] = type(exc).__name__

    if fmt == "json":
        rendered = JsonReporter().render(result) + "\n"
    elif fmt == "sarif":
        from depfence import __version__
        from depfence.reporters.sarif import render_sarif

        rendered = render_sarif(result, tool_name="depfence", tool_version=__version__)
    else:
        from depfence.core.engine import render_result

        rendered = render_result(result, "table")

    if output:
        output.write_text(rendered, encoding="utf-8")
        click.echo(f"Artifact report written to {output}")
    else:
        click.echo(rendered, nl=not rendered.endswith("\n"))

    incomplete = bool(result.errors) or any(
        state in {ScanState.INDETERMINATE, ScanState.UNPROVEN}
        for state in result.scanner_coverage.values()
    )
    if incomplete:
        raise click.exceptions.Exit(2)
    if _fails_threshold(result.findings, fail_on):
        raise click.exceptions.Exit(1)


def _fails_threshold(findings: Sequence[object], threshold: str) -> bool:
    if threshold == "none":
        return False
    if threshold == "any":
        return bool(findings)
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    limit = order[threshold]
    return any(
        order.get(getattr(getattr(finding, "severity", None), "value", Severity.INFO.value), 4)
        <= limit
        for finding in findings
    )


def register_artifact_commands(root: click.Group) -> None:
    root.add_command(artifact)


__all__ = ["artifact", "register_artifact_commands"]

