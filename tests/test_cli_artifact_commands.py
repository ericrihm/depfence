"""Smoke tests for the artifact/intake CLI command groups and their registration.

These tests only exercise Click's command wiring and ``--help`` output — the
underlying `inspect`/`doctor`/`resolve-sealed` behaviors require a container
engine and are covered elsewhere (test_visual_text_deception.py, sealed
intake tests, etc).
"""

from __future__ import annotations

import click
from click.testing import CliRunner

from depfence.cli.artifact_commands import artifact, register_artifact_commands
from depfence.cli.fleet_commands import intake, register_intake_commands
from depfence.cli.main import cli


def test_register_artifact_commands_adds_artifact_group() -> None:
    root = click.Group("root")
    register_artifact_commands(root)
    assert root.commands.get("artifact") is artifact


def test_register_fleet_commands_adds_intake_group() -> None:
    root = click.Group("root")
    register_intake_commands(root)
    assert root.commands.get("intake") is intake


def test_cli_exposes_artifact_group() -> None:
    assert isinstance(cli.commands.get("artifact"), click.Group)


def test_cli_exposes_intake_group() -> None:
    assert isinstance(cli.commands.get("intake"), click.Group)


def test_artifact_inspect_help() -> None:
    result = CliRunner().invoke(cli, ["artifact", "inspect", "--help"])
    assert result.exit_code == 0, result.output
    for option in (
        "--analysis",
        "--engine",
        "--image",
        "--runtime",
        "--certificate-identity",
        "--certificate-oidc-issuer",
        "--timeout",
        "--format",
        "--fail-on",
        "--state-root",
        "--retain-for",
        "--output",
    ):
        assert option in result.output


def test_artifact_doctor_help() -> None:
    result = CliRunner().invoke(cli, ["artifact", "doctor", "--help"])
    assert result.exit_code == 0, result.output
    for option in ("--engine", "--image", "--runtime", "--format"):
        assert option in result.output


def test_intake_inspect_sealed_help() -> None:
    result = CliRunner().invoke(cli, ["intake", "inspect-sealed", "--help"])
    assert result.exit_code == 0, result.output
    for option in (
        "--commit",
        "--approved-commit",
        "--image",
        "--analyzer-image",
        "--allow-host",
        "--acquisition-network",
        "--https-proxy",
        "--certificate-identity",
        "--certificate-oidc-issuer",
        "--engine",
        "--runtime",
        "--timeout",
        "--file-budget",
        "--byte-budget",
        "--state-root",
        "--output",
    ):
        assert option in result.output


def test_intake_resolve_sealed_help() -> None:
    result = CliRunner().invoke(cli, ["intake", "resolve-sealed", "--help"])
    assert result.exit_code == 0, result.output
    for option in (
        "--image",
        "--allow-host",
        "--acquisition-network",
        "--https-proxy",
        "--certificate-identity",
        "--certificate-oidc-issuer",
        "--engine",
        "--runtime",
        "--timeout",
        "--state-root",
        "--output",
    ):
        assert option in result.output


def test_intake_doctor_help() -> None:
    result = CliRunner().invoke(cli, ["intake", "doctor", "--help"])
    assert result.exit_code == 0, result.output
    for option in (
        "--engine",
        "--intake-image",
        "--analyzer-image",
        "--runtime",
        "--acquisition-network",
        "--https-proxy",
    ):
        assert option in result.output
