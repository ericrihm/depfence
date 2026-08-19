from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from depfence.cli.main import cli
from depfence.core.local_state import PrivateState
from depfence.core.scan_scope import ScanIncompleteError
from depfence.core.sealed_intake import (
    SealedIntakeConfig,
    SealedResolutionConfig,
    _strict_json_object,
    inspect_source_sealed,
    resolve_source_sealed,
)
from depfence.schemas import validate_document

SOURCE = "https://example.invalid/defensive/research.git"
COMMIT = "a" * 40
IMAGE = "registry.invalid/depfence-intake@sha256:" + "b" * 64
ANALYZER_IMAGE = "registry.invalid/depfence-static@sha256:" + "d" * 64
SIGNER = "https://github.com/example/depfence/.github/workflows/publish.yml@refs/tags/v0.8.0"


def _resolution() -> bytes:
    return json.dumps({
        "schema_version": "depfence.sealed-resolution-worker/v1",
        "source_host": "example.invalid",
        "symbolic_ref": "refs/heads/main",
        "exact_commit": COMMIT,
        "complete": True,
        "limitations": [],
    }).encode()


def _inventory(*, files: int = 2, bytes_total: int = 120) -> bytes:
    return json.dumps({
        "commit": COMMIT,
        "tree_sha256": "c" * 64,
        "file_count": files,
        "byte_count": bytes_total,
        "regular_files": files,
        "symlink_count": 0,
        "submodule_count": 0,
        "non_regular_count": 0,
        "suffix_counts": {".py": 1, ".md": max(0, files - 1)},
        "warning_codes": [],
    }).encode()


def _analysis(*, complete: bool = True, findings: list[dict] | None = None) -> bytes:
    finding_values = findings or []
    candidate_count = 1 if finding_values or not complete else 0
    return json.dumps({
        "schema_version": "depfence.sealed-analysis/v1",
        "commit": COMMIT,
        "complete": complete,
        "candidate_count": candidate_count,
        "analyzed_count": candidate_count,
        "analyzed_bytes": 12 if candidate_count else 0,
        "coverage_by_suffix": ({
            ".woff2": {"total": 1, "analyzed": 1, "incomplete": 0 if complete else 1}
        } if candidate_count else {}),
        "findings": finding_values,
        "limitations": [] if complete else [{
            "artifact_id": "sealed-artifact-sha256:" + "e" * 64,
            "suffix": ".woff2",
            "code": "deep_analysis_required",
        }],
        "toolchain": {"depfence": "0.8.0"},
    }).encode()


def _fake_oci(
    monkeypatch: pytest.MonkeyPatch,
    *,
    inventory: bytes | None = None,
    analysis: bytes | None = None,
):
    from depfence.core import sealed_intake

    calls: list[list[str]] = []
    def fake_run(command, _stdin, _environment, _timeout):
        calls.append(command)
        if "depfence-sealed-git-inventory" in command:
            return 0, inventory or _inventory(), b""
        if "depfence-sealed-git-analyze" in command:
            return 0, analysis or _analysis(), b""
        return 0, b"", b""

    monkeypatch.setattr(sealed_intake, "_run_bounded_subprocess", fake_run)
    monkeypatch.setattr(sealed_intake, "verify_image_signature", lambda *_args: None)
    monkeypatch.setattr(sealed_intake.platform, "system", lambda: "Linux")
    return calls


def _config() -> SealedIntakeConfig:
    return SealedIntakeConfig(
        engine="docker",
        image=IMAGE,
        analyzer_image=ANALYZER_IMAGE,
        allowed_hosts=frozenset({"example.invalid"}),
        acquisition_network="depfence-egress",
        https_proxy="http://allowlist-proxy:8080",
        certificate_identity=SIGNER,
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
        runtime="runsc",
    )


def _resolution_config() -> SealedResolutionConfig:
    return SealedResolutionConfig(
        engine="docker",
        image=IMAGE,
        allowed_hosts=frozenset({"example.invalid"}),
        acquisition_network="depfence-egress",
        https_proxy="http://allowlist-proxy:8080",
        certificate_identity=SIGNER,
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
        runtime="runsc",
    )


def test_sealed_resolution_fetches_no_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from depfence.core import sealed_intake

    calls: list[list[str]] = []

    def fake_run(command, _stdin, _environment, _timeout):
        calls.append(command)
        if "depfence-sealed-git-resolve" in command:
            return 0, _resolution(), b"untrusted remote diagnostics"
        return 1, b"", b"not found"

    monkeypatch.setattr(sealed_intake, "_run_bounded_subprocess", fake_run)
    monkeypatch.setattr(sealed_intake, "verify_image_signature", lambda *_args: None)
    monkeypatch.setattr(sealed_intake.platform, "system", lambda: "Linux")
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")

    result = resolve_source_sealed(
        SOURCE,
        state=state,
        config=_resolution_config(),
    )

    validate_document(result)
    assert result["status"] == "PASS"
    assert result["exact_commit"] == COMMIT
    assert result["objects_fetched"] is False
    assert result["materialized_on_host"] is False
    assert SOURCE not in json.dumps(result)
    resolve_call = next(call for call in calls if "depfence-sealed-git-resolve" in call)
    assert "--mount" not in resolve_call
    assert "--runtime" in resolve_call
    assert resolve_call[resolve_call.index("--runtime") + 1] == "runsc"
    assert all("fetch" not in value for value in resolve_call)


def test_sealed_resolution_worker_uses_ls_remote_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from depfence import sealed_git_worker

    commands: list[list[str]] = []

    def fake_run(command, _stdin, _environment, _timeout):
        commands.append(command)
        return 0, f"ref: refs/heads/main\tHEAD\n{COMMIT}\tHEAD\n".encode(), b""

    monkeypatch.setattr(sealed_git_worker, "_run_bounded_subprocess", fake_run)
    monkeypatch.setattr(
        "sys.argv",
        [
            "depfence-sealed-git-resolve",
            "--source", SOURCE,
            "--allowed-host", "example.invalid",
            "--no-redirects",
            "--format", "json",
        ],
    )

    sealed_git_worker.resolve_main()

    document = json.loads(capsys.readouterr().out)
    assert document["exact_commit"] == COMMIT
    assert document["symbolic_ref"] == "refs/heads/main"
    assert "ls-remote" in commands[0]
    assert "fetch" not in commands[0]


def test_sealed_intake_uses_no_host_bind_and_offline_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _fake_oci(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")

    result = inspect_source_sealed(SOURCE, COMMIT, approved_commit=COMMIT, state=state, config=_config())

    validate_document(result)
    assert result["status"] == "PASS"
    assert result["materialized_on_host"] is False
    assert result["approved"] is False
    assert SOURCE not in json.dumps(result)
    acquisition = next(call for call in calls if "depfence-sealed-git-acquire" in call)
    inventory = next(call for call in calls if "depfence-sealed-git-inventory" in call)
    analysis = next(call for call in calls if "depfence-sealed-git-analyze" in call)
    assert "--pull" in acquisition and acquisition[acquisition.index("--pull") + 1] == "never"
    assert "type=bind" not in " ".join(acquisition)
    assert "readonly" not in acquisition[acquisition.index("--mount") + 1]
    assert inventory[inventory.index("--network") + 1] == "none"
    assert "readonly" in inventory[inventory.index("--mount") + 1]
    assert analysis[analysis.index("--network") + 1] == "none"
    assert ANALYZER_IMAGE in analysis
    assert any(call[1:3] == ["volume", "rm"] for call in calls)
    records = list(state.path("intake/sealed-records").glob("*.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["commit"] == COMMIT


def test_sealed_intake_budget_is_unproven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_oci(monkeypatch, inventory=_inventory(files=3, bytes_total=500))
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")
    result = inspect_source_sealed(
        SOURCE,
        COMMIT,
        approved_commit=COMMIT,
        state=state,
        config=_config(),
        file_budget=2,
        byte_budget=100,
    )
    assert result["status"] == "UNPROVEN"
    assert result["warning_codes"] == ["byte_budget_exceeded", "file_budget_exceeded"]


def test_sealed_intake_requires_exact_commit_approval(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")
    with pytest.raises(ValueError, match="approval of the exact commit"):
        inspect_source_sealed(
            SOURCE, COMMIT, approved_commit="b" * 40, state=state, config=_config()
        )


def test_sealed_intake_reports_redacted_static_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = {
        "artifact_id": "sealed-artifact-sha256:" + "f" * 64,
        "suffix": ".docx",
        "rule_id": "DF-DOCX-001",
        "severity": "medium",
        "confidence": 0.84,
        "evidence_class": "structural_correlation",
    }
    _fake_oci(monkeypatch, analysis=_analysis(findings=[finding]))
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")

    result = inspect_source_sealed(SOURCE, COMMIT, approved_commit=COMMIT, state=state, config=_config())

    assert result["status"] == "FAIL"
    reported = result["analysis"]["findings"][0]
    assert all(reported[key] == value for key, value in finding.items())
    assert reported["rule_version"] == "2026-08-17"
    assert reported["carrier_type"] == "git_blob"
    assert result["ingestion_policy"] == "quarantine"
    assert SOURCE not in json.dumps(result)


def test_sealed_intake_never_passes_incomplete_artifact_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_oci(monkeypatch, analysis=_analysis(complete=False))
    project = tmp_path / "project"
    project.mkdir()
    state = PrivateState.open(project_root=project, root=tmp_path / "private")

    result = inspect_source_sealed(SOURCE, COMMIT, approved_commit=COMMIT, state=state, config=_config())

    assert result["status"] == "UNPROVEN"
    assert "artifact_analysis_incomplete" in result["warning_codes"]


@pytest.mark.parametrize(
    "source",
    [
        "http://example.invalid/repo.git",
        "https://user:secret@example.invalid/repo.git",
        "https://other.invalid/repo.git",
        "https://example.invalid/repo.git?token=secret",
        "https://example.invalid/repo.git\n--upload-pack=evil",
    ],
)
def test_sealed_intake_rejects_unapproved_sources_before_oci(
    source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from depfence.core import sealed_intake

    monkeypatch.setattr(sealed_intake.platform, "system", lambda: "Linux")
    with pytest.raises(ValueError):
        _config().validate(source, COMMIT)


def test_sealed_intake_cli_emits_manifest_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_oci(monkeypatch)
    result = CliRunner().invoke(
        cli,
        [
            "intake",
            "inspect-sealed",
            SOURCE,
            "--commit",
            COMMIT,
            "--approved-commit",
            COMMIT,
            "--image",
            IMAGE,
            "--analyzer-image",
            ANALYZER_IMAGE,
            "--allow-host",
            "example.invalid",
            "--acquisition-network",
            "depfence-egress",
            "--https-proxy",
            "http://allowlist-proxy:8080",
            "--certificate-identity",
            SIGNER,
            "--runtime",
            "runsc",
            "--state-root",
            str(tmp_path / "private"),
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["schema_version"] == "depfence.sealed-intake/v1"
    assert document["materialized_on_host"] is False
    assert SOURCE not in result.output


def test_intake_doctor_requires_internal_network_and_exact_local_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("depfence.cli.fleet_commands.platform.system", lambda: "Linux")
    monkeypatch.setattr("depfence.cli.fleet_commands.shutil.which", lambda _name: "/bin/docker")

    def probe(command: list[str]):
        if command[1:3] == ["image", "inspect"]:
            return True, [command[3]]
        if command[1] == "info":
            return True, {"runsc": {"path": "runsc"}}
        if command[1:3] == ["network", "inspect"]:
            return True, True
        return False, None

    monkeypatch.setattr("depfence.cli.fleet_commands._run_doctor_probe", probe)
    result = CliRunner().invoke(
        cli,
        [
            "intake", "doctor",
            "--intake-image", IMAGE,
            "--analyzer-image", ANALYZER_IMAGE,
            "--runtime", "runsc",
            "--acquisition-network", "depfence-egress",
            "--https-proxy", "http://allowlist-proxy:8080",
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    validate_document(document)
    assert document["status"] == "PASS"


def test_sealed_worker_requires_exact_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    from depfence.sealed_git_worker import _exact_commit, _sanitized_font_payloads

    assert _exact_commit("A" * 40) == "a" * 40
    with pytest.raises(SystemExit):
        _exact_commit("main")

    monkeypatch.setattr("depfence.sealed_git_worker.shutil.which", lambda _name: None)
    payloads, limitations = _sanitized_font_payloads(b"wOF2" + b"\0" * 20, ".woff2")
    assert payloads == []
    assert limitations == ["font_sanitizer_unavailable"]


def test_sealed_worker_bounds_font_collection_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from depfence.sealed_git_worker import _sanitized_font_payloads

    monkeypatch.setattr("depfence.sealed_git_worker.shutil.which", lambda _name: "/usr/bin/ots-sanitize")
    oversized_collection = b"ttcf\x00\x01\x00\x00" + (65).to_bytes(4, "big")
    payloads, limitations = _sanitized_font_payloads(oversized_collection, ".ttc")
    assert payloads == []
    assert limitations == ["font_collection_limit"]


def test_strict_json_rejects_duplicate_keys() -> None:
    with pytest.raises(ScanIncompleteError, match="duplicate key"):
        _strict_json_object(b'{"a":1,"a":2}')


def test_strict_json_rejects_non_object() -> None:
    with pytest.raises(ScanIncompleteError):
        _strict_json_object(b"[1,2,3]")


def test_strict_json_rejects_malformed() -> None:
    with pytest.raises(ScanIncompleteError):
        _strict_json_object(b"{bad")


def test_strict_json_accepts_valid() -> None:
    result = _strict_json_object(b'{"key":"value"}')

    assert result == {"key": "value"}
