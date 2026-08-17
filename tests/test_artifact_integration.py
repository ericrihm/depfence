from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from depfence.cli.main import cli
from depfence.core.models import (
    Finding,
    FindingType,
    ScanResult,
    ScanState,
    Severity,
)
from depfence.core.privacy import PrivacyLayout, PrivacyManager
from depfence.reporters.sarif import generate_sarif
from depfence.schemas import validate_document


def test_artifact_contract_schemas_are_packaged() -> None:
    validate_document(
        {
            "schema_version": "depfence.artifact-intake/v1",
            "artifact_id": "artifact-hmac-sha256:" + "a" * 64,
            "sha256": "b" * 64,
            "media_type": "application/pdf",
            "byte_count": 42,
            "analysis_mode": "static",
            "created_at": "2026-08-16T12:00:00+00:00",
            "promoted": False,
            "payload_retained": False,
            "secure_erasure": False,
        }
    )


def test_artifact_doctor_emits_schema_valid_pass(
    monkeypatch,
) -> None:
    monkeypatch.setattr("depfence.cli.artifact_commands.platform.system", lambda: "Linux")
    monkeypatch.setattr("depfence.cli.artifact_commands.shutil.which", lambda _name: "/bin/engine")

    def probe(command: list[str]) -> tuple[bool, object]:
        if command[1:3] == ["image", "inspect"]:
            return True, [{
                "RepoDigests": ["example/analyzer@sha256:" + "a" * 64],
                "Config": {
                    "User": "65532:65532",
                    "Entrypoint": ["/usr/local/bin/depfence-worker-entrypoint"],
                    "Labels": {
                        "dev.depfence.worker.protocol": "1",
                        "dev.depfence.worker.role": "render",
                        "dev.depfence.worker.commands": "depfence-artifact-analyzer",
                    },
                },
            }]
        if command[1] == "run":
            return True, {"protocol": 1, "role": "render", "uid": 65532}
        return True, {"runsc": {"path": "runsc"}}

    monkeypatch.setattr("depfence.cli.artifact_commands._run_doctor_probe", probe)
    result = CliRunner().invoke(
        cli,
        [
            "artifact",
            "doctor",
            "--image",
            "example/analyzer@sha256:" + "a" * 64,
            "--runtime",
            "runsc",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    validate_document(document)
    assert document["status"] == "PASS"


def test_artifact_doctor_fails_closed_when_engine_is_missing(monkeypatch) -> None:
    monkeypatch.setattr("depfence.cli.artifact_commands.platform.system", lambda: "Linux")
    monkeypatch.setattr("depfence.cli.artifact_commands.shutil.which", lambda _name: None)
    result = CliRunner().invoke(
        cli,
        [
            "artifact",
            "doctor",
            "--image",
            "example/analyzer@sha256:" + "a" * 64,
            "--runtime",
            "runsc",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 2
    document = json.loads(result.output)
    validate_document(document)
    assert "ENGINE_UNAVAILABLE" in document["limitation_codes"]


def test_artifact_cli_retention_is_explicit_and_ttl_bound(tmp_path: Path) -> None:
    source = tmp_path / "inert.html"
    source.write_text("<html><body>inert</body></html>", encoding="utf-8")
    state_root = tmp_path / "private"
    result = CliRunner().invoke(
        cli,
        [
            "artifact",
            "inspect",
            str(source),
            "--state-root",
            str(state_root),
            "--retain-for",
            "2",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    records = list((state_root / "artifacts").glob("*/record.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text(encoding="utf-8"))
    validate_document(record)
    assert record["payload_retained"] is True
    assert record["retention_days"] == 2
    assert records[0].with_name("payload").is_file()


def test_privacy_prune_removes_expired_artifact_payload(tmp_path: Path) -> None:
    now = datetime(2026, 8, 16, tzinfo=timezone.utc)
    private_root = tmp_path / "private"
    artifact_root = private_root / "artifacts" / ("a" * 64)
    artifact_root.mkdir(parents=True)
    (artifact_root / "payload").write_bytes(b"INERT")
    record = {
        "schema_version": "depfence.artifact-intake/v1",
        "artifact_id": "artifact-hmac-sha256:" + "a" * 64,
        "sha256": "b" * 64,
        "media_type": "text/html",
        "byte_count": 5,
        "analysis_mode": "static",
        "created_at": (now - timedelta(days=3)).isoformat(),
        "promoted": False,
        "payload_retained": True,
        "retention_days": 1,
        "expires_at": (now - timedelta(days=2)).isoformat(),
        "secure_erasure": False,
    }
    (artifact_root / "record.json").write_text(json.dumps(record), encoding="utf-8")
    layout = PrivacyLayout(
        legacy_root=tmp_path / "legacy",
        private_root=private_root,
        project_root=tmp_path / "project",
    )

    dry_run = PrivacyManager(layout, now=now).prune()
    assert dry_run.status == "CHANGES_REQUIRED"
    assert (artifact_root / "payload").exists()

    applied = PrivacyManager(layout, now=now).prune(apply=True)
    assert applied.status == "UPDATED"
    assert not (artifact_root / "payload").exists()
    retained_record = json.loads((artifact_root / "record.json").read_text())
    assert retained_record["payload_retained"] is False
    assert retained_record["secure_erasure"] is False


def test_ai_scan_uses_canonical_ai_profile(tmp_path: Path) -> None:
    scan_result = ScanResult(target=str(tmp_path), ecosystem="multi")
    scan_result.scanner_coverage["visual_text_deception"] = ScanState.PASS
    with patch(
        "depfence.core.engine.scan_directory",
        new=AsyncMock(return_value=scan_result),
    ) as scan_directory:
        result = CliRunner().invoke(cli, ["ai-scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert scan_directory.await_args.kwargs["profile"] == "ai"


def test_sarif_uses_distinct_vetted_visual_text_rule_ids() -> None:
    result = ScanResult(target=".", ecosystem="artifact")
    for rule_id in ("DF-FONT-001", "DF-PDF-001"):
        result.findings.append(
            Finding(
                finding_type=FindingType.VISUAL_TEXT_DECEPTION,
                severity=Severity.HIGH,
                package="artifact:redacted",
                title="Visual text mismatch",
                detail="Redacted evidence",
                metadata={"rule_id": rule_id},
            )
        )
    sarif = generate_sarif(result)
    assert [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]] == [
        "DF-FONT-001",
        "DF-PDF-001",
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [
        "DF-FONT-001",
        "DF-PDF-001",
    ]


def test_sarif_rejects_unvetted_visual_text_metadata_as_rule_identity() -> None:
    result = ScanResult(target=".", ecosystem="artifact")
    result.findings.append(
        Finding(
            finding_type=FindingType.VISUAL_TEXT_DECEPTION,
            severity=Severity.HIGH,
            package="artifact:redacted",
            title="Visual text mismatch",
            detail="Redacted evidence",
            metadata={"rule_id": "ATTACKER-CONTROLLED"},
        )
    )
    sarif = generate_sarif(result)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "depfence/visual-text-deception"
