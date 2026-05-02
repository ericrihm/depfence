"""Tests for CI secret exposure correlation scanner."""

from __future__ import annotations

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.ci_secrets import CiSecretsScanner


@pytest.fixture
def scanner():
    return CiSecretsScanner()


def test_detects_ai_secrets(monkeypatch, scanner):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    secrets = scanner._detect_secrets()
    names = {s["name"] for s in secrets}

    assert "ANTHROPIC_API_KEY" in names
    assert "OPENAI_API_KEY" in names

    for s in secrets:
        if s["name"] in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            assert s["category"] == "ai_ml"
            assert s["sensitivity"] == "critical"


def test_detects_cloud_secrets(monkeypatch, scanner):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key-id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")

    secrets = scanner._detect_secrets()
    names = {s["name"]: s for s in secrets}

    assert "AWS_ACCESS_KEY_ID" in names
    assert names["AWS_ACCESS_KEY_ID"]["category"] == "cloud"
    assert names["AWS_ACCESS_KEY_ID"]["sensitivity"] == "critical"


def test_general_pattern_matching(monkeypatch, scanner):
    monkeypatch.setenv("CUSTOM_API_TOKEN", "abc123")
    monkeypatch.setenv("MY_SERVICE_SECRET", "supersecret")
    monkeypatch.setenv("SOME_PASSWORD", "hunter2")

    secrets = scanner._detect_secrets()
    names = {s["name"] for s in secrets}

    assert "CUSTOM_API_TOKEN" in names
    assert "MY_SERVICE_SECRET" in names
    assert "SOME_PASSWORD" in names


def test_empty_env_clean(monkeypatch, scanner):
    # Remove all known secret-like env vars to simulate a clean environment
    secret_keys = [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
        "WANDB_API_KEY", "COMET_API_KEY", "REPLICATE_API_TOKEN", "TOGETHER_API_KEY",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "NPM_TOKEN", "PYPI_TOKEN",
        "CARGO_REGISTRY_TOKEN",
    ]
    for key in secret_keys:
        monkeypatch.delenv(key, raising=False)

    # Also patch os.environ to be minimal so general patterns don't fire
    import os
    clean_env = {k: v for k, v in os.environ.items()
                 if not any(k.endswith(p.lstrip("*")) for p in
                            ["_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_API_KEY"])}
    monkeypatch.setattr(os, "environ", clean_env)

    secrets = scanner._detect_secrets()
    assert len(secrets) == 0


def test_blast_radius_calculation(scanner):
    secrets = [
        {"name": "ANTHROPIC_API_KEY", "category": "ai_ml", "sensitivity": "critical"},
        {"name": "AWS_ACCESS_KEY_ID", "category": "cloud", "sensitivity": "critical"},
        {"name": "GITHUB_TOKEN", "category": "ci", "sensitivity": "high"},
        {"name": "SOME_TOKEN", "category": "general", "sensitivity": "medium"},
    ]
    suspicious_packages = ["pypi:openai@1.0.0", "pypi:boto3@1.26.0"]

    result = scanner.estimate_blast_radius(secrets, suspicious_packages)

    assert result["total_secrets"] == 4
    assert result["critical_secrets"] == 2
    assert result["high_secrets"] == 1
    assert result["medium_secrets"] == 1
    assert result["packages_with_access_patterns"] == 2
    assert 0 < result["estimated_impact_score"] <= 100


def test_blast_radius_no_packages(scanner):
    secrets = [
        {"name": "MY_TOKEN", "category": "general", "sensitivity": "medium"},
    ]
    result = scanner.estimate_blast_radius(secrets, [])

    assert result["total_secrets"] == 1
    assert result["packages_with_access_patterns"] == 0
    # Low single medium secret, no suspicious packages → low score
    assert result["estimated_impact_score"] < 30


def test_blast_radius_score_capped_at_100(scanner):
    secrets = [
        {"name": f"SECRET_{i}", "category": "cloud", "sensitivity": "critical"}
        for i in range(20)
    ]
    packages = [f"pypi:pkg{i}@1.0" for i in range(10)]
    result = scanner.estimate_blast_radius(secrets, packages)
    assert result["estimated_impact_score"] <= 100


def test_classify_secret_categories(scanner):
    cases = [
        ("ANTHROPIC_API_KEY", "ai_ml", "critical"),
        ("OPENAI_API_KEY", "ai_ml", "critical"),
        ("HF_TOKEN", "ai_ml", "high"),
        ("AWS_ACCESS_KEY_ID", "cloud", "critical"),
        ("AZURE_CLIENT_SECRET", "cloud", "critical"),
        ("GCP_SA_KEY", "cloud", "critical"),
        ("GITHUB_TOKEN", "ci", "high"),
        ("NPM_TOKEN", "ci", "high"),
        ("MY_API_KEY", "general", "medium"),
        ("DB_PASSWORD", "general", "high"),
        ("SERVICE_SECRET", "general", "high"),
        ("SOME_TOKEN", "general", "medium"),
    ]
    for name, expected_category, expected_sensitivity in cases:
        category, sensitivity = scanner.classify_secret(name)
        assert category == expected_category, (
            f"{name}: expected category {expected_category!r}, got {category!r}"
        )
        assert sensitivity == expected_sensitivity, (
            f"{name}: expected sensitivity {expected_sensitivity!r}, got {sensitivity!r}"
        )


def test_classify_azure_wildcard(scanner):
    category, sensitivity = scanner.classify_secret("AZURE_TENANT_ID")
    assert category == "cloud"
    assert sensitivity == "critical"


def test_classify_gcp_wildcard(scanner):
    category, sensitivity = scanner.classify_secret("GCP_SERVICE_ACCOUNT_KEY")
    assert category == "cloud"
    assert sensitivity == "critical"


@pytest.mark.asyncio
async def test_scan_environment_no_secrets_no_findings(monkeypatch, scanner, tmp_path):
    import os
    clean_env = {k: v for k, v in os.environ.items()
                 if not any(k.endswith(p.lstrip("*")) for p in
                            ["_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_API_KEY"])
                 and not k.startswith(("AZURE_", "GCP_", "AWS_", "GITHUB_", "OPENAI", "ANTHROPIC"))}
    monkeypatch.setattr(os, "environ", clean_env)

    findings = await scanner.scan_environment(tmp_path)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_environment_critical_secrets_produce_finding(monkeypatch, scanner, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key-id")

    findings = await scanner.scan_environment(tmp_path)
    assert len(findings) >= 1
    severities = {f.severity for f in findings}
    assert Severity.MEDIUM in severities or Severity.HIGH in severities
    for f in findings:
        assert f.finding_type == FindingType.BEHAVIORAL
        assert (
            "ANTHROPIC_API_KEY" in f.metadata.get("secrets_detected", [])
            or "AWS_ACCESS_KEY_ID" in f.metadata.get("secrets_detected", [])
        )
