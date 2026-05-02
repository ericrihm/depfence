"""Tests for policy-as-code configuration and evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from depfence.core.models import Finding, FindingType, PackageId, Severity
from depfence.core.policy import (
    PolicyConfig,
    PolicyRule,
    evaluate_policy,
    find_config,
    generate_default_config,
    load_config,
    should_ignore,
)


def _finding(
    name: str = "requests",
    severity: Severity = Severity.HIGH,
    cve: str | None = "CVE-2024-0001",
) -> Finding:
    return Finding(
        finding_type=FindingType.KNOWN_VULN,
        severity=severity,
        package=PackageId(ecosystem="pypi", name=name, version="1.0.0"),
        title="Test vuln",
        detail="detail",
        cve=cve,
    )


class TestFindConfig:
    def test_finds_depfence_yml(self, tmp_path):
        (tmp_path / "depfence.yml").write_text("fail_on: high\n")
        assert find_config(tmp_path) == tmp_path / "depfence.yml"

    def test_finds_depfence_yaml(self, tmp_path):
        (tmp_path / "depfence.yaml").write_text("fail_on: high\n")
        assert find_config(tmp_path) == tmp_path / "depfence.yaml"

    def test_finds_dot_prefixed(self, tmp_path):
        (tmp_path / ".depfence.yml").write_text("fail_on: high\n")
        assert find_config(tmp_path) == tmp_path / ".depfence.yml"

    def test_returns_none_when_missing(self, tmp_path):
        assert find_config(tmp_path) is None

    def test_prefers_depfence_yml_over_yaml(self, tmp_path):
        (tmp_path / "depfence.yml").write_text("a: 1\n")
        (tmp_path / "depfence.yaml").write_text("b: 2\n")
        assert find_config(tmp_path) == tmp_path / "depfence.yml"


class TestLoadConfig:
    def test_loads_basic_config(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text("fail_on: critical\n")
        cfg = load_config(cfg_path)
        assert cfg.fail_on == "critical"

    def test_loads_scanners(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text("scanners:\n  enabled: [advisory, secrets]\n  disabled: [terraform]\n")
        cfg = load_config(cfg_path)
        assert "advisory" in cfg.scanners_enabled
        assert "terraform" in cfg.scanners_disabled

    def test_loads_rules(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text(
            "rules:\n"
            "  - name: test-rule\n"
            "    description: A test rule\n"
            "    match:\n"
            "      in_threat_db: true\n"
            "    action: block\n"
        )
        cfg = load_config(cfg_path)
        assert len(cfg.rules) == 1
        assert cfg.rules[0].name == "test-rule"
        assert cfg.rules[0].action == "block"

    def test_loads_ignore_patterns(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text(
            "ignore:\n"
            "  - package: internal-*\n"
            "    reason: Pre-vetted\n"
        )
        cfg = load_config(cfg_path)
        assert len(cfg.ignore_patterns) == 1
        assert cfg.ignore_patterns[0]["package"] == "internal-*"

    def test_loads_epss_settings(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text("epss:\n  enabled: false\n  escalate_above: 0.8\n")
        cfg = load_config(cfg_path)
        assert cfg.epss_enabled is False
        assert cfg.epss_escalate_above == 0.8

    def test_loads_kev_settings(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text("kev:\n  enabled: false\n  severity_override: false\n")
        cfg = load_config(cfg_path)
        assert cfg.kev_enabled is False
        assert cfg.kev_severity_override is False

    def test_empty_file(self, tmp_path):
        cfg_path = tmp_path / "depfence.yml"
        cfg_path.write_text("")
        cfg = load_config(cfg_path)
        assert cfg.fail_on == "high"


class TestShouldIgnore:
    def test_ignores_exact_package(self):
        patterns = [{"package": "internal-lib"}]
        f = _finding(name="internal-lib")
        assert should_ignore(f, patterns) is True

    def test_ignores_wildcard_package(self):
        patterns = [{"package": "internal-*"}]
        f = _finding(name="internal-utils")
        assert should_ignore(f, patterns) is True

    def test_does_not_ignore_non_matching(self):
        patterns = [{"package": "internal-*"}]
        f = _finding(name="requests")
        assert should_ignore(f, patterns) is False

    def test_ignores_by_cve(self):
        patterns = [{"cve": "CVE-2024-0001"}]
        f = _finding(cve="CVE-2024-0001")
        assert should_ignore(f, patterns) is True

    def test_does_not_ignore_different_cve(self):
        patterns = [{"cve": "CVE-2024-0001"}]
        f = _finding(cve="CVE-2024-9999")
        assert should_ignore(f, patterns) is False

    def test_empty_patterns(self):
        f = _finding()
        assert should_ignore(f, []) is False


class TestEvaluatePolicy:
    def test_blocks_above_threshold(self):
        config = PolicyConfig(fail_on="high")
        findings = [_finding(severity=Severity.CRITICAL)]
        blocked, warned = evaluate_policy(findings, config)
        assert len(blocked) == 1
        assert len(warned) == 0

    def test_warns_below_threshold(self):
        config = PolicyConfig(fail_on="critical")
        findings = [_finding(severity=Severity.HIGH)]
        blocked, warned = evaluate_policy(findings, config)
        assert len(blocked) == 0
        assert len(warned) == 1

    def test_ignores_matching_patterns(self):
        config = PolicyConfig(
            fail_on="any",
            ignore_patterns=[{"package": "requests"}],
        )
        findings = [_finding(name="requests")]
        blocked, warned = evaluate_policy(findings, config)
        assert len(blocked) == 0
        assert len(warned) == 0

    def test_fail_on_none_warns_everything(self):
        config = PolicyConfig(fail_on="none")
        findings = [_finding(severity=Severity.CRITICAL)]
        blocked, warned = evaluate_policy(findings, config)
        assert len(blocked) == 0

    def test_multiple_findings_mixed(self):
        config = PolicyConfig(fail_on="high")
        findings = [
            _finding(name="a", severity=Severity.CRITICAL),
            _finding(name="b", severity=Severity.HIGH),
            _finding(name="c", severity=Severity.MEDIUM),
            _finding(name="d", severity=Severity.LOW),
        ]
        blocked, warned = evaluate_policy(findings, config)
        assert len(blocked) == 2  # critical + high
        assert len(warned) == 2  # medium + low


class TestGenerateDefaultConfig:
    def test_returns_valid_yaml(self):
        import yaml

        content = generate_default_config()
        parsed = yaml.safe_load(content)
        assert parsed["fail_on"] == "high"
        assert "advisory" in parsed["scanners"]["enabled"]

    def test_contains_all_sections(self):
        content = generate_default_config()
        assert "fail_on:" in content
        assert "scanners:" in content
        assert "rules:" in content
        assert "epss:" in content
        assert "kev:" in content
        assert "reporting:" in content
