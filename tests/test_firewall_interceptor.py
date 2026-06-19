"""Thorough unit tests for depfence.firewall.interceptor."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depfence.firewall.interceptor import (
    FirewallDecision,
    check_package,
    disable_firewall,
    enable_npm_firewall,
    enable_pip_firewall,
    get_status,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _mock_threat_db(is_malicious=False, verdict=None):
    """Return a MagicMock ThreatDB with configurable behaviour."""
    db = MagicMock()
    db.is_known_malicious.return_value = is_malicious
    db.lookup.return_value = [{"title": "malware", "detail": "steals creds"}] if is_malicious else []
    db.get_crawler_verdict.return_value = verdict
    return db


# ---------------------------------------------------------------------------
# check_package — decision logic
# ---------------------------------------------------------------------------

def test_check_package_blocks_known_malicious():
    """Known malicious packages must be blocked immediately."""
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(is_malicious=True)):
        result = check_package("npm", "evil-pkg", "1.0.0")
    assert result["decision"] == FirewallDecision.BLOCK
    assert "malicious" in result["reason"].lower()
    assert result["package"] == "npm:evil-pkg@1.0.0"


def test_check_package_blocks_high_score():
    """Threat score >= 80 must block."""
    verdict = {"score": 90, "signals": []}
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(verdict=verdict)):
        result = check_package("pypi", "sketchy", "2.0")
    assert result["decision"] == FirewallDecision.BLOCK
    assert "90" in result["reason"]


def test_check_package_warns_medium_score():
    """Threat score 50-79 should warn, not block."""
    verdict = {"score": 65, "signals": []}
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(verdict=verdict)):
        result = check_package("npm", "risky", "0.1.0")
    assert result["decision"] == FirewallDecision.WARN
    assert "65" in result["reason"]


def test_check_package_allows_clean():
    """Package with no threats and no verdict should be allowed."""
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db()):
        result = check_package("npm", "lodash", "4.17.21")
    assert result["decision"] == FirewallDecision.ALLOW
    assert result["details"] == {}


def test_check_package_allows_low_score():
    """Score below 50 should still be allowed."""
    verdict = {"score": 30, "signals": []}
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(verdict=verdict)):
        result = check_package("pypi", "requests", "2.31.0")
    assert result["decision"] == FirewallDecision.ALLOW


def test_check_package_no_version_formats_correctly():
    """When version is None the package string should use 'any'."""
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db()):
        result = check_package("npm", "lodash")
    assert result["package"].endswith("@any")


def test_check_package_malicious_returns_threat_detail():
    """Block result should carry through the first threat detail."""
    threat = {"title": "Credential Stealer", "detail": "Exfil via DNS"}
    db = _mock_threat_db(is_malicious=True)
    db.lookup.return_value = [threat]
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=db):
        result = check_package("npm", "evil", "1.0")
    assert result["details"] == threat


def test_check_package_score_exactly_80_blocks():
    """Boundary: score == 80 must block."""
    verdict = {"score": 80, "signals": []}
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(verdict=verdict)):
        result = check_package("npm", "edge-case")
    assert result["decision"] == FirewallDecision.BLOCK


def test_check_package_score_exactly_50_warns():
    """Boundary: score == 50 must warn."""
    verdict = {"score": 50, "signals": []}
    with patch("depfence.firewall.interceptor.ThreatDB", return_value=_mock_threat_db(verdict=verdict)):
        result = check_package("npm", "edge-warn")
    assert result["decision"] == FirewallDecision.WARN


# ---------------------------------------------------------------------------
# enable_npm_firewall
# ---------------------------------------------------------------------------

def test_enable_npm_firewall_creates_npmrc(tmp_path):
    result = enable_npm_firewall(tmp_path)
    npmrc = tmp_path / ".npmrc"
    assert npmrc.exists()
    assert "depfence" in npmrc.read_text()
    assert "enabled" in result.lower()


def test_enable_npm_firewall_preserves_existing_content(tmp_path):
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org\n")
    enable_npm_firewall(tmp_path)
    content = (tmp_path / ".npmrc").read_text()
    assert "registry=https://registry.npmjs.org" in content
    assert "depfence" in content


def test_enable_npm_firewall_idempotent(tmp_path):
    enable_npm_firewall(tmp_path)
    result = enable_npm_firewall(tmp_path)
    assert "already" in result.lower()


def test_enable_npm_firewall_injects_package_json_hook(tmp_path):
    pkg = {"name": "my-app", "scripts": {"test": "jest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    enable_npm_firewall(tmp_path)
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["scripts"].get("preinstall") == "depfence firewall check-npm"


def test_enable_npm_firewall_does_not_overwrite_existing_preinstall(tmp_path):
    pkg = {"name": "my-app", "scripts": {"preinstall": "custom-hook"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    enable_npm_firewall(tmp_path)
    data = json.loads((tmp_path / "package.json").read_text())
    # Should NOT overwrite customer's existing preinstall
    assert data["scripts"]["preinstall"] == "custom-hook"


# ---------------------------------------------------------------------------
# enable_pip_firewall
# ---------------------------------------------------------------------------

def test_enable_pip_firewall_creates_script(tmp_path):
    result = enable_pip_firewall(tmp_path)
    script = tmp_path / ".depfence" / "pip-check.sh"
    assert script.exists()
    assert script.stat().st_mode & 0o111  # executable bit set
    assert "depfence" in script.read_text()
    assert "enabled" in result.lower()


def test_enable_pip_firewall_creates_depfence_dir(tmp_path):
    enable_pip_firewall(tmp_path)
    assert (tmp_path / ".depfence").is_dir()


# ---------------------------------------------------------------------------
# disable_firewall
# ---------------------------------------------------------------------------

def test_disable_firewall_removes_depfence_from_npmrc(tmp_path):
    enable_npm_firewall(tmp_path)
    disable_firewall(tmp_path)
    npmrc = tmp_path / ".npmrc"
    if npmrc.exists():
        assert "depfence" not in npmrc.read_text()


def test_disable_firewall_removes_preinstall_from_package_json(tmp_path):
    pkg = {"name": "my-app", "scripts": {"test": "jest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    enable_npm_firewall(tmp_path)
    disable_firewall(tmp_path)
    data = json.loads((tmp_path / "package.json").read_text())
    assert "preinstall" not in data.get("scripts", {})


def test_disable_firewall_removes_pip_check_script(tmp_path):
    enable_pip_firewall(tmp_path)
    assert (tmp_path / ".depfence" / "pip-check.sh").exists()
    disable_firewall(tmp_path)
    assert not (tmp_path / ".depfence" / "pip-check.sh").exists()


def test_disable_firewall_on_clean_dir_is_noop(tmp_path):
    """Calling disable on a dir with no firewall should not raise."""
    result = disable_firewall(tmp_path)
    assert result  # returns some string


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------

def test_get_status_all_disabled_initially(tmp_path):
    status = get_status(tmp_path)
    assert not status["npm"]
    assert not status["pip"]
    assert not status["active"]


def test_get_status_npm_active_after_enable(tmp_path):
    enable_npm_firewall(tmp_path)
    status = get_status(tmp_path)
    assert status["npm"]
    assert status["active"]


def test_get_status_pip_active_after_enable(tmp_path):
    enable_pip_firewall(tmp_path)
    status = get_status(tmp_path)
    assert status["pip"]
    assert status["active"]


def test_get_status_both_active(tmp_path):
    enable_npm_firewall(tmp_path)
    enable_pip_firewall(tmp_path)
    status = get_status(tmp_path)
    assert status["npm"]
    assert status["pip"]
    assert status["active"]


def test_get_status_npm_disabled_after_disable(tmp_path):
    enable_npm_firewall(tmp_path)
    disable_firewall(tmp_path)
    status = get_status(tmp_path)
    assert not status["npm"]


# ---------------------------------------------------------------------------
# FirewallDecision constants
# ---------------------------------------------------------------------------

def test_firewall_decision_constants():
    assert FirewallDecision.ALLOW == "allow"
    assert FirewallDecision.BLOCK == "block"
    assert FirewallDecision.WARN == "warn"
