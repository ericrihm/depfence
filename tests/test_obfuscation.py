"""Tests for obfuscation detection scanner."""

import tempfile
from pathlib import Path

import pytest

from depfence.core.models import Severity
from depfence.scanners.obfuscation import ObfuscationScanner


@pytest.fixture
def scanner():
    return ObfuscationScanner()


@pytest.mark.asyncio
async def test_base64_exec_js(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "malicious.js"
        f.write_text('const payload = eval(atob("ZG9jdW1lbnQud3JpdGUoJ2hhY2tlZCcp"))')
        findings = await scanner.scan_files(Path(d), [f])
        assert len(findings) >= 1
        assert any("base64" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_base64_exec_python(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "evil.py"
        f.write_text('exec(base64.b64decode("aW1wb3J0IG9z"))')
        findings = await scanner.scan_files(Path(d), [f])
        assert any("base64" in f.title.lower() or "exec" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_hex_encoded_strings(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "hex.js"
        hex_payload = "\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c\\x2e\\x63\\x6f\\x6d"
        # Repeat to trigger threshold
        f.write_text(f'var a = "{hex_payload}";\nvar b = "{hex_payload}";\nvar c = "{hex_payload}";\nvar d = "{hex_payload}";')
        findings = await scanner.scan_files(Path(d), [f])
        assert any("hex" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_char_code_obfuscation(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "charcode.js"
        f.write_text('var x = String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 101, 118, 105, 108)')
        findings = await scanner.scan_files(Path(d), [f])
        assert any("fromcharcode" in f.title.lower() or "character" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_dynamic_function(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "dynfunc.js"
        f.write_text('var fn = new Function("re" + "turn doc" + "ument.cookie")')
        findings = await scanner.scan_files(Path(d), [f])
        assert any("dynamic" in f.title.lower() or "function" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_eval_with_manipulation(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "evalmanip.js"
        f.write_text('eval(["a","b","c"].reverse().join(""))')
        findings = await scanner.scan_files(Path(d), [f])
        assert any("eval" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_python_exec_fromhex(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "hexexec.py"
        f.write_text('exec(bytes.fromhex("696d706f7274206f73"))')
        findings = await scanner.scan_files(Path(d), [f])
        assert any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_clean_code_no_findings(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "clean.js"
        f.write_text("""
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
""")
        findings = await scanner.scan_files(Path(d), [f])
        assert len(findings) == 0


@pytest.mark.asyncio
async def test_legitimate_base64_not_flagged(scanner):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "legit.js"
        f.write_text("""
// Reading a base64 image is fine
const img = Buffer.from(data, 'base64');
fs.writeFileSync('output.png', img);
""")
        findings = await scanner.scan_files(Path(d), [f])
        assert len(findings) == 0
