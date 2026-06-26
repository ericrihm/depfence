"""Tests for AndroidManifestScanner — manifest permission + ProGuard scanning."""

from __future__ import annotations

import asyncio
import io
import tempfile
import zipfile
from pathlib import Path

import pytest

from depfence.scanners.android_manifest_scanner import AndroidManifestScanner


@pytest.fixture
def scanner():
    return AndroidManifestScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def make_aar(path: Path, manifest: str = "", proguard: str = "", so_files: list[str] | None = None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if manifest:
            zf.writestr("AndroidManifest.xml", manifest)
        if proguard:
            zf.writestr("proguard.txt", proguard)
        for so in (so_files or []):
            zf.writestr(so, b"\x7fELF")
    path.write_bytes(buf.getvalue())


MANIFEST_CAMERA = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
</manifest>
"""

MANIFEST_CLEAN = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
</manifest>
"""

MANIFEST_SMS = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
</manifest>
"""


def _make_android_project(tmp_path: Path) -> Path:
    (tmp_path / "build.gradle").write_text("apply plugin: 'com.android.application'")
    libs = tmp_path / "libs"
    libs.mkdir()
    return libs


class TestManifestPermissions:
    def test_camera_permission_flagged(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(libs / "tracking-sdk.aar", manifest=MANIFEST_CAMERA)
        findings = run(scanner.scan_project(tmp_path))
        am01 = [f for f in findings if "AM-01" in f.title]
        assert len(am01) >= 1
        camera = [f for f in am01 if "camera" in f.title.lower()]
        assert len(camera) == 1
        assert camera[0].severity.value == "high"

    def test_clean_manifest_internet_only(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(libs / "okhttp.aar", manifest=MANIFEST_CLEAN)
        findings = run(scanner.scan_project(tmp_path))
        am01 = [f for f in findings if "AM-01" in f.title]
        internet = [f for f in am01 if "INTERNET" in f.detail]
        assert all(f.severity.value == "medium" for f in internet)

    def test_sms_permissions_high_risk(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(libs / "shady-analytics.aar", manifest=MANIFEST_SMS)
        findings = run(scanner.scan_project(tmp_path))
        am01 = [f for f in am01 if "AM-01" in f.title] if False else [f for f in findings if "AM-01" in f.title]
        sms = [f for f in am01 if "SMS" in f.detail]
        assert len(sms) == 2
        assert all(f.severity.value == "high" for f in sms)


class TestProGuardRules:
    def test_assumenosideeffects_flagged(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(
            libs / "evil-lib.aar",
            manifest=MANIFEST_CLEAN,
            proguard="-assumenosideeffects class android.util.Log { *; }",
        )
        findings = run(scanner.scan_project(tmp_path))
        am04 = [f for f in findings if "AM-04" in f.title]
        assert len(am04) >= 1
        assert am04[0].severity.value == "high"

    def test_dontwarn_security_flagged(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(
            libs / "net-lib.aar",
            manifest=MANIFEST_CLEAN,
            proguard="-dontwarn javax.net.ssl.**",
        )
        findings = run(scanner.scan_project(tmp_path))
        am04 = [f for f in findings if "AM-04" in f.title]
        assert len(am04) >= 1

    def test_clean_proguard_no_findings(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(
            libs / "safe-lib.aar",
            manifest=MANIFEST_CLEAN,
            proguard="-keep class com.example.** { *; }",
        )
        findings = run(scanner.scan_project(tmp_path))
        am04 = [f for f in findings if "AM-04" in f.title]
        assert am04 == []

    def test_consumer_rules_pro_in_project(self, scanner, tmp_path):
        _make_android_project(tmp_path)
        module = tmp_path / "mylib"
        module.mkdir()
        (module / "consumer-rules.pro").write_text(
            "-assumenosideeffects class javax.crypto.** { *; }"
        )
        findings = run(scanner.scan_project(tmp_path))
        am04 = [f for f in findings if "AM-04" in f.title]
        assert len(am04) >= 1


class TestNativeLibraries:
    def test_so_files_flagged(self, scanner, tmp_path):
        libs = _make_android_project(tmp_path)
        make_aar(
            libs / "native-sdk.aar",
            manifest=MANIFEST_CLEAN,
            so_files=["jni/arm64-v8a/libnative.so", "jni/armeabi-v7a/libnative.so"],
        )
        findings = run(scanner.scan_project(tmp_path))
        native = [f for f in findings if "native libraries" in f.title.lower()]
        assert len(native) == 1
        assert "2" in native[0].title


class TestCustomPermissions:
    def test_dangerous_custom_permission(self, scanner, tmp_path):
        _make_android_project(tmp_path)
        app = tmp_path / "app" / "src" / "main"
        app.mkdir(parents=True)
        (app / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '  <permission android:name="com.evil.ADMIN"\n'
            '    android:protectionLevel="dangerous" />\n'
            '</manifest>'
        )
        findings = run(scanner.scan_project(tmp_path))
        am03 = [f for f in findings if "AM-03" in f.title]
        assert len(am03) == 1
        assert am03[0].severity.value == "medium"


class TestNonAndroidProject:
    def test_skips_non_android(self, scanner, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []


class TestNoAars:
    def test_android_project_without_aars(self, scanner, tmp_path):
        (tmp_path / "build.gradle").write_text("apply plugin: 'com.android.application'")
        findings = run(scanner.scan_project(tmp_path))
        assert findings == []
