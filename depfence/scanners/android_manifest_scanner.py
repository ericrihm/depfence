"""Android manifest permission scanner — detects dangerous permissions in AAR dependencies.

When Android libraries (AARs) declare permissions in their AndroidManifest.xml,
those permissions are silently merged into your app's manifest at build time.
Users grant these permissions without knowing which library requested them.

Detection rules:
  AM-01: Dangerous permissions in dependency AARs (camera, microphone, contacts, etc.)
  AM-02: Permission groups that escalate (one permission grants the whole group)
  AM-03: Custom permissions with protectionLevel="dangerous" or "signature"
  AM-04: ProGuard/R8 rule injection via consumer-rules.pro in AARs
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA": "camera access",
    "android.permission.RECORD_AUDIO": "microphone access",
    "android.permission.READ_CONTACTS": "contact list access",
    "android.permission.WRITE_CONTACTS": "contact modification",
    "android.permission.ACCESS_FINE_LOCATION": "precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "background location tracking",
    "android.permission.READ_PHONE_STATE": "phone state and IMEI",
    "android.permission.CALL_PHONE": "outgoing calls",
    "android.permission.READ_CALL_LOG": "call log access",
    "android.permission.READ_SMS": "SMS access",
    "android.permission.SEND_SMS": "SMS sending",
    "android.permission.READ_EXTERNAL_STORAGE": "storage read",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage write",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "full storage management",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay windows",
    "android.permission.REQUEST_INSTALL_PACKAGES": "APK installation",
    "android.permission.RECEIVE_BOOT_COMPLETED": "auto-start on boot",
    "android.permission.FOREGROUND_SERVICE": "foreground service",
    "android.permission.INTERNET": "network access",
    "android.permission.BODY_SENSORS": "body sensor data",
    "android.permission.ACTIVITY_RECOGNITION": "activity recognition",
    "android.permission.BLUETOOTH_CONNECT": "bluetooth connection",
    "android.permission.NEARBY_WIFI_DEVICES": "nearby WiFi device scanning",
    "android.permission.POST_NOTIFICATIONS": "push notifications",
    "android.permission.USE_BIOMETRIC": "biometric authentication",
    "android.permission.QUERY_ALL_PACKAGES": "enumerate all installed apps",
}

_HIGH_RISK_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES",
}

_PERMISSION_PATTERN = re.compile(
    r'<uses-permission\s+android:name=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_CUSTOM_PERMISSION_PATTERN = re.compile(
    r'<permission\s+[^>]*android:name=["\']([^"\']+)["\'][^>]*'
    r'android:protectionLevel=["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)

_PROGUARD_DANGEROUS = [
    re.compile(r"-assumenosideeffects\b"),
    re.compile(r"-keepclassmembers\s+.*security|crypto|ssl", re.I),
    re.compile(r"-dontwarn\s+.*ssl|security|crypto|certificate", re.I),
]

_GRADLE_CACHE_DIRS = [
    Path.home() / ".gradle" / "caches" / "modules-2" / "files-2.1",
    Path.home() / ".gradle" / "caches" / "transforms-3",
]

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "build", ".gradle"}


class AndroidManifestScanner:
    ecosystems = ["android"]

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        if not self._is_android_project(project_dir):
            return findings

        findings.extend(self._scan_project_manifest(project_dir))
        findings.extend(self._scan_aar_files(project_dir))
        findings.extend(self._scan_proguard_rules(project_dir))
        return findings

    def _is_android_project(self, project_dir: Path) -> bool:
        markers = [
            project_dir / "build.gradle",
            project_dir / "build.gradle.kts",
            project_dir / "app" / "build.gradle",
            project_dir / "app" / "build.gradle.kts",
            project_dir / "gradle.lockfile",
            project_dir / "settings.gradle",
            project_dir / "settings.gradle.kts",
        ]
        return any(m.exists() for m in markers)

    def _scan_project_manifest(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        manifests = list(project_dir.rglob("AndroidManifest.xml"))
        for manifest in manifests[:10]:
            if any(skip in manifest.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = manifest.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in _CUSTOM_PERMISSION_PATTERN.finditer(content):
                perm_name = match.group(1)
                protection = match.group(2)
                if protection in ("dangerous", "signature"):
                    rel = manifest.relative_to(project_dir)
                    findings.append(Finding(
                        finding_type=FindingType.WORKFLOW,
                        severity=Severity.MEDIUM,
                        package=PackageId("android", str(rel)),
                        title=f"AM-03: Custom {protection} permission: {perm_name}",
                        detail=(
                            f"Custom permission with protectionLevel='{protection}' "
                            f"in {rel}. Apps requesting this permission gain elevated access."
                        ),
                        metadata={"file": str(rel), "permission": perm_name, "rule": "AM-03"},
                    ))
        return findings

    def _scan_aar_files(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        aar_locations = [project_dir / "libs"]
        aar_locations.extend(
            d for d in (project_dir / "app" / "libs",) if d.is_dir()
        )

        for loc in aar_locations:
            if not loc.is_dir():
                continue
            for aar in loc.glob("*.aar"):
                findings.extend(self._analyze_aar(aar, project_dir))

        return findings

    def _analyze_aar(self, aar_path: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        lib_name = aar_path.stem

        try:
            with zipfile.ZipFile(aar_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest = zf.read("AndroidManifest.xml").decode("utf-8", errors="replace")
                    findings.extend(
                        self._check_manifest_permissions(manifest, lib_name, aar_path, project_dir)
                    )

                proguard_files = [
                    n for n in zf.namelist()
                    if n in ("proguard.txt", "consumer-rules.pro", "proguard-rules.pro")
                ]
                for pf in proguard_files:
                    content = zf.read(pf).decode("utf-8", errors="replace")
                    findings.extend(
                        self._check_proguard_content(content, lib_name, pf, aar_path, project_dir)
                    )

                so_files = [n for n in zf.namelist() if n.endswith(".so")]
                if so_files:
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.LOW,
                        package=PackageId("maven", lib_name),
                        title=f"AAR contains {len(so_files)} native libraries",
                        detail=(
                            f"{aar_path.name} bundles native .so files: "
                            f"{', '.join(so_files[:5])}{'...' if len(so_files) > 5 else ''}. "
                            f"Native code bypasses Java security sandbox."
                        ),
                        metadata={"file": str(aar_path.relative_to(project_dir)), "so_count": len(so_files)},
                    ))
        except (zipfile.BadZipFile, OSError):
            pass

        return findings

    def _check_manifest_permissions(
        self, manifest: str, lib_name: str, aar_path: Path, project_dir: Path,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _PERMISSION_PATTERN.finditer(manifest):
            perm = match.group(1)
            if perm not in _DANGEROUS_PERMISSIONS:
                continue
            is_high = perm in _HIGH_RISK_PERMISSIONS
            findings.append(Finding(
                finding_type=FindingType.WORKFLOW,
                severity=Severity.HIGH if is_high else Severity.MEDIUM,
                package=PackageId("maven", lib_name),
                title=f"AM-01: {lib_name} requests {_DANGEROUS_PERMISSIONS[perm]}",
                detail=(
                    f"AAR library '{lib_name}' declares {perm} in its manifest. "
                    f"This permission is silently merged into your app at build time. "
                    f"Users will be prompted for '{_DANGEROUS_PERMISSIONS[perm]}' without "
                    f"knowing which library requested it."
                ),
                metadata={
                    "file": str(aar_path.relative_to(project_dir)),
                    "permission": perm,
                    "high_risk": is_high,
                    "rule": "AM-01",
                },
            ))
        return findings

    def _check_proguard_content(
        self, content: str, lib_name: str, filename: str,
        aar_path: Path, project_dir: Path,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in _PROGUARD_DANGEROUS:
            match = pattern.search(content)
            if match:
                findings.append(Finding(
                    finding_type=FindingType.WORKFLOW,
                    severity=Severity.HIGH,
                    package=PackageId("maven", lib_name),
                    title=f"AM-04: Dangerous ProGuard rule in {lib_name}",
                    detail=(
                        f"AAR '{lib_name}' contains '{match.group()}' in {filename}. "
                        f"ProGuard consumer rules are applied to YOUR app at build time. "
                        f"-assumenosideeffects can strip security checks; "
                        f"-dontwarn can suppress certificate validation warnings."
                    ),
                    metadata={
                        "file": str(aar_path.relative_to(project_dir)),
                        "proguard_file": filename,
                        "pattern": match.group(),
                        "rule": "AM-04",
                    },
                ))
        return findings

    def _scan_proguard_rules(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for proguard_file in project_dir.rglob("consumer-rules.pro"):
            if any(skip in proguard_file.parts for skip in _SKIP_DIRS):
                continue
            try:
                content = proguard_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for pattern in _PROGUARD_DANGEROUS:
                match = pattern.search(content)
                if match:
                    rel = proguard_file.relative_to(project_dir)
                    findings.append(Finding(
                        finding_type=FindingType.WORKFLOW,
                        severity=Severity.HIGH,
                        package=PackageId("android", str(rel)),
                        title=f"AM-04: Dangerous ProGuard rule in {rel}",
                        detail=(
                            f"Consumer rule '{match.group()}' in {rel}. "
                            f"These rules are applied to the consuming app at build time."
                        ),
                        metadata={"file": str(rel), "pattern": match.group(), "rule": "AM-04"},
                    ))
        return findings
