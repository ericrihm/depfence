"""Obfuscation detector — identifies code obfuscation patterns in packages.

Detects:
1. Base64-encoded payloads executed at runtime
2. Hex-encoded strings decoded in eval/exec
3. Character code manipulation (String.fromCharCode patterns)
4. Minified code with suspicious entropy
5. Dynamic function construction (new Function(...))
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageMeta, Severity


class ObfuscationScanner:
    ecosystems = ["npm", "pypi"]

    # ANSI escape sequences used to hide content from terminal viewers
    _ANSI_INVISIBLE = re.compile(rb"\x1b\[8m")
    _ANSI_SCREEN_CLEAR = re.compile(rb"\x1b\[2J")
    _ANSI_BLACK_TEXT = re.compile(rb"\x1b\[(?:0;)?30m")
    _ANSI_OVERWRITE = re.compile(rb"\x1b\[\d+A\x1b\[2K")

    _BASE64_EXEC = re.compile(
        r"""(?:eval|exec|Function)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|"""
        r"""codecs\.decode)\s*\(""",
        re.IGNORECASE,
    )
    _HEX_DECODE = re.compile(
        r"""(?:\\x[0-9a-f]{2}){10,}""",
        re.IGNORECASE,
    )
    _CHAR_CODE = re.compile(
        r"""String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}""",
    )
    _DYNAMIC_FUNC = re.compile(
        r"""new\s+Function\s*\(\s*(?:['"`]|[a-zA-Z_]+\s*\+)""",
    )
    _EVAL_OBFUSCATED = re.compile(
        r"""(?:eval|exec)\s*\(\s*(?:.*?\.join\s*\(|.*?\.reverse\s*\(|.*?\.replace\s*\()""",
    )
    _PYTHON_EXEC_ENCODED = re.compile(
        r"""exec\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex|compile)\s*\(""",
    )

    _STAGED_UNPACK = re.compile(
        r"""(?:createDecipheriv|createDecipher)\s*\(\s*['"]aes-128-gcm['"]"""
        r"""|pbkdf2Sync\s*\(.*?(?:iterations|200000)"""
        r"""|(?:ROT|rot)\s*(?:13|47)\b""",
        re.IGNORECASE,
    )

    _LARGE_OBFUSCATED_THRESHOLD = 4 * 1024 * 1024  # 4MB

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Walk repo root + common payload dirs (no 500KB cap, not node_modules-only)."""
        files = self._find_project_script_files(project_dir)
        return await self.scan_files(project_dir, files)

    async def scan_files(self, project_dir: Path, files: list[Path] | None = None) -> list[Finding]:
        """Scan source files for obfuscation patterns."""
        findings: list[Finding] = []

        if files is None:
            files = self._find_script_files(project_dir)

        for fpath in files:
            try:
                content = fpath.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            findings.extend(self._analyze_content(content, fpath, project_dir))

        return findings

    _PROJECT_SCAN_DIRS = [
        ".github", "scripts", ".vscode", "src", "tools",
        ".claude", ".cursor", ".gemini",
    ]
    _PROJECT_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}

    def _find_project_script_files(self, project_dir: Path) -> list[Path]:
        """Find script files in repo root + payload dirs (no size cap)."""
        extensions = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh"}
        files: list[Path] = []
        seen: set[Path] = set()

        def _add(f: Path) -> None:
            rp = f.resolve()
            if rp not in seen and f.suffix in extensions:
                seen.add(rp)
                files.append(f)

        for item in project_dir.iterdir():
            if item.name in self._PROJECT_SKIP_DIRS:
                continue
            if item.is_file():
                _add(item)

        for subdir_name in self._PROJECT_SCAN_DIRS:
            subdir = project_dir / subdir_name
            if not subdir.is_dir():
                continue
            for f in subdir.rglob("*"):
                if any(skip in f.parts for skip in self._PROJECT_SKIP_DIRS):
                    continue
                if f.is_file():
                    _add(f)

        return files

    def _find_script_files(self, project_dir: Path) -> list[Path]:
        """Find JS/TS/Python files in common locations."""
        extensions = {".js", ".mjs", ".cjs", ".ts", ".py"}
        files = []
        search_dirs = [
            project_dir / "node_modules",
            project_dir / ".venv",
            project_dir / "venv",
        ]
        for d in search_dirs:
            if d.exists():
                for f in d.rglob("*"):
                    if f.suffix in extensions and f.stat().st_size < 500_000:
                        files.append(f)
                    if len(files) > 5000:
                        break
        return files

    def _analyze_content(self, content: str, fpath: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        is_child = project_dir in fpath.parents
        rel_path = str(fpath.relative_to(project_dir)) if is_child else str(fpath)

        if self._BASE64_EXEC.search(content):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "Base64-encoded payload executed at runtime",
                "Code decodes a base64 string and immediately executes it — "
                "a common pattern in malicious packages to hide credential theft.",
            ))

        if self._HEX_DECODE.search(content):
            hex_matches = self._HEX_DECODE.findall(content)
            if len(hex_matches) > 3 or any(len(m) > 40 for m in hex_matches):
                findings.append(self._make_finding(
                    rel_path, Severity.MEDIUM,
                    "Heavy hex-encoded strings detected",
                    f"Found {len(hex_matches)} hex-encoded sequences. "
                    "Legitimate code rarely embeds long hex strings.",
                ))

        if self._CHAR_CODE.search(content):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "String.fromCharCode obfuscation",
                "Code constructs strings character-by-character to evade static analysis.",
            ))

        if self._DYNAMIC_FUNC.search(content):
            findings.append(self._make_finding(
                rel_path, Severity.MEDIUM,
                "Dynamic function construction",
                "new Function() with string concatenation — may execute obfuscated code.",
            ))

        if self._EVAL_OBFUSCATED.search(content):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "Eval with string manipulation",
                "eval/exec called on manipulated strings (join/reverse/replace) — "
                "common obfuscation technique.",
            ))

        if self._PYTHON_EXEC_ENCODED.search(content):
            findings.append(self._make_finding(
                rel_path, Severity.CRITICAL,
                "Python exec with encoded payload",
                "exec() called on bytes.fromhex or compiled code — "
                "strong indicator of hidden malicious code.",
            ))

        # ANSI escape sequence content hiding (jqwik-class attack)
        raw = content.encode("utf-8", errors="ignore")
        if self._ANSI_INVISIBLE.search(raw):
            findings.append(self._make_finding(
                rel_path, Severity.CRITICAL,
                "ANSI invisible text escape sequence",
                "File uses SGR 8 (invisible text) — content hidden from terminal "
                "viewers but readable by AI assistants and static analysis.",
                FindingType.ANSI_HIDING,
            ))
        if self._ANSI_SCREEN_CLEAR.search(raw):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "ANSI screen clear in source file",
                "File contains ESC[2J (clear screen) — may hide log output "
                "containing prompt injection payloads.",
                FindingType.ANSI_HIDING,
            ))
        if self._ANSI_BLACK_TEXT.search(raw):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "ANSI black text escape sequence",
                "File sets text color to black (SGR 30) — content invisible "
                "on dark terminals but readable by AI tools.",
                FindingType.ANSI_HIDING,
            ))
        if self._ANSI_OVERWRITE.search(raw):
            findings.append(self._make_finding(
                rel_path, Severity.HIGH,
                "ANSI cursor-up + line-erase sequence",
                "File overwrites previously displayed lines — may hide "
                "malicious content that was briefly visible.",
                FindingType.ANSI_HIDING,
            ))

        entropy = self._line_entropy(content)
        if entropy > 5.5 and len(content) > 1000:
            long_lines = [ln for ln in content.splitlines() if len(ln) > 500]
            if long_lines and len(long_lines) > len(content.splitlines()) * 0.3:
                findings.append(self._make_finding(
                    rel_path, Severity.LOW,
                    "High-entropy code with long lines",
                    f"File has entropy {entropy:.2f} and {len(long_lines)} lines >500 chars. "
                    "May be obfuscated or heavily minified.",
                ))

        file_size = fpath.stat().st_size if fpath.exists() else 0
        if file_size > self._LARGE_OBFUSCATED_THRESHOLD and fpath.suffix in {".js", ".mjs", ".cjs"}:
            staged_markers = bool(self._STAGED_UNPACK.search(content))
            has_charcode = bool(self._CHAR_CODE.search(content))
            has_base64 = bool(self._BASE64_EXEC.search(content))
            has_hex = len(self._HEX_DECODE.findall(content)) > 5

            obfuscation_signals = sum([staged_markers, has_charcode, has_base64, has_hex, entropy > 5.0])
            if obfuscation_signals >= 2:
                findings.append(self._make_finding(
                    rel_path, Severity.CRITICAL,
                    "Very large obfuscated JavaScript file",
                    f"File is {file_size / (1024 * 1024):.1f}MB with {obfuscation_signals} "
                    f"obfuscation indicators (staged decryption, charcode manipulation, "
                    f"base64-exec, hex encoding, high entropy). This matches the pattern "
                    f"of multi-stage credential harvesters that unpack via ROT/charcode "
                    f"followed by AES-128-GCM decryption.",
                    FindingType.OBFUSCATION,
                ))

        return findings

    def _make_finding(
        self, path: str, severity: Severity, title: str, detail: str,
        finding_type: FindingType = FindingType.BEHAVIORAL,
    ) -> Finding:
        return Finding(
            finding_type=finding_type,
            severity=severity,
            package=f"file:{path}",
            title=title,
            detail=detail,
        )

    @staticmethod
    def _line_entropy(text: str) -> float:
        """Shannon entropy of printable characters."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        total = 0
        for ch in text:
            if ch.isprintable():
                freq[ch] = freq.get(ch, 0) + 1
                total += 1
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
