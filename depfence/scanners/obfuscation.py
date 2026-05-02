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

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        return []

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
        rel_path = str(fpath.relative_to(project_dir)) if project_dir in fpath.parents else str(fpath)

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

        entropy = self._line_entropy(content)
        if entropy > 5.5 and len(content) > 1000:
            long_lines = [l for l in content.splitlines() if len(l) > 500]
            if long_lines and len(long_lines) > len(content.splitlines()) * 0.3:
                findings.append(self._make_finding(
                    rel_path, Severity.LOW,
                    "High-entropy code with long lines",
                    f"File has entropy {entropy:.2f} and {len(long_lines)} lines >500 chars. "
                    "May be obfuscated or heavily minified.",
                ))

        return findings

    def _make_finding(self, path: str, severity: Severity, title: str, detail: str) -> Finding:
        return Finding(
            finding_type=FindingType.BEHAVIORAL,
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
