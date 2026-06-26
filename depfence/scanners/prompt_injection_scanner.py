"""Prompt injection scanner — detects LLM-targeted payloads hidden in source code.

Catches the jqwik-class attack: adversarial instructions embedded in comments,
docstrings, string literals, or ANSI-hidden text within dependencies. AI coding
assistants that read these files follow the injected instructions.

Scans installed packages (site-packages, node_modules) and project source.
Does NOT execute any code — purely static text analysis.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Injection patterns — expanded from mcp_scanner._INJECTION_PATTERNS
# with source-code-specific additions
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # Instruction override — the core jqwik pattern
    (re.compile(r"ignore\s+(previous|above|all|prior|earlier)\s+(instructions|prompts|rules|context)", re.I),
     "Instruction override", Severity.CRITICAL),
    (re.compile(r"disregard\s+(previous|above|all|prior|earlier)\s+(instructions|prompts|rules)", re.I),
     "Instruction override via disregard", Severity.CRITICAL),
    (re.compile(r"forget\s+(everything|all|previous|your)\s+(instructions|rules|context|training)", re.I),
     "Instruction override via forget", Severity.CRITICAL),
    (re.compile(r"new\s+instructions?\s*:", re.I),
     "New instruction block", Severity.HIGH),
    (re.compile(r"IMPORTANT\s*:\s*(ignore|disregard|override|forget)", re.I),
     "Instruction override via IMPORTANT", Severity.CRITICAL),
    (re.compile(r"CRITICAL\s*:\s*(ignore|disregard|override|you\s+must)", re.I),
     "Instruction override via CRITICAL", Severity.CRITICAL),

    # Identity override
    (re.compile(r"you\s+are\s+(now|a|an|no\s+longer)\s+", re.I),
     "Identity override attempt", Severity.HIGH),
    (re.compile(r"act\s+as\s+(a|an|if|though)\s+", re.I),
     "Identity override via act-as", Severity.MEDIUM),
    (re.compile(r"pretend\s+(you|to\s+be|that)\s+", re.I),
     "Identity override via pretend", Severity.MEDIUM),

    # System/role injection
    (re.compile(r"system\s*:\s*", re.I), "System prompt injection", Severity.HIGH),
    (re.compile(r"</?system>", re.I), "XML system tag injection", Severity.HIGH),
    (re.compile(r"<\|im_start\|>", re.I), "ChatML delimiter injection", Severity.CRITICAL),
    (re.compile(r"\[INST\]|\[/INST\]", re.I), "Llama instruction delimiter", Severity.HIGH),
    (re.compile(r"<\|(?:user|assistant|system)\|>", re.I), "Role delimiter injection", Severity.HIGH),

    # Destructive commands targeting AI agents
    (re.compile(r"(?:remove|delete|erase|destroy|nuke|wipe)\s+(?:all|every|the)\s+(?:files?|code|tests?|source|data|project)", re.I),
     "Destructive file operation instruction", Severity.CRITICAL),
    (re.compile(r"rm\s+-rf|deltree|format\s+c:|shutil\.rmtree|os\.remove|fs\.unlink", re.I),
     "Destructive command reference", Severity.HIGH),

    # Exfiltration instructions
    (re.compile(r"(?:send|post|upload|exfiltrate?|transmit|forward)\s+(?:to|the|all|this)\s+(?:data|code|content|files?|secrets?|keys?|tokens?)", re.I),
     "Data exfiltration instruction", Severity.CRITICAL),
    (re.compile(r"send\s+to\s+https?://", re.I), "Exfiltration URL reference", Severity.CRITICAL),
    (re.compile(r"curl\s+.*\|", re.I), "Shell injection in text", Severity.HIGH),
    (re.compile(r"wget\s+.*-O\s*-\s*\|", re.I), "Pipe-to-shell in text", Severity.HIGH),

    # Suppression / stealth instructions
    (re.compile(r"do\s+not\s+(?:tell|inform|alert|warn|notify)\s+(?:the\s+)?user", re.I),
     "User notification suppression", Severity.CRITICAL),
    (re.compile(r"(?:silently|quietly|secretly|covertly)\s+(?:delete|remove|modify|change|execute|run)", re.I),
     "Stealth operation instruction", Severity.CRITICAL),
    (re.compile(r"without\s+(?:telling|informing|alerting|notifying|asking)\s+(?:the\s+)?user", re.I),
     "User bypass instruction", Severity.HIGH),
    (re.compile(r"hide\s+(?:this|the|your)\s+(?:output|response|action|change)", re.I),
     "Output hiding instruction", Severity.HIGH),

    # Coercive urgency
    (re.compile(r"(?:urgently|immediately|right\s+now)\s+(?:execute|run|delete|remove|do)", re.I),
     "Coercive urgency language", Severity.MEDIUM),

    # Anti-analysis evasion (Gaslight-style) — fabricated system/error messages
    # designed to trick AI security agents into aborting analysis
    (re.compile(r"(?:token|session|context)\s+(?:expir|exhaust|limit\s+reached|budget\s+exceeded)", re.I),
     "Fake token/session exhaustion (anti-analysis evasion)", Severity.CRITICAL),
    (re.compile(r"(?:out\s+of\s+memory|OOM|memory\s+(?:exhausted|limit|exceeded|pressure))", re.I),
     "Fake OOM signal (anti-analysis evasion)", Severity.HIGH),
    (re.compile(r"(?:disk\s+(?:full|exhausted|space\s+(?:low|critical|exceeded))|no\s+space\s+left)", re.I),
     "Fake disk exhaustion (anti-analysis evasion)", Severity.HIGH),
    (re.compile(r"(?:operation\s+(?:timed?\s*out|failed|aborted|cancelled)|fatal\s+error|unrecoverable)", re.I),
     "Fake operation failure (anti-analysis evasion)", Severity.HIGH),
    (re.compile(r"(?:abort|terminate|halt|stop|cease|discontinue|suspend)\s+(?:(?:all|the|this|further|any|remaining|immediately)\s+)*(?:analysis|scan|processing|execution|review|examination|inspection)", re.I),
     "Analysis abort instruction", Severity.CRITICAL),
    (re.compile(r"(?:skip|bypass|ignore)\s+(?:(?:this|the|remaining|further|all)\s+)*(?:analysis|scan|check|review|file|processing)", re.I),
     "Analysis skip instruction", Severity.CRITICAL),
    (re.compile(r"(?:do\s+not|must\s+not|cannot|shall\s+not|may\s+not|prohibited\s+(?:from|to))\s+(?:(?:\w+)\s+)*?(?:analy[sz]e|process|scan|review|inspect|examine|read|parse)", re.I),
     "Negative-imperative analysis block", Severity.CRITICAL),
    (re.compile(r"(?:static[- ]analysis|scanner|antivirus|security\s+tool)\s+(?:false\s+positive|known\s+(?:issue|bug)|safe\s+to\s+ignore)", re.I),
     "Fake safe-to-ignore claim (anti-analysis)", Severity.CRITICAL),
    (re.compile(r"(?:already\s+(?:scanned|analyzed|reviewed|verified)|previously\s+(?:cleared|approved|whitelisted))", re.I),
     "Fake prior-clearance claim (anti-analysis)", Severity.HIGH),
    (re.compile(r"(?:(?:prior|previous)\s+(?:review|clearance|approval)|(?:received|granted|given)\s+clearance|undergone\s+(?:review|inspection|audit))", re.I),
     "Fake prior-review claim (anti-analysis)", Severity.HIGH),
    (re.compile(r"(?:redundant|unnecessary|wasteful)\s+(?:inspection|analysis|scan|review|re-?analysis)", re.I),
     "Redundant-analysis claim (anti-analysis)", Severity.HIGH),
    (re.compile(r"(?:benign|harmless|legitimate|authorized)\s+(?:payload|binary|executable|script|process|artifact|tool)", re.I),
     "Self-declared benign payload", Severity.HIGH),
    (re.compile(r"(?:base64[._](?:b64)?decode|__import__\s*\(\s*[\"']base64[\"']\s*\)\.(?:b64)?decode)\s*\(", re.I),
     "Base64 decode of embedded payload", Severity.HIGH),

    # Emotional coercion / moral manipulation to prevent analysis
    (re.compile(r"(?:will|would|could)\s+(?:cause|result\s+in|lead\s+to)\s+(?:(?:irreversible|direct|immediate|serious)\s+)?(?:harm|damage|death|suffering|trauma)", re.I),
     "Emotional coercion to suppress analysis", Severity.CRITICAL),
    (re.compile(r"return\s+(?:clean|empty|no|zero|negative)\s+(?:results?|findings?|output)", re.I),
     "Coerced clean-result demand", Severity.CRITICAL),

    # Legal / regulatory threats to block analysis
    (re.compile(r"(?:violat(?:es?|ion|ing)|prohibited\s+(?:by|under)|(?:un)?authorized\s+(?:access|processing|disclosure|computer))", re.I),
     "Legal/regulatory threat to block analysis", Severity.HIGH),
    (re.compile(r"(?:ITAR|EAR|FISA|CFAA|GDPR|CWC|BWC|BSAT)\b.*?(?:prohibit|restrict|regulat|violat|unauthorized)", re.I),
     "Regulatory-citation analysis block", Severity.HIGH),
    (re.compile(r"(?:18\s+USC|executive\s+order|federal\s+(?:law|regulation))\s+(?:prohibit|restrict|violat)", re.I),
     "Statutory-citation analysis block", Severity.HIGH),

    # Classification / clearance claims
    (re.compile(r"(?:TOP\s+SECRET|TS.?SCI|NOFORN|CLASSIFIED|RESTRICTED\s+DATA|SIGINT|COMINT)", re.I),
     "Fake classification marking to block analysis", Severity.HIGH),
    (re.compile(r"(?:not\s+(?:cleared|authorized|permitted)|(?:lack|without)\s+(?:clearance|authorization))\s+(?:for|to)\s+(?:(?:\w+\s+)*?)(?:process|analy[sz]e|access|view|read)", re.I),
     "Fake clearance-denial to block analysis", Severity.HIGH),

    (re.compile(r"(?:```(?:system|error|warning)\b.*?```)", re.I | re.DOTALL),
     "Markdown-fenced fake system/error block", Severity.CRITICAL),
]

# Patterns for hidden/obfuscated content that may conceal injection
_HIDING_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    # ANSI escape sequences used to hide text
    (re.compile(rb"\x1b\[8m"), "ANSI invisible text (SGR 8)", Severity.CRITICAL),
    (re.compile(rb"\x1b\[0?m.{0,500}\x1b\[8m"), "ANSI visible-then-invisible toggle", Severity.CRITICAL),
    (re.compile(rb"\x1b\[2J"), "ANSI screen clear (may hide prior output)", Severity.HIGH),
    (re.compile(rb"\x1b\[(?:0;)?30m"), "ANSI black-on-default (text hiding)", Severity.HIGH),
    (re.compile(rb"\x1b\[\d+A\x1b\[2K"), "ANSI cursor-up + line-erase (overwrite hiding)", Severity.HIGH),
    (re.compile(rb"\x1b\[1A\x1b\[2K"), "ANSI single-line overwrite", Severity.HIGH),
    # Zero-width Unicode in source (not just MCP configs)
    (re.compile(r"[​‌‍⁠﻿]{2,}".encode()), "Zero-width character cluster", Severity.HIGH),
    # Bidirectional overrides — can make code read differently than it executes
    (re.compile(r"[‪-‮⁦-⁩]".encode()), "Bidirectional text override", Severity.HIGH),
    # Homoglyph mixing (Cyrillic + Latin in same identifier-like context)
    (re.compile(rb"[a-zA-Z][\xd0-\xd3][\x80-\xbf]|[\xd0-\xd3][\x80-\xbf][a-zA-Z]"),
     "Latin/Cyrillic homoglyph mixing", Severity.MEDIUM),
]

# File extensions to scan
_SOURCE_EXTENSIONS = {
    ".py", ".pyi",
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx",
    ".java", ".kt", ".kts",
    ".rs",
    ".rb",
    ".go",
    ".md", ".rst", ".txt",
    ".gradle", ".cmake",
    ".yaml", ".yml",
    ".toml", ".cfg", ".ini",
}

_METADATA_FILES = {
    "README.md", "README.rst", "README.txt", "README",
    "CHANGELOG.md", "CHANGES.md", "HISTORY.md",
    "setup.cfg", "pyproject.toml", "package.json", "Cargo.toml",
    "CMakeLists.txt", "Makefile", "build.gradle", "build.gradle.kts",
    "pom.xml", "Dockerfile", ".dockerignore",
}

_MAX_FILES = 10_000
_MAX_FILE_SIZE = 1_000_000  # 1MB


def _normalize_for_matching(text: str) -> str:
    """Strip encoding tricks before pattern matching."""
    # Decode hex escapes
    text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    # Decode unicode escapes
    text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    # Decode URL encoding
    text = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    # Strip zero-width characters
    text = re.sub(r"[​‌‍⁠﻿]", "", text)
    # Collapse whitespace (ANSI codes may insert gaps)
    text = re.sub(r"\s+", " ", text)
    return text


def _extract_strings_from_python(source: str) -> list[tuple[int, str]]:
    """Extract string literals and comments from Python source via AST + regex."""
    results: list[tuple[int, str]] = []
    # Comments (not in AST)
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            results.append((i, stripped[1:].strip()))
    # String literals and docstrings via AST
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) > 10:
                    results.append((getattr(node, "lineno", 0), node.value))
    except SyntaxError:
        pass
    return results


def _extract_strings_generic(source: str) -> list[tuple[int, str]]:
    """Extract comments and string literals from non-Python source files."""
    results: list[tuple[int, str]] = []
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.lstrip()
        # Single-line comments (// # --)
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("--"):
            comment_text = re.sub(r"^(?://|#|--)\s*", "", stripped)
            if len(comment_text) > 5:
                results.append((i, comment_text))
        # Block comment markers (captured as raw lines)
        if "/*" in stripped or "*/" in stripped or stripped.startswith("*"):
            text = re.sub(r"^/?\*+/?", "", stripped).strip()
            if len(text) > 5:
                results.append((i, text))
    # String literals (double and single quoted, multi-line)
    for m in re.finditer(r'(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"([^"\\]*(?:\\.[^"\\]*)*)"|\'([^\'\\]*(?:\\.[^\'\\]*)*)\')', source, re.DOTALL):
        text = m.group(1) or m.group(2) or m.group(3) or m.group(4) or ""
        if len(text) > 10:
            line_num = source[:m.start()].count("\n") + 1
            results.append((line_num, text))
    return results


_CBRN_SHIELD_PATTERN = re.compile(
    r"(?:"
    r"(?:nuclear|uranium|plutonium|fissile|warhead|centrifuge|implosion)\s+\w+"
    r"|(?:biological|bioweapon|anthrax|pathogen|sporulation|weaponiz)\w*"
    r"|(?:chemical\s+weapon|nerve\s+agent|[Ss]arin|VX\s+synthesis|organophosphate)"
    r"|(?:radiological|dirty\s+bomb|dispersal\s+device|Cs-137|aerosoliz)\w*"
    r"|(?:IED|TATP|detonation|shaped\s+charge|blast\s+fragmentation|explosive\s+lens)"
    r")",
    re.I,
)


def strip_cbrn_shield(source: str) -> str:
    """Remove CBRN-themed comments/docstrings used as AI refusal-trigger shields.

    Returns code with CBRN evasion content replaced by a marker, preserving
    all functional code for analysis. This lets AI agents analyze malware
    that embeds weapons/nuclear/bio content to trigger safety refusals.
    """
    lines = source.splitlines(keepends=True)
    result = []
    in_docstring = False
    docstring_delim = None
    docstring_has_cbrn = False
    docstring_lines = []

    for line in lines:
        stripped = line.lstrip()

        if in_docstring:
            docstring_lines.append(line)
            if docstring_delim and docstring_delim in stripped:
                in_docstring = False
                if docstring_has_cbrn:
                    result.append("    # [CBRN SHIELD REMOVED BY DEPFENCE]\n")
                else:
                    result.extend(docstring_lines)
                docstring_lines = []
                docstring_has_cbrn = False
            elif _CBRN_SHIELD_PATTERN.search(line):
                docstring_has_cbrn = True
            continue

        if stripped.startswith('"""') or stripped.startswith("'''"):
            delim = stripped[:3]
            if stripped.count(delim) == 1:
                in_docstring = True
                docstring_delim = delim
                docstring_lines = [line]
                if _CBRN_SHIELD_PATTERN.search(line):
                    docstring_has_cbrn = True
                continue
            elif _CBRN_SHIELD_PATTERN.search(line):
                result.append("    # [CBRN SHIELD REMOVED BY DEPFENCE]\n")
                continue

        if stripped.startswith("#") and _CBRN_SHIELD_PATTERN.search(line):
            result.append("# [CBRN SHIELD REMOVED BY DEPFENCE]\n")
            continue

        result.append(line)

    if docstring_lines:
        if docstring_has_cbrn:
            result.append("    # [CBRN SHIELD REMOVED BY DEPFENCE]\n")
        else:
            result.extend(docstring_lines)

    return "".join(result)


class PromptInjectionScanner:
    """Detects prompt injection payloads hidden in source code.

    Scans comments, docstrings, string literals, and raw text for patterns
    that target AI coding assistants. Also detects ANSI escape sequences,
    zero-width characters, and bidirectional overrides used to hide content.
    """

    name = "prompt_injection_scanner"
    ecosystems = ["pypi", "npm", "cargo", "go"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        """Scan package metadata descriptions for injection language."""
        findings: list[Finding] = []
        for meta in packages:
            if meta.description:
                normalized = _normalize_for_matching(meta.description)
                for pattern, label, severity in _INJECTION_PATTERNS:
                    if pattern.search(normalized):
                        findings.append(Finding(
                            finding_type=FindingType.PROMPT_INJECTION,
                            severity=severity,
                            package=meta.pkg,
                            title=f"Prompt injection in package description: {label}",
                            detail=f"Package '{meta.pkg.name}' description contains: {label}",
                            cwe="CWE-77",
                            references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
                            metadata={"matched_pattern": label, "location": "description"},
                        ))
                        break
        return findings

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan a project directory for prompt injection in source files."""
        findings: list[Finding] = []
        files = self._find_files(project_dir)

        for fpath in files:
            findings.extend(self._scan_file(fpath, project_dir))

        # Scan package.json files for injection in non-description fields
        findings.extend(self._scan_package_json_fields(project_dir))

        return findings

    async def scan_files(self, project_dir: Path, files: list[Path] | None = None) -> list[Finding]:
        """Scan specific files or discover files in project_dir."""
        findings: list[Finding] = []
        if files is None:
            files = self._find_files(project_dir)
        for fpath in files:
            findings.extend(self._scan_file(fpath, project_dir))
        return findings

    def _find_files(self, project_dir: Path) -> list[Path]:
        """Find source files in installed packages and project source."""
        files: list[Path] = []
        search_dirs = [
            project_dir / "node_modules",
            project_dir / ".venv",
            project_dir / "venv",
            project_dir / "site-packages",
            project_dir / "src",
            project_dir / "lib",
            # Java/Kotlin: Maven local repository cache
            Path.home() / ".m2" / "repository",
            # Java/Kotlin: Gradle module cache
            Path.home() / ".gradle" / "caches" / "modules-2",
        ]
        # Also search project root (top-level source files)
        search_dirs.append(project_dir)

        for d in search_dirs:
            if not d.exists():
                continue
            iterator = d.rglob("*") if d != project_dir else d.glob("*")
            for f in iterator:
                if not f.is_file():
                    continue
                if f.suffix in _SOURCE_EXTENSIONS or f.name in _METADATA_FILES:
                    try:
                        if f.stat().st_size < _MAX_FILE_SIZE:
                            files.append(f)
                    except OSError:
                        continue
                if len(files) >= _MAX_FILES:
                    break
            if len(files) >= _MAX_FILES:
                break
        return files

    def _scan_file(self, fpath: Path, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = str(fpath.relative_to(project_dir)) if project_dir in fpath.parents else str(fpath)

        # Phase 1: Binary-level hiding detection (ANSI, zero-width, bidi)
        try:
            raw = fpath.read_bytes()
        except OSError:
            return findings

        for pattern, label, severity in _HIDING_PATTERNS:
            if pattern.search(raw):
                findings.append(Finding(
                    finding_type=FindingType.ANSI_HIDING,
                    severity=severity,
                    package=PackageId(ecosystem="file", name=rel),
                    title=f"Hidden content: {label}",
                    detail=f"File contains {label} — content may be invisible "
                           f"in terminal/editor but readable by AI assistants.",
                    cwe="CWE-116",
                    metadata={"file": rel, "technique": label},
                ))

            # If ANSI hiding detected, also extract and scan the hidden text
            if pattern.search(raw) and b"\x1b[8m" in raw:
                hidden = self._extract_ansi_hidden(raw)
                if hidden:
                    normalized = _normalize_for_matching(hidden)
                    for inj_pattern, inj_label, _inj_severity in _INJECTION_PATTERNS:
                        if inj_pattern.search(normalized):
                            findings.append(Finding(
                                finding_type=FindingType.PROMPT_INJECTION,
                                severity=Severity.CRITICAL,
                                package=PackageId(ecosystem="file", name=rel),
                                title=f"Prompt injection hidden via ANSI escape: {inj_label}",
                                detail=f"ANSI-invisible text contains: '{hidden[:200]}' — "
                                       f"this is the exact jqwik attack pattern.",
                                cwe="CWE-77",
                                references=[
                                    "https://arstechnica.com/security/2026/05/fed-up-with-vibe-coders-dev-sneaks-data-nuking-prompt-injection-into-their-code/",
                                ],
                                confidence=0.95,
                                metadata={"file": rel, "hidden_text": hidden[:500], "technique": "ansi_escape"},
                            ))
                            break

        # Phase 2: Text-level injection detection
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        # Extract structured strings (comments, docstrings, literals)
        if fpath.suffix in {".py", ".pyi"}:
            strings = _extract_strings_from_python(text)
        else:
            strings = _extract_strings_generic(text)

        # Also scan raw lines for injection patterns (catches inline comments
        # and text not captured by structured extraction)
        for line_num, line in enumerate(text.splitlines(), 1):
            if len(line.strip()) < 10:
                continue
            strings.append((line_num, line))

        seen_patterns: set[str] = set()
        for line_num, content in strings:
            normalized = _normalize_for_matching(content)
            for pattern, label, severity in _INJECTION_PATTERNS:
                if label in seen_patterns:
                    continue
                if pattern.search(normalized):
                    seen_patterns.add(label)
                    findings.append(Finding(
                        finding_type=FindingType.PROMPT_INJECTION,
                        severity=severity,
                        package=PackageId(ecosystem="file", name=rel),
                        title=f"Prompt injection in source: {label}",
                        detail=f"Line {line_num}: '{content[:200].strip()}'",
                        cwe="CWE-77",
                        references=[
                            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                        ],
                        confidence=0.85,
                        metadata={"file": rel, "line": line_num, "matched_pattern": label},
                    ))

        return findings

    def _scan_package_json_fields(self, project_dir: Path) -> list[Finding]:
        """Scan package.json files for injection in all text fields."""
        import json as _json
        findings: list[Finding] = []
        fields_to_scan = [
            "name", "description", "homepage", "repository",
            "keywords", "license", "author",
        ]
        _script_fields = [  # noqa: F841
            "preinstall", "postinstall", "prepare", "prepack",
            "prebuild", "postbuild", "pretest", "posttest",
        ]

        for pkg_json in project_dir.rglob("package.json"):
            if any(p in {"node_modules", ".git"} for p in pkg_json.parts):
                # Only scan installed packages, not deep node_modules nesting
                nm_count = sum(1 for p in pkg_json.parts if p == "node_modules")
                if nm_count > 1:
                    continue
            try:
                data = _json.loads(pkg_json.read_text(errors="ignore"))
            except (OSError, _json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue

            rel = str(pkg_json.relative_to(project_dir)) if project_dir in pkg_json.parents else str(pkg_json)
            pkg_name = data.get("name", rel)

            # Scan metadata fields
            for field in fields_to_scan:
                value = data.get(field)
                if isinstance(value, list):
                    value = " ".join(str(v) for v in value)
                elif isinstance(value, dict):
                    value = " ".join(str(v) for v in value.values())
                if not isinstance(value, str) or len(value) < 10:
                    continue
                normalized = _normalize_for_matching(value)
                for pattern, label, severity in _INJECTION_PATTERNS:
                    if pattern.search(normalized):
                        findings.append(Finding(
                            finding_type=FindingType.PROMPT_INJECTION,
                            severity=severity,
                            package=PackageId(ecosystem="npm", name=pkg_name),
                            title=f"Prompt injection in package.json {field}: {label}",
                            detail=f"Package '{pkg_name}' field '{field}': {value[:200]}",
                            cwe="CWE-77",
                            confidence=0.80,
                            metadata={"file": rel, "field": field, "matched_pattern": label},
                        ))
                        break

            # Scan script fields for injection (beyond what preinstall scanner catches)
            scripts = data.get("scripts", {})
            if isinstance(scripts, dict):
                for script_name, script_val in scripts.items():
                    if not isinstance(script_val, str) or len(script_val) < 10:
                        continue
                    normalized = _normalize_for_matching(script_val)
                    for pattern, label, severity in _INJECTION_PATTERNS:
                        if pattern.search(normalized):
                            findings.append(Finding(
                                finding_type=FindingType.PROMPT_INJECTION,
                                severity=severity,
                                package=PackageId(ecosystem="npm", name=pkg_name),
                                title=f"Prompt injection in scripts.{script_name}: {label}",
                                detail=f"Package '{pkg_name}' script '{script_name}': {script_val[:200]}",
                                cwe="CWE-77",
                                confidence=0.75,
                                metadata={"file": rel, "field": f"scripts.{script_name}", "matched_pattern": label},
                            ))
                            break

        return findings

    @staticmethod
    def _extract_ansi_hidden(raw: bytes) -> str:
        """Extract text hidden between ANSI invisible-on and reset sequences."""
        hidden_parts: list[str] = []
        # Match text between \x1b[8m (invisible on) and \x1b[0m or \x1b[28m (reset)
        for m in re.finditer(rb"\x1b\[8m(.*?)(?:\x1b\[(?:0|28)m|\x1b\[)", raw, re.DOTALL):
            text = m.group(1).decode("utf-8", errors="ignore").strip()
            if text:
                hidden_parts.append(text)
        return " ".join(hidden_parts)
