"""Protestware and timebomb scanner — detects date-gated, locale-gated, and
geofenced malicious logic in source files.

Real-world incidents:
  - colors.js / faker.js (Jan 2022): infinite loop added by maintainer
  - node-ipc (Mar 2022): geofenced data wiper targeting Russia/Belarus IPs
  - event-stream (Nov 2018): targeted cryptocurrency theft via flatmap-stream
  - ua-parser-js (Oct 2021): cryptominer injected via hijacked npm account
  - peacenotwar (Mar 2022): overwrites files on Russian/Belarusian systems

Detection heuristics:
  PW-01: Date/time comparisons that gate destructive or divergent behavior
  PW-02: Locale or timezone checks that branch to different logic paths
  PW-03: IP geolocation lookups followed by conditional execution
  PW-04: Infinite loops or process hangs gated on any condition
  PW-05: File system destructive ops gated on environment checks
  PW-06: Version-pinned activation (only triggers on specific package versions)
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".rb"}

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", "vendor"}

_DATE_GATE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-01a",
        re.compile(
            r"new\s+Date\(\s*\)\s*[><=!]+\s*new\s+Date\(\s*['\"]"
            r"|\bDate\.now\(\)\s*[><=!]+\s*\d{10,13}\b"
            r"|\bdatetime\.(?:now|today)\(\)\s*[><=!]+\s*datetime\(",
            re.IGNORECASE,
        ),
        "Date comparison gates behavior — possible timebomb",
    ),
    (
        "PW-01b",
        re.compile(
            r"getFullYear\(\)\s*[><=!]+\s*20\d{2}"
            r"|getMonth\(\)\s*[><=!]+\s*\d{1,2}"
            r"|\.year\s*[><=!]+\s*20\d{2}",
            re.IGNORECASE,
        ),
        "Year/month comparison may activate time-delayed payload",
    ),
]

_LOCALE_GATE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-02a",
        re.compile(
            r"Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone"
            r"|process\.env\.TZ\b"
            r"|os\.environ\[.TZ.\]"
            r"|timezone\.get(?:tz)?\(",
            re.IGNORECASE,
        ),
        "Timezone detection may be used for geofenced activation",
    ),
    (
        "PW-02b",
        re.compile(
            r"(?:navigator|Intl)\..*?locale"
            r"|process\.env\.(?:LANG|LC_ALL|LANGUAGE)\b"
            r"|os\.environ\[.(?:LANG|LC_ALL|LANGUAGE).\]"
            r"|locale\.getdefaultlocale\(",
            re.IGNORECASE,
        ),
        "Locale detection may be used for targeted activation",
    ),
]

_GEO_GATE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-03a",
        re.compile(
            r"(?:ip-api|ipinfo|ipgeolocation|freegeoip|geoip|ipapi)"
            r"\.(?:com|io|org|co)",
            re.IGNORECASE,
        ),
        "IP geolocation API — may target users by country",
    ),
    (
        "PW-03b",
        re.compile(
            r"(?:country_code|countryCode|country)\s*[=!]=+\s*['\"](?:RU|BY|UA|CN|IR|KP|SY)",
            re.IGNORECASE,
        ),
        "Country-code conditional targeting specific nations",
    ),
]

_INFINITE_LOOP_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-04a",
        re.compile(
            r"while\s*\(\s*true\s*\)\s*\{"
            r"|for\s*\(\s*;\s*;\s*\)\s*\{"
            r"|while\s+True\s*:",
        ),
        "Unconditional infinite loop — may be intentional DoS (cf. colors.js)",
    ),
]

_DESTRUCTIVE_GATED_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-05a",
        re.compile(
            r"(?:fs\.(?:writeFileSync|unlinkSync|rmSync|rmdirSync)"
            r"|os\.(?:remove|unlink|rmdir)"
            r"|shutil\.rmtree"
            r"|rm\s+-rf)"
            r"[\s\S]{0,30}"
            r"(?:heart|peace|love|protest|freedom|war|stop|ukraine|russia)",
            re.IGNORECASE,
        ),
        "Destructive filesystem op near protest-related strings",
    ),
    (
        "PW-05b",
        re.compile(
            r"(?:heart|peace|love|protest|freedom|war|stop|ukraine|russia)"
            r"[\s\S]{0,100}"
            r"(?:fs\.(?:writeFileSync|unlinkSync|rmSync)|os\.(?:remove|unlink)|shutil\.rmtree|rm\s+-rf)",
            re.IGNORECASE,
        ),
        "Protest-themed strings precede destructive filesystem operations",
    ),
]

_VERSION_GATE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PW-06a",
        re.compile(
            r"(?:version|VERSION)\s*[=!]==?\s*['\"][0-9]+\.[0-9]+\.[0-9]+"
            r"[\s\S]{0,200}"
            r"(?:eval|exec|Function|child_process|subprocess|os\.system)",
            re.IGNORECASE,
        ),
        "Version check gates code execution — may activate on specific release",
    ),
]

_ALL_PATTERNS = (
    _DATE_GATE_PATTERNS
    + _LOCALE_GATE_PATTERNS
    + _GEO_GATE_PATTERNS
    + _INFINITE_LOOP_PATTERNS
    + _DESTRUCTIVE_GATED_PATTERNS
    + _VERSION_GATE_PATTERNS
)


class ProtestwareScanner:
    ecosystems = ["npm", "pypi"]
    name = "protestware"

    async def scan_project(self, root: Path) -> list[Finding]:
        root = Path(root)
        findings: list[Finding] = []
        for path in self._walk(root):
            try:
                content = path.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            if len(content) > 500_000:
                continue
            rel = str(path.relative_to(root))
            findings.extend(self._check_file(content, rel))
        return findings

    def _walk(self, root: Path):
        for item in root.rglob("*"):
            if any(skip in item.parts for skip in _SKIP_DIRS):
                continue
            if item.is_file() and item.suffix in _EXTENSIONS:
                yield item

    def _check_file(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_rules: set[str] = set()

        for rule_id, pattern, description in _ALL_PATTERNS:
            if rule_id in seen_rules:
                continue
            match = pattern.search(content)
            if not match:
                continue
            seen_rules.add(rule_id)

            severity = self._severity_for_rule(rule_id, content, match, rel_path)
            line_num = content[:match.start()].count("\n") + 1

            findings.append(Finding(
                finding_type=FindingType.PROTESTWARE,
                severity=severity,
                package=PackageId(ecosystem="file", name=rel_path),
                title=description,
                detail=(
                    f"[{rule_id}] {description}. "
                    f"Matched at line {line_num}: {match.group()[:120]!r}. "
                    f"Protestware and timebomb packages have caused major supply chain "
                    f"incidents (colors.js, node-ipc, event-stream). Review this code "
                    f"carefully for conditional activation of malicious behavior."
                ),
                confidence=self._confidence_for_rule(rule_id),
                metadata={
                    "rule": rule_id,
                    "file": rel_path,
                    "line": line_num,
                    "matched": match.group()[:200],
                },
            ))

        if self._has_mixed_signals(content):
            findings.append(Finding(
                finding_type=FindingType.PROTESTWARE,
                severity=Severity.HIGH,
                package=PackageId(ecosystem="file", name=rel_path),
                title="Mixed signals: environment check + destructive operation + network exfil",
                detail=(
                    "This file combines environment/locale/date inspection with "
                    "destructive filesystem operations AND network exfiltration — "
                    "the exact pattern seen in node-ipc and similar protestware. "
                    "This combination is extremely rare in legitimate code."
                ),
                confidence=0.9,
                metadata={
                    "rule": "PW-COMBO",
                    "file": rel_path,
                },
            ))

        return findings

    def _severity_for_rule(
        self, rule_id: str, content: str, match: re.Match,
        rel_path: str = "",
    ) -> Severity:
        context = content[max(0, match.start() - 300):match.end() + 300]
        is_test = bool(re.search(r"(?:test|spec|mock|example|demo)", rel_path, re.I))

        if rule_id.startswith("PW-05"):
            return Severity.CRITICAL
        if rule_id.startswith("PW-03b"):
            return Severity.HIGH
        if rule_id.startswith("PW-04"):
            if is_test or re.search(r"(?:test|spec|mock|example|demo)", context, re.I):
                return Severity.LOW
            return Severity.MEDIUM

        if rule_id.startswith("PW-01"):
            if self._has_destructive_nearby(context):
                return Severity.HIGH
            return Severity.MEDIUM

        if rule_id.startswith("PW-02") or rule_id.startswith("PW-03a"):
            if self._has_destructive_nearby(context):
                return Severity.HIGH
            return Severity.MEDIUM

        if rule_id.startswith("PW-06"):
            return Severity.HIGH

        return Severity.MEDIUM

    def _confidence_for_rule(self, rule_id: str) -> float:
        confidence_map = {
            "PW-01a": 0.7,
            "PW-01b": 0.6,
            "PW-02a": 0.5,
            "PW-02b": 0.5,
            "PW-03a": 0.6,
            "PW-03b": 0.9,
            "PW-04a": 0.5,
            "PW-05a": 0.95,
            "PW-05b": 0.95,
            "PW-06a": 0.7,
        }
        return confidence_map.get(rule_id, 0.6)

    def _has_destructive_nearby(self, context: str) -> bool:
        return bool(re.search(
            r"rm\s+-rf"
            r"|unlink|rmdir|rmtree|rmSync|unlinkSync"
            r"|writeFile|overwrite"
            r"|format\s+c:"
            r"|dd\s+if=/dev/zero",
            context, re.IGNORECASE,
        ))

    def _has_mixed_signals(self, content: str) -> bool:
        has_env_check = bool(re.search(
            r"timezone|locale|country|geoip|ip-api|getFullYear|Date\.now|datetime\.now",
            content, re.IGNORECASE,
        ))
        has_destructive = bool(re.search(
            r"unlinkSync|rmSync|rmtree|os\.remove|rm\s+-rf|writeFileSync.*?/",
            content, re.IGNORECASE,
        ))
        has_network = bool(re.search(
            r"https?\.(?:get|request)|fetch\(|axios|requests\.(?:post|get)|urllib",
            content, re.IGNORECASE,
        ))
        return has_env_check and has_destructive and has_network
