"""Tests for inline suppression support (depfence:ignore comments)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depfence.core.inline_suppress import filter_findings, parse_suppressions
from depfence.core.models import Finding, FindingType, PackageId, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    name: str = "requests",
    ecosystem: str = "pypi",
    version: str = "2.28.0",
    finding_type: FindingType = FindingType.KNOWN_VULN,
    severity: Severity = Severity.HIGH,
    cve: str | None = None,
) -> Finding:
    return Finding(
        finding_type=finding_type,
        severity=severity,
        package=PackageId(ecosystem=ecosystem, name=name, version=version),
        title=f"Test finding for {name}",
        detail="Test detail",
        cve=cve,
    )


def _write(tmp_dir: str, filename: str, content: str) -> Path:
    p = Path(tmp_dir) / filename
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# parse_suppressions — requirements.txt
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    def test_no_comments_returns_empty(self, tmp_path):
        p = _write(str(tmp_path), "requirements.txt", "requests==2.28.0\nflask>=2.0\n")
        result = parse_suppressions(p)
        assert result == {}

    def test_wildcard_ignore(self, tmp_path):
        content = "requests==2.28.0  # depfence:ignore\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "requests" in result
        assert result["requests"] == []  # empty = wildcard

    def test_cve_specific_ignore(self, tmp_path):
        content = "requests==2.28.0  # depfence:ignore CVE-2024-1234\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "requests" in result
        assert "cve-2024-1234" in result["requests"]

    def test_type_specific_ignore(self, tmp_path):
        content = "requests==2.28.0  # depfence:ignore typosquat\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "requests" in result
        assert "typosquat" in result["requests"]

    def test_multiple_tokens(self, tmp_path):
        content = "requests==2.28.0  # depfence:ignore CVE-2024-1234 typosquat\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "cve-2024-1234" in result["requests"]
        assert "typosquat" in result["requests"]

    def test_only_annotated_packages_present(self, tmp_path):
        content = "requests==2.28.0  # depfence:ignore\nflask>=2.0\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "requests" in result
        assert "flask" not in result

    def test_package_name_normalised_to_lowercase(self, tmp_path):
        content = "Requests==2.28.0  # depfence:ignore\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        assert "requests" in result

    def test_comment_only_line_skipped(self, tmp_path):
        content = "# depfence:ignore CVE-2024-1234\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        # No package name extractable — falls back to wildcard key "*"
        assert "*" in result or result == {}

    def test_extras_syntax_parsed(self, tmp_path):
        content = "django[rest]>=4.0  # depfence:ignore\n"
        p = _write(str(tmp_path), "requirements.txt", content)
        result = parse_suppressions(p)
        # "django" should be extracted (up to the "[")
        assert "django" in result


# ---------------------------------------------------------------------------
# parse_suppressions — package.json
# ---------------------------------------------------------------------------


class TestParsePackageJson:
    def test_wildcard_ignore(self, tmp_path):
        content = '  "lodash": "^4.17.0"  // depfence:ignore\n'
        p = _write(str(tmp_path), "package.json", content)
        result = parse_suppressions(p)
        assert "lodash" in result
        assert result["lodash"] == []

    def test_cve_specific_ignore(self, tmp_path):
        content = '  "lodash": "^4.17.0"  // depfence:ignore CVE-2024-5678\n'
        p = _write(str(tmp_path), "package.json", content)
        result = parse_suppressions(p)
        assert "lodash" in result
        assert "cve-2024-5678" in result["lodash"]

    def test_type_specific_ignore(self, tmp_path):
        content = '  "express": "^4.18.0"  // depfence:ignore known_vulnerability\n'
        p = _write(str(tmp_path), "package.json", content)
        result = parse_suppressions(p)
        assert "express" in result
        assert "known_vulnerability" in result["express"]

    def test_no_comment_returns_empty(self, tmp_path):
        content = '  "lodash": "^4.17.0"\n'
        p = _write(str(tmp_path), "package.json", content)
        result = parse_suppressions(p)
        assert result == {}

    def test_scoped_package(self, tmp_path):
        content = '  "@babel/core": "^7.0.0"  // depfence:ignore\n'
        p = _write(str(tmp_path), "package.json", content)
        result = parse_suppressions(p)
        assert "@babel/core" in result


# ---------------------------------------------------------------------------
# parse_suppressions — Cargo.toml
# ---------------------------------------------------------------------------


class TestParseCargoToml:
    def test_wildcard_ignore(self, tmp_path):
        content = 'serde = "1.0"  # depfence:ignore\n'
        p = _write(str(tmp_path), "Cargo.toml", content)
        result = parse_suppressions(p)
        assert "serde" in result
        assert result["serde"] == []

    def test_cve_specific_ignore(self, tmp_path):
        content = 'serde = "1.0"  # depfence:ignore CVE-2024-9999\n'
        p = _write(str(tmp_path), "Cargo.toml", content)
        result = parse_suppressions(p)
        assert "serde" in result
        assert "cve-2024-9999" in result["serde"]

    def test_no_comment_returns_empty(self, tmp_path):
        content = 'serde = "1.0"\ntokio = { version = "1" }\n'
        p = _write(str(tmp_path), "Cargo.toml", content)
        result = parse_suppressions(p)
        assert result == {}

    def test_table_style_entry(self, tmp_path):
        content = 'tokio = { version = "1", features = ["full"] }  # depfence:ignore\n'
        p = _write(str(tmp_path), "Cargo.toml", content)
        result = parse_suppressions(p)
        assert "tokio" in result


# ---------------------------------------------------------------------------
# filter_findings
# ---------------------------------------------------------------------------


class TestFilterFindings:
    def test_no_suppressions_all_active(self):
        findings = [_finding("requests"), _finding("flask")]
        active, suppressed = filter_findings(findings, {})
        assert active == findings
        assert suppressed == []

    def test_wildcard_suppresses_all_findings_for_package(self):
        findings = [
            _finding("requests", finding_type=FindingType.KNOWN_VULN),
            _finding("requests", finding_type=FindingType.TYPOSQUAT),
            _finding("flask"),
        ]
        suppressions = {"requests": []}
        active, suppressed = filter_findings(findings, suppressions)
        assert len(active) == 1
        assert active[0].package.name == "flask"
        assert len(suppressed) == 2

    def test_cve_specific_suppression_only_matches_that_cve(self):
        f1 = _finding("requests", cve="CVE-2024-1234")
        f2 = _finding("requests", cve="CVE-2024-9999")
        f3 = _finding("requests")  # no CVE
        suppressions = {"requests": ["cve-2024-1234"]}
        active, suppressed = filter_findings([f1, f2, f3], suppressions)
        assert f1 in suppressed
        assert f2 in active
        assert f3 in active

    def test_type_specific_suppression(self):
        f1 = _finding("requests", finding_type=FindingType.TYPOSQUAT)
        f2 = _finding("requests", finding_type=FindingType.KNOWN_VULN)
        suppressions = {"requests": ["typosquat"]}
        active, suppressed = filter_findings([f1, f2], suppressions)
        assert f1 in suppressed
        assert f2 in active

    def test_unrelated_package_not_suppressed(self):
        findings = [_finding("requests"), _finding("flask")]
        suppressions = {"requests": []}
        active, suppressed = filter_findings(findings, suppressions)
        assert _finding("flask") not in suppressed
        flask_findings = [f for f in active if f.package.name == "flask"]
        assert len(flask_findings) == 1

    def test_empty_findings_returns_empty_tuples(self):
        active, suppressed = filter_findings([], {"requests": []})
        assert active == []
        assert suppressed == []

    def test_returns_tuple_of_two_lists(self):
        result = filter_findings([], {})
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_cve_matching_is_case_insensitive(self):
        # The suppressions dict stores tokens lowercased; CVE on finding may be uppercase.
        f = _finding("requests", cve="CVE-2024-1234")
        suppressions = {"requests": ["cve-2024-1234"]}
        active, suppressed = filter_findings([f], suppressions)
        assert f in suppressed

    def test_finding_type_value_matched(self):
        # FindingType.KNOWN_VULN.value == "known_vulnerability"
        f = _finding("requests", finding_type=FindingType.KNOWN_VULN)
        suppressions = {"requests": ["known_vulnerability"]}
        active, suppressed = filter_findings([f], suppressions)
        assert f in suppressed

    def test_wildcard_star_key_applies_to_all_packages(self):
        findings = [_finding("requests"), _finding("flask"), _finding("numpy")]
        suppressions = {"*": []}
        active, suppressed = filter_findings(findings, suppressions)
        assert active == []
        assert len(suppressed) == 3

    def test_package_specific_beats_star_for_ordering(self):
        """Package-specific suppression is checked before wildcard."""
        f = _finding("requests", finding_type=FindingType.KNOWN_VULN, cve="CVE-2024-1234")
        # Package says suppress typosquat only; wildcard says suppress everything.
        # Package-specific rule should win — CVE is NOT matched by "typosquat".
        suppressions = {"requests": ["typosquat"], "*": []}
        active, suppressed = filter_findings([f], suppressions)
        # The package-specific rule doesn't match, so wildcard kicks in.
        # Result: suppressed (because wildcard catches it after pkg-specific fails).
        assert f in suppressed

    def test_no_comment_no_suppression(self, tmp_path):
        """End-to-end: a file without any depfence:ignore has no suppressions."""
        p = _write(str(tmp_path), "requirements.txt", "requests==2.28.0\nflask>=2.0\n")
        suppressions = parse_suppressions(p)
        findings = [_finding("requests"), _finding("flask")]
        active, suppressed = filter_findings(findings, suppressions)
        assert active == findings
        assert suppressed == []
