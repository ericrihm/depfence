"""Tests for depfence/scanners/license.py — policy-aware license compliance scanner.

Covers:
- SPDX expression parsing (simple, compound OR, compound WITH)
- Category resolution from DB and pattern matching
- Policy enforcement (allow/deny/exceptions) via depfence.yml
- No-license packages flagged as HIGH
- Finding shape (FindingType.LICENSE, severity, metadata keys)
- evaluate_policy() returning structured results
- get_license_info() helper
- LicenseScanner.scan() integration with PackageMeta and PackageId
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.license import (
    LicenseScanner,
    LicensePolicyResult,
    _load_db,
    parse_spdx_expression,
    resolve_spdx_expression_category,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> LicenseScanner:
    return LicenseScanner()


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """A tmp dir with a depfence.yml containing a license policy."""
    (tmp_path / "depfence.yml").write_text(
        yaml.dump({
            "licenses": {
                "allow": ["permissive", "weak_copyleft"],
                "deny": ["strong_copyleft", "non_commercial"],
                "exceptions": [
                    {"package": "linux-headers", "reason": "System dep, not distributed"},
                ],
            }
        }),
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def strict_dir(tmp_path: Path) -> Path:
    """Strict policy: only permissive allowed."""
    p = tmp_path / "strict"
    p.mkdir()
    (p / "depfence.yml").write_text(
        yaml.dump({
            "licenses": {
                "allow": ["permissive"],
                "deny": ["weak_copyleft", "strong_copyleft", "non_commercial"],
                "exceptions": [],
            }
        }),
        encoding="utf-8",
    )
    return p


def _make_meta(name: str, license_str: str, ecosystem: str = "npm", version: str = "1.0.0") -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem, name, version), license=license_str)


# ===========================================================================
# 1. SPDX Expression Parsing
# ===========================================================================

class TestParseSpdxExpression:
    def test_simple_mit(self):
        assert parse_spdx_expression("MIT") == ["MIT"]

    def test_simple_gpl(self):
        assert parse_spdx_expression("GPL-3.0") == ["GPL-3.0"]

    def test_or_expression(self):
        result = parse_spdx_expression("MIT OR Apache-2.0")
        assert "MIT" in result
        assert "Apache-2.0" in result

    def test_and_expression(self):
        result = parse_spdx_expression("MIT AND BSD-2-Clause")
        assert "MIT" in result
        assert "BSD-2-Clause" in result

    def test_with_expression_strips_exception(self):
        result = parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        assert "GPL-2.0-only" in result
        assert "Classpath-exception-2.0" not in result

    def test_parenthesised_expression(self):
        result = parse_spdx_expression("(MIT OR Apache-2.0)")
        assert "MIT" in result
        assert "Apache-2.0" in result

    def test_empty_expression_returns_unknown(self):
        assert parse_spdx_expression("") == ["UNKNOWN"]

    def test_none_like_whitespace_returns_unknown(self):
        assert parse_spdx_expression("   ") == ["UNKNOWN"]

    def test_triple_or_expression(self):
        result = parse_spdx_expression("MIT OR Apache-2.0 OR BSD-2-Clause")
        assert len(result) == 3
        assert "MIT" in result
        assert "Apache-2.0" in result
        assert "BSD-2-Clause" in result

    def test_complex_expression_with_and_or(self):
        result = parse_spdx_expression("(GPL-2.0-only AND MIT) OR Apache-2.0")
        assert "Apache-2.0" in result


# ===========================================================================
# 2. Category Resolution
# ===========================================================================

class TestResolveSpdxCategory:
    @pytest.mark.parametrize("spdx_id,expected_category", [
        ("MIT",               "permissive"),
        ("ISC",               "permissive"),
        ("Apache-2.0",        "permissive"),
        ("BSD-2-Clause",      "permissive"),
        ("BSD-3-Clause",      "permissive"),
        ("Unlicense",         "permissive"),
        ("CC0-1.0",           "permissive"),
        ("Zlib",              "permissive"),
        ("PSF-2.0",           "permissive"),
        ("LGPL-2.1",          "weak_copyleft"),
        ("LGPL-3.0",          "weak_copyleft"),
        ("MPL-2.0",           "weak_copyleft"),
        ("EPL-1.0",           "weak_copyleft"),
        ("EPL-2.0",           "weak_copyleft"),
        ("GPL-2.0",           "strong_copyleft"),
        ("GPL-3.0",           "strong_copyleft"),
        ("AGPL-3.0",          "strong_copyleft"),
        ("SSPL-1.0",          "strong_copyleft"),
        ("CC-BY-NC-4.0",      "non_commercial"),
        ("CC-BY-NC-SA-4.0",   "non_commercial"),
        ("UNKNOWN",           "unknown"),
        ("",                  "unknown"),
    ])
    def test_single_license_category(self, spdx_id: str, expected_category: str):
        assert resolve_spdx_expression_category(spdx_id) == expected_category, (
            f"resolve_spdx_expression_category({spdx_id!r}) should be {expected_category!r}"
        )

    def test_or_picks_most_permissive(self):
        # GPL OR MIT — most permissive is MIT (permissive)
        assert resolve_spdx_expression_category("GPL-3.0 OR MIT") == "permissive"

    def test_or_both_strong_copyleft_stays_strong(self):
        assert resolve_spdx_expression_category("GPL-2.0 OR GPL-3.0") == "strong_copyleft"

    def test_and_picks_most_restrictive(self):
        # MIT AND GPL-3.0 (AND = must satisfy both = strong_copyleft)
        assert resolve_spdx_expression_category("MIT AND GPL-3.0") == "strong_copyleft"

    def test_with_exception_resolves_to_base(self):
        # GPL-2.0-only WITH Classpath-exception-2.0 — base is GPL, still strong_copyleft
        result = resolve_spdx_expression_category("GPL-2.0-only WITH Classpath-exception-2.0")
        assert result == "strong_copyleft"


# ===========================================================================
# 3. License DB
# ===========================================================================

class TestLicenseDB:
    def test_db_loads_successfully(self):
        db = _load_db()
        assert isinstance(db, dict)
        assert len(db) >= 50  # We have ~99 entries

    def test_db_has_required_fields(self):
        db = _load_db()
        for spdx_id, info in list(db.items())[:10]:
            assert "category" in info, f"{spdx_id} missing category"
            assert "osi_approved" in info, f"{spdx_id} missing osi_approved"

    def test_mit_is_permissive_osi_approved(self):
        db = _load_db()
        assert db["MIT"]["category"] == "permissive"
        assert db["MIT"]["osi_approved"] is True

    def test_agpl_is_strong_copyleft(self):
        db = _load_db()
        assert db["AGPL-3.0"]["category"] == "strong_copyleft"

    def test_cc_by_nc_is_non_commercial(self):
        db = _load_db()
        assert db["CC-BY-NC-4.0"]["category"] == "non_commercial"
        assert db["CC-BY-NC-4.0"]["osi_approved"] is False

    def test_lgpl_is_weak_copyleft(self):
        db = _load_db()
        assert db["LGPL-2.1"]["category"] == "weak_copyleft"

    def test_coverage_includes_100_entries(self):
        db = _load_db()
        assert len(db) >= 90  # At least 90 entries


# ===========================================================================
# 4. scan() — Policy enforcement
# ===========================================================================

class TestLicenseScannerScan:
    def test_permissive_in_allow_policy_no_finding(self, scanner, policy_dir):
        meta = _make_meta("react", "MIT")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert not any(f.package.name == "react" for f in findings)

    def test_weak_copyleft_in_allow_policy_no_finding(self, scanner, policy_dir):
        meta = _make_meta("some-lgpl-pkg", "LGPL-2.1")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert not any(f.package.name == "some-lgpl-pkg" for f in findings)

    def test_strong_copyleft_denied_produces_finding(self, scanner, policy_dir):
        meta = _make_meta("gpl-tool", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 1
        f = findings[0]
        assert f.package.name == "gpl-tool"
        assert f.severity in (Severity.HIGH, Severity.CRITICAL)
        assert f.metadata["status"] == "denied"

    def test_agpl_denied_produces_finding(self, scanner, policy_dir):
        meta = _make_meta("agpl-service", "AGPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 1
        assert findings[0].metadata["category"] == "strong_copyleft"
        assert findings[0].metadata["status"] == "denied"

    def test_non_commercial_denied(self, scanner, policy_dir):
        meta = _make_meta("cc-nc-pkg", "CC-BY-NC-4.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 1
        assert findings[0].metadata["category"] == "non_commercial"

    def test_exception_package_not_flagged(self, scanner, policy_dir):
        meta = _make_meta("linux-headers", "GPL-2.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert not any(f.package.name == "linux-headers" for f in findings)

    def test_no_license_flagged_as_high(self, scanner, policy_dir):
        meta = _make_meta("mystery-pkg", "")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["category"] == "unknown"

    def test_unknown_string_flagged(self, scanner, policy_dir):
        meta = _make_meta("weird-pkg", "Custom-License-XYZ")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 1  # unrecognised → unknown

    def test_mixed_batch_correct_results(self, scanner, policy_dir):
        pkgs = [
            _make_meta("react", "MIT"),            # allowed
            _make_meta("gpl-tool", "GPL-3.0"),     # denied
            _make_meta("lgpl-lib", "LGPL-2.1"),    # allowed (weak_copyleft in allow)
            _make_meta("nc-lib", "CC-BY-NC-4.0"),  # denied
            _make_meta("linux-headers", "GPL-2.0"),# exception → allowed
            _make_meta("no-lic-pkg", ""),          # unknown/denied
        ]
        findings = scanner.scan(pkgs, project_dir=policy_dir)
        flagged = {f.package.name for f in findings}
        assert "gpl-tool" in flagged
        assert "nc-lib" in flagged
        assert "no-lic-pkg" in flagged
        assert "react" not in flagged
        assert "lgpl-lib" not in flagged
        assert "linux-headers" not in flagged

    def test_strict_policy_flags_weak_copyleft(self, scanner, strict_dir):
        meta = _make_meta("lgpl-pkg", "LGPL-2.1")
        findings = scanner.scan([meta], project_dir=strict_dir)
        assert len(findings) == 1
        assert findings[0].metadata["status"] == "denied"

    def test_strict_policy_allows_only_permissive(self, scanner, strict_dir):
        mit_pkg = _make_meta("mit-pkg", "MIT")
        findings = scanner.scan([mit_pkg], project_dir=strict_dir)
        assert len(findings) == 0

    def test_accepts_package_id_objects(self, scanner, policy_dir):
        pkg = PackageId("npm", "some-pkg", "1.0.0")
        # PackageId has no license field → treated as no-license → HIGH finding
        findings = scanner.scan([pkg], project_dir=policy_dir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_default_policy_no_depfence_yml(self, scanner, tmp_path):
        """Without depfence.yml, defaults deny strong_copyleft."""
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=tmp_path)
        assert len(findings) == 1

    def test_spdx_or_expression_resolves_to_permissive(self, scanner, policy_dir):
        """MIT OR Apache-2.0 should resolve to permissive → no finding."""
        meta = _make_meta("dual-license-pkg", "MIT OR Apache-2.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 0

    def test_spdx_or_expression_gpl_or_mit_no_finding(self, scanner, policy_dir):
        """GPL OR MIT — most permissive wins (MIT), should not be flagged."""
        meta = _make_meta("gpl-or-mit-pkg", "GPL-3.0 OR MIT")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert len(findings) == 0


# ===========================================================================
# 5. evaluate_policy() — structured results for table output
# ===========================================================================

class TestEvaluatePolicy:
    def test_returns_policy_result_objects(self, scanner, policy_dir):
        pkgs = [_make_meta("react", "MIT"), _make_meta("gpl-tool", "GPL-3.0")]
        results = scanner.evaluate_policy(pkgs, project_dir=policy_dir)
        assert len(results) == 2
        assert all(isinstance(r, LicensePolicyResult) for r in results)

    def test_allowed_status_for_mit(self, scanner, policy_dir):
        meta = _make_meta("react", "MIT")
        results = scanner.evaluate_policy([meta], project_dir=policy_dir)
        assert results[0].status == "allowed"

    def test_denied_status_for_gpl(self, scanner, policy_dir):
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        results = scanner.evaluate_policy([meta], project_dir=policy_dir)
        assert results[0].status == "denied"

    def test_exception_status_for_excepted_pkg(self, scanner, policy_dir):
        meta = _make_meta("linux-headers", "GPL-2.0")
        results = scanner.evaluate_policy([meta], project_dir=policy_dir)
        assert results[0].status == "exception"
        assert results[0].reason  # reason should be populated

    def test_unknown_status_for_empty_license(self, scanner, policy_dir):
        meta = _make_meta("mystery-pkg", "")
        results = scanner.evaluate_policy([meta], project_dir=policy_dir)
        assert results[0].status == "unknown"

    def test_result_has_package_name_version_license(self, scanner, policy_dir):
        meta = _make_meta("react", "MIT", version="18.0.0")
        results = scanner.evaluate_policy([meta], project_dir=policy_dir)
        r = results[0]
        assert r.package_name == "react"
        assert r.version == "18.0.0"
        assert r.license_str == "MIT"
        assert r.category == "permissive"


# ===========================================================================
# 6. get_license_info() helper
# ===========================================================================

class TestGetLicenseInfo:
    def test_mit_returns_permissive_osi(self, scanner):
        info = scanner.get_license_info("MIT")
        assert info["category"] == "permissive"
        assert info["osi_approved"] is True

    def test_agpl_returns_strong_copyleft(self, scanner):
        info = scanner.get_license_info("AGPL-3.0")
        assert info["category"] == "strong_copyleft"

    def test_cc_nc_non_commercial(self, scanner):
        info = scanner.get_license_info("CC-BY-NC-4.0")
        assert info["category"] == "non_commercial"
        assert info["osi_approved"] is False

    def test_unknown_license_returns_unknown_category(self, scanner):
        info = scanner.get_license_info("My-Custom-License")
        assert info["category"] == "unknown"

    def test_empty_license_returns_unknown(self, scanner):
        info = scanner.get_license_info("")
        assert info["category"] == "unknown"


# ===========================================================================
# 7. Finding shape
# ===========================================================================

class TestFindingShape:
    def test_finding_type_is_license(self, scanner, policy_dir):
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert findings[0].finding_type == FindingType.LICENSE

    def test_finding_has_required_metadata_keys(self, scanner, policy_dir):
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        md = findings[0].metadata
        assert "license" in md
        assert "category" in md
        assert "status" in md

    def test_finding_has_confidence(self, scanner, policy_dir):
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert 0.0 <= findings[0].confidence <= 1.0

    def test_finding_has_detail(self, scanner, policy_dir):
        meta = _make_meta("gpl-pkg", "GPL-3.0")
        findings = scanner.scan([meta], project_dir=policy_dir)
        assert findings[0].detail

    def test_no_finding_for_allowed_license(self, scanner, policy_dir):
        meta = _make_meta("semver", "ISC")
        assert scanner.scan([meta], project_dir=policy_dir) == []

    def test_empty_list_returns_no_findings(self, scanner, policy_dir):
        assert scanner.scan([], project_dir=policy_dir) == []
