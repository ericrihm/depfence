"""Tests for dependency pinning enforcement scanner."""

import json
import tempfile
from pathlib import Path

import pytest

from depfence.scanners.pinning_scanner import PinningScanner, _npm_score, _pypi_score, _cargo_score
from depfence.core.models import Severity


@pytest.fixture
def scanner():
    return PinningScanner()


# ---------------------------------------------------------------------------
# Unit tests for scoring helpers
# ---------------------------------------------------------------------------

class TestNpmScore:
    def test_wildcard(self):
        assert _npm_score("*") == "unpinned"

    def test_latest(self):
        assert _npm_score("latest") == "unpinned"

    def test_empty(self):
        assert _npm_score("") == "unpinned"

    def test_exact(self):
        assert _npm_score("1.2.3") == "pinned"

    def test_caret(self):
        assert _npm_score("^4.18.0") == "range"

    def test_tilde(self):
        assert _npm_score("~1.2.3") == "range"

    def test_gte(self):
        assert _npm_score(">=1.0.0") == "range"

    def test_gt(self):
        assert _npm_score(">1.0.0") == "range"


class TestPypiScore:
    def test_exact(self):
        assert _pypi_score("requests==2.31.0") == "pinned"

    def test_gte(self):
        assert _pypi_score("requests>=2.28.0") == "range"

    def test_no_constraint(self):
        assert _pypi_score("flask") == "unpinned"

    def test_tilde_eq(self):
        assert _pypi_score("django~=4.2") == "range"

    def test_not_equal(self):
        assert _pypi_score("requests!=2.0.0") == "range"


class TestCargoScore:
    def test_exact_pin(self):
        assert _cargo_score("=1.2.3") == "pinned"

    def test_bare_semver(self):
        # bare "1.2.3" in Cargo is ^1.2.3 — range
        assert _cargo_score("1.2.3") == "range"

    def test_caret(self):
        assert _cargo_score("^1.2.3") == "range"

    def test_wildcard(self):
        assert _cargo_score("*") == "unpinned"

    def test_empty(self):
        assert _cargo_score("") == "unpinned"

    def test_gte(self):
        assert _cargo_score(">=1.0.0") == "range"

    def test_gt(self):
        assert _cargo_score(">1.0.0") == "unpinned"


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

class TestRequirements:
    @pytest.mark.asyncio
    async def test_unpinned_dep(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask\nrequests\n")
            findings = await scanner.scan_project(p)
            unpinned = [f for f in findings if "Unpinned" in f.title]
            assert len(unpinned) == 2

    @pytest.mark.asyncio
    async def test_range_constraint(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("requests>=2.28.0\n")
            findings = await scanner.scan_project(p)
            assert any("Loosely pinned" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_range_severity_medium(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("requests>=2.28.0\n")
            findings = await scanner.scan_project(p)
            rng = [f for f in findings if "Loosely pinned" in f.title]
            assert all(f.severity == Severity.MEDIUM for f in rng)

    @pytest.mark.asyncio
    async def test_exact_pin_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
            findings = await scanner.scan_project(p)
            assert not any("pypi:" in f.package for f in findings
                           if not "lockfile" in f.title.lower())

    @pytest.mark.asyncio
    async def test_comment_lines_ignored(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text(
                "# This is a comment\n-r other.txt\nrequests==2.31.0\n"
            )
            findings = await scanner.scan_project(p)
            assert not any("pypi:requests" in f.package for f in findings)

    @pytest.mark.asyncio
    async def test_metadata_pin_score_present(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask\n")
            findings = await scanner.scan_project(p)
            f = next(f for f in findings if "pypi:flask" in f.package)
            assert f.metadata.get("pin_score") == "unpinned"

    @pytest.mark.asyncio
    async def test_tilde_eq_constraint(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("django~=4.2\n")
            findings = await scanner.scan_project(p)
            assert any("Loosely pinned" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_multiple_req_files(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("requests==2.31.0\n")
            (p / "requirements-dev.txt").write_text("pytest\n")
            findings = await scanner.scan_project(p)
            assert any("pypi:pytest" in f.package for f in findings)


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------

class TestPackageJson:
    @pytest.mark.asyncio
    async def test_wildcard_version(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"evil-pkg": "*"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            assert any("Wildcard" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_wildcard_severity_high(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"evil-pkg": "*"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            wc = [f for f in findings if "Wildcard" in f.title]
            assert all(f.severity == Severity.HIGH for f in wc)

    @pytest.mark.asyncio
    async def test_latest_version(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"some-pkg": "latest"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            assert any("Wildcard" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_open_range_medium(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"some-pkg": ">=1.0.0"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            oe = [f for f in findings if "Open-ended" in f.title]
            assert oe
            assert all(f.severity == Severity.MEDIUM for f in oe)

    @pytest.mark.asyncio
    async def test_caret_range_low(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"express": "^4.18.0"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            sr = [f for f in findings if "Semver range" in f.title and "npm:express" in f.package]
            assert sr
            assert all(f.severity == Severity.LOW for f in sr)

    @pytest.mark.asyncio
    async def test_tilde_range_low(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"lodash": "~4.17.21"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            sr = [f for f in findings if "Semver range" in f.title and "npm:lodash" in f.package]
            assert sr
            assert sr[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_exact_version_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"react": "18.2.0"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            react = [f for f in findings if "npm:react" in f.package]
            assert not react

    @pytest.mark.asyncio
    async def test_dev_dependencies_scanned(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "devDependencies": {"jest": "latest"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            assert any("npm:jest" in f.package for f in findings)

    @pytest.mark.asyncio
    async def test_peer_dependencies_scanned(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "peerDependencies": {"react": "*"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            assert any("npm:react" in f.package for f in findings)

    @pytest.mark.asyncio
    async def test_metadata_section_present(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({
                "dependencies": {"lodash": "~4.17.21"},
            }))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            f = next(f for f in findings if "npm:lodash" in f.package)
            assert f.metadata.get("section") == "dependencies"
            assert f.metadata.get("pin_score") == "range"


# ---------------------------------------------------------------------------
# Cargo.toml
# ---------------------------------------------------------------------------

class TestCargo:
    @pytest.mark.asyncio
    async def test_bare_semver_range_low(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\nserde = "1.0"\n'
            )
            (p / "Cargo.lock").write_text("")
            findings = await scanner.scan_project(p)
            serde_findings = [f for f in findings if "cargo:serde" in f.package]
            assert serde_findings
            assert serde_findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_wildcard_dep_medium(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\ntokio = "*"\n'
            )
            (p / "Cargo.lock").write_text("")
            findings = await scanner.scan_project(p)
            tokio_findings = [f for f in findings if "cargo:tokio" in f.package]
            assert tokio_findings
            assert tokio_findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_exact_pin_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\nserde = "=1.0.195"\n'
            )
            (p / "Cargo.lock").write_text("")
            findings = await scanner.scan_project(p)
            serde_findings = [f for f in findings if "cargo:serde" in f.package]
            assert not serde_findings

    @pytest.mark.asyncio
    async def test_no_cargo_toml_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            findings = await scanner.scan_project(p)
            assert not any("cargo:" in f.package for f in findings)

    @pytest.mark.asyncio
    async def test_metadata_pin_score(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\nserde = "1.0"\n'
            )
            (p / "Cargo.lock").write_text("")
            findings = await scanner.scan_project(p)
            f = next(f for f in findings if "cargo:serde" in f.package)
            assert f.metadata.get("pin_score") == "range"


# ---------------------------------------------------------------------------
# Lockfile presence checks
# ---------------------------------------------------------------------------

class TestLockfiles:
    @pytest.mark.asyncio
    async def test_missing_npm_lockfile_high(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({"dependencies": {"x": "^1"}}))
            findings = await scanner.scan_project(p)
            lf = [f for f in findings if "lockfile" in f.title.lower() and "npm" in f.title.lower()]
            assert lf
            assert lf[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_npm_lockfile_present_no_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({"dependencies": {"x": "^1"}}))
            (p / "package-lock.json").write_text("{}")
            findings = await scanner.scan_project(p)
            assert not any("No npm lockfile" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_yarn_lock_accepted(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({"dependencies": {"x": "^1"}}))
            (p / "yarn.lock").write_text("")
            findings = await scanner.scan_project(p)
            assert not any("No npm lockfile" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_pnpm_lock_accepted(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(json.dumps({"dependencies": {"x": "^1"}}))
            (p / "pnpm-lock.yaml").write_text("")
            findings = await scanner.scan_project(p)
            assert not any("No npm lockfile" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_missing_cargo_lock_high(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\nserde = "1.0"\n'
            )
            findings = await scanner.scan_project(p)
            cargo_lf = [f for f in findings if "Cargo.lock" in f.title]
            assert cargo_lf
            assert cargo_lf[0].severity == Severity.HIGH
            assert cargo_lf[0].metadata.get("lockfile") is None

    @pytest.mark.asyncio
    async def test_cargo_lock_present_no_lockfile_finding(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "Cargo.toml").write_text(
                '[package]\nname = "myapp"\nversion = "0.1.0"\n\n'
                '[dependencies]\nserde = "1.0"\n'
            )
            (p / "Cargo.lock").write_text("")
            findings = await scanner.scan_project(p)
            assert not any("Cargo.lock" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_python_unpinned_no_lockfile_high(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask\nrequests\n")
            findings = await scanner.scan_project(p)
            py_lf = [f for f in findings if "Python lockfile" in f.title]
            assert py_lf
            assert py_lf[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_python_pinned_no_lockfile_finding(self, scanner):
        """requirements.txt with == pins — no separate lockfile warning needed."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask==3.0.0\nrequests==2.31.0\n")
            findings = await scanner.scan_project(p)
            assert not any("Python lockfile" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_poetry_lock_accepted(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask\n")
            (p / "poetry.lock").write_text("")
            findings = await scanner.scan_project(p)
            assert not any("Python lockfile" in f.title for f in findings)


# ---------------------------------------------------------------------------
# scan() interface (package-level scan — always empty)
# ---------------------------------------------------------------------------

class TestScanInterface:
    @pytest.mark.asyncio
    async def test_scan_returns_empty(self, scanner):
        result = await scanner.scan([])
        assert result == []

    @pytest.mark.asyncio
    async def test_scan_with_packages_returns_empty(self, scanner):
        from depfence.core.models import PackageMeta, PackageId
        metas = [PackageMeta(pkg=PackageId(ecosystem="npm", name="express", version="4.18.0"))]
        result = await scanner.scan(metas)
        assert result == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_directory(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            findings = await scanner.scan_project(p)
            assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_json_package_json(self, scanner):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text("NOT JSON {{{")
            findings = await scanner.scan_project(p)
            # Should not crash, may produce 0 findings from package.json
            assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_finding_type_unpinned(self, scanner):
        """All findings from this scanner should use FindingType.UNPINNED."""
        from depfence.core.models import FindingType
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "requirements.txt").write_text("flask\n")
            (p / "package.json").write_text(json.dumps({"dependencies": {"x": "*"}}))
            findings = await scanner.scan_project(p)
            for f in findings:
                assert f.finding_type == FindingType.UNPINNED, (
                    f"Expected UNPINNED but got {f.finding_type} for: {f.title}"
                )
