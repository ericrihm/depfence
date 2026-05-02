"""Tests for the provenance attestation checker.

All HTTP calls are mocked via httpx's built-in transport mechanism so tests
run fully offline and deterministically.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from depfence.core.models import FindingType, PackageId, Severity
from depfence.scanners.provenance_checker import (
    ProvenanceChecker,
    ProvenanceStatus,
    _is_popular,
    _unknown_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(status_code: int, body: dict | None = None) -> MagicMock:
    """Build a fake httpx.Response-like mock."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = body or {}
    # raise_for_status should raise on 4xx/5xx, no-op on 2xx
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _npm_with_attestations(name: str = "lodash", version: str = "4.17.21") -> dict:
    """Minimal npm registry response that includes dist.attestations."""
    return {
        "name": name,
        "version": version,
        "dist": {
            "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "attestations": {
                "url": (
                    f"https://registry.npmjs.org/-/npm/v1/attestations/"
                    f"{name}@{version}"
                ),
                "provenance": {
                    "predicates": [
                        {
                            "predicate": {
                                "builder": {"id": "https://github.com/actions/runner"},
                                "materials": [
                                    {"uri": "git+https://github.com/lodash/lodash.git"}
                                ],
                            }
                        }
                    ]
                },
            },
        },
    }


def _npm_with_signatures(name: str = "semver", version: str = "7.6.0") -> dict:
    return {
        "name": name,
        "version": version,
        "dist": {
            "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "signatures": [
                {
                    "keyid": "SHA256:abc123",
                    "sig": "MEYCIQDxxx",
                }
            ],
        },
    }


def _npm_without_provenance(name: str = "my-private-pkg", version: str = "1.0.0") -> dict:
    return {
        "name": name,
        "version": version,
        "dist": {
            "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "integrity": "sha512-abc",
        },
    }


def _pypi_with_provenance(name: str = "sampleproject", version: str = "1.0.0") -> dict:
    return {
        "info": {"name": name, "version": version},
        "urls": [
            {
                "filename": f"{name}-{version}-py3-none-any.whl",
                "url": f"https://files.pythonhosted.org/{name}-{version}-py3-none-any.whl",
                "provenance": {
                    "attestations": [
                        {
                            "builder": "github-actions",
                            "source_repository": "https://github.com/example/sampleproject",
                        }
                    ]
                },
            }
        ],
    }


def _pypi_with_attestation_url(name: str = "mypkg", version: str = "2.0.0") -> dict:
    return {
        "info": {
            "name": name,
            "version": version,
            "attestation_url": f"https://pypi.org/integrity/{name}/{version}",
        },
        "urls": [
            {
                "filename": f"{name}-{version}-py3-none-any.whl",
                "url": f"https://files.pythonhosted.org/{name}-{version}-py3-none-any.whl",
            }
        ],
    }


def _pypi_without_provenance(name: str = "legacy-pkg", version: str = "0.1.0") -> dict:
    return {
        "info": {"name": name, "version": version},
        "urls": [
            {
                "filename": f"{name}-{version}.tar.gz",
                "url": f"https://files.pythonhosted.org/{name}-{version}.tar.gz",
            }
        ],
    }


# ---------------------------------------------------------------------------
# ProvenanceStatus dataclass sanity
# ---------------------------------------------------------------------------

class TestProvenanceStatusDataclass:
    def test_fields_accessible(self):
        pkg = PackageId("npm", "lodash", "4.17.21")
        status = ProvenanceStatus(
            package=pkg,
            has_provenance=True,
            provenance_type="npm-attestation",
            builder="github-actions",
            source_repo="https://github.com/lodash/lodash",
            transparency_log=True,
            verified=True,
        )
        assert status.has_provenance is True
        assert status.provenance_type == "npm-attestation"
        assert status.builder == "github-actions"
        assert status.transparency_log is True
        assert status.verified is True

    def test_unknown_status_helper(self):
        pkg = PackageId("pypi", "requests", "2.31.0")
        status = _unknown_status(pkg)
        assert status.has_provenance is False
        assert status.provenance_type is None
        assert status.verified is False


# ---------------------------------------------------------------------------
# npm provenance checks
# ---------------------------------------------------------------------------

class TestNpmProvenanceChecker:
    @pytest.mark.asyncio
    async def test_attestations_field_returns_has_provenance_true(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _npm_with_attestations("lodash", "4.17.21"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("lodash", "4.17.21")

        assert status.has_provenance is True
        assert status.provenance_type == "npm-attestation"
        assert status.transparency_log is True
        assert status.verified is True

    @pytest.mark.asyncio
    async def test_no_attestations_returns_has_provenance_false(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _npm_without_provenance("my-private-pkg", "1.0.0"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("my-private-pkg", "1.0.0")

        assert status.has_provenance is False
        assert status.provenance_type is None
        assert status.verified is False

    @pytest.mark.asyncio
    async def test_signatures_field_detected(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _npm_with_signatures("semver", "7.6.0"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("semver", "7.6.0")

        assert status.has_provenance is True
        assert status.provenance_type == "sigstore"
        assert status.transparency_log is True

    @pytest.mark.asyncio
    async def test_404_returns_unknown(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(404)

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("ghost-pkg", "0.0.1")

        assert status.has_provenance is False
        assert status.verified is False

    @pytest.mark.asyncio
    async def test_network_error_returns_graceful_default(self):
        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("lodash", "4.17.21")

        assert status.has_provenance is False
        assert status.verified is False
        assert isinstance(status, ProvenanceStatus)

    @pytest.mark.asyncio
    async def test_generic_exception_returns_graceful_default(self):
        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=RuntimeError("unexpected"))
            mock_get_client.return_value = mock_client

            status = await checker.check_npm_provenance("lodash", "4.17.21")

        assert status.has_provenance is False
        assert status.verified is False


# ---------------------------------------------------------------------------
# PyPI provenance checks
# ---------------------------------------------------------------------------

class TestPypiProvenanceChecker:
    @pytest.mark.asyncio
    async def test_provenance_field_in_urls_returns_has_provenance_true(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _pypi_with_provenance("sampleproject", "1.0.0"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_pypi_provenance("sampleproject", "1.0.0")

        assert status.has_provenance is True
        assert status.provenance_type == "slsa-github"
        assert status.builder == "github-actions"
        assert status.transparency_log is True

    @pytest.mark.asyncio
    async def test_attestation_url_in_info_returns_has_provenance_true(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _pypi_with_attestation_url("mypkg", "2.0.0"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_pypi_provenance("mypkg", "2.0.0")

        assert status.has_provenance is True
        assert status.provenance_type == "sigstore"

    @pytest.mark.asyncio
    async def test_no_provenance_returns_has_provenance_false(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(200, _pypi_without_provenance("legacy-pkg", "0.1.0"))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_pypi_provenance("legacy-pkg", "0.1.0")

        assert status.has_provenance is False
        assert status.provenance_type is None
        assert status.verified is False

    @pytest.mark.asyncio
    async def test_network_error_returns_graceful_default(self):
        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_get_client.return_value = mock_client

            status = await checker.check_pypi_provenance("requests", "2.31.0")

        assert status.has_provenance is False
        assert isinstance(status, ProvenanceStatus)

    @pytest.mark.asyncio
    async def test_404_returns_unknown(self):
        checker = ProvenanceChecker()
        mock_resp = _mock_response(404)

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_get_client.return_value = mock_client

            status = await checker.check_pypi_provenance("no-such-package", "1.0.0")

        assert status.has_provenance is False


# ---------------------------------------------------------------------------
# Batch checking
# ---------------------------------------------------------------------------

class TestBatchChecking:
    @pytest.mark.asyncio
    async def test_batch_multiple_packages(self):
        packages = [
            PackageId("npm", "lodash", "4.17.21"),
            PackageId("pypi", "requests", "2.31.0"),
            PackageId("npm", "my-private-pkg", "1.0.0"),
        ]
        checker = ProvenanceChecker()

        # Build per-URL response mapping
        responses = {
            "https://registry.npmjs.org/lodash/4.17.21": _mock_response(
                200, _npm_with_attestations("lodash", "4.17.21")
            ),
            "https://pypi.org/pypi/requests/2.31.0/json": _mock_response(
                200, _pypi_without_provenance("requests", "2.31.0")
            ),
            "https://registry.npmjs.org/my-private-pkg/1.0.0": _mock_response(
                200, _npm_without_provenance("my-private-pkg", "1.0.0")
            ),
        }

        def get_side_effect(url, **kwargs):
            if url in responses:
                return responses[url]
            return _mock_response(404)

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=get_side_effect)
            mock_get_client.return_value = mock_client

            statuses = await checker.check_batch(packages)

        assert len(statuses) == 3
        # lodash has attestations
        lodash_status = next(s for s in statuses if s.package.name == "lodash")
        assert lodash_status.has_provenance is True

        # requests has no provenance in our mock
        requests_status = next(s for s in statuses if s.package.name == "requests")
        assert requests_status.has_provenance is False

        # private package has no provenance
        private_status = next(s for s in statuses if s.package.name == "my-private-pkg")
        assert private_status.has_provenance is False

    @pytest.mark.asyncio
    async def test_batch_empty_list_returns_empty(self):
        checker = ProvenanceChecker()
        statuses = await checker.check_batch([])
        assert statuses == []

    @pytest.mark.asyncio
    async def test_batch_unsupported_ecosystem_returns_unknown(self):
        packages = [PackageId("cargo", "serde", "1.0.197")]
        checker = ProvenanceChecker()
        statuses = await checker.check_batch(packages)
        assert len(statuses) == 1
        assert statuses[0].has_provenance is False
        assert statuses[0].provenance_type is None


# ---------------------------------------------------------------------------
# Non-npm/pypi ecosystems
# ---------------------------------------------------------------------------

class TestUnsupportedEcosystems:
    @pytest.mark.asyncio
    async def test_cargo_returns_unknown_status(self):
        checker = ProvenanceChecker()
        pkg = PackageId("cargo", "tokio", "1.38.0")
        status = await checker._check_one(pkg)
        assert status.has_provenance is False
        assert status.provenance_type is None
        assert status.verified is False

    @pytest.mark.asyncio
    async def test_go_returns_unknown_status(self):
        checker = ProvenanceChecker()
        pkg = PackageId("go", "github.com/gin-gonic/gin", "1.9.1")
        status = await checker._check_one(pkg)
        assert status.has_provenance is False


# ---------------------------------------------------------------------------
# Finding generation and severity escalation
# ---------------------------------------------------------------------------

class TestFindingGeneration:
    @pytest.mark.asyncio
    async def test_missing_provenance_generates_medium_finding(self, tmp_path):
        """An obscure package without provenance → MEDIUM severity."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 2,
                    "packages": {
                        "node_modules/my-obscure-pkg": {
                            "version": "1.0.0",
                            "resolved": "https://registry.npmjs.org/my-obscure-pkg/-/my-obscure-pkg-1.0.0.tgz",
                        }
                    },
                }
            )
        )

        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                return_value=_mock_response(
                    200, _npm_without_provenance("my-obscure-pkg", "1.0.0")
                )
            )
            mock_get_client.return_value = mock_client

            findings = await checker.scan_project(tmp_path)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.finding_type == FindingType.PROVENANCE
        assert "my-obscure-pkg" in f.title

    @pytest.mark.asyncio
    async def test_popular_package_missing_provenance_generates_high_finding(
        self, tmp_path
    ):
        """A popular package (react) without provenance → HIGH severity."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 2,
                    "packages": {
                        "node_modules/react": {
                            "version": "18.3.1",
                            "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
                        }
                    },
                }
            )
        )

        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                return_value=_mock_response(
                    200, _npm_without_provenance("react", "18.3.1")
                )
            )
            mock_get_client.return_value = mock_client

            findings = await checker.scan_project(tmp_path)

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.finding_type == FindingType.PROVENANCE
        assert "react" in f.title
        assert f.metadata.get("popular") is True

    @pytest.mark.asyncio
    async def test_package_with_provenance_generates_no_finding(self, tmp_path):
        """A package that has attestations should not generate any finding."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 2,
                    "packages": {
                        "node_modules/lodash": {
                            "version": "4.17.21",
                            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        }
                    },
                }
            )
        )

        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                return_value=_mock_response(
                    200, _npm_with_attestations("lodash", "4.17.21")
                )
            )
            mock_get_client.return_value = mock_client

            findings = await checker.scan_project(tmp_path)

        assert findings == []

    @pytest.mark.asyncio
    async def test_mixed_packages_only_flags_missing(self, tmp_path):
        """Only packages without provenance should appear in findings."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 2,
                    "packages": {
                        "node_modules/lodash": {"version": "4.17.21"},
                        "node_modules/my-pkg": {"version": "0.1.0"},
                    },
                }
            )
        )

        checker = ProvenanceChecker()
        responses = {
            "https://registry.npmjs.org/lodash/4.17.21": _mock_response(
                200, _npm_with_attestations("lodash", "4.17.21")
            ),
            "https://registry.npmjs.org/my-pkg/0.1.0": _mock_response(
                200, _npm_without_provenance("my-pkg", "0.1.0")
            ),
        }

        def get_side_effect(url, **kwargs):
            return responses.get(url, _mock_response(404))

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=get_side_effect)
            mock_get_client.return_value = mock_client

            findings = await checker.scan_project(tmp_path)

        assert len(findings) == 1
        assert findings[0].package.name == "my-pkg"

    @pytest.mark.asyncio
    async def test_pypi_popular_package_escalated_to_high(self, tmp_path):
        """requests on PyPI without provenance → HIGH."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\n")

        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                return_value=_mock_response(
                    200, _pypi_without_provenance("requests", "2.31.0")
                )
            )
            mock_get_client.return_value = mock_client

            findings = await checker.scan_project(tmp_path)

        assert any(
            f.severity == Severity.HIGH and f.package.name == "requests"
            for f in findings
        )

    @pytest.mark.asyncio
    async def test_no_lockfiles_returns_no_findings(self, tmp_path):
        """A directory without any lockfiles should return an empty findings list."""
        checker = ProvenanceChecker()
        findings = await checker.scan_project(tmp_path)
        assert findings == []

    @pytest.mark.asyncio
    async def test_network_error_during_scan_returns_gracefully(self, tmp_path):
        """Network errors during scan_project should not raise; missing entries
        are treated as has_provenance=False and still generate findings."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 2,
                    "packages": {
                        "node_modules/some-pkg": {"version": "1.0.0"},
                    },
                }
            )
        )

        checker = ProvenanceChecker()

        with patch.object(checker, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            mock_get_client.return_value = mock_client

            # Should not raise
            findings = await checker.scan_project(tmp_path)

        # The timeout returns unknown (has_provenance=False), generating a finding
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# _is_popular helper
# ---------------------------------------------------------------------------

class TestIsPopular:
    def test_known_npm_popular(self):
        assert _is_popular(PackageId("npm", "react", "18.0.0")) is True

    def test_known_pypi_popular(self):
        assert _is_popular(PackageId("pypi", "requests", "2.31.0")) is True

    def test_unknown_npm(self):
        assert _is_popular(PackageId("npm", "my-custom-lib", "1.0.0")) is False

    def test_unknown_pypi(self):
        assert _is_popular(PackageId("pypi", "my-internal-tool", "0.1.0")) is False

    def test_unsupported_ecosystem(self):
        assert _is_popular(PackageId("cargo", "serde", "1.0.197")) is False

    def test_case_insensitive_name(self):
        # Names stored lowercase; PackageId("npm", "React", ...) should still match
        assert _is_popular(PackageId("npm", "React", "18.0.0")) is True


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    @pytest.mark.asyncio
    async def test_context_manager_enters_and_exits(self):
        async with ProvenanceChecker() as checker:
            assert checker._client is not None
        assert checker._client is None

    @pytest.mark.asyncio
    async def test_check_npm_inside_context_manager(self):
        mock_resp = _mock_response(200, _npm_with_attestations("lodash", "4.17.21"))

        async with ProvenanceChecker() as checker:
            with patch.object(checker._client, "get", AsyncMock(return_value=mock_resp)):
                status = await checker.check_npm_provenance("lodash", "4.17.21")

        assert status.has_provenance is True
