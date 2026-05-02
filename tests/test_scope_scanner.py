"""Tests for scope squatting / namespace confusion scanner."""

import pytest

from depfence.core.models import FindingType, PackageId, PackageMeta, Severity
from depfence.scanners.scope_scanner import ScopeScanner, _levenshtein


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _npm(name: str, version: str = "1.0.0", **kwargs) -> PackageMeta:
    """Convenience factory for npm PackageMeta."""
    return PackageMeta(pkg=PackageId("npm", name, version), **kwargs)


def _pypi(name: str, version: str = "1.0.0") -> PackageMeta:
    return PackageMeta(pkg=PackageId("pypi", name, version))


@pytest.fixture
def scanner() -> ScopeScanner:
    return ScopeScanner()


# ---------------------------------------------------------------------------
# Levenshtein unit tests
# ---------------------------------------------------------------------------

def test_levenshtein_identical():
    assert _levenshtein("@angular", "@angular") == 0


def test_levenshtein_single_deletion():
    # "@angulr" vs "@angular" — 1 insertion away
    assert _levenshtein("@angulr", "@angular") == 1


def test_levenshtein_two_edits():
    assert _levenshtein("@angula", "@angular") == 1
    assert _levenshtein("@angul", "@angular") == 2


def test_levenshtein_empty():
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("abc", "") == 3


# ---------------------------------------------------------------------------
# Rule 1 — Scope typosquatting
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_typosquat_distance_1_high_severity(scanner):
    """@anglar is distance 1 from @angular → HIGH."""
    meta = _npm("@anglar/core")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.TYPOSQUAT
    assert f.severity == Severity.HIGH
    assert "@angular" in f.detail
    assert f.metadata["edit_distance"] == 1


@pytest.mark.asyncio
async def test_scope_typosquat_distance_2_medium_severity(scanner):
    """@angula is distance 2 from @angular → MEDIUM."""
    # "@angula" vs "@angular": drop 'r' and you need edit-dist 1; drop both
    # trailing chars for 2. Let's use "@anglar" already tested as dist-1,
    # so use "@angul" which is dist 2.
    meta = _npm("@angul/core")
    findings = await scanner.scan([meta])
    # @angul is 2 away from @angular
    assert any(f.severity == Severity.MEDIUM for f in findings)
    assert any(f.finding_type == FindingType.TYPOSQUAT for f in findings)


@pytest.mark.asyncio
async def test_scope_typosquat_react_native_variation(scanner):
    """@react-nativ (drop one char) → distance 1 from @react-native."""
    meta = _npm("@react-nativ/utils")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "react-native" in findings[0].detail


@pytest.mark.asyncio
async def test_scope_typosquat_openai_variation(scanner):
    """@openia is distance 2 from @openai -> MEDIUM (still flagged as typosquat)."""
    meta = _npm("@openia/sdk")
    findings = await scanner.scan([meta])
    assert len(findings) == 1
    # edit distance 2 -> MEDIUM severity
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].finding_type == FindingType.TYPOSQUAT


@pytest.mark.asyncio
async def test_scope_legitimate_popular_scope_no_finding(scanner):
    """Exact match on a popular scope should produce no typosquat finding."""
    meta = _npm("@angular/core")
    findings = await scanner.scan([meta])
    typosquat_findings = [f for f in findings if f.metadata.get("check") == "scope_typosquat"]
    assert len(typosquat_findings) == 0


@pytest.mark.asyncio
async def test_scope_completely_different_no_finding(scanner):
    """A scope far from all popular scopes should not trigger."""
    meta = _npm("@my-totally-unique-corp/utils")
    findings = await scanner.scan([meta])
    typosquat_findings = [f for f in findings if f.metadata.get("check") == "scope_typosquat"]
    assert len(typosquat_findings) == 0


@pytest.mark.asyncio
async def test_scope_typosquat_metadata_populated(scanner):
    """Finding metadata must contain scope, similar_to, edit_distance."""
    meta = _npm("@babels/preset-env")
    findings = await scanner.scan([meta])
    # @babels is distance 1 from @babel
    typosquat = [f for f in findings if f.metadata.get("check") == "scope_typosquat"]
    assert len(typosquat) == 1
    md = typosquat[0].metadata
    assert "scope" in md
    assert "similar_to" in md
    assert "edit_distance" in md
    assert md["edit_distance"] <= 2


# ---------------------------------------------------------------------------
# Rule 2 — Fake official packages
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fake_official_aws_prefix(scanner):
    """aws-new-service → implies @aws-sdk affiliation → MEDIUM."""
    meta = _npm("aws-new-service")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 1
    assert fake[0].severity == Severity.MEDIUM
    assert "@aws-sdk" in fake[0].detail


@pytest.mark.asyncio
async def test_fake_official_google_prefix(scanner):
    meta = _npm("google-some-client")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 1
    assert "@google-cloud" in fake[0].detail


@pytest.mark.asyncio
async def test_fake_official_openai_prefix(scanner):
    meta = _npm("openai-unofficial-sdk")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 1
    assert fake[0].finding_type == FindingType.TYPOSQUAT


@pytest.mark.asyncio
async def test_fake_official_azure_prefix(scanner):
    meta = _npm("azure-custom-blob")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 1


@pytest.mark.asyncio
async def test_fake_official_bare_prefix_no_suffix_ignored(scanner):
    """A name that is exactly the prefix (no package name after) should not trigger."""
    # "aws-" alone isn't a real name — but "aws" (no dash) shouldn't match either.
    meta = _npm("aws")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 0


@pytest.mark.asyncio
async def test_fake_official_unrelated_name_clean(scanner):
    meta = _npm("my-custom-library")
    findings = await scanner.scan([meta])
    fake = [f for f in findings if f.metadata.get("check") == "fake_official"]
    assert len(fake) == 0


# ---------------------------------------------------------------------------
# Rule 3 — Scope confusion
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_confusion_with_input_scoped_package(scanner):
    """If input contains @myorg/utils AND utils (unscoped), flag utils."""
    scoped = _npm("@myorg/utils")
    unscoped = _npm("utils")
    findings = await scanner.scan([scoped, unscoped])
    confusion = [f for f in findings if f.metadata.get("check") == "scope_confusion"]
    assert len(confusion) == 1
    assert confusion[0].package == unscoped.pkg
    assert confusion[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_scope_confusion_with_known_static_name(scanner):
    """'node' is in the static known-scoped-names set (@types/node) → flag."""
    meta = _npm("node")
    findings = await scanner.scan([meta])
    confusion = [f for f in findings if f.metadata.get("check") == "scope_confusion"]
    assert len(confusion) == 1
    assert confusion[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_scope_confusion_scoped_package_itself_not_flagged(scanner):
    """The scoped package should NOT get a scope confusion finding."""
    meta = _npm("@types/node")
    findings = await scanner.scan([meta])
    confusion = [f for f in findings if f.metadata.get("check") == "scope_confusion"]
    assert len(confusion) == 0


@pytest.mark.asyncio
async def test_scope_confusion_unique_name_clean(scanner):
    meta = _npm("my-absolutely-unique-lib-xyz")
    findings = await scanner.scan([meta])
    confusion = [f for f in findings if f.metadata.get("check") == "scope_confusion"]
    assert len(confusion) == 0


# ---------------------------------------------------------------------------
# Rule 4 — Recently-created / suspicious new scope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_new_scope_flagged_when_signals_present(scanner):
    """Zero downloads, no description, no deps → flag as suspicious new scope."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@suspicious-new-org/helper", "0.0.1"),
        description="",
        download_count=0,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    new_scope = [f for f in findings if f.metadata.get("check") == "new_scope"]
    assert len(new_scope) == 1
    assert new_scope[0].severity == Severity.MEDIUM
    assert "@suspicious-new-org" in new_scope[0].detail


@pytest.mark.asyncio
async def test_new_scope_not_flagged_when_downloads_present(scanner):
    """Packages with downloads should not trigger the new-scope rule."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@my-new-org/helper", "1.0.0"),
        description="",
        download_count=500,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    new_scope = [f for f in findings if f.metadata.get("check") == "new_scope"]
    assert len(new_scope) == 0


@pytest.mark.asyncio
async def test_new_scope_not_flagged_when_description_present(scanner):
    """Packages with a real description should not trigger the new-scope rule."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@my-new-org/helper", "1.0.0"),
        description="A useful utility library",
        download_count=0,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    new_scope = [f for f in findings if f.metadata.get("check") == "new_scope"]
    assert len(new_scope) == 0


@pytest.mark.asyncio
async def test_new_scope_popular_scope_never_flagged(scanner):
    """Popular scopes are exempted from the new-scope heuristic."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@angular/core", "17.0.0"),
        description="",
        download_count=0,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    new_scope = [f for f in findings if f.metadata.get("check") == "new_scope"]
    assert len(new_scope) == 0


@pytest.mark.asyncio
async def test_new_scope_download_count_none_not_flagged(scanner):
    """If download_count is None (unknown), don't false-positive."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@unknown-org/pkg", "1.0.0"),
        description="",
        download_count=None,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    new_scope = [f for f in findings if f.metadata.get("check") == "new_scope"]
    assert len(new_scope) == 0


# ---------------------------------------------------------------------------
# Ecosystem filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_npm_packages_skipped(scanner):
    """PyPI packages must not be checked by this scanner."""
    meta = _pypi("google-auth")
    findings = await scanner.scan([meta])
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Multiple findings on one package
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_typosquat_and_new_scope_combined(scanner):
    """A package can trigger both scope-typosquat AND new-scope rules."""
    meta = PackageMeta(
        pkg=PackageId("npm", "@angulr/utils", "0.0.1"),
        description="",
        download_count=0,
        dependency_count=0,
        transitive_count=0,
    )
    findings = await scanner.scan([meta])
    checks = {f.metadata.get("check") for f in findings}
    assert "scope_typosquat" in checks
    assert "new_scope" in checks


@pytest.mark.asyncio
async def test_empty_package_list(scanner):
    findings = await scanner.scan([])
    assert findings == []
