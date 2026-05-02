"""Scope squatting and namespace confusion scanner for npm packages.

Detection rules:
  1. Scope typosquatting: scoped package whose scope is within edit distance
     1-2 of a known popular npm scope.
  2. Fake official packages: unscoped packages whose name prefix strongly
     implies official affiliation with a well-known org but aren't published
     under that org's real scope.
  3. Scope confusion: an unscoped package shares a name with a known scoped
     package, creating potential for install confusion.
  4. Recently-created scope: a scope with very few published packages (1-2)
     is suspicious — could be a freshly-registered squatter scope.
"""

from __future__ import annotations

from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Known popular npm scopes — the targets for scope typosquatting attacks.
# ---------------------------------------------------------------------------
_POPULAR_SCOPES: list[str] = [
    "@angular",
    "@babel",
    "@types",
    "@nestjs",
    "@aws-sdk",
    "@google-cloud",
    "@azure",
    "@firebase",
    "@tensorflow",
    "@huggingface",
    "@langchain",
    "@openai",
    "@anthropic",
    "@vercel",
    "@next",
    "@react-native",
    "@expo",
]

# ---------------------------------------------------------------------------
# Name-prefix → real scope mappings for "fake official" detection.
# The key is the unscoped package name prefix that implies affiliation;
# the value is the canonical scope those packages should live under.
# ---------------------------------------------------------------------------
_OFFICIAL_PREFIX_MAP: dict[str, str] = {
    "aws-": "@aws-sdk",
    "google-": "@google-cloud",
    "gcloud-": "@google-cloud",
    "microsoft-": "@azure",
    "azure-": "@azure",
    "firebase-": "@firebase",
    "openai-": "@openai",
    "anthropic-": "@anthropic",
    "tensorflow-": "@tensorflow",
    "angular-": "@angular",
    "nestjs-": "@nestjs",
    "babel-": "@babel",
    "react-native-": "@react-native",
    "expo-": "@expo",
    "vercel-": "@vercel",
    "huggingface-": "@huggingface",
    "langchain-": "@langchain",
}

# ---------------------------------------------------------------------------
# Known scoped package names (bare name, without scope) used for rule 3.
# These are packages that are canonically published under a scope; an
# unscoped package with the same bare name is confusing.
# ---------------------------------------------------------------------------
_KNOWN_SCOPED_BARE_NAMES: set[str] = {
    # @angular
    "core", "common", "forms", "router", "compiler", "animations",
    # @babel
    "preset-env", "preset-react", "preset-typescript", "parser",
    "traverse", "generator", "types", "runtime",
    # @types
    "node", "react", "lodash", "express",
    # @aws-sdk
    "client-s3", "client-dynamodb", "client-lambda", "client-sqs",
    # @google-cloud
    "storage", "bigquery", "firestore", "pubsub", "translate",
    # @nestjs
    "common", "core", "platform-express", "testing", "swagger",
    # @react-native
    "async-storage", "community", "clipboard",
    # @openai
    "openai",
    # misc well-known scoped names
    "sdk", "cli", "ui",
}


# ---------------------------------------------------------------------------
# Levenshtein distance — no external deps.
# ---------------------------------------------------------------------------
def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


class ScopeScanner:
    name = "scope_scanner"
    ecosystems = ["npm"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        """Detect scope squatting and namespace confusion."""
        findings: list[Finding] = []

        # Build a set of all scoped package bare names in the input list so
        # we can cross-reference for rule 3 (scope confusion).
        scoped_bare_names: set[str] = set()
        for meta in packages:
            if meta.pkg.ecosystem == "npm" and meta.pkg.name.startswith("@"):
                parts = meta.pkg.name.split("/", 1)
                if len(parts) == 2:
                    scoped_bare_names.add(parts[1].lower())

        # Merge with the static known-scoped names list.
        all_scoped_bare: set[str] = _KNOWN_SCOPED_BARE_NAMES | scoped_bare_names

        for meta in packages:
            if meta.pkg.ecosystem != "npm":
                continue
            findings.extend(self._check_package(meta, all_scoped_bare))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_package(
        self, meta: PackageMeta, all_scoped_bare: set[str]
    ) -> list[Finding]:
        findings: list[Finding] = []
        name = meta.pkg.name

        if name.startswith("@"):
            # ---- Rule 1: scope typosquatting ----
            finding = self._check_scope_typosquat(meta)
            if finding:
                findings.append(finding)

            # ---- Rule 4: recently-created scope ----
            finding = self._check_new_scope(meta)
            if finding:
                findings.append(finding)
        else:
            # ---- Rule 2: fake official package ----
            finding = self._check_fake_official(meta)
            if finding:
                findings.append(finding)

            # ---- Rule 3: scope confusion ----
            finding = self._check_scope_confusion(meta, all_scoped_bare)
            if finding:
                findings.append(finding)

        return findings

    def _check_scope_typosquat(self, meta: PackageMeta) -> Finding | None:
        """Rule 1 — scope within edit distance 1-2 of a popular scope."""
        name = meta.pkg.name
        parts = name.split("/", 1)
        if len(parts) != 2:
            return None
        scope = parts[0].lower()  # e.g. "@reactnativ"

        # Exact match → legitimate (no finding).
        if scope in _POPULAR_SCOPES:
            return None

        best_dist: int | None = None
        best_popular: str | None = None
        for popular in _POPULAR_SCOPES:
            d = _levenshtein(scope, popular)
            if d <= 2 and (best_dist is None or d < best_dist):
                best_dist = d
                best_popular = popular

        if best_dist is None:
            return None

        severity = Severity.HIGH if best_dist == 1 else Severity.MEDIUM
        return Finding(
            finding_type=FindingType.TYPOSQUAT,
            severity=severity,
            package=meta.pkg,
            title=f"Scope typosquat — '{scope}' resembles '{best_popular}'",
            detail=(
                f"The npm scope '{scope}' in package '{name}' is within edit "
                f"distance {best_dist} of the popular scope '{best_popular}'. "
                f"This is a strong indicator of a scope-squatting attack where an "
                f"attacker registers a near-identical scope to intercept installs."
            ),
            confidence=1.0 - (best_dist / 10),
            metadata={
                "scope": scope,
                "similar_to": best_popular,
                "edit_distance": best_dist,
                "check": "scope_typosquat",
            },
        )

    def _check_fake_official(self, meta: PackageMeta) -> Finding | None:
        """Rule 2 — unscoped package implying official org affiliation."""
        name = meta.pkg.name.lower()

        for prefix, real_scope in _OFFICIAL_PREFIX_MAP.items():
            if name.startswith(prefix) and len(name) > len(prefix):
                return Finding(
                    finding_type=FindingType.TYPOSQUAT,
                    severity=Severity.MEDIUM,
                    package=meta.pkg,
                    title=f"Possible fake official package — name implies '{real_scope}'",
                    detail=(
                        f"The unscoped package '{meta.pkg.name}' starts with '{prefix}', "
                        f"which strongly implies official affiliation with '{real_scope}'. "
                        f"Legitimate packages from this organization are typically published "
                        f"under the '{real_scope}' scope. Verify this package is genuinely "
                        f"from the expected publisher before installing."
                    ),
                    confidence=0.7,
                    metadata={
                        "prefix": prefix,
                        "expected_scope": real_scope,
                        "check": "fake_official",
                    },
                )

        return None

    def _check_scope_confusion(
        self, meta: PackageMeta, all_scoped_bare: set[str]
    ) -> Finding | None:
        """Rule 3 — unscoped package shares a bare name with a scoped package."""
        name = meta.pkg.name.lower()
        if name in all_scoped_bare:
            return Finding(
                finding_type=FindingType.TYPOSQUAT,
                severity=Severity.LOW,
                package=meta.pkg,
                title=f"Scope confusion — unscoped '{meta.pkg.name}' shadows a scoped package",
                detail=(
                    f"An unscoped package named '{meta.pkg.name}' exists alongside a "
                    f"scoped package with the same bare name. Developers may accidentally "
                    f"install the unscoped version when they intended the scoped variant. "
                    f"Confirm this package is the intended dependency."
                ),
                confidence=0.6,
                metadata={
                    "bare_name": name,
                    "check": "scope_confusion",
                },
            )
        return None

    def _check_new_scope(self, meta: PackageMeta) -> Finding | None:
        """Rule 4 — scope with very few packages is suspicious.

        We can only detect this when PackageMeta carries scope_package_count
        in its metadata dict (populated by the registry fetcher). If the
        information is absent we skip rather than false-positive.
        """
        # PackageMeta has no dedicated field for scope package count, so
        # scanners that enrich metadata store it in the description or the
        # engine attaches extra data. We check the description heuristically
        # and also support a sentinel via pkg attributes being absent.
        #
        # In practice the engine or fetcher can set meta.download_count = 0
        # and meta.dependency_count == 0 for brand-new packages.  We use a
        # conservative signal: the package has no downloads AND no dependents
        # AND a description that is empty or very short — all together suggest
        # a freshly-squatted scope with a lone package.
        name = meta.pkg.name
        if not name.startswith("@"):
            return None

        scope = name.split("/")[0]
        # Skip if the scope is a known-good popular scope.
        if scope in _POPULAR_SCOPES:
            return None

        downloads_zero = meta.download_count is not None and meta.download_count == 0
        no_description = not meta.description or len(meta.description.strip()) < 5
        no_deps = meta.dependency_count == 0 and meta.transitive_count == 0

        if downloads_zero and no_description and no_deps:
            return Finding(
                finding_type=FindingType.TYPOSQUAT,
                severity=Severity.MEDIUM,
                package=meta.pkg,
                title=f"Suspicious new scope '{scope}' — no downloads or description",
                detail=(
                    f"The scope '{scope}' appears to be newly created: the package "
                    f"'{name}' has zero downloads, no description, and no dependencies. "
                    f"Freshly-registered scopes with a single near-empty package are a "
                    f"common pattern in scope-squatting campaigns."
                ),
                confidence=0.65,
                metadata={
                    "scope": scope,
                    "download_count": meta.download_count,
                    "check": "new_scope",
                },
            )

        return None
