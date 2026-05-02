"""Package reputation scoring — composite score from multiple signals.

Enhanced with:
- Typosquatting detection (edit distance, separator confusion, prefix/suffix, scope)
- Name similarity scoring (Levenshtein) against top popular packages per ecosystem
- Age/popularity heuristics (newly created packages shadowing popular names)
- Known malicious pattern detection (install scripts, obfuscation markers)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageMeta, Severity

# ---------------------------------------------------------------------------
# Popular package registry
# ---------------------------------------------------------------------------

def _load_popular_packages() -> dict[str, list[str]]:
    """Load popular packages from the bundled JSON registry."""
    data_path = Path(__file__).parent.parent / "data" / "popular_packages.json"
    try:
        with data_path.open() as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"npm": [], "pypi": []}


_POPULAR_PACKAGES: dict[str, list[str]] = _load_popular_packages()


# ---------------------------------------------------------------------------
# Malicious pattern regexes
# ---------------------------------------------------------------------------

_RE_NETWORK_IN_SCRIPT = re.compile(
    r"""(?:curl|wget|fetch|http\.get|https\.get|urllib\.request|requests\.get|"""
    r"""socket\.connect|subprocess.*?(?:curl|wget|nc\b|ncat|netcat))""",
    re.IGNORECASE,
)

_RE_BASE64_EXEC = re.compile(
    r"""(?:eval|exec|Function)\s*\(?\s*"""
    r"""(?:atob|Buffer\.from|base64\.b64decode|codecs\.decode|bytes\.fromhex)\s*\(""",
    re.IGNORECASE,
)

_RE_OBFUSCATED_BASE64 = re.compile(
    r"""(?<![#"\'])([A-Za-z0-9+/]{60,}={0,2})""",
)

_RE_ENV_EXFIL = re.compile(
    r"""(?:process\.env|os\.environ|getenv)\b.*?(?:http|curl|fetch|requests)""",
    re.IGNORECASE | re.DOTALL,
)

_RE_POSTINSTALL_NET = re.compile(
    r"""postinstall.*?(?:curl|wget|http|fetch)""",
    re.IGNORECASE,
)

_RE_SHELL_EXEC = re.compile(
    r"""(?:child_process|subprocess|os\.system|popen|shell_exec|exec\s*\()""",
    re.IGNORECASE,
)

# Common suspicious prefix/suffix patterns used to impersonate popular packages
_SUSPICIOUS_SUFFIXES = [
    "-js", "js", "-node", "-lib", "-sdk", "-api", "-cli", "-tool",
    "-utils", "-util", "-core", "-extra", "-plus", "-pro", "-free",
    "-fork", "-fix", "-patch", "-new", "-next", "-v2", "-v3",
    "2", "3", "x", "s",
]
_SUSPICIOUS_PREFIXES = [
    "py", "python-", "python_", "node-", "js-",
    "get-", "use-", "is-", "has-", "to-", "from-",
]


# ---------------------------------------------------------------------------
# Levenshtein distance (pure Python, no deps)
# ---------------------------------------------------------------------------

def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


# ---------------------------------------------------------------------------
# Typosquatting helpers
# ---------------------------------------------------------------------------

# Character confusions commonly exploited (leet-speak style + visual)
_CHAR_CONFUSIONS: dict[str, list[str]] = {
    "l": ["1", "i", "I"],
    "1": ["l", "i"],
    "0": ["o", "O"],
    "o": ["0"],
    "O": ["0"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "cl": ["d"],
    "d": ["cl"],
    "nn": ["m"],
}


def _normalize_separators(name: str) -> str:
    """Strip hyphens, underscores, dots for separator-confusion comparison."""
    return name.replace("-", "").replace("_", "").replace(".", "")


def _strip_scope(name: str) -> str:
    """Remove npm scope prefix: @scope/name -> name."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


def _char_confused(name: str, popular: str) -> bool:
    """Return True if name is a single character-confusion away from popular."""
    for orig, replacements in _CHAR_CONFUSIONS.items():
        for repl in replacements:
            candidate = popular.replace(orig, repl, 1)
            if candidate == name and candidate != popular:
                return True
    return False


def _typosquat_similarity(name: str, popular: str) -> tuple[float, str]:
    """
    Return (score, reason) where score in [0, 1].
    0.0 means no similarity; 1.0 means identical (caller already filters that).
    """
    name_low = name.lower()
    pop_low = popular.lower()

    # 1. Exact separator confusion (python_dateutil vs python-dateutil)
    if _normalize_separators(name_low) == _normalize_separators(pop_low) and name_low != pop_low:
        return (0.92, "separator confusion (hyphen/underscore/dot swap)")

    # 2. Scope stripping (babel-core vs @babel/core)
    if _strip_scope(name_low) == _strip_scope(pop_low) and name_low != pop_low:
        return (0.88, "npm scope confusion")

    # 3. Character confusion (l1, O0, rn/m ...)
    if _char_confused(name_low, pop_low):
        return (0.90, "character substitution (visual/leet confusion)")

    # 4. Levenshtein <= 2
    max_len = max(len(name_low), len(pop_low))
    if max_len == 0:
        return (0.0, "")
    dist = _levenshtein(name_low, pop_low)
    if dist == 1:
        return (1.0 - 1.0 / max_len, f"edit distance 1 from '{popular}'")
    if dist == 2 and max_len >= 6:
        return (1.0 - 2.0 / max_len, f"edit distance 2 from '{popular}'")

    # 5. Prefix / suffix additions
    for sfx in _SUSPICIOUS_SUFFIXES:
        if name_low == pop_low + sfx or name_low == pop_low.rstrip("-_") + sfx:
            return (0.78, f"suspicious suffix addition ('{sfx}')")
    for pfx in _SUSPICIOUS_PREFIXES:
        if name_low == pfx + pop_low or name_low == pfx + pop_low.lstrip("-_"):
            return (0.78, f"suspicious prefix addition ('{pfx}')")

    return (0.0, "")


# ---------------------------------------------------------------------------
# Malicious pattern scanner (operates on raw text)
# ---------------------------------------------------------------------------

def detect_malicious_patterns(text: str) -> list[tuple[str, Severity]]:
    """
    Scan arbitrary text (e.g. setup.py contents, package.json scripts) for
    patterns commonly used in malicious packages.

    Returns a list of (description, Severity) tuples.
    """
    findings: list[tuple[str, Severity]] = []

    if _RE_BASE64_EXEC.search(text):
        findings.append((
            "Base64-encoded payload decoded and executed at runtime (common exfil pattern)",
            Severity.CRITICAL,
        ))

    if _RE_OBFUSCATED_BASE64.search(text):
        findings.append((
            "Long base64-like string found — may be hidden payload",
            Severity.HIGH,
        ))

    if _RE_NETWORK_IN_SCRIPT.search(text):
        findings.append((
            "Install/setup script appears to make network calls (curl/wget/requests)",
            Severity.HIGH,
        ))

    if _RE_ENV_EXFIL.search(text):
        findings.append((
            "Environment variable access combined with network call — potential credential exfiltration",
            Severity.CRITICAL,
        ))

    if _RE_POSTINSTALL_NET.search(text):
        findings.append((
            "postinstall script contains network call",
            Severity.HIGH,
        ))

    if _RE_SHELL_EXEC.search(text):
        findings.append((
            "Shell execution (subprocess/child_process/os.system) detected in install context",
            Severity.MEDIUM,
        ))

    return findings


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class ReputationScanner:
    name = "reputation"
    ecosystems = ["npm", "pypi", "cargo", "go"]

    # Tunable thresholds
    TYPOSQUAT_THRESHOLD = 0.75       # similarity score that triggers a finding
    TYPOSQUAT_HIGH_THRESHOLD = 0.88  # above this -> HIGH severity
    LOW_SCORE_THRESHOLD = 40         # reputation score below which we emit a finding
    VERY_NEW_DAYS = 7                # packages newer than this are "very new"
    NEW_DAYS = 30                    # packages newer than this are "new"
    LOW_DOWNLOADS = 100              # weekly download threshold for "no traction"

    def __init__(self) -> None:
        # Build lookup sets for O(1) membership test
        self._popular_sets: dict[str, set[str]] = {
            eco: {p.lower() for p in pkgs}
            for eco, pkgs in _POPULAR_PACKAGES.items()
        }
        # Keep ordered lists for similarity scanning
        self._popular_lists: dict[str, list[str]] = {
            eco: [p.lower() for p in pkgs]
            for eco, pkgs in _POPULAR_PACKAGES.items()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for meta in packages:
            findings.extend(self._analyze(meta))
        return findings

    # ------------------------------------------------------------------
    # Core analysis (synchronous, usable in tests without async)
    # ------------------------------------------------------------------

    def analyze(self, meta: PackageMeta) -> list[Finding]:
        """Synchronous entry point for unit testing."""
        return self._analyze(meta)

    def _analyze(self, meta: PackageMeta) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Typosquatting check
        findings.extend(self._check_typosquat(meta))

        # 2. Reputation score + age/popularity heuristics
        score = self.compute_score(meta)
        if score < self.LOW_SCORE_THRESHOLD:
            findings.append(Finding(
                finding_type=FindingType.REPUTATION,
                severity=Severity.HIGH if score < 20 else Severity.MEDIUM,
                package=meta.pkg,
                title=f"Low reputation score: {score}/100",
                detail=self._explain_score(meta, score),
                confidence=min(1.0, (100 - score) / 100),
                metadata={"reputation_score": score},
            ))

        # 3. Age + name-shadowing combo (very new package with popular-ish name)
        findings.extend(self._check_age_shadow(meta))

        # 4. Suspicious download count
        findings.extend(self._check_download_heuristics(meta))

        # 5. Malicious pattern detection via install-script flag + description hints
        findings.extend(self._check_malicious_patterns(meta))

        return findings

    # ------------------------------------------------------------------
    # 1. Typosquatting
    # ------------------------------------------------------------------

    def _check_typosquat(self, meta: PackageMeta) -> list[Finding]:
        eco = meta.pkg.ecosystem
        popular = self._popular_lists.get(eco, [])
        if not popular:
            return []

        name = meta.pkg.name.lower()

        # If this IS a known-popular package, skip
        if name in self._popular_sets.get(eco, set()):
            return []

        best_score = 0.0
        best_match = ""
        best_reason = ""

        for pop in popular:
            if pop == name:
                continue
            score, reason = _typosquat_similarity(name, pop)
            if score > best_score:
                best_score = score
                best_match = pop
                best_reason = reason

        if best_score >= self.TYPOSQUAT_THRESHOLD:
            severity = (
                Severity.HIGH
                if best_score >= self.TYPOSQUAT_HIGH_THRESHOLD
                else Severity.MEDIUM
            )
            return [Finding(
                finding_type=FindingType.TYPOSQUAT,
                severity=severity,
                package=meta.pkg,
                title=f"Possible typosquat of '{best_match}'",
                detail=(
                    f"Package '{meta.pkg.name}' is suspiciously similar to well-known "
                    f"package '{best_match}' ({best_reason}). "
                    f"Similarity score: {best_score:.2f}. "
                    f"Verify this is the intended dependency."
                ),
                confidence=best_score,
                metadata={
                    "similar_to": best_match,
                    "similarity_score": best_score,
                    "reason": best_reason,
                },
            )]

        return []

    # ------------------------------------------------------------------
    # 2. Reputation score
    # ------------------------------------------------------------------

    def compute_score(self, meta: PackageMeta) -> int:
        score = 50

        # Age signals
        if meta.first_published:
            tz = timezone.utc
            pub = meta.first_published
            if pub.tzinfo is None:
                pub = pub.replace(tzinfo=tz)
            age_days = (datetime.now(tz) - pub).days
            if age_days > 365:
                score += 15
            elif age_days > 90:
                score += 8
            elif age_days < self.VERY_NEW_DAYS:
                score -= 20
            elif age_days < self.NEW_DAYS:
                score -= 10

        # Maintainer signals
        if meta.maintainers:
            if len(meta.maintainers) >= 3:
                score += 10
            elif len(meta.maintainers) == 1:
                score -= 5
            if any(m.recent_ownership_change for m in meta.maintainers):
                score -= 25

        # Repository presence
        if meta.repository:
            score += 10
        else:
            score -= 10

        # Provenance / supply-chain attestation
        if meta.has_provenance:
            score += 10

        # Install scripts (postinstall etc.) lower trust
        if meta.has_install_scripts:
            score -= 10

        # Description quality
        if meta.description:
            if len(meta.description) < 10:
                score -= 5
        else:
            score -= 10

        # License
        if meta.license:
            score += 5
        else:
            score -= 5

        # Download count signals
        if meta.download_count is not None:
            if meta.download_count == 0:
                score -= 15
            elif meta.download_count < self.LOW_DOWNLOADS:
                score -= 8

        # Native code with no provenance is riskier
        if meta.has_native_code and not meta.has_provenance:
            score -= 8

        return max(0, min(100, score))

    # ------------------------------------------------------------------
    # 3. Age / name-shadowing
    # ------------------------------------------------------------------

    def _check_age_shadow(self, meta: PackageMeta) -> list[Finding]:
        """Flag very-new packages that share a close name with a popular package."""
        if not meta.first_published:
            return []

        tz = timezone.utc
        pub = meta.first_published
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=tz)
        age_days = (datetime.now(tz) - pub).days

        if age_days >= self.VERY_NEW_DAYS:
            return []

        eco = meta.pkg.ecosystem
        popular = self._popular_lists.get(eco, [])
        if not popular:
            return []

        name = meta.pkg.name.lower()
        if name in self._popular_sets.get(eco, set()):
            return []

        # Check if any popular package has a Levenshtein distance <= 3
        for pop in popular:
            dist = _levenshtein(name, pop)
            if dist <= 3:
                return [Finding(
                    finding_type=FindingType.TYPOSQUAT,
                    severity=Severity.HIGH,
                    package=meta.pkg,
                    title=f"Very new package shadows popular name '{pop}'",
                    detail=(
                        f"Package '{meta.pkg.name}' was published only {age_days} day(s) ago "
                        f"and has a name very close to well-known package '{pop}' "
                        f"(edit distance {dist}). This is a strong typosquatting signal."
                    ),
                    confidence=0.85,
                    metadata={
                        "age_days": age_days,
                        "similar_to": pop,
                        "edit_distance": dist,
                    },
                )]

        return []

    # ------------------------------------------------------------------
    # 4. Download heuristics
    # ------------------------------------------------------------------

    def _check_download_heuristics(self, meta: PackageMeta) -> list[Finding]:
        findings: list[Finding] = []
        if meta.download_count is None:
            return findings

        if meta.download_count == 0:
            findings.append(Finding(
                finding_type=FindingType.REPUTATION,
                severity=Severity.LOW,
                package=meta.pkg,
                title="Package has zero recorded downloads",
                detail=(
                    "This package has never been downloaded according to registry data. "
                    "It may be a test package, a typosquat, or an unpublished placeholder."
                ),
                confidence=0.7,
                metadata={"download_count": 0},
            ))
        elif meta.download_count < self.LOW_DOWNLOADS:
            findings.append(Finding(
                finding_type=FindingType.REPUTATION,
                severity=Severity.INFO,
                package=meta.pkg,
                title=f"Very low download count ({meta.download_count})",
                detail=(
                    f"Only {meta.download_count} downloads recorded. "
                    "Low-traction packages receive less community scrutiny."
                ),
                confidence=0.6,
                metadata={"download_count": meta.download_count},
            ))

        return findings

    # ------------------------------------------------------------------
    # 5. Malicious pattern detection
    # ------------------------------------------------------------------

    def _check_malicious_patterns(self, meta: PackageMeta) -> list[Finding]:
        """
        Detect patterns commonly seen in malicious packages using meta-level signals.

        For deep source scanning, use the ObfuscationScanner and NetworkScanner.
        This method provides lightweight heuristics based on PackageMeta fields.
        """
        findings: list[Finding] = []

        # Install script present with zero/low downloads — high suspicion
        if meta.has_install_scripts and (
            meta.download_count is not None and meta.download_count < self.LOW_DOWNLOADS
        ):
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=meta.pkg,
                title="Install script on near-zero-download package",
                detail=(
                    f"'{meta.pkg.name}' has an install script (postinstall/preinstall) "
                    f"but only {meta.download_count} downloads. Install scripts in "
                    "obscure packages are a primary supply-chain attack vector."
                ),
                confidence=0.80,
                metadata={
                    "has_install_scripts": True,
                    "download_count": meta.download_count,
                },
            ))
        elif meta.has_install_scripts:
            # General install-script finding (less severe)
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.LOW,
                package=meta.pkg,
                title="Package has install scripts",
                detail=(
                    f"'{meta.pkg.name}' registers postinstall/preinstall scripts. "
                    "These run automatically on npm install and may execute arbitrary code."
                ),
                confidence=0.6,
                metadata={"has_install_scripts": True},
            ))

        # Description matches known obfuscation description markers
        desc = meta.description or ""
        if _RE_OBFUSCATED_BASE64.search(desc):
            findings.append(Finding(
                finding_type=FindingType.OBFUSCATION,
                severity=Severity.HIGH,
                package=meta.pkg,
                title="Obfuscated content in package description",
                detail=(
                    "The package description contains what appears to be base64-encoded data. "
                    "Malicious packages sometimes embed payloads in description fields."
                ),
                confidence=0.75,
                metadata={},
            ))

        # Native code with no provenance and install scripts = triple risk
        if meta.has_native_code and meta.has_install_scripts and not meta.has_provenance:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=meta.pkg,
                title="Native code + install scripts + no provenance",
                detail=(
                    f"'{meta.pkg.name}' has native compiled code, install scripts, "
                    "and no supply-chain provenance attestation. This combination "
                    "is used by sophisticated supply-chain attacks."
                ),
                confidence=0.85,
                metadata={
                    "has_native_code": True,
                    "has_install_scripts": True,
                    "has_provenance": False,
                },
            ))

        return findings

    # ------------------------------------------------------------------
    # Explanation helpers
    # ------------------------------------------------------------------

    def _explain_score(self, meta: PackageMeta, score: int) -> str:
        reasons: list[str] = []

        if not meta.repository:
            reasons.append("no source repository linked")
        if not meta.description or len(meta.description) < 10:
            reasons.append("missing or minimal description")
        if meta.has_install_scripts:
            reasons.append("has install scripts")
        if not meta.has_provenance and meta.pkg.ecosystem == "npm":
            reasons.append("no provenance attestation")
        if meta.maintainers and any(m.recent_ownership_change for m in meta.maintainers):
            reasons.append("recent maintainer ownership change")
        if not meta.license:
            reasons.append("no license specified")
        if meta.download_count is not None and meta.download_count < self.LOW_DOWNLOADS:
            reasons.append(f"very low download count ({meta.download_count})")
        if meta.first_published:
            tz = timezone.utc
            pub = meta.first_published
            if pub.tzinfo is None:
                pub = pub.replace(tzinfo=tz)
            age_days = (datetime.now(tz) - pub).days
            if age_days < self.VERY_NEW_DAYS:
                reasons.append(f"published only {age_days} day(s) ago")

        if reasons:
            return f"Reputation score {score}/100. Concerns: {'; '.join(reasons)}."
        return f"Reputation score {score}/100."
