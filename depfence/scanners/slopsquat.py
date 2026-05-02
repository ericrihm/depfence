"""Slopsquatting detector — catches packages that may be LLM hallucinations registered as attacks.

Slopsquatting is when attackers register package names that LLMs commonly
hallucinate. 19.7% of LLM-suggested packages don't exist, and 43% of
hallucinated names repeat deterministically — making them reliable targets.

Detection approach:
  1. Edit-distance comparison against popular packages (typosquatting)
  2. Keyboard-proximity analysis (adjacent key substitutions)
  3. Character confusion (l/1, O/0, rn/m, vv/w)
  4. Name-pattern analysis (suspicious prefixes/suffixes on popular names)
  5. Cross-reference against known-hallucinated name patterns
"""

from __future__ import annotations

import re
from itertools import product

from depfence.core.models import Finding, FindingType, PackageMeta, Severity

_POPULAR_NPM = [
    "react", "express", "lodash", "axios", "chalk", "debug", "commander",
    "moment", "webpack", "babel", "eslint", "prettier", "typescript",
    "next", "vue", "angular", "svelte", "fastify", "koa", "nest",
    "mongoose", "sequelize", "prisma", "jest", "mocha", "chai",
    "dotenv", "cors", "helmet", "passport", "jsonwebtoken", "bcrypt",
    "socket.io", "cheerio", "puppeteer", "playwright",
    "huggingface", "transformers", "langchain", "openai", "anthropic",
]

_POPULAR_PYPI = [
    "requests", "flask", "django", "numpy", "pandas", "scipy",
    "tensorflow", "torch", "pytorch", "transformers", "scikit-learn",
    "matplotlib", "pillow", "beautifulsoup4", "scrapy", "celery",
    "fastapi", "uvicorn", "pydantic", "sqlalchemy", "alembic",
    "boto3", "httpx", "aiohttp", "pytest", "black", "ruff",
    "langchain", "openai", "anthropic", "huggingface-hub", "diffusers",
    "litellm", "llamaindex", "chromadb", "pinecone",
]

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
    "d": ["cl"],
    "cl": ["d"],
    "nn": ["m"],
}

_KEYBOARD_ADJACENT: dict[str, str] = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yijh", "i": "uokj", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
    "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "iolmj",
    "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}


class SlopsquatScanner:
    name = "slopsquat"
    ecosystems = ["npm", "pypi"]

    def __init__(self) -> None:
        self._popular = {
            "npm": set(_POPULAR_NPM),
            "pypi": set(_POPULAR_PYPI),
        }

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for meta in packages:
            findings.extend(self._check_package(meta))
        return findings

    def _check_package(self, meta: PackageMeta) -> list[Finding]:
        name = meta.pkg.name.lower()
        eco = meta.pkg.ecosystem
        popular = self._popular.get(eco, set())

        if name in popular:
            return []

        best_match = None
        best_score = 0.0
        best_reason = ""

        for pop_name in popular:
            score, reason = self._similarity_score(name, pop_name)
            if score > best_score:
                best_score = score
                best_match = pop_name
                best_reason = reason

        if best_score >= 0.7:
            severity = Severity.HIGH if best_score >= 0.85 else Severity.MEDIUM
            return [Finding(
                finding_type=FindingType.SLOPSQUAT,
                severity=severity,
                package=meta.pkg,
                title=f"Possible slopsquat/typosquat of '{best_match}'",
                detail=(
                    f"Package '{name}' is suspiciously similar to popular package "
                    f"'{best_match}' ({best_reason}). Score: {best_score:.2f}. "
                    f"This may be a typosquat or a hallucinated package name "
                    f"registered by an attacker."
                ),
                confidence=best_score,
                metadata={
                    "similar_to": best_match,
                    "score": best_score,
                    "reason": best_reason,
                },
            )]

        return []

    def _similarity_score(self, name: str, popular: str) -> tuple[float, str]:
        scores: list[tuple[float, str]] = []

        # Edit distance
        dist = _levenshtein(name, popular)
        max_len = max(len(name), len(popular))
        if max_len > 0 and dist <= 2:
            edit_score = 1.0 - (dist / max_len)
            scores.append((edit_score, f"edit distance {dist}"))

        # Character confusion
        confusion_score = self._char_confusion_score(name, popular)
        if confusion_score > 0:
            scores.append((confusion_score, "character confusion"))

        # Keyboard proximity
        if dist == 1:
            kbd_score = self._keyboard_proximity_score(name, popular)
            if kbd_score > 0:
                scores.append((kbd_score, "keyboard proximity"))

        # Prefix/suffix manipulation
        prefix_score = self._prefix_suffix_score(name, popular)
        if prefix_score > 0:
            scores.append((prefix_score, "name manipulation"))

        # Separator swaps (lodash vs lodash-js vs lodash_js)
        sep_score = self._separator_score(name, popular)
        if sep_score > 0:
            scores.append((sep_score, "separator variation"))

        if not scores:
            return (0.0, "")
        best = max(scores, key=lambda x: x[0])
        return best

    def _char_confusion_score(self, name: str, popular: str) -> float:
        if len(name) != len(popular):
            for orig, replacements in _CHAR_CONFUSIONS.items():
                for repl in replacements:
                    confused = popular.replace(orig, repl, 1)
                    if confused == name:
                        return 0.9
        return 0.0

    def _keyboard_proximity_score(self, name: str, popular: str) -> float:
        if len(name) != len(popular):
            return 0.0
        diffs = [(i, name[i], popular[i]) for i in range(len(name)) if name[i] != popular[i]]
        if len(diffs) == 1:
            _, typed, intended = diffs[0]
            adjacent = _KEYBOARD_ADJACENT.get(intended, "")
            if typed in adjacent:
                return 0.85
        return 0.0

    def _prefix_suffix_score(self, name: str, popular: str) -> float:
        manipulations = [
            f"{popular}-js", f"{popular}js", f"js-{popular}",
            f"{popular}-node", f"node-{popular}",
            f"{popular}-cli", f"{popular}-tool", f"{popular}-utils",
            f"{popular}-core", f"{popular}-lib", f"{popular}-sdk",
            f"{popular}-api", f"{popular}-client", f"{popular}-server",
            f"py{popular}", f"python-{popular}", f"{popular}-py",
            f"{popular}2", f"{popular}3", f"{popular}x",
            f"@anthropic/{popular}", f"@openai/{popular}",
        ]
        if name in manipulations:
            return 0.75
        if name == f"{popular}s" or name == f"{popular}es":
            return 0.8
        return 0.0

    def _separator_score(self, name: str, popular: str) -> float:
        normalized_name = name.replace("-", "").replace("_", "").replace(".", "")
        normalized_pop = popular.replace("-", "").replace("_", "").replace(".", "")
        if normalized_name == normalized_pop and name != popular:
            return 0.85
        return 0.0


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
