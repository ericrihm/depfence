"""Typosquatting detector using multiple string distance algorithms.

Identifies potential typosquat packages by comparing against popular package
lists using Levenshtein distance, keyboard proximity, and common substitution
patterns.
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Popular package lists (top ~200 per ecosystem)
# ---------------------------------------------------------------------------

POPULAR_NPM: list[str] = [
    "react", "express", "lodash", "axios", "chalk", "commander", "debug",
    "moment", "request", "webpack", "babel-core", "typescript", "eslint",
    "prettier", "jest", "mocha", "next", "vue", "angular", "svelte",
    "underscore", "async", "glob", "minimist", "yargs", "inquirer", "ora",
    "colors", "dotenv", "uuid", "semver", "rimraf", "mkdirp", "fs-extra",
    "node-fetch", "got", "superagent", "cheerio", "puppeteer", "playwright",
    "bluebird", "q", "rxjs", "ramda", "immutable", "redux", "mobx",
    "socket.io", "cors", "body-parser", "multer", "passport", "jsonwebtoken",
    "bcrypt", "nodemailer", "mongoose", "sequelize", "knex", "typeorm",
    "prisma", "graphql", "apollo-server", "grpc", "protobufjs", "ws",
    "handlebars", "ejs", "pug", "mustache", "nunjucks", "marked", "showdown",
    "lodash-es", "date-fns", "dayjs", "luxon", "validator", "joi", "yup",
    "zod", "ajv", "yaml", "toml", "ini", "dotenv-expand", "cross-env",
    "concurrently", "nodemon", "pm2", "forever", "nvm", "volta",
    "webpack-cli", "rollup", "parcel", "vite", "esbuild", "swc",
    "babel-preset-env", "babel-loader", "ts-node", "tsx", "tsc",
    "eslint-plugin-react", "eslint-config-prettier", "husky", "lint-staged",
    "commitlint", "conventional-changelog", "semantic-release", "lerna",
    "turborepo", "nx", "rush", "changesets",
    "react-dom", "react-router", "react-router-dom", "react-query",
    "react-hook-form", "react-table", "react-select", "react-modal",
    "vue-router", "vuex", "pinia", "nuxt",
    "tailwindcss", "postcss", "autoprefixer", "sass", "less", "stylus",
    "classnames", "styled-components", "emotion", "stitches",
    "framer-motion", "gsap", "three", "d3", "chart.js", "recharts",
    "lodash.get", "lodash.set", "lodash.merge", "lodash.clonedeep",
    "mime", "mime-types", "content-type", "accepts", "negotiator",
    "path-to-regexp", "qs", "querystring", "url-parse", "whatwg-url",
    "form-data", "multiparty", "busboy", "formidable",
    "sharp", "jimp", "canvas", "svg.js",
    "winston", "pino", "bunyan", "loglevel", "debug",
    "config", "convict", "nconf", "rc",
    "redis", "ioredis", "memcached", "level",
    "aws-sdk", "azure-sdk", "google-cloud", "firebase",
    "stripe", "paypal", "braintree",
    "twilio", "sendgrid", "mailchimp",
    "jest-dom", "testing-library", "enzyme", "sinon", "chai", "nock",
    "supertest", "cypress", "playwright-chromium",
    "execa", "cross-spawn", "which", "shell-quote",
    "tar", "archiver", "unzipper", "decompress",
    "csv-parse", "csv-stringify", "papaparse", "xlsx",
    "pdf-lib", "pdfkit", "puppeteer-pdf",
    "jsdom", "htmlparser2", "parse5", "node-html-parser",
    "cron", "node-schedule", "agenda", "bull", "bee-queue",
    "dotenv", "envalid", "env-var",
    "pLimit", "throat", "bottleneck", "p-queue",
    "flat", "deepmerge", "merge-deep", "object-assign",
    "memoize", "lru-cache", "node-cache", "memory-cache",
    "event-emitter", "mitt", "nanoevents", "eventemitter3",
    "uuid", "nanoid", "cuid", "ulid", "shortid",
    "he", "entities", "html-entities", "striptags",
    "dompurify", "sanitize-html", "xss",
    "argparse", "meow", "cac", "caporal",
    "open", "opener", "opn",
    "clipboardy", "copy-paste",
    "qrcode", "jsbarcode",
    "socket.io-client", "sockjs", "primus",
    "mqtt", "aedes", "mosca",
    "kafka-node", "kafkajs", "amqplib", "rhea",
    "ssh2", "node-ssh", "sftp",
    "ldapjs", "activedirectory2",
    "node-forge", "crypto-js", "tweetnacl",
    "passport-local", "passport-jwt", "passport-google-oauth20",
    "helmet", "csurf", "express-rate-limit", "express-validator",
    "morgan", "compression", "serve-static",
    "connect", "finalhandler", "on-finished",
    "depd", "inherits", "util-deprecate",
    "readable-stream", "through2", "pump", "pumpify",
    "concat-stream", "get-stream", "into-stream",
    "is-stream", "is-buffer", "is-plain-object",
    "type-fest", "ts-essentials", "utility-types",
]

POPULAR_PYPI: list[str] = [
    "requests", "flask", "django", "numpy", "pandas", "scipy", "matplotlib",
    "tensorflow", "torch", "transformers", "fastapi", "sqlalchemy", "celery",
    "boto3", "pillow", "cryptography", "pydantic", "httpx", "aiohttp",
    "beautifulsoup4", "scrapy", "pytest", "black", "mypy", "ruff", "poetry",
    "setuptools", "wheel", "pip", "virtualenv", "click", "rich", "typer",
    "langchain", "openai", "anthropic", "litellm", "gradio", "streamlit",
    "huggingface-hub", "scikit-learn", "xgboost", "lightgbm", "catboost",
    "keras", "jax", "flax", "optax", "haiku",
    "uvicorn", "gunicorn", "starlette", "sanic", "aiohttp", "tornado",
    "django-rest-framework", "flask-restful", "marshmallow", "cerberus",
    "alembic", "peewee", "tortoise-orm", "databases", "asyncpg", "aiomysql",
    "psycopg2", "pymysql", "pymongo", "motor", "redis", "aioredis",
    "elasticsearch", "opensearch-py", "cassandra-driver", "aiokafka",
    "pika", "kombu", "dramatiq", "rq", "apscheduler",
    "pytest-asyncio", "pytest-mock", "pytest-cov", "pytest-xdist",
    "hypothesis", "faker", "factory-boy", "model-bakery",
    "coverage", "codecov", "coveralls",
    "pylint", "flake8", "bandit", "safety", "pip-audit",
    "isort", "autopep8", "yapf", "pyupgrade",
    "sphinx", "mkdocs", "pdoc", "pydoc-markdown",
    "loguru", "structlog", "python-json-logger",
    "python-dotenv", "dynaconf", "pydantic-settings", "decouple",
    "arrow", "pendulum", "dateutil", "pytz", "tzdata",
    "attrs", "cattrs", "dataclasses-json", "dacite",
    "tenacity", "backoff", "retry", "stamina",
    "tqdm", "alive-progress", "yaspin", "halo",
    "tabulate", "prettytable", "texttable",
    "colorama", "termcolor", "blessed", "curtsies",
    "jinja2", "mako", "chameleon", "cheetah3",
    "lxml", "html5lib", "cssselect", "pyquery",
    "selenium", "playwright", "mechanize", "httpretty",
    "paramiko", "fabric", "invoke", "plumbum",
    "pexpect", "ptyprocess", "sh",
    "psutil", "py-spy", "memory-profiler", "objgraph",
    "pyzmq", "pynng", "nanomsg",
    "grpcio", "protobuf", "thrift", "avro",
    "pyyaml", "toml", "tomli", "tomllib",
    "python-multipart", "multidict", "yarl",
    "chardet", "charset-normalizer", "cchardet",
    "certifi", "urllib3", "httplib2", "treq",
    "twisted", "gevent", "greenlet", "eventlet",
    "trio", "anyio", "asyncio-throttle",
    "pytest-trio", "pytest-anyio",
    "networkx", "igraph", "graph-tool",
    "sympy", "mpmath", "gmpy2",
    "nltk", "spacy", "gensim", "fasttext",
    "cv2", "imageio", "scikit-image", "Wand",
    "pyaudio", "librosa", "soundfile",
    "reportlab", "fpdf2", "weasyprint", "pdfminer",
    "xlrd", "xlwt", "openpyxl", "xlsxwriter",
    "pyarrow", "fastparquet", "feather-format",
    "dask", "ray", "joblib", "multiprocess",
    "cffi", "ctypes", "cython", "numba",
    "python-dateutil", "isodate", "humanize",
    "passlib", "itsdangerous", "pyjwt", "oauthlib",
    "google-auth", "azure-identity", "msal",
    "aws-cdk", "pulumi", "troposphere", "awscli",
    "parameterized", "nose", "unittest2",
    "mock", "responses", "vcrpy", "respx",
    "freezegun", "time-machine", "fakeredis",
    "pydantic-v1", "pydantic-extra-types",
    "starlette-testclient", "httpx-mock",
    "sentry-sdk", "rollbar", "bugsnag",
    "datadog", "prometheus-client", "opentelemetry-sdk",
    "boto3-stubs", "types-requests", "types-redis",
    "django-debug-toolbar", "flask-debugtoolbar",
    "python-slugify", "unidecode", "ftfy",
    "qrcode", "barcode", "pillow-avif-plugin",
    "pygments", "colorlog", "icecream",
    "invoke", "nox", "tox", "hatch",
    "flit", "pdm", "build", "installer",
    "packaging", "importlib-metadata", "importlib-resources",
    "platformdirs", "appdirs", "click-completion",
    "questionary", "prompt-toolkit", "readline",
]

# ---------------------------------------------------------------------------
# QWERTY keyboard layout for proximity scoring
# ---------------------------------------------------------------------------

# Map each key to its (row, col) position on a standard QWERTY keyboard
_QWERTY_POS: dict[str, tuple[int, float]] = {
    # row 0 (numbers)
    "1": (0, 0), "2": (0, 1), "3": (0, 2), "4": (0, 3), "5": (0, 4),
    "6": (0, 5), "7": (0, 6), "8": (0, 7), "9": (0, 8), "0": (0, 9),
    # row 1 (qwerty)
    "q": (1, 0), "w": (1, 1), "e": (1, 2), "r": (1, 3), "t": (1, 4),
    "y": (1, 5), "u": (1, 6), "i": (1, 7), "o": (1, 8), "p": (1, 9),
    # row 2 (asdf) — offset by 0.5
    "a": (2, 0.5), "s": (2, 1.5), "d": (2, 2.5), "f": (2, 3.5),
    "g": (2, 4.5), "h": (2, 5.5), "j": (2, 6.5), "k": (2, 7.5),
    "l": (2, 8.5),
    # row 3 (zxcv) — offset by 1.0
    "z": (3, 1.0), "x": (3, 2.0), "c": (3, 3.0), "v": (3, 4.0),
    "b": (3, 5.0), "n": (3, 6.0), "m": (3, 7.0),
}

# Homoglyph substitution table
_HOMOGLYPHS: dict[str, list[str]] = {
    "l": ["1", "I"],
    "o": ["0"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["@", "4"],
    "s": ["5", "$"],
    "b": ["6"],
    "g": ["9"],
    "t": ["7"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "cl": ["d"],
    "d": ["cl"],
}

# Separator characters used in package names
_SEPARATORS = ["-", "_", ".", ""]


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class TyposquatMatch:
    suspect: str
    target: str
    distance: int
    confidence: float  # 0–1
    attack_type: str   # "transposition", "omission", "insertion", "homoglyph", "separator", "scope"


# ---------------------------------------------------------------------------
# Core distance algorithms
# ---------------------------------------------------------------------------

def levenshtein_distance(a: str, b: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings.

    Pure Python implementation using the standard DP matrix approach.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Keep only two rows to save memory
    prev = list(range(len(b) + 1))
    curr = [0] * (len(b) + 1)

    for i, ca in enumerate(a, 1):
        curr[0] = i
        for j, cb in enumerate(b, 1):
            if ca == cb:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j],      # deletion
                                   curr[j - 1],   # insertion
                                   prev[j - 1])   # substitution
        prev, curr = curr, prev

    return prev[len(b)]


def _key_dist(c1: str, c2: str) -> float:
    """Return Euclidean distance between two keys on the QWERTY keyboard.

    Returns 1.5 (a generous maximum) when a key is not on the layout.
    """
    if c1 == c2:
        return 0.0
    p1 = _QWERTY_POS.get(c1.lower())
    p2 = _QWERTY_POS.get(c2.lower())
    if p1 is None or p2 is None:
        return 1.5
    return ((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2) ** 0.5


def keyboard_distance(a: str, b: str) -> float:
    """Compute a keyboard-weighted edit distance between two strings.

    Substitution cost is proportional to the physical distance between keys
    on a QWERTY layout (max cost 1.0 per substitution).  Insertions and
    deletions still cost 1.0 each.

    Uses a standard DP matrix.
    """
    if a == b:
        return 0.0
    if not a:
        return float(len(b))
    if not b:
        return float(len(a))

    la, lb = len(a), len(b)
    prev = [float(j) for j in range(lb + 1)]
    curr = [0.0] * (lb + 1)

    for i, ca in enumerate(a, 1):
        curr[0] = float(i)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                sub_cost = 0.0
            else:
                # Normalise key distance: max observed diagonal is ~sqrt(10)≈3.16
                # We cap to 1.0 so substitution is never more expensive than
                # a delete + insert.
                raw = _key_dist(ca, cb)
                sub_cost = min(raw / 3.16, 1.0)
            curr[j] = min(
                prev[j] + 1.0,          # deletion
                curr[j - 1] + 1.0,      # insertion
                prev[j - 1] + sub_cost, # substitution
            )
        prev, curr = curr, prev

    return prev[lb]


# ---------------------------------------------------------------------------
# Variant generation
# ---------------------------------------------------------------------------

def common_substitutions(name: str) -> list[str]:
    """Generate common typosquat variants of *name*.

    Covers:
    - Adjacent transpositions    ("lodash" → "lodahs")
    - Character omissions        ("requests" → "reqests")
    - Character insertions       ("flask" → "flaask")
    - Homoglyph substitutions    ("l"→"1", "o"→"0", "rn"→"m", …)
    - Separator confusion        ("my-package" → "mypackage" → "my_package")
    - Scope squatting            ("package" → "@someuser/package")
    """
    variants: set[str] = set()
    n = len(name)

    # 1. Adjacent transpositions
    for i in range(n - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        v = "".join(swapped)
        if v != name:
            variants.add(v)

    # 2. Character omissions (drop one character)
    for i in range(n):
        v = name[:i] + name[i + 1:]
        if v and v != name:
            variants.add(v)

    # 3. Character insertions (duplicate a character)
    for i in range(n):
        v = name[:i] + name[i] + name[i:]
        if v != name:
            variants.add(v)

    # 4. Homoglyph substitutions
    # Single-character homoglyphs
    for i, ch in enumerate(name):
        ch_lower = ch.lower()
        for replacement in _HOMOGLYPHS.get(ch_lower, []):
            v = name[:i] + replacement + name[i + 1:]
            if v != name:
                variants.add(v)
    # Multi-character homoglyphs (e.g. "rn"→"m", "m"→"rn")
    for pattern, replacements in _HOMOGLYPHS.items():
        if len(pattern) > 1:
            idx = 0
            while True:
                idx = name.find(pattern, idx)
                if idx == -1:
                    break
                for rep in replacements:
                    v = name[:idx] + rep + name[idx + len(pattern):]
                    if v != name:
                        variants.add(v)
                idx += 1

    # 5. Separator confusion – normalise the name then re-emit with all separators
    # Detect which separator is present (if any)
    has_sep = any(s in name for s in ("-", "_", "."))
    # Build the "bare" form (no separators)
    bare = name.replace("-", "").replace("_", "").replace(".", "")
    if has_sep and bare != name:
        variants.add(bare)  # no separator
    # Add all separator variants
    for sep in ("-", "_", "."):
        if sep in name:
            # Replace existing separators with alternatives
            for alt_sep in ("-", "_", ".", ""):
                if alt_sep != sep:
                    v = name.replace(sep, alt_sep)
                    if v != name:
                        variants.add(v)

    # 6. Scope squatting – add fake npm-style scope prefix variants
    # (These are illustrative; the caller may filter by ecosystem)
    if "/" not in name:
        for scope in ("@attacker", "@evil", "@malware"):
            variants.add(f"{scope}/{name}")

    return sorted(variants)


# ---------------------------------------------------------------------------
# Confidence scoring helpers
# ---------------------------------------------------------------------------

_ATTACK_TYPES = {
    "transposition": 0.85,
    "omission": 0.80,
    "insertion": 0.75,
    "homoglyph": 0.90,
    "separator": 0.85,
    "scope": 0.95,
}


def _classify_attack(suspect: str, target: str) -> str:
    """Heuristically classify the typosquat attack type."""
    s, t = suspect.lower(), target.lower()

    # Scope squatting
    if "/" in s:
        return "scope"

    # Separator confusion: normalised forms are equal
    s_norm = s.replace("-", "").replace("_", "").replace(".", "")
    t_norm = t.replace("-", "").replace("_", "").replace(".", "")
    if s_norm == t_norm:
        return "separator"

    # Homoglyph: after digit↔letter substitution the strings match
    _hg_map = str.maketrans("10@43$5679", "loaaesbgqt")
    if s.translate(_hg_map) == t.translate(_hg_map):
        return "homoglyph"
    # Also check "rn"↔"m"
    if s.replace("rn", "m") == t or s.replace("m", "rn") == t:
        return "homoglyph"

    # Length-based heuristics for omission vs insertion vs transposition
    if len(s) < len(t):
        return "omission"
    if len(s) > len(t):
        return "insertion"
    return "transposition"


def _compute_confidence(
    suspect: str,
    target: str,
    lev_dist: int,
    attack_type: str,
) -> float:
    """Return a confidence score in [0, 1].

    Base confidence comes from the attack type.  It is then penalised by the
    Levenshtein distance and the ratio of lengths (very different lengths →
    lower confidence).
    """
    base = _ATTACK_TYPES.get(attack_type, 0.70)

    # Distance penalty: each edit above 1 reduces confidence
    dist_penalty = 0.1 * max(0, lev_dist - 1)

    # Length ratio penalty: penalise when lengths differ significantly
    max_len = max(len(suspect), len(target), 1)
    min_len = min(len(suspect), len(target))
    length_ratio = min_len / max_len
    len_penalty = 0.15 * (1.0 - length_ratio)

    confidence = base - dist_penalty - len_penalty
    return round(max(0.0, min(1.0, confidence)), 4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_against_popular(name: str, ecosystem: str) -> TyposquatMatch | None:
    """Check whether *name* looks like a typosquat of a popular package.

    Compares *name* against the top-200 list for the given *ecosystem*
    ("npm" or "pypi").  Returns a :class:`TyposquatMatch` when
    levenshtein_distance ≤ 2 **and** confidence > 0.7, otherwise ``None``.

    Packages that are clearly just extensions of a popular name (e.g.
    "express-validator" vs "express") are excluded via a length guard: if the
    suspect is more than 1.5× longer than the target (and the target is
    non-trivially short) the match is skipped.

    The suspect itself is also excluded if it appears in the popular list.
    """
    eco = ecosystem.lower()
    if eco == "npm":
        popular = POPULAR_NPM
    elif eco in ("pypi", "pip"):
        popular = POPULAR_PYPI
    else:
        popular = POPULAR_NPM + POPULAR_PYPI

    suspect_lower = name.lower()

    # Exact match → it IS a popular package, not a typosquat
    if suspect_lower in [p.lower() for p in popular]:
        return None

    best: TyposquatMatch | None = None

    for target in popular:
        t_lower = target.lower()

        # --- Separator normalisation pre-check ---
        s_norm = suspect_lower.replace("-", "").replace("_", "").replace(".", "")
        t_norm = t_lower.replace("-", "").replace("_", "").replace(".", "")
        if s_norm == t_norm and s_norm != "" and s_norm != suspect_lower:
            # The names are the same modulo separators
            attack = "separator"
            lev = levenshtein_distance(suspect_lower, t_lower)
            confidence = _compute_confidence(suspect_lower, t_lower, lev, attack)
            if confidence > 0.7:
                match = TyposquatMatch(
                    suspect=name,
                    target=target,
                    distance=lev,
                    confidence=confidence,
                    attack_type=attack,
                )
                if best is None or confidence > best.confidence:
                    best = match
            continue

        # --- Length guard ---
        # Skip if the suspect is substantially longer than the target.
        # Allow up to 1 extra char more than 1.5× to prevent false positives
        # like "express-validator" being flagged as "express" typosquat.
        if len(t_lower) >= 4 and len(suspect_lower) > len(t_lower) * 1.5 + 1:
            continue

        lev = levenshtein_distance(suspect_lower, t_lower)
        if lev > 2:
            continue

        attack = _classify_attack(suspect_lower, t_lower)
        confidence = _compute_confidence(suspect_lower, t_lower, lev, attack)

        if confidence <= 0.7:
            continue

        match = TyposquatMatch(
            suspect=name,
            target=target,
            distance=lev,
            confidence=confidence,
            attack_type=attack,
        )
        if best is None or confidence > best.confidence:
            best = match

    return best


def batch_check(names: list[str], ecosystem: str) -> list[TyposquatMatch]:
    """Check multiple package names for typosquatting.

    Returns a list of :class:`TyposquatMatch` objects (one per flagged name).
    Names that are not suspicious are omitted from the result.
    """
    results: list[TyposquatMatch] = []
    for name in names:
        match = check_against_popular(name, ecosystem)
        if match is not None:
            results.append(match)
    return results
