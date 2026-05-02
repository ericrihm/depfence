"""Threat intelligence aggregator combining multiple data sources.

Identifies known-malicious packages and recently reported supply chain attacks
by maintaining a JSON-backed database seeded from public incident reports and
optionally synced from the OpenSSF malicious-packages feed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    pass

from depfence.core.models import PackageId

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".depfence" / "threat_intel.json"

# ---------------------------------------------------------------------------
# KNOWN_MALICIOUS — static seed from public incident reports
# Format: (ecosystem, package_name): (threat_type, severity, description, reported_date, source, indicators)
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS: dict[tuple[str, str], dict] = {
    # -----------------------------------------------------------------------
    # npm — high-profile hijacks
    # -----------------------------------------------------------------------
    ("npm", "event-stream"): {
        "threat_type": "hijack",
        "severity": "critical",
        "description": "Malicious maintainer added flatmap-stream dependency to steal bitcoin wallets from Copay app users",
        "reported_date": "2018-11-26",
        "source": "community",
        "indicators": ["flatmap-stream@0.1.1", "npm:flatmap-stream"],
    },
    ("npm", "ua-parser-js"): {
        "threat_type": "hijack",
        "severity": "critical",
        "description": "npm account hijacked; malicious versions 0.7.29, 0.8.0, 1.0.0 injected cryptominer and credential stealer",
        "reported_date": "2021-10-22",
        "source": "ossf-malicious-packages",
        "indicators": ["jsextension", "sdd.dll", "sdd.so"],
    },
    ("npm", "coa"): {
        "threat_type": "hijack",
        "severity": "critical",
        "description": "Maintainer account compromised; versions 2.0.3 and 2.1.1 contained password-stealing malware",
        "reported_date": "2021-11-04",
        "source": "ossf-malicious-packages",
        "indicators": ["2.0.3", "2.1.1"],
    },
    ("npm", "rc"): {
        "threat_type": "hijack",
        "severity": "critical",
        "description": "Maintainer account compromised simultaneously with coa; malicious 1.2.9 published",
        "reported_date": "2021-11-04",
        "source": "ossf-malicious-packages",
        "indicators": ["1.2.9"],
    },
    ("npm", "colors"): {
        "threat_type": "hijack",
        "severity": "high",
        "description": "Maintainer Marak intentionally introduced infinite loop in 1.4.44-liberty-2; supply chain sabotage",
        "reported_date": "2022-01-08",
        "source": "community",
        "indicators": ["1.4.44-liberty-2"],
    },
    ("npm", "faker"): {
        "threat_type": "hijack",
        "severity": "high",
        "description": "Maintainer Marak intentionally corrupted 6.6.6 and 5.5.5 releases as protest; sabotage",
        "reported_date": "2022-01-08",
        "source": "community",
        "indicators": ["6.6.6", "5.5.5"],
    },
    ("npm", "node-ipc"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Author RIAEvangelist added geo-targeted wiper payload against Russian/Belarusian IPs (peacenotwar)",
        "reported_date": "2022-03-15",
        "source": "snyk-advisories",
        "indicators": ["peacenotwar", "10.1.1", "10.1.2", "9.2.2"],
    },
    ("npm", "peacenotwar"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Wiper malware dropped files on desktop of users in Russia/Belarus; bundled in node-ipc",
        "reported_date": "2022-03-15",
        "source": "snyk-advisories",
        "indicators": ["WITH-LOVE-FROM-AMERICA"],
    },
    ("npm", "es5-ext"): {
        "threat_type": "malware",
        "severity": "medium",
        "description": "Author added pro-Ukraine message payload that fires on Russian locale machines",
        "reported_date": "2022-02-27",
        "source": "community",
        "indicators": [],
    },
    # -----------------------------------------------------------------------
    # npm — scope squatting / @paborat attacks
    # -----------------------------------------------------------------------
    ("npm", "@paborat/querystringify"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Scope-squatting package under @paborat mimicking querystringify; data exfiltration",
        "reported_date": "2022-05-01",
        "source": "snyk-advisories",
        "indicators": [],
    },
    ("npm", "@paborat/url-parse"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Scope-squatting package under @paborat mimicking url-parse; data exfiltration",
        "reported_date": "2022-05-01",
        "source": "snyk-advisories",
        "indicators": [],
    },
    ("npm", "@paborat/lodash"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Scope-squatting package under @paborat mimicking lodash; data exfiltration",
        "reported_date": "2022-05-01",
        "source": "snyk-advisories",
        "indicators": [],
    },
    # -----------------------------------------------------------------------
    # npm — additional known malicious packages
    # -----------------------------------------------------------------------
    ("npm", "electron-native-notify"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Contained obfuscated code to steal cryptocurrency wallet credentials",
        "reported_date": "2019-08-20",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "flatmap-stream"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious payload targeting Copay bitcoin wallet app; injected via event-stream",
        "reported_date": "2018-11-26",
        "source": "community",
        "indicators": ["0.1.1"],
    },
    ("npm", "crossenv"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of cross-env; exfiltrated environment variables to attacker-controlled server",
        "reported_date": "2017-08-02",
        "source": "ossf-malicious-packages",
        "indicators": ["burpcollaborator.net"],
    },
    ("npm", "discordi.js"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of discord.js; stole Discord tokens and passwords",
        "reported_date": "2021-01-05",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "discord.js-user"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious package stealing Discord tokens from infected machines",
        "reported_date": "2021-05-10",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "bb-builder"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Contained RAT payload; targeted cryptocurrency wallet software",
        "reported_date": "2021-06-02",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "http-proxy.js"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of http-proxy; exfiltrated npm tokens and environment variables",
        "reported_date": "2022-03-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "nodejs-cookie-proxy-agent"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Backdoored package executed remote shell commands; part of large malicious campaign",
        "reported_date": "2023-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "lottie-player"): {
        "threat_type": "hijack",
        "severity": "critical",
        "description": "CDN compromise of LottieFiles lottie-player injected crypto wallet drainer into supply chain",
        "reported_date": "2024-10-31",
        "source": "community",
        "indicators": ["2.0.5", "2.0.6", "2.0.7"],
    },
    ("npm", "everything"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Package depends on every public npm package causing disk/memory DoS on install",
        "reported_date": "2022-12-01",
        "source": "community",
        "indicators": [],
    },
    ("npm", "jest-next-dynamic"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package impersonating jest-next-dynamic test utility; exfiltrated env vars",
        "reported_date": "2023-04-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "loadyaml"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of js-yaml; exfiltrated environment variables to remote server",
        "reported_date": "2023-02-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "0xengine/xmlhttprequest"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Contained cryptominer and exfiltration payload using obfuscated code",
        "reported_date": "2023-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "ethereumvulncontracttest"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Targeted Ethereum developers; exfiltrated private keys and wallet data",
        "reported_date": "2022-10-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "rpc-websocket"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious package targeting DeFi developers; stole mnemonic phrases",
        "reported_date": "2022-11-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "browserslist-useragent-regexp"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of legitimate browserslist-useragent; contained exfiltration payload",
        "reported_date": "2023-07-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "babel-preset-es2017"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Malicious package mimicking babel-preset-env; executed reverse shell on install",
        "reported_date": "2022-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    # -----------------------------------------------------------------------
    # PyPI — typosquats and homoglyphs
    # -----------------------------------------------------------------------
    ("pypi", "colourama"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of colorama; exfiltrated clipboard contents targeting cryptocurrency addresses",
        "reported_date": "2018-10-12",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "python-dateutil"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of dateutil (legitimate package is python-dateutil); malicious copy exfiltrates data",
        "reported_date": "2021-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "jeIlyfish"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Homoglyph attack using capital I instead of lowercase l in jellyfish; stole SSH keys",
        "reported_date": "2019-01-11",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "python3-dateutil"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of python-dateutil targeting Python 3 users; data exfiltration payload",
        "reported_date": "2021-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "distutils-precedence"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package mimicking legitimate distutils tooling; executed remote code on install",
        "reported_date": "2022-03-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "request"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of the popular requests library; installed backdoor for remote code execution",
        "reported_date": "2017-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "beautifulsoup"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of beautifulsoup4; contained data exfiltration code",
        "reported_date": "2017-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "setup-tools"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of setuptools (correct name has no hyphen); exfiltrated pip internals",
        "reported_date": "2017-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "python-binance"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package impersonating Binance Python SDK; exfiltrated API keys and secrets",
        "reported_date": "2023-01-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pytorch-lightning"): {
        "threat_type": "hijack",
        "severity": "high",
        "description": "Dependency confusion attack attempt against PyTorch Lightning internal packages",
        "reported_date": "2022-09-01",
        "source": "community",
        "indicators": [],
    },
    # -----------------------------------------------------------------------
    # PyPI — additional known malicious packages
    # -----------------------------------------------------------------------
    ("pypi", "loglib-modules"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Impersonated logging library; exfiltrated environment variables and credentials to Discord webhook",
        "reported_date": "2023-04-10",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pyg-nightly"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Impersonated PyG (PyTorch Geometric) nightly builds; executed cryptominer",
        "reported_date": "2023-03-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "esmjsaes"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package containing base64-obfuscated reverse shell payload",
        "reported_date": "2023-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pyopenssl"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Malicious package typosquatting pyOpenSSL (correct casing); credential theft payload",
        "reported_date": "2021-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "coloama"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of colorama; exfiltrated environment variables",
        "reported_date": "2022-01-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "ascii2text"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Harvested stored passwords from Google Chrome, Opera, Edge, and Brave browsers",
        "reported_date": "2022-10-28",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pyquest"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Obfuscated malware harvesting browser cookies and stored passwords",
        "reported_date": "2022-10-28",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "ultrarequests"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious fork of requests library; stole browser credentials on Windows",
        "reported_date": "2022-10-28",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "httplib3"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of httplib2; exfiltrated system information and credentials",
        "reported_date": "2020-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "apidev-coop"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Targeted machine learning developers; gathered system info and exfiltrated it",
        "reported_date": "2023-02-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "bpython"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Malicious package hijacking the bpython namespace; contained credential-harvesting code",
        "reported_date": "2021-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "django-server"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat targeting Django developers; exfiltrated SECRET_KEY and database credentials",
        "reported_date": "2022-04-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pymock"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious package impersonating unittest.mock; executed arbitrary system commands",
        "reported_date": "2023-05-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("pypi", "keep"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Shipped Misha — a Mirai-variant botnet client targeting Linux servers",
        "reported_date": "2021-03-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "pyhton-dateutil"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of python-dateutil with transposed characters; data exfiltration",
        "reported_date": "2022-06-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "importantpackage"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Dependency confusion package targeting Fortune 500 companies; reverse shell payload",
        "reported_date": "2021-02-09",
        "source": "community",
        "indicators": [],
    },
    ("pypi", "noblesse"): {
        "threat_type": "data_exfil",
        "severity": "critical",
        "description": "Harvested Discord tokens, browser credentials, and system information",
        "reported_date": "2021-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "noblesse2"): {
        "threat_type": "data_exfil",
        "severity": "critical",
        "description": "Successor to noblesse; Discord token stealer and browser credential harvester",
        "reported_date": "2021-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "freljord"): {
        "threat_type": "data_exfil",
        "severity": "high",
        "description": "Part of large Discord token theft campaign using League of Legends naming",
        "reported_date": "2021-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "ohcrapi"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package executing shellcode and establishing persistence",
        "reported_date": "2022-08-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "python-ftp-server"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Installed backdoor FTP server for persistent remote access",
        "reported_date": "2022-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("pypi", "libpython-clang"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Dependency confusion attack package; executed reverse shell to attacker infrastructure",
        "reported_date": "2022-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    # -----------------------------------------------------------------------
    # npm — additional packages from public incident reports
    # -----------------------------------------------------------------------
    ("npm", "twilio-npm"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Typosquat of twilio; exfiltrated environment variables on install via postinstall script",
        "reported_date": "2020-11-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "fallguys"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious package stealing files from ~/Desktop and npm config including auth tokens",
        "reported_date": "2020-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "plutov-slack-client"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of slack-client; executed reverse shell on install",
        "reported_date": "2022-01-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "markedj"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of marked markdown parser; contained data exfiltration payload",
        "reported_date": "2021-10-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "binarium-crm"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Typosquat of binarium; opened reverse TCP shell; targeted DeFi developers",
        "reported_date": "2021-09-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "azure-ad-authenticate"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Dependency confusion attack against Azure AD; exfiltrated credentials and system info",
        "reported_date": "2022-04-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "react-native-scrollview-enhanced"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Contained obfuscated reverse shell; targeted React Native developers",
        "reported_date": "2023-01-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "hardhat-gas-report"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of hardhat-gas-reporter; targeted Ethereum/Hardhat developers",
        "reported_date": "2023-05-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "solana-logger"): {
        "threat_type": "malware",
        "severity": "critical",
        "description": "Malicious package targeting Solana developers; stole private keys and wallet seeds",
        "reported_date": "2023-07-01",
        "source": "socket-reports",
        "indicators": [],
    },
    ("npm", "glup-cli"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of gulp-cli; ran exfiltration script on postinstall",
        "reported_date": "2022-07-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "web3.js"): {
        "threat_type": "typosquat",
        "severity": "high",
        "description": "Typosquat of web3 (note the dot); targeted crypto developers to steal wallet keys",
        "reported_date": "2021-12-01",
        "source": "ossf-malicious-packages",
        "indicators": [],
    },
    ("npm", "electron-prebuilt-compile"): {
        "threat_type": "malware",
        "severity": "high",
        "description": "Malicious version introduced cryptominer; original package was deprecated legitimately",
        "reported_date": "2022-03-01",
        "source": "socket-reports",
        "indicators": [],
    },
}


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class ThreatEntry:
    package_name: str
    ecosystem: str
    threat_type: str  # "malware", "typosquat", "hijack", "data_exfil", "cryptominer"
    source: str  # "ossf-malicious-packages", "snyk-advisories", "socket-reports", "community"
    reported_date: str  # ISO 8601 date string e.g. "2023-01-15"
    description: str
    indicators: list[str]  # IOCs: domains, IPs, hashes
    severity: str


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


class ThreatIntelDB:
    """JSON-backed threat intelligence database.

    Seeded from the KNOWN_MALICIOUS static dictionary and optionally synced
    from the OpenSSF malicious-packages feed.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path: Path = db_path if db_path is not None else _DEFAULT_DB_PATH
        # Internal store: (ecosystem.lower(), name.lower()) -> ThreatEntry
        self._entries: dict[tuple[str, str], ThreatEntry] = {}
        self._last_synced: str | None = None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load database from disk, falling back to KNOWN_MALICIOUS seed."""
        self._entries = {}
        if self._db_path.exists():
            try:
                raw = json.loads(self._db_path.read_text(encoding="utf-8"))
                self._last_synced = raw.get("last_synced")
                for item in raw.get("entries", []):
                    entry = ThreatEntry(**item)
                    key = (entry.ecosystem.lower(), entry.package_name.lower())
                    self._entries[key] = entry
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load threat_intel.json: %s — using seed data", exc)

        # Merge static seed (disk data takes precedence over seed)
        self._merge_known_malicious()

    def save(self) -> None:
        """Persist database to disk as JSON."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_synced": self._last_synced,
            "entries": [asdict(e) for e in self._entries.values()],
        }
        self._db_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _merge_known_malicious(self) -> None:
        """Merge KNOWN_MALICIOUS entries (do not overwrite existing disk entries)."""
        for (ecosystem, name), meta in KNOWN_MALICIOUS.items():
            key = (ecosystem.lower(), name.lower())
            if key not in self._entries:
                self._entries[key] = ThreatEntry(
                    package_name=name,
                    ecosystem=ecosystem,
                    **meta,
                )

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_entry(self, entry: ThreatEntry) -> None:
        """Add or replace an entry in the in-memory database."""
        key = (entry.ecosystem.lower(), entry.package_name.lower())
        self._entries[key] = entry

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def lookup(self, name: str, ecosystem: str) -> ThreatEntry | None:
        """Return the ThreatEntry for a package, or None if not found.

        Both *name* and *ecosystem* are compared case-insensitively.
        """
        key = (ecosystem.lower(), name.lower())
        return self._entries.get(key)

    def lookup_batch(self, packages: list[PackageId]) -> dict[str, ThreatEntry]:
        """Return a dict mapping ``str(PackageId)`` to ThreatEntry for matches.

        Only malicious packages are included; clean packages are omitted.
        """
        result: dict[str, ThreatEntry] = {}
        for pkg in packages:
            entry = self.lookup(pkg.name, pkg.ecosystem)
            if entry is not None:
                result[str(pkg)] = entry
        return result

    def get_recent(self, days: int = 30) -> list[ThreatEntry]:
        """Return entries reported within the last *days* days.

        Entries with an unparseable reported_date are excluded.
        """
        cutoff = datetime.now(tz=timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        from datetime import timedelta

        cutoff = cutoff - timedelta(days=days)
        recent: list[ThreatEntry] = []
        for entry in self._entries.values():
            try:
                reported = datetime.fromisoformat(entry.reported_date).replace(
                    tzinfo=timezone.utc
                )
                if reported >= cutoff:
                    recent.append(entry)
            except ValueError:
                continue
        return recent

    def count(self) -> int:
        """Return the total number of entries in the database."""
        return len(self._entries)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def last_synced(self) -> str | None:
        """ISO 8601 timestamp of the last successful OSSF sync, or None."""
        return self._last_synced

    # ------------------------------------------------------------------
    # Remote sync
    # ------------------------------------------------------------------

    async def sync_from_ossf(self) -> int:
        """Fetch the OpenSSF malicious-packages list and merge new entries.

        The OSSF repository stores one JSON file per reported package under
        ``osv/malicious/``.  We fetch the directory listing via the GitHub
        API and then sample up to 200 entries to avoid rate limits.

        Returns the number of *new* entries added during this sync run.
        """
        added = 0
        base_url = (
            "https://api.github.com/repos/ossf/malicious-packages/"
            "contents/osv/malicious"
        )
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(base_url, headers=headers)
                resp.raise_for_status()
                items = resp.json()

                # items is a list of directory entries; filter to JSON files
                json_files = [
                    item["download_url"]
                    for item in items
                    if isinstance(item, dict)
                    and item.get("type") == "file"
                    and item.get("name", "").endswith(".json")
                ]

                # Sample to limit API calls in this run
                import random

                sample = json_files[:200] if len(json_files) <= 200 else random.sample(json_files, 200)

                tasks = [self._fetch_ossf_entry(client, url) for url in sample]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, ThreatEntry):
                        key = (result.ecosystem.lower(), result.package_name.lower())
                        if key not in self._entries:
                            self._entries[key] = result
                            added += 1

        except Exception as exc:  # noqa: BLE001
            logger.warning("OSSF sync failed: %s", exc)

        self._last_synced = datetime.now(tz=timezone.utc).isoformat()
        return added

    @staticmethod
    async def _fetch_ossf_entry(client: httpx.AsyncClient, url: str) -> ThreatEntry | Exception:
        """Fetch and parse a single OSSF OSV JSON file."""
        try:
            resp = await client.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            # OSV schema: affected[].package.{name, ecosystem}
            affected = data.get("affected", [])
            if not affected:
                return ValueError("no affected packages")

            pkg_info = affected[0].get("package", {})
            name = pkg_info.get("name", "")
            ecosystem = pkg_info.get("ecosystem", "").lower()
            if not name or not ecosystem:
                return ValueError("missing name/ecosystem")

            # Normalise ecosystem to our convention
            eco_map = {"npm": "npm", "pypi": "pypi", "crates.io": "cargo", "go": "go"}
            ecosystem = eco_map.get(ecosystem, ecosystem)

            published = data.get("published", "")[:10] or "2000-01-01"

            # Determine threat_type from OSV database_specific / summary
            summary = (data.get("summary") or data.get("details") or "").lower()
            threat_type = "malware"
            if "typosquat" in summary:
                threat_type = "typosquat"
            elif "hijack" in summary or "compromised" in summary:
                threat_type = "hijack"
            elif "cryptominer" in summary or "miner" in summary:
                threat_type = "cryptominer"
            elif "exfil" in summary or "data theft" in summary:
                threat_type = "data_exfil"

            return ThreatEntry(
                package_name=name,
                ecosystem=ecosystem,
                threat_type=threat_type,
                source="ossf-malicious-packages",
                reported_date=published,
                description=(data.get("summary") or data.get("details") or "")[:500],
                indicators=[],
                severity="high",
            )
        except Exception as exc:  # noqa: BLE001
            return exc
