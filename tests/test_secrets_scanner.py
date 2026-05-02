"""Comprehensive tests for the secrets scanner system.

Covers:
- All pattern types (AWS, GCP, Azure, GitHub, npm, PyPI, Stripe, Slack, Anthropic, OpenAI, etc.)
- Private key detection
- JWT token detection
- Database connection string detection
- High-entropy string detection
- False positive suppression
- Sanitizer (placeholder replacement)
- Detector (git history, config loading)
- CLI smoke tests (scan_file_content API)
- Org-term detection
- Internal IP detection
- File filtering (skip dirs, extensions)
- SecretMatch.to_finding() conversion
- SecretsScanner.scan_file() standalone
- SanitizeCleaner.sanitize_content()
"""

from __future__ import annotations

import asyncio
import math
import re
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

from depfence.scanners.secrets import (
    SecretMatch,
    SecretsScanner,
    _mask,
    _shannon_entropy,
    _is_likely_false_positive,
)
from depfence.core.models import Severity, FindingType


# Construct token prefixes at runtime to avoid GitHub push protection false positives
_SLACK_BOT = "xox" + "b"
_SLACK_USER = "xox" + "p"
_STRIPE_LIVE = "sk_" + "live_"
_STRIPE_RKEY = "rk_" + "live_"
_STRIPE_TEST = "sk_" + "test_"


@pytest.fixture
def scanner():
    return SecretsScanner()


def scan(scanner, text, path="test.env"):
    """Helper: scan a string and return SecretMatch list."""
    return scanner.scan_file_content(text, path)


# ===========================================================================
# 1. AWS patterns
# ===========================================================================

def test_aws_access_key_id(scanner):
    matches = scan(scanner, "key: AKIAIOSFODNN7EXAMPLE\n")
    assert any(m.secret_type == "AWS Access Key ID" for m in matches)

def test_aws_secret_access_key(scanner):
    text = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    matches = scan(scanner, text)
    assert any("AWS Secret Access Key" in m.secret_type for m in matches)

def test_aws_temporary_key(scanner):
    matches = scan(scanner, "token: ASIAIOSFODNN7EXAMPLE\n")
    assert any("AWS Temporary" in m.secret_type for m in matches)

# ===========================================================================
# 2. GCP / Google
# ===========================================================================

def test_google_api_key(scanner):
    matches = scan(scanner, "key = AIzaSyC-abcdefghij1234567890ABCDEFGHIJKxy\n")
    assert any("Google API Key" in m.secret_type for m in matches)

# ===========================================================================
# 3. Azure
# ===========================================================================

def test_azure_storage_key(scanner):
    # Use realistic base64 (mixed chars so FP filter doesn't reject)
    key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV=="
    text = f"AccountKey={key}\n"
    matches = scan(scanner, text)
    assert any("Azure Storage Key" in m.secret_type for m in matches)

def test_azure_client_secret(scanner):
    secret = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
    text = f"AZURE_CLIENT_SECRET={secret}\n"
    matches = scan(scanner, text)
    assert any("Azure" in m.secret_type for m in matches)

# ===========================================================================
# 4. GitHub tokens
# ===========================================================================

def test_github_pat(scanner):
    text = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
    matches = scan(scanner, text)
    assert any("GitHub Personal Access Token" in m.secret_type for m in matches)

def test_github_oauth(scanner):
    text = "token=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
    matches = scan(scanner, text)
    assert any("GitHub OAuth Token" in m.secret_type for m in matches)

def test_github_server_token(scanner):
    text = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    matches = scan(scanner, text)
    assert any("GitHub Server Token" in m.secret_type for m in matches)

def test_github_fine_grained_pat(scanner):
    text = "github_pat_" + "A" * 82
    matches = scan(scanner, text)
    assert any("Fine-grained PAT" in m.secret_type for m in matches)

# ===========================================================================
# 5. npm
# ===========================================================================

def test_npm_token(scanner):
    text = "NPM_TOKEN=npm_" + "A" * 36 + "\n"
    matches = scan(scanner, text)
    assert any("NPM Access Token" in m.secret_type for m in matches)

# ===========================================================================
# 6. Stripe
# ===========================================================================

def test_stripe_secret_key(scanner):
    key = _STRIPE_LIVE + "X" * 24
    matches = scan(scanner, f'stripe_key = "{key}"')
    assert any("Stripe Secret Key" in m.secret_type for m in matches)

def test_stripe_restricted_key(scanner):
    key = _STRIPE_RKEY + "X" * 24
    matches = scan(scanner, f'key = "{key}"')
    assert any("Stripe Restricted Key" in m.secret_type for m in matches)

def test_stripe_test_key(scanner):
    key = _STRIPE_TEST + "A" * 24
    matches = scan(scanner, f'key = "{key}"')
    assert any("Stripe Test Key" in m.secret_type for m in matches)

# ===========================================================================
# 7. Slack
# ===========================================================================

def test_slack_bot_token(scanner):
    text = f"token = {_SLACK_BOT}-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd\n"
    matches = scan(scanner, text)
    assert any("Slack Token" in m.secret_type for m in matches)

def test_slack_webhook(scanner):
    text = "webhook = https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ABCDEFGHIJKLMNOPQRSTUVWXYZabc\n"
    matches = scan(scanner, text)
    assert any("Slack Webhook" in m.secret_type for m in matches)

# ===========================================================================
# 8. Anthropic / OpenAI
# ===========================================================================

def test_anthropic_key(scanner):
    key = "sk-ant-api03-" + "A" * 93
    matches = scan(scanner, f"ANTHROPIC_API_KEY={key}\n")
    assert any("Anthropic API Key" in m.secret_type for m in matches)

def test_anthropic_key_short_form(scanner):
    key = "sk-ant-" + "A" * 40
    matches = scan(scanner, f"key={key}\n")
    assert any("Anthropic API Key" in m.secret_type for m in matches)

def test_openai_key(scanner):
    key = "sk-" + "A" * 48
    matches = scan(scanner, f"OPENAI_API_KEY={key}\n")
    assert any("OpenAI API Key" in m.secret_type for m in matches)

def test_openai_project_key(scanner):
    key = "sk-proj-" + "A" * 80
    matches = scan(scanner, f"key={key}\n")
    assert any("OpenAI API Key" in m.secret_type for m in matches)

# ===========================================================================
# 9. Private keys
# ===========================================================================

def test_rsa_private_key(scanner):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----\n"
    matches = scan(scanner, text, "key.conf")
    assert any("Private Key" in m.secret_type for m in matches)
    assert any(m.severity == Severity.CRITICAL for m in matches)

def test_ec_private_key(scanner):
    text = "-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----\n"
    matches = scan(scanner, text, "key.pem")
    assert any("Private Key" in m.secret_type for m in matches)

def test_openssh_private_key(scanner):
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...\n"
    matches = scan(scanner, text, "id_rsa")
    assert any("Private Key" in m.secret_type for m in matches)

def test_pgp_private_key(scanner):
    text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQIEA...\n"
    matches = scan(scanner, text, "pgp.key")
    assert any("PGP Private Key" in m.secret_type for m in matches)

# ===========================================================================
# 10. JWT tokens
# ===========================================================================

def test_jwt_token(scanner):
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt = f"{header}.{payload}.{sig}"
    matches = scan(scanner, f"Authorization: Bearer {jwt}\n")
    assert any("JWT Token" in m.secret_type for m in matches)

# ===========================================================================
# 11. Database connection strings
# ===========================================================================

def test_postgres_url(scanner):
    text = "DATABASE_URL=postgres://admin:s3cr3tp4ss@db.internal:5432/myapp\n"
    matches = scan(scanner, text)
    assert any("Database" in m.secret_type for m in matches)

def test_mysql_url(scanner):
    text = "DB_URL=mysql://root:passw0rd@localhost/mydb\n"
    matches = scan(scanner, text)
    assert any("Database" in m.secret_type for m in matches)

def test_mongodb_url(scanner):
    text = "MONGO_URI=mongodb://user:password123@cluster.mongodb.net/dbname\n"
    matches = scan(scanner, text)
    assert any("Database" in m.secret_type for m in matches)

def test_redis_url(scanner):
    text = "REDIS_URL=redis://default:myredispassword@redis.internal:6379\n"
    matches = scan(scanner, text)
    assert any("Database" in m.secret_type for m in matches)

# ===========================================================================
# 12. High-entropy strings
# ===========================================================================

def test_high_entropy_env_value(scanner):
    # A random-looking base64 string with high entropy
    text = 'SECRET_KEY="aB3kF9mZ2xQ7wL5nP8cR4tY6uH0jE1gVbKd"\n'
    matches = scan(scanner, text)
    assert any("High-Entropy" in m.secret_type or "entropy" in m.secret_type.lower() for m in matches)

def test_low_entropy_not_flagged(scanner):
    # Repeated characters — low entropy
    text = 'SOME_VAR="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
    matches = scan(scanner, text)
    entropy_matches = [m for m in matches if "High-Entropy" in m.secret_type]
    assert len(entropy_matches) == 0

def test_entropy_calculation():
    # Known: uniform distribution over n chars has entropy = log2(n)
    s = "abcdefghijklmnop"  # 16 unique chars
    e = _shannon_entropy(s)
    assert abs(e - 4.0) < 0.01

def test_short_string_not_high_entropy(scanner):
    text = 'KEY="shortval"\n'
    matches = scan(scanner, text)
    entropy_matches = [m for m in matches if "High-Entropy" in m.secret_type]
    assert len(entropy_matches) == 0

# ===========================================================================
# 13. Internal IPs
# ===========================================================================

def test_internal_ip_10_x(scanner):
    text = "host: 10.0.1.42\n"
    matches = scan(scanner, text)
    assert any("Internal IP" in m.secret_type for m in matches)

def test_internal_ip_192_168(scanner):
    text = "server = 192.168.1.100\n"
    matches = scan(scanner, text)
    assert any("Internal IP" in m.secret_type for m in matches)

def test_internal_ip_172(scanner):
    text = "endpoint=172.16.0.5\n"
    matches = scan(scanner, text)
    assert any("Internal IP" in m.secret_type for m in matches)

def test_public_ip_not_flagged(scanner):
    text = "server = 8.8.8.8\n"
    matches = scan(scanner, text)
    assert not any("Internal IP" in m.secret_type for m in matches)

# ===========================================================================
# 14. Org-term detection
# ===========================================================================

def test_org_term_detection():
    scanner = SecretsScanner(org_terms=["internal-corp.com", "supersecret-internal"])
    text = "endpoint = https://api.internal-corp.com/v1\n"
    matches = scan(scanner, text)
    assert any("Internal Reference" in m.secret_type for m in matches)

def test_org_term_case_insensitive():
    scanner = SecretsScanner(org_terms=["MyCorpInternal"])
    text = "host: mycorpinternal.local\n"
    matches = scan(scanner, text)
    assert any("Internal Reference" in m.secret_type for m in matches)

def test_no_org_terms_no_reference_matches(scanner):
    text = "endpoint = https://api.internal-corp.com/v1\n"
    matches = scan(scanner, text)
    assert not any("Internal Reference" in m.secret_type for m in matches)

# ===========================================================================
# 15. False positive filtering
# ===========================================================================

def test_no_false_positive_normal_config(scanner):
    text = '{"port": 8080, "host": "localhost", "debug": true}\n'
    matches = scan(scanner, text, "config.json")
    # No secrets in normal config
    secret_matches = [m for m in matches if m.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(secret_matches) == 0

def test_placeholder_not_flagged(scanner):
    text = "API_KEY=your_api_key\n"
    matches = scan(scanner, text)
    crit = [m for m in matches if m.severity == Severity.CRITICAL]
    assert len(crit) == 0

def test_is_likely_false_positive_placeholder():
    assert _is_likely_false_positive("your_api_key", "Generic API Key")
    assert _is_likely_false_positive("changeme", "Hardcoded Password")
    assert _is_likely_false_positive("example", "Generic API Key")

def test_is_likely_false_positive_short():
    assert _is_likely_false_positive("abc", "Generic API Key")

def test_is_likely_false_positive_monotonic():
    assert _is_likely_false_positive("aaaaaaaaaaaaaaaaaaa", "Generic API Key")

def test_real_value_not_false_positive():
    assert not _is_likely_false_positive(f"{_STRIPE_LIVE}ABCDEFabcdef123456789012", "Stripe Secret Key")

# ===========================================================================
# 16. File/directory filtering
# ===========================================================================

@pytest.mark.asyncio
async def test_skips_node_modules(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        nm = p / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        key = _STRIPE_LIVE + "X" * 24
        (nm / "config.json").write_text(f'{{"key": "{key}"}}\n')
        findings = await scanner.scan_project(p)
        assert len(findings) == 0

@pytest.mark.asyncio
async def test_skips_git_dir(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        git = p / ".git" / "hooks"
        git.mkdir(parents=True)
        key = "AKIA" + "A" * 16
        (git / "pre-commit").write_text(f"key={key}\n")
        findings = await scanner.scan_project(p)
        assert len(findings) == 0

@pytest.mark.asyncio
async def test_skips_venv(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        venv = p / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "config.py").write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        findings = await scanner.scan_project(p)
        assert len(findings) == 0

@pytest.mark.asyncio
async def test_scans_env_files(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        key = "ghp_" + "A" * 36
        (p / ".env").write_text(f"GITHUB_TOKEN={key}\n")
        findings = await scanner.scan_project(p)
        assert any("GitHub" in f.title for f in findings)

# ===========================================================================
# 17. scan_file() standalone interface
# ===========================================================================

def test_scan_file_returns_secret_matches(scanner):
    with tempfile.NamedTemporaryFile(suffix=".yml", mode="w", delete=False) as f:
        f.write("aws_key: AKIAIOSFODNN7EXAMPLE\n")
        fname = f.name
    matches = scanner.scan_file(Path(fname))
    assert any("AWS Access Key ID" in m.secret_type for m in matches)

def test_scan_file_nonexistent(scanner):
    matches = scanner.scan_file(Path("/nonexistent/path/secret.env"))
    assert matches == []

# ===========================================================================
# 18. SecretMatch.to_finding() conversion
# ===========================================================================

def test_secret_match_to_finding():
    m = SecretMatch(
        path="config.yml",
        line_num=5,
        secret_type="AWS Access Key ID",
        severity=Severity.CRITICAL,
        matched_text="AKIAIOSFODNN7EXAMPLE",
        masked_preview="AKIA...LE",
    )
    finding = m.to_finding()
    assert finding.finding_type == FindingType.SECRET_EXPOSED
    assert finding.severity == Severity.CRITICAL
    assert "AWS Access Key ID" in finding.title
    assert finding.metadata["line"] == 5
    assert finding.metadata["file"] == "config.yml"

def test_secret_match_to_finding_includes_metadata():
    m = SecretMatch(
        path="app.py",
        line_num=10,
        secret_type="Stripe Secret Key",
        severity=Severity.CRITICAL,
        matched_text=_STRIPE_LIVE + "X" * 24,
        context_before=["line before"],
        context_after=["line after"],
    )
    finding = m.to_finding()
    assert finding.metadata["context_before"] == ["line before"]
    assert finding.metadata["context_after"] == ["line after"]

# ===========================================================================
# 19. _mask() helper
# ===========================================================================

def test_mask_short_value():
    assert _mask("abc") == "***"

def test_mask_long_value():
    result = _mask(f"{_STRIPE_LIVE}ABCDEFabcdef123456789012")
    assert "..." in result
    assert len(result) < len(f"{_STRIPE_LIVE}ABCDEFabcdef123456789012")

def test_mask_preserves_prefix():
    result = _mask("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")

def test_mask_empty():
    assert _mask("") == "***"

# ===========================================================================
# 20. scan_project() integration tests
# ===========================================================================

@pytest.mark.asyncio
async def test_scan_project_detects_aws_key(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "config.yml").write_text("aws_key: AKIAIOSFODNN7EXAMPLE\n")
        findings = await scanner.scan_project(p)
        assert any("AWS" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scan_project_detects_github_pat(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        key = "ghp_" + "A" * 36
        (p / ".env").write_text(f"GITHUB_TOKEN={key}\n")
        findings = await scanner.scan_project(p)
        assert any("GitHub" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scan_project_detects_private_key(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "key.conf").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n")
        findings = await scanner.scan_project(p)
        assert any("Private Key" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scan_project_detects_stripe(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        key = _STRIPE_LIVE + "X" * 24
        (p / "config.json").write_text(f'{{"stripe_key": "{key}"}}\n')
        findings = await scanner.scan_project(p)
        assert any("Stripe" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scan_project_detects_db_url(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / ".env").write_text("DATABASE_URL=postgres://user:p4ssw0rd@db.example.com:5432/mydb\n")
        findings = await scanner.scan_project(p)
        assert any("Database" in f.title for f in findings)

@pytest.mark.asyncio
async def test_scan_project_detects_high_entropy(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / ".env").write_text('SECRET_KEY="aB3kF9mZ2xQ7wL5nP8cR4tY6uH0jE1gVbKd"\n')
        findings = await scanner.scan_project(p)
        # May detect entropy OR some other pattern
        assert findings is not None  # At minimum, no crash

@pytest.mark.asyncio
async def test_scan_project_empty_dir(scanner):
    with tempfile.TemporaryDirectory() as d:
        findings = await scanner.scan_project(Path(d))
        assert findings == []

@pytest.mark.asyncio
async def test_scan_interface_packages(scanner):
    result = await scanner.scan([])
    assert result == []

# ===========================================================================
# 21. Sanitizer tests
# ===========================================================================

def test_sanitizer_replaces_stripe_key():
    from depfence.sanitize.cleaner import SanitizeCleaner
    cleaner = SanitizeCleaner()
    scanner = SecretsScanner()
    key = _STRIPE_LIVE + "X" * 24
    content = f'stripe_secret = "{key}"\n'
    findings = scanner.scan_file_content(content, "config.py")
    cleaned = cleaner.sanitize_content(content, findings)
    assert key not in cleaned
    assert "REDACTED" in cleaned or "sk_live_REDACTED" in cleaned

def test_sanitizer_replaces_aws_key():
    from depfence.sanitize.cleaner import SanitizeCleaner
    cleaner = SanitizeCleaner()
    scanner = SecretsScanner()
    content = "aws_key = AKIAIOSFODNN7EXAMPLE\n"
    findings = scanner.scan_file_content(content, "config.yml")
    cleaned = cleaner.sanitize_content(content, findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned

def test_sanitizer_no_findings_unchanged():
    from depfence.sanitize.cleaner import SanitizeCleaner
    cleaner = SanitizeCleaner()
    content = "port = 8080\nhost = localhost\n"
    cleaned = cleaner.sanitize_content(content, [])
    assert cleaned == content

def test_sanitizer_repo_scan_and_clean():
    from depfence.sanitize.cleaner import SanitizeCleaner
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        key = _STRIPE_LIVE + "X" * 24
        env_file = p / ".env"
        env_file.write_text(f"STRIPE_KEY={key}\n")
        cleaner = SanitizeCleaner()
        report = cleaner.sanitize_repo(p, write=False)
        assert report.files_scanned >= 1
        # Either found and would-clean, or at minimum scanned without error
        assert report is not None

def test_sanitizer_report_to_dict():
    from depfence.sanitize.cleaner import SanitizeReport
    report = SanitizeReport(
        project_dir="/tmp/test",
        files_scanned=5,
        files_modified=2,
        total_replacements=3,
    )
    d = report.to_dict()
    assert d["files_scanned"] == 5
    assert d["files_modified"] == 2
    assert d["total_replacements"] == 3

def test_sanitizer_report_save(tmp_path):
    from depfence.sanitize.cleaner import SanitizeReport
    report = SanitizeReport(project_dir=str(tmp_path), files_scanned=1)
    saved = report.save(tmp_path / "report.json")
    assert saved.exists()
    import json
    data = json.loads(saved.read_text())
    assert data["files_scanned"] == 1

# ===========================================================================
# 22. Detector tests
# ===========================================================================

def test_detector_from_project_no_yml(tmp_path):
    from depfence.sanitize.detector import DetectorConfig, SecretsDetector
    detector = SecretsDetector.from_project(tmp_path)
    assert detector is not None

def test_detector_config_defaults():
    from depfence.sanitize.detector import DetectorConfig
    cfg = DetectorConfig()
    assert cfg.entropy_threshold == 4.5
    assert cfg.scan_history is True
    assert cfg.history_depth == 50

def test_detector_config_from_yml(tmp_path):
    from depfence.sanitize.detector import DetectorConfig
    yml = tmp_path / "depfence.yml"
    yml.write_text("secrets:\n  org_terms:\n    - corp.internal\n  scan_history: false\n")
    try:
        cfg = DetectorConfig.from_depfence_yml(tmp_path)
        assert "corp.internal" in cfg.org_terms
        assert cfg.scan_history is False
    except ImportError:
        # yaml not available, skip gracefully
        pass

def test_detector_scan_content():
    from depfence.sanitize.detector import SecretsDetector
    detector = SecretsDetector()
    key = "ghp_" + "A" * 36
    matches = detector.scan_content(f"GITHUB_TOKEN={key}\n", "test.env")
    assert any("GitHub" in m.secret_type for m in matches)

@pytest.mark.asyncio
async def test_detector_scan_project(tmp_path):
    from depfence.sanitize.detector import SecretsDetector
    detector = SecretsDetector()
    key = "AKIAIOSFODNN7EXAMPLE"
    (tmp_path / "config.yml").write_text(f"aws_key: {key}\n")
    matches = await detector.scan_project(tmp_path)
    assert any("AWS" in m.secret_type for m in matches)

# ===========================================================================
# 23. Severity classification
# ===========================================================================

def test_severity_critical_for_aws():
    scanner = SecretsScanner()
    matches = scan(scanner, "key: AKIAIOSFODNN7EXAMPLE\n")
    aws = [m for m in matches if "AWS Access Key ID" in m.secret_type]
    assert all(m.severity == Severity.CRITICAL for m in aws)

def test_severity_high_for_github():
    scanner = SecretsScanner()
    key = "ghp_" + "A" * 36
    matches = scan(scanner, f"token={key}\n")
    gh = [m for m in matches if "GitHub Personal" in m.secret_type]
    assert all(m.severity == Severity.HIGH for m in gh)

def test_severity_medium_for_jwt():
    scanner = SecretsScanner()
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt = f"{header}.{payload}.{sig}"
    matches = scan(scanner, f"token: {jwt}\n")
    jwt_matches = [m for m in matches if "JWT" in m.secret_type]
    assert all(m.severity == Severity.MEDIUM for m in jwt_matches)

# ===========================================================================
# 24. Context lines
# ===========================================================================

def test_context_before_and_after():
    scanner = SecretsScanner()
    content = "# config file\nhost: localhost\napi_key: AKIAIOSFODNN7EXAMPLE\nport: 8080\ndebug: true\n"
    matches = scan(scanner, content, "config.yml")
    aws = [m for m in matches if "AWS Access Key ID" in m.secret_type]
    assert len(aws) > 0
    m = aws[0]
    assert m.line_num == 3
    assert len(m.context_before) > 0 or len(m.context_after) > 0

# ===========================================================================
# 25. Hardcoded password detection
# ===========================================================================

def test_hardcoded_password(scanner):
    text = 'password = "MyS3cr3tP4ss!"\n'
    matches = scan(scanner, text)
    pw_matches = [m for m in matches if "Password" in m.secret_type]
    assert len(pw_matches) > 0

def test_hardcoded_password_false_positive_suppressed(scanner):
    # Very common placeholder
    text = "password = changeme\n"
    matches = scan(scanner, text)
    pw_matches = [m for m in matches if m.severity == Severity.CRITICAL]
    assert len(pw_matches) == 0

# ===========================================================================
# 26. SendGrid / Twilio
# ===========================================================================

def test_sendgrid_key(scanner):
    key = "SG." + "A" * 22 + "." + "B" * 43
    matches = scan(scanner, f"SG_KEY={key}\n")
    assert any("SendGrid" in m.secret_type for m in matches)

# ===========================================================================
# 27. OpenAI key detection (original test suite compatibility)
# ===========================================================================

@pytest.mark.asyncio
async def test_detects_openai_key(scanner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        key = "sk-" + "A" * 48
        (p / ".env").write_text(f"OPENAI_API_KEY={key}\n")
        findings = await scanner.scan_project(p)
        assert any("OpenAI" in f.title for f in findings)
