"""Tests for the PostToolUse secrets leak detector hook."""

from __future__ import annotations

import pytest

from depfence.integrations import secrets_leak_detector as hook

# ---------------------------------------------------------------------------
# Construct secret-pattern test strings at runtime to avoid triggering push
# protection or on-write security hooks on the test source file itself.
# ---------------------------------------------------------------------------
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"            # 20 chars, valid AKIA format
_GH_TOKEN = "ghp_" + "x" * 36                     # 40 chars, ghp_ prefix
_STRIPE_KEY = "sk_" + "live_" + "A" * 24          # sk_live_ + 24 chars
_GOOGLE_KEY = "AIza" + "B" * 35                   # AIza + 35 chars
_SLACK_TOKEN = "xox" + "b-" + "C" * 20            # xoxb- + 20 chars

# PEM markers split so no single literal matches a scanner pattern.
_PEM_TYPE_RSA = "RSA"
_PEM_TYPE_OPENSSH = "OPENSSH"
_PEM_BEGIN = "-----BEGIN "
_PEM_KEY_SUFFIX = " PRIVATE KEY-----"
_PEM_END_PREFIX = "-----END "
_PEM_HEADER = _PEM_BEGIN + _PEM_TYPE_RSA + _PEM_KEY_SUFFIX
_PEM_HEADER_OPENSSH = _PEM_BEGIN + _PEM_TYPE_OPENSSH + _PEM_KEY_SUFFIX
_PEM_FOOTER = _PEM_END_PREFIX + _PEM_TYPE_RSA + _PEM_KEY_SUFFIX


def _patch(monkeypatch):
    """Clear the kill-switch so tests always run with the hook enabled."""
    monkeypatch.delenv("DEPFENCE_SECRETS_LEAK", raising=False)


# ===========================================================================
# 1. Non-file tools are no-op
# ===========================================================================

def test_non_file_tool_bash_is_noop(monkeypatch):
    _patch(monkeypatch)
    assert hook.main({"tool_name": "Bash", "tool_input": {"command": "echo hi"}}) == {}


def test_non_file_tool_read_is_noop(monkeypatch):
    _patch(monkeypatch)
    assert hook.main({"tool_name": "Read", "tool_input": {"file_path": "x.py"}}) == {}


def test_non_file_tool_grep_is_noop(monkeypatch):
    _patch(monkeypatch)
    assert hook.main({"tool_name": "Grep", "tool_input": {"pattern": "foo"}}) == {}


# ===========================================================================
# 2. Clean code file is no-op
# ===========================================================================

def test_clean_python_is_noop(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "src/app.py",
        "content": "def hello():\n    return 'world'\n",
    }})
    assert out == {}


def test_clean_yaml_is_noop(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.yml",
        "content": "environment: production\nport: 8080\n",
    }})
    assert out == {}


# ===========================================================================
# 3. AWS access key emits warning with redacted value
# ===========================================================================

def test_aws_access_key_warns(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"AWS_ACCESS_KEY_ID = '{_AWS_KEY}'\n",
    }})
    assert "systemMessage" in out
    assert "AWS access key" in out["systemMessage"]


def test_aws_access_key_has_redacted_hint(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }})
    msg = out["systemMessage"]
    # Prefix visible (type is identifiable from the AKIA marker)
    assert "AKIA" in msg
    # Mask present
    assert "****" in msg
    # Full raw key value must NOT appear
    assert _AWS_KEY not in msg


# ===========================================================================
# 4. GitHub token emits warning with redacted value
# ===========================================================================

def test_github_personal_token_warns(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "auth.py",
        "content": f"token = '{_GH_TOKEN}'\n",
    }})
    assert "systemMessage" in out
    assert "GitHub" in out["systemMessage"]
    assert "****" in out["systemMessage"]
    assert _GH_TOKEN not in out["systemMessage"]


def test_github_token_no_raw_value_in_message(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "ci.py",
        "content": f"GH_TOKEN = '{_GH_TOKEN}'\n",
    }})
    assert _GH_TOKEN not in out["systemMessage"]


# ===========================================================================
# 5. Private key PEM block emits warning
# ===========================================================================

def test_rsa_private_key_warns(monkeypatch):
    _patch(monkeypatch)
    content = (
        _PEM_HEADER + "\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4VE...\n"
        + _PEM_FOOTER + "\n"
    )
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "server.py",
        "content": content,
    }})
    assert "systemMessage" in out
    assert "Private key" in out["systemMessage"]


def test_openssh_private_key_warns(monkeypatch):
    _patch(monkeypatch)
    content = _PEM_HEADER_OPENSSH + "\nb3BlbnNzaC1rZXktdjEA...\n"
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "deploy.py",
        "content": content,
    }})
    assert "systemMessage" in out
    assert "Private key" in out["systemMessage"]


# ===========================================================================
# 6. Exempt files are skipped
# ===========================================================================

def test_dotenv_file_is_skipped(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "/project/.env",
        "content": f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n",
    }})
    assert out == {}


def test_dotenv_variant_local_is_skipped(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": ".env.local",
        "content": f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n",
    }})
    assert out == {}


def test_dotenv_variant_production_is_skipped(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config/.env.production",
        "content": f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n",
    }})
    assert out == {}


def test_pem_file_is_skipped(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "certs/server.pem",
        "content": _PEM_HEADER + "\n...\n",
    }})
    assert out == {}


def test_key_file_is_skipped(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "/etc/ssl/private/server.key",
        "content": _PEM_HEADER + "\n...\n",
    }})
    assert out == {}


# ===========================================================================
# 7. Multiple secrets in one file — all are reported
# ===========================================================================

def test_multiple_secrets_all_reported(monkeypatch):
    _patch(monkeypatch)
    content = (
        f"aws_key = '{_AWS_KEY}'\n"
        f"gh_token = '{_GH_TOKEN}'\n"
    )
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": content,
    }})
    assert "systemMessage" in out
    msg = out["systemMessage"]
    assert "AWS access key" in msg
    assert "GitHub" in msg


def test_three_different_secret_types(monkeypatch):
    _patch(monkeypatch)
    content = (
        f"aws = '{_AWS_KEY}'\n"
        f"stripe = '{_STRIPE_KEY}'\n"
        + _PEM_HEADER + "\n"
    )
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "secrets.py",
        "content": content,
    }})
    msg = out["systemMessage"]
    assert "AWS access key" in msg
    assert "Stripe" in msg
    assert "Private key" in msg
    # Count in header message reflects all three
    assert "3" in msg


def test_duplicate_same_secret_deduplicated(monkeypatch):
    _patch(monkeypatch)
    # Same key twice in same file → only one finding
    content = f"A = '{_AWS_KEY}'\nB = '{_AWS_KEY}'\n"
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": content,
    }})
    assert "systemMessage" in out
    # Should say "1 potential secret" not "2"
    assert "1 potential secret" in out["systemMessage"]


# ===========================================================================
# 8. Disabled via env var is no-op
# ===========================================================================

def test_disabled_zero_is_noop(monkeypatch):
    monkeypatch.setenv("DEPFENCE_SECRETS_LEAK", "0")
    assert hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }}) == {}


def test_disabled_false_is_noop(monkeypatch):
    monkeypatch.setenv("DEPFENCE_SECRETS_LEAK", "false")
    assert hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }}) == {}


def test_disabled_no_is_noop(monkeypatch):
    monkeypatch.setenv("DEPFENCE_SECRETS_LEAK", "no")
    assert hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }}) == {}


def test_disabled_off_is_noop(monkeypatch):
    monkeypatch.setenv("DEPFENCE_SECRETS_LEAK", "off")
    assert hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }}) == {}


# ===========================================================================
# 9. Secret values are NEVER in the systemMessage output
# ===========================================================================

def test_raw_aws_key_absent_from_message(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }})
    assert _AWS_KEY not in out["systemMessage"]


def test_raw_github_token_absent_from_message(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "auth.py",
        "content": f"token = '{_GH_TOKEN}'\n",
    }})
    assert _GH_TOKEN not in out["systemMessage"]


def test_raw_stripe_key_absent_from_message(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "payments.py",
        "content": f"STRIPE_KEY = '{_STRIPE_KEY}'\n",
    }})
    assert "systemMessage" in out
    assert _STRIPE_KEY not in out["systemMessage"]


def test_multiple_raw_values_all_absent_from_message(monkeypatch):
    _patch(monkeypatch)
    content = f"a = '{_AWS_KEY}'\nb = '{_GH_TOKEN}'\nc = '{_STRIPE_KEY}'\n"
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": content,
    }})
    msg = out["systemMessage"]
    assert _AWS_KEY not in msg
    assert _GH_TOKEN not in msg
    assert _STRIPE_KEY not in msg


# ===========================================================================
# Edit and MultiEdit tool support
# ===========================================================================

def test_edit_uses_new_string_not_content(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Edit", "tool_input": {
        "file_path": "src/config.py",
        "old_string": "TOKEN = ''",
        "new_string": f"TOKEN = '{_GH_TOKEN}'",
        # 'content' field should be ignored for Edit
        "content": "this field is not used by the Edit tool",
    }})
    assert "systemMessage" in out
    assert "GitHub" in out["systemMessage"]


def test_edit_clean_new_string_is_noop(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Edit", "tool_input": {
        "file_path": "src/config.py",
        "old_string": "x = 1",
        "new_string": "x = 2",
    }})
    assert out == {}


def test_multiedit_scans_all_new_strings(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "MultiEdit", "tool_input": {
        "file_path": "src/config.py",
        "edits": [
            {"old_string": "x", "new_string": "clean code here"},
            {"old_string": "y", "new_string": f"key = '{_AWS_KEY}'"},
        ],
    }})
    assert "systemMessage" in out
    assert "AWS access key" in out["systemMessage"]


def test_multiedit_all_clean_is_noop(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "MultiEdit", "tool_input": {
        "file_path": "src/config.py",
        "edits": [
            {"old_string": "a", "new_string": "b"},
            {"old_string": "c", "new_string": "d"},
        ],
    }})
    assert out == {}


# ===========================================================================
# Additional pattern coverage
# ===========================================================================

def test_google_api_key_warns(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "maps.py",
        "content": f"MAPS_KEY = '{_GOOGLE_KEY}'\n",
    }})
    assert "systemMessage" in out
    assert "Google API key" in out["systemMessage"]
    assert _GOOGLE_KEY not in out["systemMessage"]


def test_slack_token_warns(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "notify.py",
        "content": f"SLACK_TOKEN = '{_SLACK_TOKEN}'\n",
    }})
    assert "systemMessage" in out
    assert "Slack" in out["systemMessage"]
    assert _SLACK_TOKEN not in out["systemMessage"]


# ===========================================================================
# _redact unit tests
# ===========================================================================

def test_redact_normal_value():
    val = "A" * 20
    result = hook._redact(val)
    assert result == "AAAAAAAA****AAAA"
    assert "****" in result


def test_redact_aws_key_format():
    result = hook._redact(_AWS_KEY)
    assert result.startswith("AKIA")
    assert "****" in result
    assert _AWS_KEY not in result


def test_redact_short_value_fully_masked():
    # Values ≤ prefix+suffix (12) chars → just ****
    assert hook._redact("short") == "****"
    assert hook._redact("AB") == "****"
    assert hook._redact("x" * 12) == "****"


def test_redact_just_over_threshold():
    # 13 chars: prefix(8) + **** + suffix(4) = overlapping representation
    val = "A" * 13
    result = hook._redact(val)
    assert "****" in result
    assert val not in result


# ===========================================================================
# _is_exempt unit tests
# ===========================================================================

def test_is_exempt_dotenv_variants():
    assert hook._is_exempt(".env")
    assert hook._is_exempt(".env.local")
    assert hook._is_exempt(".env.production")
    assert hook._is_exempt(".env.test")
    assert hook._is_exempt("/full/path/to/.env")
    assert hook._is_exempt("config/.env.staging")


def test_is_exempt_pem_and_key():
    assert hook._is_exempt("server.pem")
    assert hook._is_exempt("ca.pem")
    assert hook._is_exempt("/etc/ssl/server.key")
    assert hook._is_exempt("id_rsa.key")


def test_is_not_exempt_normal_files():
    assert not hook._is_exempt("config.py")
    assert not hook._is_exempt("settings.py")
    assert not hook._is_exempt("src/app.js")
    assert not hook._is_exempt(".github/workflows/ci.yml")
    assert not hook._is_exempt("Makefile")


def test_is_not_exempt_env_without_dot():
    # "env" without leading dot is not an exempt dotenv file
    assert not hook._is_exempt("env")
    assert not hook._is_exempt("env.py")


# ===========================================================================
# PostToolUse contract: systemMessage only, never permissionDecision
# ===========================================================================

def test_output_never_contains_permission_decision(monkeypatch):
    _patch(monkeypatch)
    out = hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": f"key = '{_AWS_KEY}'\n",
    }})
    # PostToolUse hooks must never emit permissionDecision
    assert "hookSpecificOutput" not in out
    assert "permissionDecision" not in out
    assert "systemMessage" in out


def test_empty_content_is_noop(monkeypatch):
    _patch(monkeypatch)
    assert hook.main({"tool_name": "Write", "tool_input": {
        "file_path": "config.py",
        "content": "",
    }}) == {}


def test_missing_tool_input_is_noop(monkeypatch):
    _patch(monkeypatch)
    assert hook.main({"tool_name": "Write"}) == {}
