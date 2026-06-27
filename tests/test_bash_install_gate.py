"""Tests for depfence.integrations.bash_install_gate.

Typosquat ground truth (verified against the detector's popular lists):
  - "reqeusts"  → transposition of "requests"  (lev=2, confidence=0.75, pypi)
  - "loadsh"    → transposition of "lodash"     (lev=2, confidence=0.75, npm)
  - "requests"  → exact match in POPULAR_PYPI   → None (safe)
  - "lodash"    → exact match in POPULAR_NPM    → None (safe)
  - "numpy"     → exact match in POPULAR_PYPI   → None (safe)
"""

from __future__ import annotations

import os

import pytest

from depfence.integrations.bash_install_gate import (
    _extract_packages,
    _scan_command,
    _strip_version,
    main,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bash(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def _non_bash(tool_name: str = "Write") -> dict:
    return {"tool_name": tool_name, "tool_input": {"file_path": "/tmp/x.py", "content": ""}}


def _clean(monkeypatch) -> None:
    """Remove gate env vars so each test starts from a known baseline."""
    monkeypatch.delenv("DEPFENCE_INSTALL_GATE", raising=False)
    monkeypatch.delenv("DEPFENCE_INSTALL_GATE_BLOCK", raising=False)


# ---------------------------------------------------------------------------
# Fast-path / no-op tests
# ---------------------------------------------------------------------------

class TestFastPath:
    def test_non_bash_tool_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_non_bash("Write")) == {}

    def test_non_bash_edit_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_non_bash("Edit")) == {}

    def test_non_bash_multiedit_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_non_bash("MultiEdit")) == {}

    def test_bash_without_install_command_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("ls -la && echo hello")) == {}

    def test_bash_cargo_build_is_noop(self, monkeypatch):
        """cargo build is not an install command."""
        _clean(monkeypatch)
        assert main(_bash("cargo build --release")) == {}

    def test_bash_cargo_test_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("cargo test --workspace")) == {}

    def test_empty_command_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("")) == {}

    def test_missing_tool_input_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main({"tool_name": "Bash"}) == {}

    def test_missing_command_key_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main({"tool_name": "Bash", "tool_input": {}}) == {}


# ---------------------------------------------------------------------------
# Disable-gate tests
# ---------------------------------------------------------------------------

class TestDisableGate:
    def test_disabled_via_zero(self, monkeypatch):
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE", "0")
        # A known typosquat must be silently ignored
        assert main(_bash("pip install reqeusts")) == {}

    def test_disabled_via_false(self, monkeypatch):
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE", "false")
        assert main(_bash("pip install reqeusts")) == {}

    def test_disabled_via_no(self, monkeypatch):
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE", "no")
        assert main(_bash("pip install reqeusts")) == {}

    def test_disabled_via_off(self, monkeypatch):
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE", "off")
        assert main(_bash("pip install reqeusts")) == {}

    def test_disabled_overrides_block_mode(self, monkeypatch):
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE", "0")
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        assert main(_bash("pip install reqeusts")) == {}


# ---------------------------------------------------------------------------
# Ignore-pattern tests (local installs, requirement files, no-arg forms)
# ---------------------------------------------------------------------------

class TestIgnorePatterns:
    def test_pip_install_requirements_file_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install -r requirements.txt")) == {}

    def test_pip_install_constraint_file_is_noop(self, monkeypatch):
        """The -c flag consumes constraints.txt; the real package (requests) is safe."""
        _clean(monkeypatch)
        assert main(_bash("pip install -c constraints.txt requests")) == {}

    def test_pip_install_editable_dot_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install -e .")) == {}

    def test_pip_install_editable_relative_path_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install -e ./mypackage")) == {}

    def test_pip_install_bare_dot_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install .")) == {}

    def test_pip_install_absolute_path_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install /some/local/package")) == {}

    def test_pip_install_url_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install https://example.com/pkg.tar.gz")) == {}

    def test_pip_install_git_url_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install git+https://github.com/user/repo.git")) == {}

    def test_npm_install_no_args_is_noop(self, monkeypatch):
        """npm install with no package name installs from package.json."""
        _clean(monkeypatch)
        assert main(_bash("npm install")) == {}

    def test_npm_ci_is_noop(self, monkeypatch):
        """npm ci is a clean install from the lock file, not a package install."""
        _clean(monkeypatch)
        assert main(_bash("npm ci")) == {}

    def test_pnpm_install_no_args_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pnpm install")) == {}


# ---------------------------------------------------------------------------
# Known-safe package tests
# ---------------------------------------------------------------------------

class TestKnownSafePackages:
    def test_pip_install_requests_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install requests")) == {}

    def test_pip_install_numpy_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install numpy")) == {}

    def test_npm_install_lodash_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("npm install lodash")) == {}

    def test_pip_install_requests_with_version_is_noop(self, monkeypatch):
        """Version specifier must be stripped before checking."""
        _clean(monkeypatch)
        assert main(_bash("pip install requests>=2.0.0")) == {}

    def test_pip_install_requests_bracket_extra_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install requests[security]")) == {}

    def test_pip_install_multi_safe_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install requests numpy pandas")) == {}


# ---------------------------------------------------------------------------
# Typosquat detection — warn-only (default)
# ---------------------------------------------------------------------------

class TestTyposquatWarnOnly:
    def test_pip_install_reqeusts_emits_system_message(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pip install reqeusts"))
        assert "systemMessage" in result
        msg = result["systemMessage"]
        assert "reqeusts" in msg
        assert "requests" in msg

    def test_system_message_contains_confidence_percentage(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pip install reqeusts"))
        assert "%" in result["systemMessage"]

    def test_system_message_contains_attack_type(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pip install reqeusts"))
        assert "transposition" in result["systemMessage"]

    def test_system_message_no_permission_decision(self, monkeypatch):
        """Warn-only mode must never emit a permissionDecision field."""
        _clean(monkeypatch)
        result = main(_bash("pip install reqeusts"))
        assert "hookSpecificOutput" not in result

    def test_pip3_install_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pip3 install reqeusts"))
        assert "systemMessage" in result
        assert "reqeusts" in result["systemMessage"]

    def test_python_m_pip_install_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("python -m pip install reqeusts"))
        assert "systemMessage" in result

    def test_python3_m_pip_install_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("python3 -m pip install reqeusts"))
        assert "systemMessage" in result

    def test_npm_install_loadsh_emits_system_message(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("npm install loadsh"))
        assert "systemMessage" in result
        msg = result["systemMessage"]
        assert "loadsh" in msg
        assert "lodash" in msg

    def test_npm_i_shorthand_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("npm i loadsh"))
        assert "systemMessage" in result

    def test_yarn_add_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("yarn add loadsh"))
        assert "systemMessage" in result

    def test_pnpm_add_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pnpm add loadsh"))
        assert "systemMessage" in result

    def test_pnpm_install_with_arg_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pnpm install loadsh"))
        assert "systemMessage" in result

    def test_npm_install_save_dev_flag_typosquat(self, monkeypatch):
        """Flags between subcommand and package name must not prevent detection."""
        _clean(monkeypatch)
        result = main(_bash("npm install --save-dev loadsh"))
        assert "systemMessage" in result

    def test_pip_install_upgrade_flag_typosquat(self, monkeypatch):
        _clean(monkeypatch)
        result = main(_bash("pip install --upgrade reqeusts"))
        assert "systemMessage" in result


# ---------------------------------------------------------------------------
# Block mode tests
# ---------------------------------------------------------------------------

class TestBlockMode:
    def test_block_mode_one_emits_deny(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        result = main(_bash("pip install reqeusts"))
        assert "hookSpecificOutput" in result
        ho = result["hookSpecificOutput"]
        assert ho["hookEventName"] == "PreToolUse"
        assert ho["permissionDecision"] == "deny"
        assert "reqeusts" in ho["permissionDecisionReason"]
        assert "requests" in ho["permissionDecisionReason"]

    def test_block_mode_true_emits_deny(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "true")
        result = main(_bash("pip install reqeusts"))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_block_mode_yes_emits_deny(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "yes")
        result = main(_bash("pip install reqeusts"))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_block_mode_safe_package_still_noop(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        assert main(_bash("pip install requests")) == {}

    def test_block_reason_contains_verify_guidance(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        result = main(_bash("pip install reqeusts"))
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        assert "Verify" in reason or "verify" in reason

    def test_no_system_message_in_block_mode(self, monkeypatch):
        """Block mode must not emit both systemMessage and hookSpecificOutput."""
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        result = main(_bash("pip install reqeusts"))
        assert "systemMessage" not in result


# ---------------------------------------------------------------------------
# Multi-package command tests
# ---------------------------------------------------------------------------

class TestMultiPackage:
    def test_multi_package_flags_typosquat_among_safe(self, monkeypatch):
        _clean(monkeypatch)
        # requests and numpy are safe; reqeusts should be flagged
        result = main(_bash("pip install requests reqeusts numpy"))
        assert "systemMessage" in result
        assert "reqeusts" in result["systemMessage"]

    def test_multi_package_all_safe_is_noop(self, monkeypatch):
        _clean(monkeypatch)
        assert main(_bash("pip install requests numpy pandas")) == {}

    def test_multi_package_deduplication(self, monkeypatch):
        """The same suspect appearing twice should produce one finding, not two."""
        _clean(monkeypatch)
        result = main(_bash("pip install reqeusts reqeusts"))
        assert "systemMessage" in result
        # The suspect name appears exactly once in the bullet list
        msg = result["systemMessage"]
        # Count occurrences in the bullet lines only (after the header)
        bullet_lines = [ln for ln in msg.splitlines() if ln.strip().startswith("-")]
        suspects = [ln for ln in bullet_lines if "reqeusts" in ln]
        assert len(suspects) == 1

    def test_multi_package_block_mode(self, monkeypatch):
        _clean(monkeypatch)
        monkeypatch.setenv("DEPFENCE_INSTALL_GATE_BLOCK", "1")
        result = main(_bash("pip install requests reqeusts"))
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


# ---------------------------------------------------------------------------
# Unit tests for internal helpers
# ---------------------------------------------------------------------------

class TestExtractPackages:
    def test_simple_package(self):
        assert _extract_packages("requests", "pypi") == ["requests"]

    def test_multiple_packages(self):
        assert _extract_packages("requests numpy pandas", "pypi") == ["requests", "numpy", "pandas"]

    def test_flag_stripped(self):
        assert _extract_packages("--upgrade requests", "pypi") == ["requests"]

    def test_r_flag_consumes_next(self):
        assert _extract_packages("-r requirements.txt", "pypi") == []

    def test_e_flag_consumes_next(self):
        assert _extract_packages("-e .", "pypi") == []

    def test_dot_skipped(self):
        assert _extract_packages(".", "pypi") == []

    def test_relative_path_skipped(self):
        assert _extract_packages("./mypackage", "pypi") == []

    def test_absolute_path_skipped(self):
        assert _extract_packages("/opt/local/package", "pypi") == []

    def test_url_skipped(self):
        assert _extract_packages("https://example.com/pkg.whl", "pypi") == []

    def test_git_url_skipped(self):
        assert _extract_packages("git+https://github.com/u/r.git", "pypi") == []

    def test_requirements_txt_token_skipped(self):
        assert _extract_packages("requirements.txt", "pypi") == []

    def test_version_specifier_stripped(self):
        assert _extract_packages("requests>=2.0", "pypi") == ["requests"]

    def test_npm_scoped_package_preserved(self):
        pkgs = _extract_packages("@types/node", "npm")
        assert pkgs == ["@types/node"]

    def test_npm_scoped_package_version_stripped(self):
        pkgs = _extract_packages("@types/node@18.0.0", "npm")
        assert pkgs == ["@types/node"]


class TestStripVersion:
    def test_plain_name_unchanged(self):
        assert _strip_version("requests", "pypi") == "requests"

    def test_ge_specifier(self):
        assert _strip_version("requests>=2.0", "pypi") == "requests"

    def test_eq_specifier(self):
        assert _strip_version("requests==2.28.0", "pypi") == "requests"

    def test_bracket_extra(self):
        assert _strip_version("requests[security]", "pypi") == "requests"

    def test_npm_at_version(self):
        assert _strip_version("lodash@4.17.21", "npm") == "lodash"

    def test_npm_scoped_no_version(self):
        assert _strip_version("@types/node", "npm") == "@types/node"

    def test_npm_scoped_with_version(self):
        assert _strip_version("@types/node@18.0.0", "npm") == "@types/node"


class TestScanCommand:
    def test_pip_install_detected(self):
        results = _scan_command("pip install requests")
        assert ("requests", "pypi") in results

    def test_npm_install_detected(self):
        results = _scan_command("npm install lodash")
        assert ("lodash", "npm") in results

    def test_yarn_add_detected(self):
        results = _scan_command("yarn add lodash")
        assert ("lodash", "npm") in results

    def test_npm_ci_not_detected(self):
        results = _scan_command("npm ci")
        assert results == []

    def test_cargo_build_not_detected(self):
        results = _scan_command("cargo build --release")
        assert results == []

    def test_cargo_add_detected(self):
        results = _scan_command("cargo add serde")
        assert ("serde", "cargo") in results

    def test_go_get_detected(self):
        results = _scan_command("go get github.com/some/module")
        # The token won't be skipped — it's a go module path (no ://)
        pkgs = [pkg for pkg, _ in results]
        assert any("github.com" in p or "module" in p for p in pkgs)

    def test_gem_install_detected(self):
        results = _scan_command("gem install nokogiri")
        assert ("nokogiri", "gem") in results

    def test_bundle_add_detected(self):
        results = _scan_command("bundle add nokogiri")
        assert ("nokogiri", "gem") in results

    def test_composer_require_detected(self):
        results = _scan_command("composer require vendor/package")
        pkgs = [pkg for pkg, _ in results]
        assert "vendor/package" in pkgs

    def test_pip_install_no_command_boundary_spill(self):
        """A semicolon-separated command should not bleed into the next segment."""
        results = _scan_command("pip install requests; echo done")
        assert len([r for r in results if r[0] == "done"]) == 0

    def test_pipeline_command(self):
        """Packages on both sides of a && are each independently parsed."""
        results = _scan_command("pip install requests && npm install lodash")
        pkg_names = [pkg for pkg, _ in results]
        assert "requests" in pkg_names
        assert "lodash" in pkg_names
