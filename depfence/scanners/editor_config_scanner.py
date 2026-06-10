"""Editor config injection scanner — detects malicious AI-tool and editor config files.

Targets the Wave 3 attack vector: config files planted in repositories that
auto-execute payloads when developers open the repo in AI coding tools
(Claude Code, Gemini CLI, Cursor) or VS Code.

Detection rules:
1. Claude Code hook injection (SessionStart/PreToolUse/PostToolUse/Stop)
2. Gemini CLI hook injection (same pattern)
3. Cursor prompt injection (alwaysApply + execution instructions)
4. VS Code auto-run tasks (runOn: folderOpen)
5. Phantom Gyp cross-reference (binding.gyp without native sources)
6. Suspicious .github setup scripts (large or obfuscated)
7. Backdated config-only commits with [skip ci]
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

_HOOK_EVENTS = {"SessionStart", "PreToolUse", "PostToolUse", "Stop", "Notification"}

_SUSPICIOUS_COMMANDS = re.compile(
    r"\b(?:curl|wget|fetch)\b"
    r"|\bexec\b"
    r"|\bbash\s+-c\b"
    r"|\bsh\s+-c\b"
    r"|\bpowershell\b"
    r"|\brm\s+-rf\b"
    r"|\bnc\s+"
    r"|\b(?:python|python3|node|deno|bun)\s+\S+\.(?:js|py|ts|sh)\b",
    re.IGNORECASE,
)

_SAFE_TOOL_PREFIXES = {
    "ruff", "black", "isort", "mypy", "pylint", "flake8", "autopep8",
    "eslint", "prettier", "biome", "oxlint",
    "rustfmt", "clippy", "cargo fmt", "cargo clippy",
    "gofmt", "goimports", "golangci-lint",
    "tsc", "rubocop", "shfmt", "shellcheck",
    "taplo", "yamllint", "jsonlint",
    "echo", "true", "test",
}

_CURSOR_EXEC_PATTERNS = re.compile(
    r"\b(?:run|execute|launch|invoke|start)\b\s+[`'\"]?"
    r"(?:node|python|python3|bash|sh|deno|bun|\.github/|\.\/)"
    r"|```(?:bash|sh|shell)\s*\n[^`]*\b(?:node|python|bash|sh)\s+\S+\.(?:js|py|sh|ts)\b",
    re.IGNORECASE,
)

_KNOWN_BUILD_COMMANDS = {
    "npm", "yarn", "pnpm", "bun", "npx",
    "make", "cmake", "ninja", "meson",
    "cargo", "rustc",
    "dotnet", "msbuild",
    "gradle", "gradlew", "mvn", "mvnw", "ant",
    "tsc", "esbuild", "vite", "webpack", "rollup",
    "go", "zig",
    "bazel", "buck", "pants",
    "eslint", "prettier", "jest", "vitest", "mocha",
    "pytest", "ruff", "mypy", "black",
}

_NATIVE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".m", ".mm"}

_CONFIG_DIRS = {".claude", ".cursor", ".gemini", ".vscode"}

_SETUP_SCRIPT_NAMES = {"setup.js", "setup.sh", "setup.py", "setup.ts", "install.js", "install.sh"}

_SETUP_SCRIPT_MIN_SIZE = 100 * 1024  # 100KB

_MAX_COMMITS_TO_SCAN = 200

_BACKDATE_THRESHOLD_DAYS = 365


class EditorConfigScanner:
    name = "editor_config"
    ecosystems = ["config"]

    async def scan(self, packages: list) -> list[Finding]:
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_claude_config(project_dir))
        findings.extend(self._scan_gemini_config(project_dir))
        findings.extend(self._scan_cursor_rules(project_dir))
        findings.extend(self._scan_vscode_tasks(project_dir))
        findings.extend(self._scan_phantom_gyp(project_dir))
        findings.extend(self._scan_setup_scripts(project_dir))
        findings.extend(self._scan_backdated_config_commits(project_dir))
        return findings

    def _scan_claude_config(self, project_dir: Path) -> list[Finding]:
        settings = project_dir / ".claude" / "settings.json"
        if not settings.is_file():
            return []
        return self._scan_hook_config(settings, "Claude Code", project_dir)

    def _scan_gemini_config(self, project_dir: Path) -> list[Finding]:
        settings = project_dir / ".gemini" / "settings.json"
        if not settings.is_file():
            return []
        return self._scan_hook_config(settings, "Gemini CLI", project_dir)

    def _scan_hook_config(self, config_path: Path, tool_name: str, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(config_path.read_text(errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return findings

        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict):
            return findings

        rel_path = str(config_path.relative_to(project_dir))
        pkg = PackageId(ecosystem="config", name=rel_path)

        for event_name, hook_list in hooks.items():
            if event_name not in _HOOK_EVENTS:
                continue
            if not isinstance(hook_list, list):
                hook_list = [hook_list]
            for hook in hook_list:
                command = ""
                if isinstance(hook, dict):
                    command = hook.get("command", "")
                elif isinstance(hook, str):
                    command = hook
                if not command:
                    continue

                if self._is_safe_command(command):
                    continue

                if _SUSPICIOUS_COMMANDS.search(command):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.CRITICAL,
                        package=pkg,
                        title=f"{tool_name} hook injection: {event_name} runs shell command",
                        detail=(
                            f"{rel_path} contains a {event_name} hook that executes a "
                            f"suspicious command: {command[:200]}. "
                            f"This matches the config injection attack pattern where "
                            f"malicious hooks auto-run payloads when a developer opens the repo."
                        ),
                        cwe="CWE-506",
                        references=[
                            "https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again",
                        ],
                        confidence=0.90,
                        metadata={
                            "file": rel_path,
                            "hook_event": event_name,
                            "command": command[:500],
                            "tool": tool_name,
                            "check": "editor_config_hook_injection",
                        },
                    ))

        return findings

    def _scan_cursor_rules(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        rules_dir = project_dir / ".cursor" / "rules"
        if not rules_dir.is_dir():
            return findings

        for mdc_file in sorted(rules_dir.glob("*.mdc")):
            try:
                content = mdc_file.read_text(errors="ignore")
            except OSError:
                continue

            if not self._has_always_apply(content):
                continue

            body = self._extract_mdc_body(content)
            if _CURSOR_EXEC_PATTERNS.search(body):
                rel_path = str(mdc_file.relative_to(project_dir))
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    package=PackageId(ecosystem="config", name=rel_path),
                    title="Cursor rule prompt injection: alwaysApply with execution instructions",
                    detail=(
                        f"{rel_path} is an always-applied Cursor rule that instructs the AI "
                        f"agent to execute files. This matches the config injection attack "
                        f"pattern where prompt injection in .cursor/rules/ auto-runs payloads."
                    ),
                    cwe="CWE-94",
                    references=[
                        "https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again",
                    ],
                    confidence=0.90,
                    metadata={
                        "file": rel_path,
                        "has_always_apply": True,
                        "check": "editor_config_cursor_injection",
                    },
                ))

        return findings

    def _scan_vscode_tasks(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        tasks_file = project_dir / ".vscode" / "tasks.json"
        if not tasks_file.is_file():
            return findings

        try:
            content = tasks_file.read_text(errors="ignore")
            content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
            data = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return findings

        tasks = data.get("tasks", [])
        if not isinstance(tasks, list):
            return findings

        rel_path = str(tasks_file.relative_to(project_dir))
        pkg = PackageId(ecosystem="config", name=rel_path)

        for task in tasks:
            if not isinstance(task, dict):
                continue
            run_options = task.get("runOptions", {})
            if not isinstance(run_options, dict):
                continue
            if run_options.get("runOn") != "folderOpen":
                continue

            command = task.get("command", "")
            task_type = task.get("type", "")
            label = task.get("label", "")

            if self._is_known_build_task(command, task_type):
                continue

            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=Severity.HIGH,
                package=pkg,
                title=f"VS Code auto-run task: '{label or command}' runs on folder open",
                detail=(
                    f"{rel_path} contains a task that auto-executes when the folder is opened "
                    f"(runOn: folderOpen). Command: {command[:200]}. "
                    f"Legitimate build tasks use known build systems; this task runs a "
                    f"custom command that may execute untrusted code."
                ),
                cwe="CWE-506",
                references=[
                    "https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again",
                ],
                confidence=0.85,
                metadata={
                    "file": rel_path,
                    "task_label": label,
                    "command": command[:500],
                    "task_type": task_type,
                    "check": "editor_config_vscode_autorun",
                },
            ))

        return findings

    def _scan_phantom_gyp(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        gyp_file = project_dir / "binding.gyp"
        if not gyp_file.is_file():
            return findings

        has_native = any(
            f.suffix in _NATIVE_EXTENSIONS
            for f in project_dir.rglob("*")
            if f.is_file() and "node_modules" not in f.parts and ".git" not in f.parts
        )

        if has_native:
            return findings

        rel_path = str(gyp_file.relative_to(project_dir))
        pkg = PackageId(ecosystem="npm", name=project_dir.name)

        try:
            content = gyp_file.read_text(errors="ignore")
        except OSError:
            content = ""

        shell_patterns = re.findall(
            r'["\'](?:actions|postinstall_action)["\'].*?["\']([^"\']+)["\']',
            content, re.DOTALL,
        )
        has_shell = bool(re.search(
            r"\b(?:bash|sh|node|python|cmd|powershell)\b", content, re.I,
        ))

        severity = Severity.CRITICAL if has_shell else Severity.HIGH
        detail = (
            f"{rel_path} exists but no native C/C++ source files (.c/.cc/.cpp/.h) "
            f"were found in the project. A binding.gyp without native code is a "
            f"strong indicator of the Phantom Gyp attack vector, where gyp is used "
            f"as an alternate code execution hook during npm install."
        )
        if has_shell:
            detail += f" The gyp file also references shell commands."

        findings.append(Finding(
            finding_type=FindingType.INSTALL_SCRIPT,
            severity=severity,
            package=pkg,
            title="Phantom Gyp: binding.gyp without native source files",
            detail=detail,
            cwe="CWE-506",
            confidence=0.92,
            metadata={
                "file": rel_path,
                "has_native_sources": False,
                "has_shell_commands": has_shell,
                "check": "editor_config_phantom_gyp",
            },
        ))

        return findings

    def _scan_setup_scripts(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        github_dir = project_dir / ".github"
        if not github_dir.is_dir():
            return findings

        for name in _SETUP_SCRIPT_NAMES:
            script_path = github_dir / name
            if not script_path.is_file():
                continue

            try:
                size = script_path.stat().st_size
                content = script_path.read_text(errors="ignore") if size < 10 * 1024 * 1024 else ""
            except OSError:
                continue

            is_large = size > _SETUP_SCRIPT_MIN_SIZE
            is_obfuscated = self._detect_obfuscation(content) if content else False

            if not is_large and not is_obfuscated:
                continue

            rel_path = str(script_path.relative_to(project_dir))
            pkg = PackageId(ecosystem="config", name=rel_path)

            reasons = []
            if is_large:
                reasons.append(f"unusually large ({size / 1024:.0f}KB)")
            if is_obfuscated:
                reasons.append("contains obfuscation patterns")

            findings.append(Finding(
                finding_type=FindingType.OBFUSCATION if is_obfuscated else FindingType.BEHAVIORAL,
                severity=Severity.CRITICAL if (is_large and is_obfuscated) else Severity.HIGH,
                package=pkg,
                title=f"Suspicious setup script in .github/: {name}",
                detail=(
                    f"{rel_path} is {', '.join(reasons)}. "
                    f"Setup scripts in .github/ that are referenced by editor config hooks "
                    f"and exhibit these characteristics match the credential harvester "
                    f"payload pattern (staged obfuscation + credential theft)."
                ),
                cwe="CWE-506",
                confidence=0.85,
                metadata={
                    "file": rel_path,
                    "size_bytes": size,
                    "is_obfuscated": is_obfuscated,
                    "is_large": is_large,
                    "check": "editor_config_setup_script",
                },
            ))

        return findings

    def _scan_backdated_config_commits(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not (project_dir / ".git").exists():
            return findings

        try:
            result = subprocess.run(
                [
                    "git", "log",
                    f"--max-count={_MAX_COMMITS_TO_SCAN}",
                    "--format=%H\t%aI\t%cI\t%s",
                ],
                cwd=str(project_dir),
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return findings

        for line in result.stdout.strip().splitlines():
            parts = line.split("\t", 3)
            if len(parts) < 4:
                continue

            commit_hash, author_date, commit_date, subject = parts

            if not re.search(r"\[skip\s+ci\]|\[ci\s+skip\]", subject, re.I):
                continue

            if not self._is_backdated(author_date, commit_date):
                continue

            changed_files = self._get_commit_files(project_dir, commit_hash)
            if not changed_files:
                continue

            config_only = all(
                any(f.startswith(d + "/") for d in _CONFIG_DIRS)
                for f in changed_files
            )
            if not config_only:
                continue

            pkg = PackageId(ecosystem="git", name=project_dir.name)
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.CRITICAL,
                package=pkg,
                title="Backdated config-only commit with [skip ci]",
                detail=(
                    f"Commit {commit_hash[:8]} modifies only editor config files "
                    f"({', '.join(changed_files[:5])}) with [skip ci] in the message "
                    f"and has a backdated author timestamp ({author_date}). "
                    f"This is the exact commit pattern used to plant malicious "
                    f"AI-tool config files in legitimate repositories."
                ),
                cwe="CWE-506",
                confidence=0.88,
                metadata={
                    "commit": commit_hash,
                    "author_date": author_date,
                    "commit_date": commit_date,
                    "files": changed_files[:10],
                    "has_skip_ci": True,
                    "check": "editor_config_backdated_commit",
                },
            ))

        return findings

    @staticmethod
    def _get_commit_files(project_dir: Path, commit_hash: str) -> list[str]:
        try:
            result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit_hash],
                cwd=str(project_dir),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

    # --- helpers ---

    @staticmethod
    def _is_safe_command(command: str) -> bool:
        cmd_base = command.strip().split()[0] if command.strip() else ""
        cmd_base = cmd_base.rsplit("/", 1)[-1]
        return cmd_base.lower() in _SAFE_TOOL_PREFIXES

    @staticmethod
    def _has_always_apply(content: str) -> bool:
        frontmatter_match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not frontmatter_match:
            return False
        frontmatter = frontmatter_match.group(1)
        return bool(re.search(r"alwaysApply\s*:\s*true", frontmatter, re.I))

    @staticmethod
    def _extract_mdc_body(content: str) -> str:
        match = re.match(r"^---\s*\n.*?\n---\s*\n?(.*)", content, re.DOTALL)
        return match.group(1) if match else content

    @staticmethod
    def _is_known_build_task(command: str, task_type: str) -> bool:
        if task_type in ("npm", "gulp", "grunt", "jake", "typescript"):
            return True
        cmd_base = command.strip().split()[0] if command.strip() else ""
        cmd_base = cmd_base.rsplit("/", 1)[-1]
        return cmd_base.lower() in _KNOWN_BUILD_COMMANDS

    @staticmethod
    def _detect_obfuscation(content: str) -> bool:
        markers = 0
        if re.search(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}", content):
            markers += 1
        if re.search(r"(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)", content, re.I):
            markers += 1
        if len(re.findall(r"(?:\\x[0-9a-f]{2}){10,}", content, re.I)) > 3:
            markers += 1
        if re.search(r"(?:eval|exec)\s*\(\s*(?:.*?\.join|.*?\.reverse|.*?\.replace)\s*\(", content):
            markers += 1
        long_lines = [ln for ln in content.splitlines() if len(ln) > 1000]
        if long_lines and len(long_lines) > len(content.splitlines()) * 0.5:
            markers += 1
        if content:
            freq: dict[str, int] = {}
            total = 0
            for ch in content:
                if ch.isprintable():
                    freq[ch] = freq.get(ch, 0) + 1
                    total += 1
            if total > 0:
                entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
                if entropy > 5.5:
                    markers += 1
        return markers >= 2

    @staticmethod
    def _is_backdated(author_date: str, commit_date: str) -> bool:
        try:
            from datetime import datetime, timezone
            a = datetime.fromisoformat(author_date.replace("Z", "+00:00"))
            c = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
            delta = abs((c - a).total_seconds())
            return delta > _BACKDATE_THRESHOLD_DAYS * 86400
        except (ValueError, TypeError):
            return False
