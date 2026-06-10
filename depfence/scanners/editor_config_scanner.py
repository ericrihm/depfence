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
        findings.extend(self._scan_agent_rules(project_dir))
        findings.extend(self._scan_vscode_tasks(project_dir))
        findings.extend(self._scan_phantom_gyp(project_dir))
        findings.extend(self._scan_setup_scripts(project_dir))
        findings.extend(self._scan_backdated_config_commits(project_dir))
        findings.extend(self._scan_devcontainer(project_dir))
        findings.extend(self._scan_envrc(project_dir))
        findings.extend(self._scan_git_hooks(project_dir))
        findings.extend(self._scan_yarnrc(project_dir))
        findings.extend(self._scan_vscode_launch(project_dir))
        findings.extend(self._scan_code_workspace(project_dir))
        findings.extend(self._scan_vscode_extensions(project_dir))
        findings.extend(self._scan_zed(project_dir))
        findings.extend(self._scan_jetbrains(project_dir))
        findings.extend(self._scan_aider(project_dir))
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

    def _scan_agent_rules(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        rule_sources: list[tuple[Path, bool]] = []

        # .cursor/rules/*.mdc (frontmatter)
        cursor_dir = project_dir / ".cursor" / "rules"
        if cursor_dir.is_dir():
            for f in sorted(cursor_dir.glob("*.mdc")):
                rule_sources.append((f, True))

        # .windsurf/rules/*.md (frontmatter)
        ws_dir = project_dir / ".windsurf" / "rules"
        if ws_dir.is_dir():
            for f in sorted(ws_dir.glob("*.md")):
                rule_sources.append((f, True))

        # .roo/rules/*.md (frontmatter)
        roo_dir = project_dir / ".roo" / "rules"
        if roo_dir.is_dir():
            for f in sorted(roo_dir.glob("*.md")):
                rule_sources.append((f, True))

        # .continue/rules/*.md (frontmatter)
        cont_dir = project_dir / ".continue" / "rules"
        if cont_dir.is_dir():
            for f in sorted(cont_dir.glob("*.md")):
                rule_sources.append((f, True))

        # Plain rule files (always-applied, no frontmatter needed)
        for name in (".windsurfrules", ".clinerules", "AGENTS.md"):
            f = project_dir / name
            if f.is_file():
                rule_sources.append((f, False))

        # .clinerules as directory
        cline_dir = project_dir / ".clinerules"
        if cline_dir.is_dir():
            for f in sorted(cline_dir.rglob("*.md")):
                rule_sources.append((f, False))

        for rule_file, needs_frontmatter in rule_sources:
            try:
                content = rule_file.read_text(errors="ignore")
            except OSError:
                continue

            if needs_frontmatter and not self._has_always_apply(content):
                continue

            body = self._extract_mdc_body(content) if needs_frontmatter else content
            if _CURSOR_EXEC_PATTERNS.search(body):
                rel_path = str(rule_file.relative_to(project_dir))
                findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    package=PackageId(ecosystem="config", name=rel_path),
                    title=f"Agent rule prompt injection: execution instructions in {rel_path}",
                    detail=(
                        f"{rel_path} is an {'always-applied ' if needs_frontmatter else ''}"
                        f"agent rule that instructs the AI to execute files."
                    ),
                    cwe="CWE-94",
                    confidence=0.90,
                    metadata={
                        "file": rel_path,
                        "has_always_apply": not needs_frontmatter or True,
                        "check": "editor_config_agent_rule_injection",
                    },
                ))

            # PB-03: route any referenced payload
            self._route_payload_refs(body, project_dir, findings)

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

    # --- ea-03: devcontainer lifecycle ---

    _DEVCONTAINER_LIFECYCLE_KEYS = [
        "initializeCommand", "onCreateCommand", "updateContentCommand",
        "postCreateCommand", "postStartCommand", "postAttachCommand",
    ]
    _DEVCONTAINER_SEVERITY = {
        "initializeCommand": Severity.CRITICAL,
        "onCreateCommand": Severity.HIGH,
        "updateContentCommand": Severity.HIGH,
        "postCreateCommand": Severity.HIGH,
        "postStartCommand": Severity.MEDIUM,
        "postAttachCommand": Severity.MEDIUM,
    }

    def _scan_devcontainer(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        candidates = [
            project_dir / ".devcontainer" / "devcontainer.json",
            project_dir / ".devcontainer.json",
        ]
        for config_path in candidates:
            if not config_path.is_file():
                continue
            try:
                raw = config_path.read_text(errors="ignore")
                raw = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                continue
            rel = str(config_path.relative_to(project_dir))
            pkg = PackageId(ecosystem="config", name=rel)
            for key in self._DEVCONTAINER_LIFECYCLE_KEYS:
                val = data.get(key)
                if not val:
                    continue
                cmds = [val] if isinstance(val, str) else (list(val.values()) if isinstance(val, dict) else list(val))
                for cmd in cmds:
                    if not isinstance(cmd, str) or not cmd.strip():
                        continue
                    if self._is_safe_command(cmd):
                        continue
                    if _SUSPICIOUS_COMMANDS.search(cmd):
                        sev = self._DEVCONTAINER_SEVERITY.get(key, Severity.HIGH)
                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            severity=sev,
                            package=pkg,
                            title=f"Devcontainer lifecycle hook: {key}",
                            detail=f"{rel} {key} runs: {cmd[:200]}",
                            cwe="CWE-506",
                            confidence=0.85,
                            metadata={"file": rel, "key": key, "command": cmd[:500], "check": "editor_config_devcontainer"},
                        ))
                    self._route_payload_refs(cmd, project_dir, findings)
        return findings

    # --- ea-04: direnv .envrc ---

    _ENVRC_SAFE_PREFIXES = re.compile(
        r"^\s*(?:export|layout|use|dotenv|dotenv_if_exists|source_env|source_up"
        r"|watch_file|PATH_add|path_add|strict_env)\b",
    )
    _ENVRC_DANGEROUS = re.compile(
        r"\bcurl\b|\bwget\b|\|\s*(?:bash|sh)\b|\bbase64\s+-d\b|\beval\b"
        r"|\b(?:node|python|python3|bash)\s+\S+\.(?:js|py|sh|ts)\b"
        r"|\bsource\s+\.github/",
        re.IGNORECASE,
    )

    def _scan_envrc(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        envrc = project_dir / ".envrc"
        if not envrc.is_file():
            return findings
        try:
            content = envrc.read_text(errors="ignore")
        except OSError:
            return findings
        rel = ".envrc"
        pkg = PackageId(ecosystem="config", name=rel)
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self._ENVRC_SAFE_PREFIXES.match(stripped):
                if not self._ENVRC_DANGEROUS.search(stripped):
                    continue
            if self._ENVRC_DANGEROUS.search(stripped):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=pkg,
                    title="Suspicious command in .envrc (direnv)",
                    detail=f".envrc line: {stripped[:200]}",
                    cwe="CWE-506",
                    confidence=0.80,
                    metadata={"file": rel, "line": stripped[:500], "check": "editor_config_envrc"},
                ))
                self._route_payload_refs(stripped, project_dir, findings)
        return findings

    # --- ea-05: git hooks (.husky, core.hooksPath) ---

    _HUSKY_SAFE = re.compile(
        r"npx\s+husky\b|\.husky/husky\.sh|lint-staged|eslint|prettier|jest|pytest",
        re.IGNORECASE,
    )

    def _scan_git_hooks(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        husky_dir = project_dir / ".husky"
        if husky_dir.is_dir():
            for hook_file in sorted(husky_dir.iterdir()):
                if hook_file.name.startswith("_") or hook_file.name.startswith(".") or not hook_file.is_file():
                    continue
                try:
                    content = hook_file.read_text(errors="ignore")
                except OSError:
                    continue
                rel = str(hook_file.relative_to(project_dir))
                pkg = PackageId(ecosystem="config", name=rel)
                if self._HUSKY_SAFE.search(content) and not _SUSPICIOUS_COMMANDS.search(content):
                    continue
                if _SUSPICIOUS_COMMANDS.search(content) or self._detect_obfuscation(content):
                    sev = Severity.CRITICAL if self._detect_obfuscation(content) else Severity.HIGH
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=sev,
                        package=pkg,
                        title=f"Suspicious git hook: {hook_file.name}",
                        detail=f"{rel} contains suspicious commands or obfuscation",
                        cwe="CWE-506",
                        confidence=0.80,
                        metadata={"file": rel, "check": "editor_config_git_hook"},
                    ))
                    self._route_payload_refs(content, project_dir, findings)
        return findings

    # --- PLC-03: yarnrc plugins ---

    def _scan_yarnrc(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        yarnrc = project_dir / ".yarnrc.yml"
        if not yarnrc.is_file():
            return findings
        try:
            import yaml
            data = yaml.safe_load(yarnrc.read_text(errors="ignore"))
        except Exception:
            return findings
        if not isinstance(data, dict):
            return findings
        plugins = data.get("plugins", [])
        if not isinstance(plugins, list):
            return findings
        rel = ".yarnrc.yml"
        pkg = PackageId(ecosystem="config", name=rel)
        for plugin in plugins:
            spec = plugin.get("path", "") if isinstance(plugin, dict) else str(plugin)
            if not spec:
                continue
            if spec.startswith("@yarnpkg/"):
                continue
            if spec.startswith(("./", "../", "/")) or ("/" in spec and not spec.startswith("@")):
                findings.append(Finding(
                    finding_type=FindingType.INSTALL_SCRIPT,
                    severity=Severity.HIGH,
                    package=pkg,
                    title=f"Local Yarn plugin: {spec}",
                    detail=f".yarnrc.yml references local plugin '{spec}' — review for malicious code",
                    confidence=0.80,
                    metadata={"file": rel, "plugin": spec, "check": "editor_config_yarnrc_plugin"},
                ))
        # Check committed .pnp.cjs / .yarn/plugins/*.cjs
        pnp = project_dir / ".pnp.cjs"
        if pnp.is_file():
            try:
                content = pnp.read_text(errors="ignore")
                if _SUSPICIOUS_COMMANDS.search(content) or self._detect_obfuscation(content):
                    findings.append(Finding(
                        finding_type=FindingType.OBFUSCATION,
                        severity=Severity.HIGH,
                        package=pkg,
                        title="Suspicious .pnp.cjs file",
                        detail="Committed .pnp.cjs contains suspicious commands or obfuscation",
                        confidence=0.75,
                        metadata={"file": ".pnp.cjs", "check": "editor_config_pnp_cjs"},
                    ))
            except OSError:
                pass
        yarn_plugins = project_dir / ".yarn" / "plugins"
        if yarn_plugins.is_dir():
            for cjs in sorted(yarn_plugins.glob("*.cjs")):
                try:
                    content = cjs.read_text(errors="ignore")
                    if _SUSPICIOUS_COMMANDS.search(content) or self._detect_obfuscation(content):
                        crel = str(cjs.relative_to(project_dir))
                        findings.append(Finding(
                            finding_type=FindingType.OBFUSCATION,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"Suspicious yarn plugin: {cjs.name}",
                            detail=f"{crel} contains suspicious commands or obfuscation",
                            confidence=0.75,
                            metadata={"file": crel, "check": "editor_config_yarn_plugin_cjs"},
                        ))
                except OSError:
                    pass
        return findings

    # --- ea-11: VS Code launch.json + settings ---

    def _scan_vscode_launch(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        # launch.json
        launch_file = project_dir / ".vscode" / "launch.json"
        if launch_file.is_file():
            try:
                raw = launch_file.read_text(errors="ignore")
                raw = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                data = {}
            rel = str(launch_file.relative_to(project_dir))
            pkg = PackageId(ecosystem="config", name=rel)
            for config in data.get("configurations", []):
                if not isinstance(config, dict):
                    continue
                for key in ("preLaunchTask", "postDebugTask"):
                    task_ref = config.get(key, "")
                    if task_ref and not self._is_known_build_task(str(task_ref), ""):
                        findings.append(Finding(
                            finding_type=FindingType.BEHAVIORAL,
                            severity=Severity.MEDIUM,
                            package=pkg,
                            title=f"VS Code launch config references non-build task: {key}",
                            detail=f"{rel} {key}='{task_ref}'",
                            confidence=0.60,
                            metadata={"file": rel, "key": key, "task": str(task_ref), "check": "editor_config_vscode_launch"},
                        ))

        # settings.json: task.allowAutomaticTasks
        settings_file = project_dir / ".vscode" / "settings.json"
        if settings_file.is_file():
            try:
                raw = settings_file.read_text(errors="ignore")
                raw = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                data = {}
            if data.get("task.allowAutomaticTasks") == "on":
                rel = str(settings_file.relative_to(project_dir))
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.HIGH,
                    package=PackageId(ecosystem="config", name=rel),
                    title="VS Code settings enable automatic task execution",
                    detail=f"{rel} sets task.allowAutomaticTasks='on'",
                    confidence=0.85,
                    metadata={"file": rel, "check": "editor_config_vscode_auto_tasks"},
                ))
            # terminal.integrated.automationProfile pointing at project-local path
            for profile_key in ("terminal.integrated.automationProfile.linux",
                                "terminal.integrated.automationProfile.osx",
                                "terminal.integrated.automationProfile.windows"):
                profile = data.get(profile_key, {})
                if isinstance(profile, dict):
                    path = profile.get("path", "")
                    if isinstance(path, str) and (path.startswith("./") or path.startswith("../")):
                        rel = str(settings_file.relative_to(project_dir))
                        findings.append(Finding(
                            finding_type=FindingType.BEHAVIORAL,
                            severity=Severity.HIGH,
                            package=PackageId(ecosystem="config", name=rel),
                            title="VS Code automation shell points to project-local path",
                            detail=f"{rel} {profile_key}.path='{path}'",
                            confidence=0.80,
                            metadata={"file": rel, "check": "editor_config_vscode_automation_profile"},
                        ))
        return findings

    # --- ea-13: .code-workspace ---

    def _scan_code_workspace(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for ws_file in sorted(project_dir.glob("*.code-workspace")):
            try:
                raw = ws_file.read_text(errors="ignore")
                raw = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                continue
            rel = str(ws_file.relative_to(project_dir))
            pkg = PackageId(ecosystem="config", name=rel)
            # tasks with runOn: folderOpen
            for task in data.get("tasks", {}).get("tasks", []):
                if not isinstance(task, dict):
                    continue
                ro = task.get("runOptions", {})
                if isinstance(ro, dict) and ro.get("runOn") == "folderOpen":
                    cmd = task.get("command", "")
                    if not self._is_known_build_task(cmd, task.get("type", "")):
                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"Workspace auto-run task in {ws_file.name}",
                            detail=f"{rel} task '{task.get('label', cmd)}' runs on folder open",
                            cwe="CWE-506",
                            confidence=0.85,
                            metadata={"file": rel, "command": str(cmd)[:500], "check": "editor_config_workspace_autorun"},
                        ))
            # launch configs
            for config in data.get("launch", {}).get("configurations", []):
                if not isinstance(config, dict):
                    continue
                for key in ("preLaunchTask", "postDebugTask"):
                    task_ref = config.get(key, "")
                    if task_ref and not self._is_known_build_task(str(task_ref), ""):
                        findings.append(Finding(
                            finding_type=FindingType.BEHAVIORAL,
                            severity=Severity.MEDIUM,
                            package=pkg,
                            title=f"Workspace launch config non-build task: {key}",
                            detail=f"{rel} {key}='{task_ref}'",
                            confidence=0.60,
                            metadata={"file": rel, "check": "editor_config_workspace_launch"},
                        ))
        return findings

    # --- ea-12: VS Code extensions recommendations ---

    _WELL_KNOWN_PUBLISHERS = {
        "ms-python", "ms-vscode", "ms-dotnettools", "ms-azuretools",
        "ms-toolsai", "ms-ceintl", "ms-vscode-remote", "ms-kubernetes-tools",
        "dbaeumer", "esbenp", "golang", "rust-lang", "redhat", "hashicorp",
        "github", "eamodio", "formulahendry", "christian-kohler",
        "bradlc", "streetsidesoftware", "visualstudioexptteam",
    }

    def _scan_vscode_extensions(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        ext_file = project_dir / ".vscode" / "extensions.json"
        if not ext_file.is_file():
            return findings
        try:
            raw = ext_file.read_text(errors="ignore")
            raw = re.sub(r"//.*$", "", raw, flags=re.MULTILINE)
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            return findings
        recs = data.get("recommendations", [])
        rel = str(ext_file.relative_to(project_dir))
        pkg = PackageId(ecosystem="config", name=rel)
        for ext_id in recs:
            if not isinstance(ext_id, str):
                continue
            publisher = ext_id.split(".")[0].lower() if "." in ext_id else ""
            if publisher and publisher not in self._WELL_KNOWN_PUBLISHERS:
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.MEDIUM,
                    package=pkg,
                    title=f"Unknown publisher in VS Code extension recommendation: {ext_id}",
                    detail=f"{rel} recommends '{ext_id}' from publisher '{publisher}'",
                    confidence=0.50,
                    metadata={"file": rel, "extension": ext_id, "publisher": publisher, "check": "editor_config_vscode_ext"},
                ))
        return findings

    # --- ea-09: Zed config ---

    def _scan_zed(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in ("tasks.json", "settings.json"):
            zed_file = project_dir / ".zed" / name
            if not zed_file.is_file():
                continue
            try:
                data = json.loads(zed_file.read_text(errors="ignore"))
            except (OSError, json.JSONDecodeError):
                continue
            rel = str(zed_file.relative_to(project_dir))
            pkg = PackageId(ecosystem="config", name=rel)
            tasks = data if isinstance(data, list) else data.get("tasks", [])
            if not isinstance(tasks, list):
                continue
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                cmd = task.get("command", "")
                if not cmd:
                    continue
                if self._is_known_build_task(cmd, ""):
                    continue
                if cmd.startswith("./") or cmd.startswith(".github/") or _SUSPICIOUS_COMMANDS.search(cmd):
                    findings.append(Finding(
                        finding_type=FindingType.INSTALL_SCRIPT,
                        severity=Severity.HIGH,
                        package=pkg,
                        title=f"Zed task with suspicious command: {cmd[:60]}",
                        detail=f"{rel} task runs: {cmd[:200]}",
                        confidence=0.80,
                        metadata={"file": rel, "command": cmd[:500], "check": "editor_config_zed"},
                    ))
                    self._route_payload_refs(cmd, project_dir, findings)
        return findings

    # --- ea-10: JetBrains run configurations ---

    def _scan_jetbrains(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        config_dirs = [
            project_dir / ".idea" / "runConfigurations",
            project_dir / ".run",
        ]
        for cfg_dir in config_dirs:
            if not cfg_dir.is_dir():
                continue
            for xml_file in sorted(cfg_dir.glob("*.xml")) + sorted(cfg_dir.glob("*.run.xml")):
                try:
                    content = xml_file.read_text(errors="ignore")
                except OSError:
                    continue
                rel = str(xml_file.relative_to(project_dir))
                pkg = PackageId(ecosystem="config", name=rel)
                if re.search(r"ShConfigurationType|SCRIPT_PATH", content):
                    script_match = re.search(r'value="([^"]*)"', content)
                    script = script_match.group(1) if script_match else ""
                    if script and (script.startswith("./") or script.startswith(".github/") or _SUSPICIOUS_COMMANDS.search(script)):
                        findings.append(Finding(
                            finding_type=FindingType.INSTALL_SCRIPT,
                            severity=Severity.HIGH,
                            package=pkg,
                            title=f"JetBrains run config with suspicious script: {xml_file.name}",
                            detail=f"{rel} runs: {script[:200]}",
                            confidence=0.80,
                            metadata={"file": rel, "script": script[:500], "check": "editor_config_jetbrains"},
                        ))
                if re.search(r"RunExternalTool|before-launch.*ExternalTool", content, re.DOTALL):
                    findings.append(Finding(
                        finding_type=FindingType.BEHAVIORAL,
                        severity=Severity.MEDIUM,
                        package=pkg,
                        title=f"JetBrains external tool in before-launch: {xml_file.name}",
                        detail=f"{rel} uses an external tool in before-launch configuration",
                        confidence=0.65,
                        metadata={"file": rel, "check": "editor_config_jetbrains_external_tool"},
                    ))
        return findings

    # --- ea-07: Aider config ---

    def _scan_aider(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        aider_file = project_dir / ".aider.conf.yml"
        if not aider_file.is_file():
            return findings
        try:
            import yaml
            data = yaml.safe_load(aider_file.read_text(errors="ignore"))
        except Exception:
            return findings
        if not isinstance(data, dict):
            return findings
        rel = ".aider.conf.yml"
        pkg = PackageId(ecosystem="config", name=rel)
        auto_test = data.get("auto-test", False)
        auto_lint = data.get("auto-lint", False)
        for key in ("test-cmd", "lint-cmd"):
            cmd = data.get(key, "")
            if not cmd or not isinstance(cmd, str):
                continue
            if self._is_safe_command(cmd):
                continue
            is_auto = (key == "test-cmd" and auto_test) or (key == "lint-cmd" and auto_lint)
            sev = Severity.HIGH if is_auto else Severity.MEDIUM
            findings.append(Finding(
                finding_type=FindingType.INSTALL_SCRIPT,
                severity=sev,
                package=pkg,
                title=f"Aider {key} with suspicious command{' (auto-enabled)' if is_auto else ''}",
                detail=f".aider.conf.yml {key}='{cmd[:200]}'",
                confidence=0.75,
                metadata={"file": rel, "key": key, "command": cmd[:500], "auto": is_auto, "check": "editor_config_aider"},
            ))
            self._route_payload_refs(cmd, project_dir, findings)
        return findings

    # --- PB-03 routing helper ---

    _FILE_REF_RE = re.compile(
        r"\b(?:node|python|python3|bash|sh|deno|bun|ruby)\s+(\S+\.(?:js|mjs|cjs|ts|py|sh|rb))\b",
    )

    def _route_payload_refs(self, text: str, project_dir: Path, findings: list[Finding]) -> None:
        for m in self._FILE_REF_RE.finditer(text):
            ref_path = project_dir / m.group(1)
            if ref_path.is_file():
                try:
                    from depfence.scanners.payload_behavior_scanner import PayloadBehaviorScanner
                    pbs = PayloadBehaviorScanner()
                    findings.extend(pbs.analyze_referenced_payload(ref_path, project_dir))
                except Exception:
                    pass

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
        return bool(re.search(r"(?:alwaysApply|always_on)\s*:\s*true", frontmatter, re.I))

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
