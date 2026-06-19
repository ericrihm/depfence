"""AI Bill of Materials (AI-BOM) generator.

Produces a structured inventory of all AI/ML components in a project:
  - Model weight files (.safetensors, .bin, .pkl, .pt, .npy, .npz, .onnx, .gguf)
  - config.json / model.json architecture metadata
  - MCP server configurations (Claude Code, Cursor, VS Code, etc.)
  - AI framework packages from lockfiles and requirement files

Output extends the CycloneDX/SPDX SBOM concept with AI-specific fields.
One INFO finding carries the full BOM as metadata; additional WARNING/HIGH
findings flag risky items (pickle models, MCP servers with shell access).
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Any

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Model file definitions
# ---------------------------------------------------------------------------

# (extension, format_label, is_pickle_based)
_MODEL_EXTENSIONS: list[tuple[str, str, bool]] = [
    (".safetensors", "safetensors", False),
    (".bin",         "pytorch-bin (pickle)", True),
    (".pkl",         "pickle", True),
    (".pickle",      "pickle", True),
    (".pt",          "pytorch (pickle)", True),
    (".pth",         "pytorch-checkpoint (pickle)", True),
    (".ckpt",        "checkpoint (pickle)", True),
    (".joblib",      "joblib (pickle)", True),
    (".npy",         "numpy", False),
    (".npz",         "numpy-archive", False),
    (".onnx",        "onnx", False),
    (".gguf",        "gguf", False),
]

_MODEL_EXT_INFO: dict[str, tuple[str, bool]] = {
    ext: (fmt, is_pickle) for ext, fmt, is_pickle in _MODEL_EXTENSIONS
}

# Minimum file size to be considered actual model weights (not a stub/config).
_MIN_MODEL_BYTES = 64

# Chunk size for streaming sha256 — never load full weight files into memory.
_HASH_CHUNK = 64 * 1024  # 64 KB

# Config filenames that may carry architecture / checksum metadata.
_MODEL_CONFIG_NAMES: frozenset[str] = frozenset({
    "config.json",
    "model.json",
    "model_card.json",
    "metadata.json",
})

# Architecture hints extracted from filename/path tokens.
_ARCH_HINTS: list[str] = [
    "7b", "13b", "30b", "34b", "65b", "70b", "1b", "3b", "6b",
    "bert", "gpt", "llama", "mistral", "falcon", "phi", "gemma",
    "qwen", "t5", "roberta", "bloom", "mpt", "starcoder", "whisper",
    "clip", "vit", "stable-diffusion", "sd", "flux",
]

# ---------------------------------------------------------------------------
# AI framework package names (all ecosystems)
# ---------------------------------------------------------------------------

_AI_PACKAGES: frozenset[str] = frozenset({
    # Deep learning
    "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-cpu",
    "tensorflow-gpu", "tf-nightly", "jax", "jaxlib", "flax", "paddle",
    "paddlepaddle", "mxnet", "theano", "caffe", "caffe2",
    # HuggingFace stack
    "transformers", "datasets", "huggingface-hub", "huggingface_hub",
    "accelerate", "peft", "trl", "evaluate", "tokenizers", "diffusers",
    "optimum", "sentence-transformers",
    # LLM orchestration
    "langchain", "langchain-core", "langchain-community", "langchain-openai",
    "langchain-anthropic", "langchain-google-genai", "langchain-experimental",
    "llama-index", "llama_index", "llamaindex", "llama-index-core",
    "llama-index-llms-openai", "llama-index-llms-anthropic",
    "openai", "anthropic", "google-generativeai", "google-genai",
    "cohere", "mistralai", "groq", "together",
    # Vector stores
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "faiss-cpu", "faiss-gpu", "lancedb", "milvus",
    # Agents / tools
    "crewai", "autogen", "pyautogen", "smolagents", "agno",
    "pydantic-ai", "instructor",
    # Serving / APIs
    "gradio", "streamlit", "fastapi", "uvicorn", "vllm", "ray", "ray[serve]",
    "bentoml", "triton", "onnxruntime", "onnxruntime-gpu",
    # MLOps
    "mlflow", "wandb", "neptune", "clearml", "dvc",
    # Embeddings / NLP
    "spacy", "nltk", "gensim", "sklearn", "scikit-learn", "xgboost", "lightgbm",
})

# npm AI packages
_AI_PACKAGES_NPM: frozenset[str] = frozenset({
    "openai", "@anthropic-ai/sdk", "anthropic",
    "@google/generative-ai", "llamaindex", "@llamaindex/core",
    "langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic",
    "ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "@ai-sdk/google",
    "ollama", "transformers.js", "@xenova/transformers",
    "gpt4all", "node-llama-cpp", "@huggingface/inference",
    "@huggingface/transformers",
})

# ---------------------------------------------------------------------------
# MCP config locations (reused from mcp_scanner)
# ---------------------------------------------------------------------------

def _mcp_config_locations() -> list[Path]:
    paths: list[Path] = [
        Path.home() / ".claude" / "settings.json",
        Path.home() / ".claude" / "settings.local.json",
        Path.home() / ".claude.json",
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".vscode" / "settings.json",
        Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
        Path.home() / ".config" / "zed" / "settings.json",
        Path.home() / ".continue" / "config.json",
    ]
    if platform.system() == "Darwin":
        paths.append(
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    else:
        paths.append(Path.home() / ".config" / "Claude" / "claude_desktop_config.json")
    return paths


_PROJECT_MCP_LOCATIONS: list[Path] = [
    Path(".mcp.json"),
    Path(".cursor/mcp.json"),
    Path(".vscode/mcp.json"),
    Path(".vscode/settings.json"),
    Path(".claude/settings.json"),
]

# ---------------------------------------------------------------------------
# Shell-access detection patterns for MCP servers
# ---------------------------------------------------------------------------

_SHELL_COMMANDS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh",
    "nc", "ncat", "netcat",
})

_SHELL_ARG_PATTERNS: list[re.Pattern] = [
    re.compile(r"\|\s*(sh|bash|zsh)", re.IGNORECASE),
    re.compile(r"curl\s+.*\|", re.IGNORECASE),
    re.compile(r"base64\s+-d", re.IGNORECASE),
    re.compile(r"eval\s", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_streaming(path: Path) -> str:
    """Compute sha256 of a file in chunks — safe for large model weight files."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _arch_hints_from_path(path: Path) -> list[str]:
    """Extract architecture hints from file name and parent directory names."""
    text = " ".join([path.stem.lower()] + [p.lower() for p in path.parts[:-1]])
    return [hint for hint in _ARCH_HINTS if hint in text]


def _extract_mcp_servers(data: dict) -> dict:
    if "mcpServers" in data:
        return data["mcpServers"]
    if "mcp" in data and isinstance(data["mcp"], dict):
        return data["mcp"].get("servers", {})
    if "servers" in data:
        return data["servers"]
    return {}


def _mcp_server_has_shell_access(config: dict) -> bool:
    """Return True if the MCP server command/args suggest shell or exec access."""
    command = config.get("command", "")
    if command in _SHELL_COMMANDS:
        return True
    args = config.get("args", [])
    full = f"{command} {' '.join(str(a) for a in args)}"
    return any(pat.search(full) for pat in _SHELL_ARG_PATTERNS)


def _skip_path(path: Path) -> bool:
    """Return True for vendor/cache/venv directories to skip."""
    skip_parts = {
        ".venv", "venv", "env", "node_modules", "__pycache__",
        "site-packages", ".git", "dist", "build", ".tox",
    }
    return any(p in skip_parts for p in path.parts)


# ---------------------------------------------------------------------------
# Model inventory
# ---------------------------------------------------------------------------

def _scan_model_files(project_dir: Path) -> list[dict[str, Any]]:
    """Walk project for model weight files and return inventory records."""
    records: list[dict[str, Any]] = []

    for ext, (fmt, is_pickle) in _MODEL_EXT_INFO.items():
        for model_path in sorted(project_dir.rglob(f"*{ext}")):
            if _skip_path(model_path):
                continue
            try:
                size = model_path.stat().st_size
            except OSError:
                continue
            if size < _MIN_MODEL_BYTES:
                continue

            record: dict[str, Any] = {
                "path": str(model_path.relative_to(project_dir)),
                "format": fmt,
                "size_bytes": size,
                "is_pickle": is_pickle,
                "architecture_hints": _arch_hints_from_path(model_path),
                "sha256": None,
                "has_checksum": False,
            }

            # Stream sha256 — skip if file is too large (>= 10 GB) to avoid
            # stalling the scan; flag as unverified instead.
            if size < 10 * 1024 * 1024 * 1024:
                try:
                    record["sha256"] = _sha256_streaming(model_path)
                    record["has_checksum"] = True
                except OSError:
                    pass

            records.append(record)

    # Also check config.json / model.json for declared architecture.
    for cfg_name in _MODEL_CONFIG_NAMES:
        for cfg_path in sorted(project_dir.rglob(cfg_name)):
            if _skip_path(cfg_path):
                continue
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue

            arch_keys = {
                "model_type", "architectures", "model_architecture",
                "_name_or_path", "pretrained_cfg",
            }
            arch_info = {k: data[k] for k in arch_keys if k in data}
            if arch_info:
                # Attach architecture metadata to any model records in the same dir
                cfg_dir = cfg_path.parent
                for rec in records:
                    rec_path = project_dir / rec["path"]
                    if rec_path.parent == cfg_dir and not rec.get("architecture_from_config"):
                        rec["architecture_from_config"] = arch_info

    return records


# ---------------------------------------------------------------------------
# MCP server inventory
# ---------------------------------------------------------------------------

def _scan_mcp_servers(project_dir: Path) -> list[dict[str, Any]]:
    """Collect MCP server entries from all known config locations."""
    servers: list[dict[str, Any]] = []
    seen: set[Path] = set()

    def _process_config(config_path: Path) -> None:
        if config_path in seen or not config_path.exists():
            return
        seen.add(config_path)
        try:
            data = json.loads(config_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return
        mcp_servers = _extract_mcp_servers(data)
        for name, cfg in mcp_servers.items():
            if not isinstance(cfg, dict):
                continue
            command = cfg.get("command", "")
            args = cfg.get("args", [])
            transport = cfg.get("transport", cfg.get("type", "stdio"))
            tools = cfg.get("tools", [])
            servers.append({
                "name": name,
                "command": command,
                "args": args,
                "transport": transport,
                "tool_count": len(tools) if isinstance(tools, list) else 0,
                "has_shell_access": _mcp_server_has_shell_access(cfg),
                "config_source": str(config_path),
                "env_keys": list(cfg.get("env", {}).keys()),
            })

    # Project-level configs
    for rel in _PROJECT_MCP_LOCATIONS:
        _process_config(project_dir / rel)

    # Global configs
    for p in _mcp_config_locations():
        _process_config(p)

    return servers


# ---------------------------------------------------------------------------
# AI framework inventory
# ---------------------------------------------------------------------------

def _parse_requirements_txt(req_file: Path) -> list[tuple[str, str]]:
    """Return (package_name, version_constraint) pairs from a requirements file."""
    results: list[tuple[str, str]] = []
    try:
        content = req_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return results
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "http")):
            continue
        # Strip extras and markers: "torch[cuda]>=2.0 ; python_version>='3.8'"
        stripped = stripped.split(";")[0].strip()
        name_match = re.match(r"^([A-Za-z0-9_.\-]+)", stripped)
        if not name_match:
            continue
        name = name_match.group(1).replace("-", "_").lower()
        version_part = stripped[len(name_match.group(1)):].strip()
        results.append((name, version_part))
    return results


def _parse_package_json(pkg_file: Path) -> list[tuple[str, str, str]]:
    """Return (name, version, ecosystem='npm') triples from package.json."""
    results: list[tuple[str, str, str]] = []
    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return results
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            results.append((name, str(version), "npm"))
    return results


def _parse_pyproject_toml(pyproject: Path) -> list[tuple[str, str]]:
    """Return (name, version) from pyproject.toml dependencies."""
    results: list[tuple[str, str]] = []
    try:
        import tomllib  # type: ignore[import]
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[import,no-reuse-declared]
        except ModuleNotFoundError:
            return results
    try:
        data = tomllib.loads(pyproject.read_bytes().decode())
    except Exception:
        return results
    # PEP 621 style
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        if isinstance(dep, str):
            name_match = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
            if name_match:
                name = name_match.group(1).replace("-", "_").lower()
                version_part = dep[len(name_match.group(1)):].strip()
                results.append((name, version_part))
    # Poetry style
    for section in ("dependencies", "dev-dependencies", "group"):
        section_data = data.get("tool", {}).get("poetry", {}).get(section, {})
        if isinstance(section_data, dict):
            for name, ver in section_data.items():
                if name == "python":
                    continue
                norm = name.replace("-", "_").lower()
                version_str = ver if isinstance(ver, str) else str(ver.get("version", ""))
                results.append((norm, version_str))
    return results


def _scan_ai_frameworks(project_dir: Path) -> list[dict[str, Any]]:
    """Scan lockfiles and requirement files for AI packages."""
    found: dict[str, dict[str, Any]] = {}  # keyed by "ecosystem:name"

    def _add(name: str, version: str, ecosystem: str) -> None:
        key = f"{ecosystem}:{name}"
        if key not in found:
            found[key] = {"name": name, "version": version or "unknown", "ecosystem": ecosystem}

    # Python: requirements*.txt
    for req_file in project_dir.rglob("requirements*.txt"):
        if _skip_path(req_file):
            continue
        for name, version in _parse_requirements_txt(req_file):
            norm = name.replace("-", "_").lower()
            if norm in _AI_PACKAGES or name.lower() in _AI_PACKAGES:
                _add(name, version, "pypi")

    # Python: pyproject.toml
    for pyproject in project_dir.rglob("pyproject.toml"):
        if _skip_path(pyproject):
            continue
        for name, version in _parse_pyproject_toml(pyproject):
            norm = name.replace("-", "_").lower()
            if norm in _AI_PACKAGES or name.lower() in _AI_PACKAGES:
                _add(name, version, "pypi")

    # Python: setup.cfg
    for setup_cfg in project_dir.rglob("setup.cfg"):
        if _skip_path(setup_cfg):
            continue
        try:
            content = setup_cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"install_requires\s*=", stripped):
                in_deps = True
                continue
            if in_deps:
                if stripped.startswith("[") or (stripped and not stripped[0].isspace() and "=" in stripped):
                    in_deps = False
                    continue
                name_match = re.match(r"^([A-Za-z0-9_.\-]+)", stripped)
                if name_match:
                    name = name_match.group(1)
                    norm = name.replace("-", "_").lower()
                    if norm in _AI_PACKAGES or name.lower() in _AI_PACKAGES:
                        version_part = stripped[len(name_match.group(1)):].strip()
                        _add(name, version_part, "pypi")

    # JavaScript: package.json
    for pkg_json in project_dir.rglob("package.json"):
        if _skip_path(pkg_json):
            continue
        for name, version, eco in _parse_package_json(pkg_json):
            if name in _AI_PACKAGES_NPM or name.lower() in _AI_PACKAGES_NPM:
                _add(name, version, eco)

    return list(found.values())


# ---------------------------------------------------------------------------
# BOM assembler
# ---------------------------------------------------------------------------

def _build_bom(
    models: list[dict[str, Any]],
    mcp_servers: list[dict[str, Any]],
    frameworks: list[dict[str, Any]],
) -> dict[str, Any]:
    pickle_count = sum(1 for m in models if m.get("is_pickle"))
    unverified_count = sum(1 for m in models if not m.get("has_checksum"))
    return {
        "ai_bom_version": "1.0",
        "models": models,
        "mcp_servers": mcp_servers,
        "ai_frameworks": frameworks,
        "risk_summary": {
            "total_models": len(models),
            "pickle_models": pickle_count,
            "unverified_models": unverified_count,
            "mcp_servers": len(mcp_servers),
        },
    }


# ---------------------------------------------------------------------------
# Finding generators
# ---------------------------------------------------------------------------

def _findings_from_bom(
    bom: dict[str, Any],
    project_dir: Path,
) -> list[Finding]:
    findings: list[Finding] = []

    # One INFO finding carries the full BOM.
    bom_pkg = PackageId("ai-bom", str(project_dir), None)
    findings.append(Finding(
        finding_type=FindingType.BEHAVIORAL,
        severity=Severity.INFO,
        package=bom_pkg,
        title=f"AI-BOM: {bom['risk_summary']['total_models']} model(s), "
              f"{bom['risk_summary']['mcp_servers']} MCP server(s), "
              f"{len(bom['ai_frameworks'])} AI framework(s)",
        detail=(
            f"Full AI component inventory: "
            f"{bom['risk_summary']['total_models']} model file(s) "
            f"({bom['risk_summary']['pickle_models']} pickle-based, "
            f"{bom['risk_summary']['unverified_models']} without checksum), "
            f"{bom['risk_summary']['mcp_servers']} MCP server(s), "
            f"{len(bom['ai_frameworks'])} AI framework package(s) detected."
        ),
        confidence=1.0,
        metadata={"ai_bom": bom},
    ))

    # WARNING: pickle model files without checksums.
    for model in bom["models"]:
        if model.get("is_pickle") and not model.get("has_checksum"):
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=PackageId("ai-model", model["path"], None),
                title=f"Pickle model without integrity verification: {Path(model['path']).name}",
                detail=(
                    f"File '{model['path']}' is a {model['format']} file (pickle-based), "
                    "which can execute arbitrary Python code on load. "
                    "No sha256 checksum was recorded (file may exceed 10 GB or be unreadable). "
                    "Verify provenance before loading, or migrate to .safetensors format."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security-pickle",
                    "https://huggingface.co/docs/safetensors/index",
                ],
                confidence=0.9,
                metadata={
                    "path": model["path"],
                    "format": model["format"],
                    "size_bytes": model.get("size_bytes"),
                },
            ))
        elif model.get("is_pickle") and model.get("has_checksum"):
            # Pickle with checksum — still risky, emit a MEDIUM.
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=PackageId("ai-model", model["path"], None),
                title=f"Pickle model file: {Path(model['path']).name}",
                detail=(
                    f"File '{model['path']}' is a {model['format']} file (pickle-based). "
                    "Pickle archives can embed __reduce__ hooks that execute code on torch.load(). "
                    f"SHA-256: {model.get('sha256', 'n/a')}. "
                    "Consider migrating to .safetensors format."
                ),
                references=[
                    "https://huggingface.co/docs/hub/security-pickle",
                ],
                confidence=0.85,
                metadata={
                    "path": model["path"],
                    "format": model["format"],
                    "sha256": model.get("sha256"),
                    "size_bytes": model.get("size_bytes"),
                },
            ))

    # WARNING: MCP servers with shell access.
    for server in bom["mcp_servers"]:
        if server.get("has_shell_access"):
            cmd_display = server.get("command", "")
            args_display = " ".join(str(a) for a in server.get("args", []))
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.HIGH,
                package=PackageId("mcp", server["name"], None),
                title=f"MCP server with shell access: {server['name']}",
                detail=(
                    f"MCP server '{server['name']}' (configured in {server['config_source']}) "
                    f"uses command '{cmd_display} {args_display}'.strip() that grants direct shell "
                    "or script execution access. A compromised server description or tool call "
                    "could execute arbitrary commands in the agent's environment."
                ),
                confidence=0.85,
                metadata={
                    "command": cmd_display,
                    "args": server.get("args", []),
                    "transport": server.get("transport"),
                    "config_source": server["config_source"],
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Public scanner interface
# ---------------------------------------------------------------------------

class AiBomGenerator:
    """AI Bill of Materials scanner.

    Produces a full inventory of AI/ML components (models, MCP servers,
    AI framework packages) and emits security findings for risky items.

    Implements the standard depfence scanner interface:
      - async scan(packages) -> list[Finding]  (no-op; BOM needs project tree)
      - async scan_project(project_dir) -> list[Finding]
    """

    name = "ai_bom"
    ecosystems = ["all"]

    async def scan(self, packages: list) -> list[Finding]:
        """Standard package-list interface — BOM generation requires scan_project."""
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        """Scan *project_dir* and return BOM info finding + risk findings."""
        project_dir = Path(project_dir).resolve()

        models = _scan_model_files(project_dir)
        mcp_servers = _scan_mcp_servers(project_dir)
        frameworks = _scan_ai_frameworks(project_dir)

        bom = _build_bom(models, mcp_servers, frameworks)
        return _findings_from_bom(bom, project_dir)


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def generate_ai_bom(project_dir: Path | str) -> dict[str, Any]:
    """Generate and return the raw AI-BOM dict without emitting findings.

    Useful for embedding in other reports or exporting to JSON.
    """
    d = Path(project_dir).resolve()
    models = _scan_model_files(d)
    mcp_servers = _scan_mcp_servers(d)
    frameworks = _scan_ai_frameworks(d)
    return _build_bom(models, mcp_servers, frameworks)
