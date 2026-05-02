"""Model registry / weight file scanner — detects HuggingFace model supply chain risks.

AI applications pull model weights via `from_pretrained()` and similar APIs with no
lockfile, no hash pinning, and no visibility in any existing dependency scanner.
Pickle-format weights (.bin, .pkl) can execute arbitrary code on load.

This scanner closes that gap by:
  1. Parsing Python source files for model-loading call sites and extracting model IDs.
  2. Walking the project tree for model weight files and assessing their format risk.
  3. Flagging unverified model origins and unsafe serialisation formats.
"""

from __future__ import annotations

import re
from pathlib import Path

from depfence.core.models import Finding, FindingType, PackageId, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# HuggingFace organisations whose models are considered low-risk by default.
# Presence here only reduces the base risk — it does not eliminate it.
_KNOWN_SAFE_ORGS: frozenset[str] = frozenset({
    "meta-llama",
    "google",
    "microsoft",
    "openai",
    "mistralai",
    "anthropic",
    "stabilityai",
    "facebook",
    "huggingface",
    "bert-base-uncased",  # canonical single-name models treated as safe
    "gpt2",
    "distilbert",
    "roberta",
    "t5",
    "openai-community",
    "EleutherAI",
    "tiiuae",
    "bigscience",
    "allenai",
    "sentence-transformers",
    "Helsinki-NLP",
    "facebook",
    "nvidia",
})

# Minimum file size (bytes) below which a file is unlikely to be actual model
# weights and should be skipped.
_MIN_MODEL_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

# (extension, Severity, format_label, detail_snippet)
_MODEL_FILE_RISKS: list[tuple[str, Severity, str, str]] = [
    (
        ".pkl",
        Severity.CRITICAL,
        "pickle",
        "Pickle files can execute arbitrary Python code when loaded via pickle.load(). "
        "This is a well-known code-execution vector. Never load untrusted .pkl files. "
        "Migrate to .safetensors immediately.",
    ),
    (
        ".pickle",
        Severity.CRITICAL,
        "pickle",
        "Pickle files can execute arbitrary Python code when loaded via pickle.load(). "
        "This is a well-known code-execution vector. Never load untrusted .pickle files. "
        "Migrate to .safetensors immediately.",
    ),
    (
        ".bin",
        Severity.HIGH,
        "pytorch-bin (pickle)",
        "PyTorch .bin files are pickle archives. A malicious model distributed via "
        "HuggingFace Hub can embed __reduce__ hooks that execute code on torch.load(). "
        "Prefer .safetensors format or verify the file hash before loading.",
    ),
    (
        ".onnx",
        Severity.MEDIUM,
        "onnx",
        "ONNX models can embed custom operators implemented as shared libraries. "
        "A malicious ONNX file from an untrusted source could load arbitrary native code. "
        "Verify the model source and use a sandboxed inference runtime.",
    ),
    (
        ".safetensors",
        Severity.LOW,
        "safetensors",
        "safetensors is a safe serialisation format that does not allow code execution. "
        "No immediate risk — recorded for inventory purposes.",
    ),
    (
        ".gguf",
        Severity.LOW,
        "gguf",
        "GGUF (llama.cpp quantized) is a safe binary format that does not support "
        "arbitrary code execution. Recorded for inventory purposes.",
    ),
]

# Pre-compute a lookup: extension -> (Severity, format_label, detail)
_EXT_RISK: dict[str, tuple[Severity, str, str]] = {
    ext: (sev, fmt, detail) for ext, sev, fmt, detail in _MODEL_FILE_RISKS
}

# ---------------------------------------------------------------------------
# Regex patterns for model-loading call sites
# ---------------------------------------------------------------------------

# Each pattern has a single named group `model_id` that captures the model
# identifier string.  Patterns are tried in order; first match wins per line.
_RAW_PATTERNS: list[str] = [
    # AutoClass.from_pretrained("model_id") / AutoClass.from_pretrained('model_id')
    r"""(?:AutoModel|AutoTokenizer|AutoConfig|AutoProcessor|AutoFeatureExtractor|
         AutoModelForCausalLM|AutoModelForSeq2SeqLM|AutoModelForSequenceClassification|
         AutoModelForTokenClassification|AutoModelForQuestionAnswering|
         AutoModelForMaskedLM|AutoModelForImageClassification|
         AutoModelForObjectDetection|TFAutoModel|FlaxAutoModel|
         [A-Za-z][A-Za-z0-9_]*Model|[A-Za-z][A-Za-z0-9_]*Tokenizer
    )\.from_pretrained\(\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # pipeline("task", model="model_id") / pipeline("task", model='model_id')
    r"""pipeline\([^)]*model\s*=\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # pipeline("task", "model_id") — positional model arg (2nd arg)
    r"""pipeline\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # hf_hub_download(repo_id="model_id")
    r"""hf_hub_download\([^)]*repo_id\s*=\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # snapshot_download("model_id") or snapshot_download(repo_id="model_id")
    r"""snapshot_download\(\s*[\"'](?P<model_id>[^\"']+)[\"']""",
    r"""snapshot_download\([^)]*repo_id\s*=\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # hub.load("model_id") or hub.download("model_id")
    r"""hub\.(?:load|download)\(\s*[\"'](?P<model_id>[^\"']+)[\"']""",

    # Generic from_pretrained("model_id") catch-all
    r"""from_pretrained\(\s*[\"'](?P<model_id>[^\"']+)[\"']""",
]

# Compile with VERBOSE to allow inline whitespace in the multi-line raw strings
_MODEL_LOADING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.VERBOSE | re.IGNORECASE) for p in _RAW_PATTERNS
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_known_safe_org(model_id: str) -> bool:
    """Return True if the model_id's org prefix is in the known-safe set."""
    org = model_id.split("/")[0].strip()
    return org in _KNOWN_SAFE_ORGS or org.lower() in {s.lower() for s in _KNOWN_SAFE_ORGS}


def _extract_model_refs(source: str) -> list[tuple[str, int]]:
    """Scan *source* for model-loading call sites.

    Returns a list of (model_id, line_number) tuples.  Line numbers are
    1-based.  Duplicate (model_id, line) pairs are deduplicated, but the same
    model_id may appear on multiple lines.
    """
    results: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    lines = source.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for pattern in _MODEL_LOADING_PATTERNS:
            m = pattern.search(line)
            if m:
                model_id = m.group("model_id").strip()
                if model_id and (model_id, lineno) not in seen:
                    seen.add((model_id, lineno))
                    results.append((model_id, lineno))
                break  # first pattern match wins for this line

    return results


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class ModelScanner:
    """Scan a project directory for model supply chain risks.

    Two independent detection strategies:
      1. Source-code scanning: find model-loading calls and extract model IDs.
      2. Weight-file scanning: find actual model files and assess format risk.
    """

    name = "model_scanner"
    ecosystems = ["huggingface", "gguf", "onnx"]

    async def scan(self, packages: list) -> list:
        """Standard interface — this scanner uses scan_project() instead."""
        return []

    async def scan_project(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_source_files(project_dir))
        findings.extend(self._scan_model_files(project_dir))
        return findings

    # ------------------------------------------------------------------
    # Strategy 1: source code scanning
    # ------------------------------------------------------------------

    def _scan_source_files(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        py_files = list(project_dir.rglob("*.py"))
        for py_file in sorted(py_files):
            # Skip vendored / virtualenv directories
            parts = py_file.parts
            if any(p in parts for p in (".venv", "venv", "env", "node_modules", "__pycache__", "site-packages")):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            refs = _extract_model_refs(source)
            for model_id, lineno in refs:
                findings.extend(
                    self._assess_model_ref(model_id, py_file, lineno)
                )

        return findings

    def _assess_model_ref(
        self, model_id: str, source_file: Path, line: int
    ) -> list[Finding]:
        """Return zero or more findings for a detected model reference."""
        findings: list[Finding] = []

        pkg = PackageId("huggingface", model_id)
        safe_org = _is_known_safe_org(model_id)

        # Model IDs without a "/" are single-name (e.g. "gpt2") — usually
        # canonical HuggingFace-hosted models, treat as low risk.
        if "/" not in model_id:
            if not safe_org:
                # Unusual single-name that isn't in our known-safe list.
                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=Severity.LOW,
                    package=pkg,
                    title=f"Unverified model reference: {model_id}",
                    detail=(
                        f"Model '{model_id}' is loaded via from_pretrained() or similar. "
                        "Single-name identifiers without an org prefix cannot be attributed "
                        "to a verified publisher. Confirm the model origin before use."
                    ),
                    confidence=0.5,
                    metadata={
                        "model_id": model_id,
                        "format": "unknown",
                        "source_file": str(source_file),
                        "line": line,
                    },
                ))
            return findings

        # org/name format — check the org
        org = model_id.split("/")[0]
        if not safe_org:
            findings.append(Finding(
                finding_type=FindingType.BEHAVIORAL,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Unverified model organisation: {org}",
                detail=(
                    f"Model '{model_id}' is loaded from organisation '{org}', which is not "
                    "in the known-safe publisher list. An attacker can publish a model under "
                    "any HuggingFace username. Verify the model page, download count, and "
                    "community reports before loading it in production."
                ),
                references=[
                    f"https://huggingface.co/{model_id}",
                    "https://huggingface.co/docs/hub/security",
                ],
                confidence=0.75,
                metadata={
                    "model_id": model_id,
                    "format": "unknown",
                    "source_file": str(source_file),
                    "line": line,
                },
            ))

        return findings

    # ------------------------------------------------------------------
    # Strategy 2: weight file scanning
    # ------------------------------------------------------------------

    def _scan_model_files(self, project_dir: Path) -> list[Finding]:
        findings: list[Finding] = []

        extensions = set(_EXT_RISK.keys())
        for ext in extensions:
            for model_file in sorted(project_dir.rglob(f"*{ext}")):
                # Skip virtualenv / hidden directories
                parts = model_file.parts
                if any(
                    p in parts
                    for p in (".venv", "venv", "env", "node_modules", "__pycache__", "site-packages")
                ):
                    continue

                # Skip tiny files that are almost certainly not model weights
                try:
                    size = model_file.stat().st_size
                except OSError:
                    continue
                if size < _MIN_MODEL_FILE_SIZE:
                    continue

                severity, fmt, detail = _EXT_RISK[ext]
                pkg = PackageId("huggingface", model_file.name)

                findings.append(Finding(
                    finding_type=FindingType.BEHAVIORAL,
                    severity=severity,
                    package=pkg,
                    title=f"Model weight file ({fmt}): {model_file.name}",
                    detail=detail,
                    references=[
                        "https://huggingface.co/docs/safetensors/index",
                        "https://huggingface.co/docs/hub/security-pickle",
                    ],
                    confidence=0.95,
                    metadata={
                        "model_id": model_file.stem,
                        "format": fmt,
                        "source_file": str(model_file),
                        "line": 0,
                        "file_size_bytes": size,
                    },
                ))

        return findings
