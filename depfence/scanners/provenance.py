"""SLSA provenance verification scanner.

Checks whether packages have verifiable build provenance attestations.
Packages without provenance are higher risk — especially high-value AI
framework packages that are prime targets for supply chain attacks.
"""

from __future__ import annotations

import httpx

from depfence.core.fetcher import fetch_enabled
from depfence.core.models import Finding, FindingType, PackageId, PackageMeta, Severity

_HIGH_VALUE_PACKAGES = {
    "npm": {
        "express", "react", "next", "axios", "lodash", "typescript",
        "webpack", "babel", "eslint", "prettier", "vite",
    },
    "pypi": {
        "langchain", "langchain-core", "langchain-community", "langgraph",
        "litellm", "transformers", "torch", "tensorflow", "numpy", "pandas",
        "scikit-learn", "openai", "anthropic", "huggingface-hub", "safetensors",
        "tokenizers", "datasets", "accelerate", "peft", "trl",
        "llamaindex", "llama-index", "vllm", "guidance", "dspy",
        "flask", "django", "fastapi", "uvicorn", "pydantic",
        "requests", "httpx", "boto3", "google-cloud-aiplatform",
    },
}


class ProvenanceScanner:
    name = "provenance"
    ecosystems = ["npm", "pypi"]

    async def scan(self, packages: list[PackageMeta]) -> list[Finding]:
        findings: list[Finding] = []
        for meta in packages:
            finding = await self._check_provenance(meta)
            if finding:
                findings.append(finding)
        return findings

    async def _check_provenance(self, meta: PackageMeta) -> Finding | None:
        pkg = meta.pkg
        is_high_value = pkg.name in _HIGH_VALUE_PACKAGES.get(pkg.ecosystem, set())

        if is_high_value and meta.has_provenance:
            return Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"Build provenance present but unverified: {pkg.name}",
                detail=(
                    f"Registry metadata advertises provenance for {pkg.name}, but DepFence "
                    "has not verified the signature, artifact digest, signer identity and "
                    "issuer, transparency evidence, source revision, or build parameters."
                ),
                metadata={
                    "check": "provenance",
                    "high_value": True,
                    "provenance_status": "present_unverified",
                },
            )

        if is_high_value:
            return Finding(
                finding_type=FindingType.PROVENANCE,
                severity=Severity.MEDIUM,
                package=pkg,
                title=f"High-value package without build provenance: {pkg.name}",
                detail=(
                    f"{pkg.name} is a critical infrastructure package but lacks SLSA "
                    f"provenance attestation. This means its published artifacts cannot "
                    f"be verified against its source repository. Consider pinning to a "
                    f"specific hash or verifying manually."
                ),
                metadata={"check": "provenance", "high_value": True},
            )
        return None

    async def verify_npm_provenance(self, pkg: PackageId) -> dict:
        """Check npm registry for sigstore provenance attestation."""
        if not fetch_enabled():
            return {"verified": False, "reason": "offline"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                url = f"https://registry.npmjs.org/{pkg.name}/{pkg.version or 'latest'}"
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"verified": False, "reason": "not_found"}
                data = resp.json()
                dist = data.get("dist", {})
                if dist.get("attestations"):
                    return {
                        "verified": False,
                        "present": True,
                        "status": "present_unverified",
                        "attestations": dist["attestations"],
                        "reason": "attestation bundle was not cryptographically verified",
                    }
                if dist.get("signatures"):
                    return {
                        "verified": False,
                        "present": True,
                        "status": "present_unverified",
                        "signatures": len(dist["signatures"]),
                        "reason": "signature metadata was not cryptographically verified",
                    }
                return {"verified": False, "reason": "no_attestation"}
            except Exception:
                return {"verified": False, "reason": "error"}

    async def verify_pypi_provenance(self, pkg: PackageId) -> dict:
        """Check PyPI for PEP 740 attestations."""
        if not fetch_enabled():
            return {"verified": False, "reason": "offline"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                url = f"https://pypi.org/pypi/{pkg.name}/{pkg.version or ''}/json"
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {"verified": False, "reason": "not_found"}
                data = resp.json()
                urls = data.get("urls", [])
                for release_file in urls:
                    if release_file.get("provenance"):
                        return {
                            "verified": False,
                            "present": True,
                            "status": "present_unverified",
                            "provenance": release_file["provenance"],
                            "reason": "attestation bundle was not cryptographically verified",
                        }
                info = data.get("info", {})
                if info.get("attestation_url"):
                    return {
                        "verified": False,
                        "present": True,
                        "status": "present_unverified",
                        "attestation_url": info["attestation_url"],
                        "reason": "attestation URL was not fetched or cryptographically verified",
                    }
                return {"verified": False, "reason": "no_attestation"}
            except Exception:
                return {"verified": False, "reason": "error"}
