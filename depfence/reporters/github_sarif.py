"""GitHub Code Scanning SARIF uploader.

Uploads a SARIF document to the GitHub Code Scanning API so that findings
appear as alerts in the repository's *Security > Code scanning* tab.

Requirements
------------
* A GitHub token with the ``security_events: write`` scope (typically
  ``GITHUB_TOKEN`` in a GitHub Actions workflow).
* The ``httpx`` package (already a depfence dependency).

References
----------
* GitHub REST API — Upload an analysis for a repository:
  https://docs.github.com/en/rest/code-scanning/code-scanning?apiVersion=2022-11-28#upload-an-analysis-as-sarif-data
"""

from __future__ import annotations

import base64
import gzip
import json
import os
from typing import Any


def _compress_sarif(sarif: dict[str, Any]) -> str:
    """Gzip-compress and base64-encode a SARIF dict for the GitHub API."""
    raw = json.dumps(sarif).encode("utf-8")
    compressed = gzip.compress(raw)
    return base64.b64encode(compressed).decode("ascii")


def upload_sarif(
    sarif: dict[str, Any],
    repo: str,
    ref: str,
    commit_sha: str,
    *,
    token: str | None = None,
    tool_name: str = "depfence",
    checkout_uri: str = "file:///github/workspace/",
) -> dict[str, Any]:
    """Upload a SARIF document to GitHub Code Scanning.

    Args:
        sarif: SARIF 2.1.0 document as a Python dict (e.g. from
               :func:`~depfence.reporters.sarif.generate_sarif`).
        repo: Repository in ``owner/name`` format (e.g. ``"acme/myapp"``).
        ref: Git ref being analysed (e.g. ``"refs/heads/main"`` or a
             ``refs/pull/<n>/merge`` ref for PRs).
        commit_sha: Full 40-character commit SHA being analysed.
        token: GitHub personal access token or ``GITHUB_TOKEN``.  When
               ``None`` the value is read from the ``GITHUB_TOKEN``
               environment variable.
        tool_name: Free-form label attached to the upload (defaults to
                   ``"depfence"``).
        checkout_uri: The ``checkoutUri`` field tells GitHub how to map SARIF
                      artifact URIs to repository paths.  In Actions workflows
                      this is normally ``"file:///github/workspace/"``.

    Returns:
        The parsed JSON response body from the GitHub API (a dict with at
        least an ``"id"`` field on success).

    Raises:
        ImportError: If ``httpx`` is not installed.
        RuntimeError: If no GitHub token is available or the API call fails
                      with a non-2xx status code.
    """
    try:
        import httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for GitHub SARIF upload.  "
            "Install it with: pip install httpx"
        ) from exc

    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        raise RuntimeError(
            "A GitHub token is required.  Pass token= or set the "
            "GITHUB_TOKEN environment variable."
        )

    sarif_b64 = _compress_sarif(sarif)

    payload: dict[str, Any] = {
        "commit_sha": commit_sha,
        "ref": ref,
        "sarif": sarif_b64,
        "tool_name": tool_name,
        "checkout_uri": checkout_uri,
    }

    url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {resolved_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }

    response = httpx.post(url, json=payload, headers=headers, timeout=30.0)

    if response.status_code not in (200, 201, 202):
        raise RuntimeError(
            f"GitHub API error {response.status_code}: {response.text}"
        )

    try:
        return response.json()
    except Exception:
        return {"status": response.status_code, "text": response.text}
