"""Automated vulnerability remediation — PR generation and manifest editing."""

from depfence.remediate.pr_generator import PullRequestDraft, RemediationPR
from depfence.remediate.strategies import RemoveStrategy, ReplaceStrategy, VersionBumpStrategy

__all__ = [
    "RemediationPR",
    "PullRequestDraft",
    "VersionBumpStrategy",
    "ReplaceStrategy",
    "RemoveStrategy",
]
