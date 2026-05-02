"""Hook system for extending depfence behavior via plugins.

Hooks allow external integrations to react to scan events without
coupling to the core scanner. Plugins register callbacks via the
plugin registry's hook system.

Available hooks:
  - pre_scan: Before scanning starts (kwargs: project_dir, ecosystems)
  - post_scan: After scanning completes (kwargs: findings, metas)
  - on_finding: When a finding is created (kwargs: finding)
  - on_threat: When a high-confidence threat is detected (kwargs: finding, meta)
"""

from __future__ import annotations

from depfence.core.models import Finding, Severity
from depfence.core.registry import get_registry


async def notify_threat(finding: Finding) -> None:
    if finding.severity in (Severity.CRITICAL, Severity.HIGH) and finding.confidence >= 0.7:
        registry = get_registry()
        await registry.fire_hook("on_threat", finding=finding)


def register_defaults() -> None:
    """Register default hook handlers. Extended by plugins at load time."""
    pass
