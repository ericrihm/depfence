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

from typing import Any, Callable


def register(event: str, callback: Callable[..., Any]) -> None:
    """Register a hook callback for the given event name.

    This is a convenience wrapper around the plugin registry's hook system.
    """
    from depfence.core.registry import get_registry

    registry = get_registry()
    registry.register_hook(event, callback)


async def fire(event: str, **kwargs: Any) -> None:
    """Fire all registered callbacks for the given event.

    Convenience wrapper — engine.py calls ``registry.fire_hook`` directly,
    but integrations that don't hold a registry reference can use this.
    """
    from depfence.core.registry import get_registry

    registry = get_registry()
    await registry.fire_hook(event, **kwargs)
