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
