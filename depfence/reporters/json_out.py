"""JSON reporter."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime

from depfence.core.models import ScanResult


class JsonReporter:
    name = "json"
    format = "json"

    def render(self, result: ScanResult) -> str:
        data = asdict(result)
        return json.dumps(data, indent=2, default=_serialize)


def _serialize(obj: object) -> object:
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)
