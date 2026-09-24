"""Loads the K (trusted knowledge) channel from an external config file
instead of hardcoding approved repos/packages/accounts per scenario --
a real deployment maintains this as its CMDB, approved-repository list,
and IAM directory, updated independently of any single incident.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from witness_core import Channel, TelemetryEvent

DEFAULT_PATH = Path(__file__).parent / "trusted_knowledge.yaml"


def load_trusted_knowledge(path: Optional[str | Path] = None) -> list[TelemetryEvent]:
    path = Path(path) if path else DEFAULT_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    events: list[TelemetryEvent] = []
    field_map = {
        "approved_repositories": "approved_repository",
        "approved_package_pins": "approved_package_pin",
        "known_admin_accounts": "known_admin_username",
        "golden_config_values": "golden_config_value",
    }
    for section, field in field_map.items():
        for i, value in enumerate(data.get(section, []) or []):
            events.append(
                TelemetryEvent(
                    event_id=f"k-{section}-{i}",
                    channel=Channel.K,
                    channel_id=f"golden_config:{section}",
                    field=field,
                    value=value,
                )
            )
    return events
