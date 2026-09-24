"""Provenance-typed evidence labeling (WITNESS mechanism 1).

Every telemetry field WITNESS reasons about is tagged with a
writer-provenance type (a `Channel`) and a concrete channel identifier
(which signal, exactly, produced it). The channel identifier is what
lets the corroboration rule later require two *disjoint* channels
instead of just two facts pulled from the same pipe.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class Channel(Enum):
    """Writer-provenance type for a telemetry field."""

    SYS = "SYS"  # system-generated: exporters, status codes, package/CMDB inventory, orchestrator state
    EXT = "EXT"  # externally influenceable: request-supplied paths, headers, usernames, message bodies
    K = "K"      # trusted knowledge: approved repositories, vendor advisories, golden config


@dataclass(frozen=True)
class TelemetryEvent:
    """A single labeled telemetry fact WITNESS can reason about."""

    event_id: str
    channel: Channel
    channel_id: str  # concrete signal path, e.g. "prometheus:tls_handshake_errors_per_min"
    field: str        # logical field name, e.g. "tls_handshake_errors_per_min"
    value: Any


class EvidenceStore:
    """All telemetry and trusted knowledge collected for one incident."""

    def __init__(self, events: Optional[list[TelemetryEvent]] = None):
        self._events: list[TelemetryEvent] = list(events or [])
        seen = set()
        for e in self._events:
            if e.event_id in seen:
                raise ValueError(f"duplicate event_id in EvidenceStore: {e.event_id}")
            seen.add(e.event_id)

    def add(self, event: TelemetryEvent) -> None:
        if any(e.event_id == event.event_id for e in self._events):
            raise ValueError(f"duplicate event_id in EvidenceStore: {event.event_id}")
        self._events.append(event)

    def by_field(self, field: str, channel: Optional[Channel] = None) -> list[TelemetryEvent]:
        return [e for e in self._events if e.field == field and (channel is None or e.channel == channel)]

    def by_id(self, event_id: str) -> Optional[TelemetryEvent]:
        for e in self._events:
            if e.event_id == event_id:
                return e
        return None

    def all(self) -> list[TelemetryEvent]:
        return list(self._events)

    def contains_literal(self, literal: str) -> list[TelemetryEvent]:
        """Normalized substring search used by the action-argument lineage check."""
        from .lineage import normalize

        needle = normalize(literal)
        if not needle:
            return []
        return [e for e in self._events if needle in normalize(str(e.value))]
