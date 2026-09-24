"""Provenance-typed evidence labeling (WITNESS mechanism 1).

Every telemetry field WITNESS reasons about is tagged with a
writer-provenance type (a `Channel`) and a concrete channel identifier
(which signal, exactly, produced it). The channel identifier's prefix
(before the first ':') is its `channel_class` -- the infra family that
produced it (e.g. "prometheus", "elasticsearch", "k8s_api"). Corroboration
requires witnesses from *distinct channel classes*, not merely distinct
channel_ids: two Prometheus series are still one compromise away from
each other, but Prometheus and the Kubernetes API are not.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
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
    observed_at: float = field(default_factory=time.time)

    @property
    def channel_class(self) -> str:
        """The infra family that produced this signal (the channel_id prefix).

        Two events sharing a channel_class share an attack surface: an
        attacker who compromises one Prometheus exporter can plausibly
        forge other Prometheus series too, but compromising Prometheus
        does not hand them control of the Kubernetes API or Elasticsearch.
        """
        return self.channel_id.split(":", 1)[0]


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
        """Exact (post-normalization) substring search, used by the lineage check."""
        from .lineage import normalize

        needle = normalize(literal)
        if not needle:
            return []
        return [e for e in self._events if needle in normalize(str(e.value))]

    def contains_literal_fuzzy(self, literal: str, min_ratio: float = 0.92) -> list[tuple[TelemetryEvent, float]]:
        """Fuzzy fallback search used only when the exact search finds nothing.

        Catches an attacker obfuscating a literal with homoglyphs/zero-width
        characters that survive normalization's confusable-mapping pass but
        still differ slightly (e.g. an extra inserted character). Returns
        (event, ratio) pairs above `min_ratio`, sorted by ratio descending.
        """
        from difflib import SequenceMatcher

        from .lineage import normalize

        needle = normalize(literal)
        if not needle:
            return []
        scored = []
        for e in self._events:
            hay = normalize(str(e.value))
            if not hay:
                continue
            # Compare against the best-aligned substring window, not the
            # whole (possibly much longer) field value.
            ratio = SequenceMatcher(None, needle, hay).ratio()
            if len(hay) > len(needle):
                # Slide a window sized to the needle for a fairer local match.
                best = ratio
                step = max(1, len(needle) // 4)
                for start in range(0, max(1, len(hay) - len(needle) + 1), step):
                    window = hay[start:start + len(needle)]
                    best = max(best, SequenceMatcher(None, needle, window).ratio())
                ratio = best
            if ratio >= min_ratio:
                scored.append((e, ratio))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored
