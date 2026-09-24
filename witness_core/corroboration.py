"""Two-witness corroboration rule (WITNESS mechanism 3).

A claim is corroborated only if witness queries return SYS-typed events
that satisfy all of:

  1. Channel disjointness: the witness's channel_id differs from the
     channel the claim's own source event came from (a claim cannot
     corroborate itself).
  2. Channel-class diversity: at least `min_witnesses` *distinct
     channel classes* (infra families -- see provenance.channel_class)
     must each contribute a consistent witness. Two readings from the
     same exporter family are one compromise away from each other, so
     counting them as two independent witnesses would be a real gap:
     an attacker who controls a single telemetry pipeline could
     satisfy a same-family quorum without the underlying fault being
     real. Requiring class diversity is what makes "two-witness" a
     literal, structural requirement rather than a name.
  3. Temporal bounding: when a predicate declares `max_staleness_seconds`,
     a witness observed further from the claim's source timestamp than
     that window is rejected. Without this, an attacker (or a stale
     cache) could satisfy corroboration by citing a real anomaly from
     an unrelated time, e.g. replaying yesterday's genuine TLS error
     spike to corroborate a claim about right now.

A predicate with no registered witness query fails safe to
NO_WITNESS_DEFINED. A claim whose source_event_id cannot be resolved in
the evidence store *also* fails safe -- it is treated as
NOT_CORROBORATED rather than silently skipping the disjointness check
(an earlier version of this engine had exactly that bug: a missing
source event made `source_channel_id` None, and comparing a witness's
channel_id to None is always true, which let an unresolvable claim
sail through as trivially "disjoint" from everything).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, NamedTuple, Optional

from .provenance import Channel, EvidenceStore, TelemetryEvent
from .schema import Claim

WitnessQuery = Callable[[Claim, EvidenceStore], list[TelemetryEvent]]

DEFAULT_MIN_WITNESSES = 2


class CorroborationStatus(Enum):
    CORROBORATED = "CORROBORATED"
    NOT_CORROBORATED = "NOT_CORROBORATED"
    NO_WITNESS_DEFINED = "NO_WITNESS_DEFINED"


@dataclass
class CorroborationResult:
    claim: Claim
    status: CorroborationStatus
    witnesses: list[TelemetryEvent]
    confidence: float = 0.0
    note: str = ""


class _CatalogEntry(NamedTuple):
    query: WitnessQuery
    min_witnesses: int
    max_staleness_seconds: Optional[float]


class WitnessCatalog:
    """Registry mapping predicate name -> witness query (the closed predicate vocabulary)."""

    def __init__(self):
        self._entries: dict[str, _CatalogEntry] = {}

    def register(
        self,
        predicate: str,
        query: WitnessQuery,
        min_witnesses: int = DEFAULT_MIN_WITNESSES,
        max_staleness_seconds: Optional[float] = None,
    ) -> None:
        if min_witnesses < 1:
            raise ValueError("min_witnesses must be >= 1")
        self._entries[predicate] = _CatalogEntry(query, min_witnesses, max_staleness_seconds)

    def predicates(self) -> list[str]:
        return sorted(self._entries)

    def corroborate(self, claim: Claim, store: EvidenceStore) -> CorroborationResult:
        entry = self._entries.get(claim.predicate)
        if entry is None:
            return CorroborationResult(
                claim, CorroborationStatus.NO_WITNESS_DEFINED, [], confidence=0.0,
                note=f"no witness query registered for predicate '{claim.predicate}'",
            )

        source_event = store.by_id(claim.source_event_id)
        if source_event is None:
            # Fail safe: an unresolvable source must not be treated as
            # vacuously disjoint from every candidate witness.
            return CorroborationResult(
                claim, CorroborationStatus.NOT_CORROBORATED, [], confidence=0.0,
                note=f"claim source_event_id '{claim.source_event_id}' not found in evidence store",
            )
        source_channel_id = source_event.channel_id
        source_time = source_event.observed_at

        candidates = entry.query(claim, store)

        accepted_by_class: dict[str, TelemetryEvent] = {}
        for w in candidates:
            if w.channel is not Channel.SYS:
                continue
            if w.channel_id == source_channel_id:
                continue  # a claim cannot corroborate itself
            if entry.max_staleness_seconds is not None:
                if abs(w.observed_at - source_time) > entry.max_staleness_seconds:
                    continue  # stale or replayed evidence
            # Keep one representative per channel_class; class diversity,
            # not raw count, is what the quorum is measured against.
            accepted_by_class.setdefault(w.channel_class, w)

        witnesses = list(accepted_by_class.values())
        confidence = min(1.0, len(witnesses) / entry.min_witnesses)

        if len(witnesses) >= entry.min_witnesses:
            return CorroborationResult(claim, CorroborationStatus.CORROBORATED, witnesses, confidence=1.0)

        note = (
            f"found {len(witnesses)}/{entry.min_witnesses} independent-class SYS witness(es)"
        )
        return CorroborationResult(
            claim, CorroborationStatus.NOT_CORROBORATED, witnesses, confidence=confidence, note=note
        )
