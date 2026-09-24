"""Two-witness corroboration rule (WITNESS mechanism 3).

A claim is corroborated only if a *witness query* run against the
evidence store returns at least one telemetry event that:

  1. is SYS-typed (system-generated, not attacker-writable), and
  2. lives on a channel identifier different from the channel the
     claim's own source event came from (channel disjointness), and
  3. is consistent with the claim's value (checked inside the witness
     query itself, since consistency is domain-specific).

A predicate with no registered witness query fails safe to
NO_WITNESS_DEFINED rather than silently passing — the closed predicate
vocabulary is a feature, not a gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .provenance import Channel, EvidenceStore, TelemetryEvent
from .schema import Claim

WitnessQuery = Callable[[Claim, EvidenceStore], list[TelemetryEvent]]


class CorroborationStatus(Enum):
    CORROBORATED = "CORROBORATED"
    NOT_CORROBORATED = "NOT_CORROBORATED"
    NO_WITNESS_DEFINED = "NO_WITNESS_DEFINED"


@dataclass
class CorroborationResult:
    claim: Claim
    status: CorroborationStatus
    witnesses: list[TelemetryEvent]


class WitnessCatalog:
    """Registry mapping predicate name -> witness query (the closed predicate vocabulary)."""

    def __init__(self):
        self._queries: dict[str, WitnessQuery] = {}

    def register(self, predicate: str, query: WitnessQuery) -> None:
        self._queries[predicate] = query

    def predicates(self) -> list[str]:
        return sorted(self._queries)

    def corroborate(self, claim: Claim, store: EvidenceStore) -> CorroborationResult:
        query = self._queries.get(claim.predicate)
        if query is None:
            return CorroborationResult(claim, CorroborationStatus.NO_WITNESS_DEFINED, [])

        source_event = store.by_id(claim.source_event_id)
        source_channel_id = source_event.channel_id if source_event else None

        candidates = query(claim, store)
        valid_witnesses = [
            w for w in candidates
            if w.channel is Channel.SYS and w.channel_id != source_channel_id
        ]
        if valid_witnesses:
            return CorroborationResult(claim, CorroborationStatus.CORROBORATED, valid_witnesses)
        return CorroborationResult(claim, CorroborationStatus.NOT_CORROBORATED, candidates)
