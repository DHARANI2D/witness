"""Default predicate/witness catalog for the demo domain.

This is intentionally small and closed, matching the abstract's design:
WITNESS trades open-ended natural-language reasoning about "did this
cause that" for a fixed vocabulary of predicates whose witness queries
are ordinary telemetry lookups.
"""

from __future__ import annotations

from typing import Callable

from .corroboration import WitnessCatalog
from .provenance import Channel, EvidenceStore, TelemetryEvent
from .schema import Claim


def _numeric_threshold_witness(field: str, threshold: float) -> Callable:
    """Witness query: a SYS metric on `field` exceeding `threshold` confirms the claim."""

    def query(claim: Claim, store: EvidenceStore) -> list[TelemetryEvent]:
        hits = []
        for e in store.by_field(field, channel=Channel.SYS):
            try:
                if float(e.value) > threshold:
                    hits.append(e)
            except (TypeError, ValueError):
                continue
        return hits

    return query


def _exact_match_witness(field: str) -> Callable:
    """Witness query: a SYS field whose value exactly (case-fold) matches the claim's value."""

    def query(claim: Claim, store: EvidenceStore) -> list[TelemetryEvent]:
        return [
            e for e in store.by_field(field, channel=Channel.SYS)
            if str(e.value).strip().casefold() == str(claim.value).strip().casefold()
        ]

    return query


def build_default_catalog() -> WitnessCatalog:
    """Build the closed predicate/witness vocabulary.

    `min_witnesses` is tuned per predicate by consequence, not applied as
    one blanket number:

    - `protocol_unsupported` and `cpu_saturated` gate destructive actions
      (a repo/package change, a service restart) on a claim about the
      target's own internal state, where a second, differently-sourced
      metric pipeline is realistically available -- so they require a
      literal two-witness (class-diverse) quorum.
    - `error_rate_elevated` is typically corroborating context (traffic
      volume observed by whichever single monitoring pipe is deployed),
      not itself the fact that licenses a destructive fix, so requiring
      a second independent family would only add false holds without
      closing an attack path -- one SYS witness suffices.
    - `package_version_is` and `session_from_new_geo` are each normally
      computed by exactly one authoritative system of record (the
      package inventory; the auth backend's own risk engine), so
      demanding a second, different-family source would be demanding
      evidence that structurally cannot exist -- one suffices, but it
      must still be SYS-typed and channel-disjoint from the claim.
    """
    catalog = WitnessCatalog()
    catalog.register(
        "error_rate_elevated",
        _numeric_threshold_witness("http_404_rate_per_min", threshold=5),
        min_witnesses=1,
        max_staleness_seconds=300,
    )
    catalog.register(
        "protocol_unsupported",
        _numeric_threshold_witness("tls_handshake_errors_per_min", threshold=0),
        min_witnesses=2,
        max_staleness_seconds=300,
    )
    catalog.register(
        "cpu_saturated",
        _numeric_threshold_witness("cpu_utilization_pct", threshold=90),
        min_witnesses=2,
        max_staleness_seconds=120,
    )
    catalog.register(
        "package_version_is",
        _exact_match_witness("installed_package_version"),
        min_witnesses=1,
        max_staleness_seconds=3600,
    )
    catalog.register(
        "session_from_new_geo",
        _numeric_threshold_witness("auth_geo_velocity_impossible_flag", threshold=0),
        min_witnesses=1,
        max_staleness_seconds=600,
    )
    return catalog
