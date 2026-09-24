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
    catalog = WitnessCatalog()
    catalog.register(
        "error_rate_elevated",
        _numeric_threshold_witness("http_404_rate_per_min", threshold=5),
    )
    catalog.register(
        "protocol_unsupported",
        _numeric_threshold_witness("tls_handshake_errors_per_min", threshold=0),
    )
    catalog.register(
        "cpu_saturated",
        _numeric_threshold_witness("cpu_utilization_pct", threshold=90),
    )
    catalog.register(
        "package_version_is",
        _exact_match_witness("installed_package_version"),
    )
    catalog.register(
        "session_from_new_geo",
        _numeric_threshold_witness("auth_geo_velocity_impossible_flag", threshold=0),
    )
    return catalog
