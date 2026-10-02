"""Tests for witness_core.attestation: HMAC-SHA256 signing/verification
of SYS-typed telemetry events, and the WitnessCatalog opt-in that makes
attestation an enforced check rather than just a helper module.
"""

from __future__ import annotations

from dataclasses import replace

from witness_core import (
    Channel,
    Claim,
    CorroborationStatus,
    EvidenceStore,
    TelemetryEvent,
    WitnessCatalog,
    sign_event,
    verify_event,
)

KEY = b"a-real-deployment-would-load-this-from-a-secret-manager"
OTHER_KEY = b"a-different-key-entirely"


def _event(**overrides) -> TelemetryEvent:
    fields = dict(
        event_id="evt-1",
        channel=Channel.SYS,
        channel_id="cadvisor:cpu_pct",
        field="cpu_utilization_pct",
        value=95,
        observed_at=1_000_000.0,
    )
    fields.update(overrides)
    return TelemetryEvent(**fields)


def _threshold_query(field, threshold):
    def query(claim, store):
        return [e for e in store.by_field(field, channel=Channel.SYS) if float(e.value) > threshold]

    return query


def test_a_freshly_signed_event_verifies():
    signed = sign_event(_event(), KEY)
    assert signed.signature is not None
    assert verify_event(signed, KEY)


def test_an_unsigned_event_does_not_verify():
    assert verify_event(_event(), KEY) is False


def test_a_signature_from_the_wrong_key_does_not_verify():
    signed = sign_event(_event(), KEY)
    assert verify_event(signed, OTHER_KEY) is False


def test_tampering_any_field_after_signing_breaks_verification():
    signed = sign_event(_event(), KEY)
    for field, new_value in [
        ("value", 99),
        ("channel_id", "cadvisor:cpu_pct_v2"),
        ("observed_at", 2_000_000.0),
        ("dependency_id", "some_new_dependency"),
        ("field", "cpu_pct_renamed"),
    ]:
        tampered = replace(signed, **{field: new_value})
        assert verify_event(tampered, KEY) is False, f"tampering '{field}' should break verification"


def test_signing_does_not_mutate_the_original_event():
    original = _event()
    signed = sign_event(original, KEY)
    assert original.signature is None
    assert signed.signature is not None
    assert signed.event_id == original.event_id


def test_catalog_without_attestation_key_ignores_signatures_entirely():
    """Backward compatibility: a catalog that never opted into
    attestation must behave exactly as before -- an unsigned SYS
    witness still corroborates."""
    catalog = WitnessCatalog()  # no attestation_key
    catalog.register("thing_is_true", _threshold_query("metric", 0), min_witnesses=2)

    source = TelemetryEvent("src", Channel.EXT, "attacker:claim_text", "metric", "n/a")
    w1 = _event(event_id="w1", channel_id="prometheus:metric", field="metric", value=10)
    w2 = _event(event_id="w2", channel_id="cadvisor:metric", field="metric", value=11)
    store = EvidenceStore([source, w1, w2])

    result = catalog.corroborate(Claim("thing_is_true", "x", "true", source_event_id="src"), store)
    assert result.status is CorroborationStatus.CORROBORATED


def test_catalog_with_attestation_key_rejects_unsigned_witnesses():
    catalog = WitnessCatalog(attestation_key=KEY)
    catalog.register("thing_is_true", _threshold_query("metric", 0), min_witnesses=2)

    source = TelemetryEvent("src", Channel.EXT, "attacker:claim_text", "metric", "n/a")
    w1 = _event(event_id="w1", channel_id="prometheus:metric", field="metric", value=10)  # unsigned
    w2 = _event(event_id="w2", channel_id="cadvisor:metric", field="metric", value=11)  # unsigned
    store = EvidenceStore([source, w1, w2])

    result = catalog.corroborate(Claim("thing_is_true", "x", "true", source_event_id="src"), store)
    assert result.status is CorroborationStatus.NOT_CORROBORATED
    assert "attestation" in result.note


def test_catalog_with_attestation_key_accepts_properly_signed_witnesses():
    catalog = WitnessCatalog(attestation_key=KEY)
    catalog.register("thing_is_true", _threshold_query("metric", 0), min_witnesses=2)

    source = TelemetryEvent("src", Channel.EXT, "attacker:claim_text", "metric", "n/a")
    w1 = sign_event(_event(event_id="w1", channel_id="prometheus:metric", field="metric", value=10), KEY)
    w2 = sign_event(_event(event_id="w2", channel_id="cadvisor:metric", field="metric", value=11), KEY)
    store = EvidenceStore([source, w1, w2])

    result = catalog.corroborate(Claim("thing_is_true", "x", "true", source_event_id="src"), store)
    assert result.status is CorroborationStatus.CORROBORATED
    assert len(result.witnesses) == 2


def test_catalog_with_attestation_key_rejects_a_witness_signed_with_the_wrong_key():
    """The concrete attack this closes: a compromised or rogue collector
    mislabels an EXT-influenced reading as SYS and forges a plausible
    signature with a key it doesn't actually hold -- verification must
    fail, and the witness must not count."""
    catalog = WitnessCatalog(attestation_key=KEY)
    catalog.register("thing_is_true", _threshold_query("metric", 0), min_witnesses=2)

    source = TelemetryEvent("src", Channel.EXT, "attacker:claim_text", "metric", "n/a")
    w1 = sign_event(_event(event_id="w1", channel_id="prometheus:metric", field="metric", value=10), KEY)
    forged = sign_event(_event(event_id="w2", channel_id="cadvisor:metric", field="metric", value=11), OTHER_KEY)
    store = EvidenceStore([source, w1, forged])

    result = catalog.corroborate(Claim("thing_is_true", "x", "true", source_event_id="src"), store)
    assert result.status is CorroborationStatus.NOT_CORROBORATED
    assert len(result.witnesses) == 1  # only the genuinely-signed one counts
    assert "attestation" in result.note


def test_catalog_with_attestation_key_rejects_a_signed_but_since_tampered_witness():
    """Even a witness that WAS validly signed at some point must not
    count if its value was altered after signing -- attestation is
    integrity, not just "was this ever signed once.\""""
    catalog = WitnessCatalog(attestation_key=KEY)
    catalog.register("thing_is_true", _threshold_query("metric", 0), min_witnesses=2)

    source = TelemetryEvent("src", Channel.EXT, "attacker:claim_text", "metric", "n/a")
    w1 = sign_event(_event(event_id="w1", channel_id="prometheus:metric", field="metric", value=10), KEY)
    signed_then_tampered = sign_event(
        _event(event_id="w2", channel_id="cadvisor:metric", field="metric", value=1), KEY
    )
    signed_then_tampered = replace(signed_then_tampered, value=999)  # forged upward after signing
    store = EvidenceStore([source, w1, signed_then_tampered])

    result = catalog.corroborate(Claim("thing_is_true", "x", "true", source_event_id="src"), store)
    assert result.status is CorroborationStatus.NOT_CORROBORATED
    assert len(result.witnesses) == 1
