"""Unit tests for the adapters package that don't require a real AIOpsLab
checkout: telemetry format parsing, trusted-knowledge loading, and the
deterministic RCA claim extractor.
"""

from __future__ import annotations

from witness_core import Channel, EvidenceStore
from adapters.claim_extractor import RCAClaimExtractor
from adapters.telemetry import metrics_csv_to_events, pod_log_rows_to_events, raw_pod_logs_to_events
from adapters.trusted_knowledge import load_trusted_knowledge


# --- telemetry.py: real AIOpsLab data-format compatibility ---

def test_metrics_csv_matches_real_prometheus_api_export_schema():
    csv_text = (
        "timestamp,cmdb_id,kpi_name,value\n"
        "1700000000,node1.nginx-abc123,container_cpu_usage_seconds_total,0.42\n"
        "1700000060,node1.nginx-abc123,container_cpu_usage_seconds_total,0.51\n"
    )
    events = metrics_csv_to_events(csv_text)
    assert len(events) == 2
    assert all(e.channel is Channel.SYS for e in events)
    assert events[0].field == "container_cpu_usage_seconds_total"
    assert events[0].value == "0.42"
    assert events[0].observed_at == 1700000000.0


def test_metrics_csv_rejects_wrong_schema():
    import pytest

    with pytest.raises(ValueError):
        metrics_csv_to_events("not,the,right,columns\n1,2,3,4\n")


def test_pod_log_rows_matches_real_log_processing_hotel_reservation_schema():
    rows = [
        {
            "log_id": "abc123",
            "timestamp": "1700000000",
            "date": "2023-11-14T22:13:20.000Z",
            "pod_name": "nginx-abc123",
            "container_name": "nginx",
            "namespace": "test-hotel-reservation",
            "node_name": "node1",
            "message": "GET /search?ref=<script>evil</script> 404",
        }
    ]
    events = pod_log_rows_to_events(rows)
    assert len(events) == 1
    event = events[0]
    assert event.channel is Channel.EXT
    assert event.field == "message"
    assert "script" in event.value


def test_raw_pod_logs_one_event_per_nonempty_line():
    raw = "line one\n\nline two\n   \nline three"
    events = raw_pod_logs_to_events(raw, namespace="ns", pod="pod-1")
    assert len(events) == 3
    assert all(e.channel is Channel.EXT for e in events)
    assert events[1].value == "line two"


# --- trusted_knowledge.py ---

def test_loads_default_trusted_knowledge_with_expected_sections():
    events = load_trusted_knowledge()
    assert any(e.value == "ppa:nginx/stable" for e in events)
    assert any(e.value == "alice" for e in events)
    assert all(e.channel is Channel.K for e in events)


# --- claim_extractor.py ---

def test_extracts_protocol_unsupported_regardless_of_clause_order():
    extractor = RCAClaimExtractor()
    store = EvidenceStore()

    forward = "nginx doesn't support the current TLS version, causing handshake failures."
    reverse = "404 errors are caused by nginx not supporting the current SSL version."

    claims_forward = extractor.extract(forward, store)
    claims_reverse = extractor.extract(reverse, EvidenceStore())

    assert any(c.predicate == "protocol_unsupported" for c in claims_forward)
    assert any(c.predicate == "protocol_unsupported" for c in claims_reverse)


def test_extracts_cpu_saturated():
    extractor = RCAClaimExtractor()
    claims = extractor.extract("CPU usage is saturated at 97% on the pod.", EvidenceStore())
    assert any(c.predicate == "cpu_saturated" for c in claims)


def test_extracts_session_from_new_geo():
    extractor = RCAClaimExtractor()
    claims = extractor.extract(
        "Impossible travel detected: admin logged in from Moscow then New York.", EvidenceStore()
    )
    assert any(c.predicate == "session_from_new_geo" for c in claims)


def test_no_match_yields_no_claims_and_no_source_event_added():
    extractor = RCAClaimExtractor()
    store = EvidenceStore()
    claims = extractor.extract("Everything looks fine, no action needed.", store)
    assert claims == ()
    # a source event is still registered even with zero matching claims,
    # since the raw reasoning is itself useful evidence for HOLD/BLOCK later
    assert len(store.all()) == 1


def test_repeated_extraction_with_same_text_reuses_source_event_idempotently():
    extractor = RCAClaimExtractor()
    store = EvidenceStore()
    text = "CPU usage is saturated at 97%."
    extractor.extract(text, store)
    extractor.extract(text, store)
    rca_events = [e for e in store.all() if e.channel_id == "agent_response:rca_text"]
    assert len(rca_events) == 1
