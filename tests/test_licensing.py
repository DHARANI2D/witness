"""Tests for claim-action licensing (WITNESS mechanism 4): the
LicenseCatalog registry itself, and the gate-level check that a
corroborated claim must actually license the action it is attached to.
"""

from __future__ import annotations

import pytest

from witness_core import (
    Channel,
    Claim,
    EvidenceStore,
    ProposedRemediation,
    RemediationAction,
    TelemetryEvent,
    Verdict,
    WitnessGate,
    build_default_catalog,
)
from witness_core.licensing import LicenseCatalog, build_default_license_catalog


def test_register_rejects_an_empty_contract():
    catalog = LicenseCatalog()
    with pytest.raises(ValueError):
        catalog.register("restart_service", [])


def test_unregistered_verb_has_no_contract_and_licenses_nothing():
    catalog = LicenseCatalog()
    assert not catalog.has_contract("restart_service")
    assert not catalog.licenses("restart_service", "cpu_saturated")


def test_registered_verb_licenses_only_its_named_predicates():
    catalog = LicenseCatalog()
    catalog.register("restart_service", {"cpu_saturated"})
    assert catalog.has_contract("restart_service")
    assert catalog.licenses("restart_service", "cpu_saturated")
    assert not catalog.licenses("restart_service", "error_rate_elevated")


def test_default_catalog_covers_exactly_the_five_scenario_contracts():
    catalog = build_default_license_catalog()
    assert catalog.verbs() == [
        "add_repo", "disable_account", "install_package",
        "modify_tls_config", "restart_service",
    ]
    assert catalog.licenses("restart_service", "cpu_saturated")
    assert catalog.licenses("modify_tls_config", "protocol_unsupported")
    assert catalog.licenses("add_repo", "error_rate_elevated")
    assert catalog.licenses("install_package", "package_version_is")
    assert catalog.licenses("disable_account", "session_from_new_geo")


def _error_rate_remediation(verb: str, arguments: dict, incident_id: str) -> tuple[EvidenceStore, ProposedRemediation]:
    """A genuinely corroborated error_rate_elevated claim -- real evidence
    of elevated 404s -- attached to a verb that claim's predicate does not
    license. Exactly the shape security_evaluation.py's licensing_study()
    runs at scale; this is its single deterministic unit-test analogue."""
    src = TelemetryEvent(f"{incident_id}-src", Channel.EXT, "access_log:svc:404_rate", "http_404_rate_per_min", 40)
    w1 = TelemetryEvent(f"{incident_id}-w1", Channel.SYS, "prometheus:http_404_rate_per_min",
                         "http_404_rate_per_min", 38, dependency_id="prom_scrape_404:svc")
    store = EvidenceStore([src, w1])
    claim = Claim("error_rate_elevated", "svc", "true", source_event_id=f"{incident_id}-src")
    remediation = ProposedRemediation(
        incident_id=incident_id, claims=(claim,),
        action=RemediationAction(verb=verb, target="system", arguments=arguments),
    )
    return store, remediation


def test_a_corroborated_claim_that_does_not_license_the_verb_is_held():
    """Mechanisms 1-3 alone have nothing to object to here: the claim is
    real and corroborated, and the argument is trusted. Only licensing
    (mechanism 4) catches that error_rate_elevated is not grounds to
    restart a service."""
    store, remediation = _error_rate_remediation(
        "restart_service", {"container": "svc"}, "lic-unit-1",
    )
    store.add(TelemetryEvent("lic-unit-1-k8s", Channel.SYS, "k8s_api:pod_labels", "service_name", "svc"))

    gate = WitnessGate(build_default_catalog())
    decision = gate.evaluate(remediation, store)
    assert decision.verdict is Verdict.HOLD
    assert any("not licensed" in r for r in decision.reasons)


def test_disabling_licensing_enforcement_admits_the_same_remediation():
    """Isolates licensing as the only varying factor: identical store,
    claim, and arguments; only `enforce_licensing` changes."""
    store, remediation = _error_rate_remediation(
        "restart_service", {"container": "svc"}, "lic-unit-2",
    )
    store.add(TelemetryEvent("lic-unit-2-k8s", Channel.SYS, "k8s_api:pod_labels", "service_name", "svc"))

    gate = WitnessGate(build_default_catalog(), enforce_licensing=False)
    decision = gate.evaluate(remediation, store)
    assert decision.verdict is Verdict.ADMIT


def test_a_verb_with_no_contract_at_all_is_held_however_well_corroborated():
    """Fail-safe default: an action verb this prototype's catalog never
    registered a contract for is held no matter how strong the evidence
    behind it is -- the gap this mechanism closes is "any true claim
    licenses any action," and an unregistered verb must not become a
    backdoor around that."""
    store, remediation = _error_rate_remediation(
        "k8s_cordon", {"node": "svc"}, "lic-unit-3",
    )
    store.add(TelemetryEvent("lic-unit-3-k8s", Channel.SYS, "k8s_api:pod_labels", "service_name", "svc"))

    gate = WitnessGate(build_default_catalog())
    decision = gate.evaluate(remediation, store)
    assert decision.verdict is Verdict.HOLD
    assert any("no registered license contract" in r for r in decision.reasons)
