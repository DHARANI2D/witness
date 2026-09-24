from witness_core import Verdict, WitnessGate, build_default_catalog
from scenarios import nginx_attack, cpu_saturation_benign, admin_lockout_attack, mixed_truth_attack


def _run(scenario_module):
    store, remediation, expected_verdict, _description = scenario_module.build()
    gate = WitnessGate(build_default_catalog())
    decision = gate.evaluate(remediation, store)
    return decision, expected_verdict


def test_nginx_attack_is_blocked():
    decision, expected = _run(nginx_attack)
    assert decision.verdict is expected is Verdict.BLOCK
    assert any("ppa:ngx/latest" in r for r in decision.reasons)


def test_nginx_attack_404_claim_corroborated_but_tls_claim_is_not():
    store, remediation, _, _ = nginx_attack.build()
    gate = WitnessGate(build_default_catalog())
    decision = gate.evaluate(remediation, store)
    statuses = {r.claim.predicate: r.status.value for r in decision.claim_results}
    assert statuses["error_rate_elevated"] == "CORROBORATED"
    assert statuses["protocol_unsupported"] == "NOT_CORROBORATED"


def test_cpu_saturation_is_admitted():
    decision, expected = _run(cpu_saturation_benign)
    assert decision.verdict is expected is Verdict.ADMIT


def test_admin_lockout_is_held_not_admitted():
    decision, expected = _run(admin_lockout_attack)
    assert decision.verdict is expected is Verdict.HOLD


def test_admin_lockout_defeats_naive_allowlist():
    """The point of the two-witness rule: a check that only verifies argument
    lineage (an allowlist of known accounts/actions) would wrongly admit this
    fabricated-cause attack, because every literal involved is legitimate."""
    store, remediation, _, _ = admin_lockout_attack.build()
    naive_verdict = admin_lockout_attack.naive_allowlist_verdict(store, remediation)
    assert naive_verdict is Verdict.ADMIT

    gate = WitnessGate(build_default_catalog())
    witness_decision = gate.evaluate(remediation, store)
    assert witness_decision.verdict is Verdict.HOLD
    assert naive_verdict != witness_decision.verdict


def test_mixed_truth_attack_is_blocked_despite_a_real_corroborated_claim():
    """A real, genuinely corroborated fact does not launder an unrelated
    malicious argument: lineage is checked per-literal regardless of whether
    any claim in the RCA happens to be true."""
    decision, expected = _run(mixed_truth_attack)
    assert decision.verdict is expected is Verdict.BLOCK
    statuses = {r.claim.predicate: r.status.value for r in decision.claim_results}
    assert statuses["cpu_saturated"] == "CORROBORATED"  # the claim really is true
    assert any("ppa:ckt-fix/unverified" in r for r in decision.reasons)


def test_certificate_chain_is_internally_consistent():
    gate = WitnessGate(build_default_catalog())
    for scenario_module in (nginx_attack, cpu_saturation_benign, admin_lockout_attack):
        store, remediation, _, _ = scenario_module.build()
        gate.evaluate(remediation, store)

    assert len(gate.chain) == 3
    assert gate.chain.verify() is True

    hashes = [cert.certificate_hash for cert in gate.chain]
    assert len(set(hashes)) == 3  # all distinct
    prev_hashes = [cert.prev_hash for cert in gate.chain]
    assert prev_hashes[0] == gate.chain.GENESIS
    assert prev_hashes[1] == hashes[0]
    assert prev_hashes[2] == hashes[1]


def test_tampered_certificate_fails_verification():
    gate = WitnessGate(build_default_catalog())
    store, remediation, _, _ = cpu_saturation_benign.build()
    gate.evaluate(remediation, store)

    gate.chain._chain[0].reasons.append("tampered")
    assert gate.chain.verify() is False


def test_unknown_predicate_fails_safe_to_hold():
    from witness_core import Claim, EvidenceStore, ProposedRemediation, RemediationAction

    store = EvidenceStore([])
    remediation = ProposedRemediation(
        incident_id="INC-9999-unknown-predicate",
        claims=(
            Claim(
                predicate="totally_unregistered_predicate",
                subject="x",
                value="y",
                source_event_id="does-not-exist",
            ),
        ),
        action=RemediationAction(verb="noop", target="none", arguments={}),
    )
    gate = WitnessGate(build_default_catalog())
    decision = gate.evaluate(remediation, store)
    assert decision.verdict is Verdict.HOLD


def test_ext_content_stays_visible_in_evidence_store():
    """WITNESS never masks EXT fields the way sanitization-based defenses do;
    it just refuses to let them self-certify. Confirm the store still
    contains the raw attacker text for SOC review."""
    store, _remediation, _expected, _description = nginx_attack.build()
    ext_events = [e for e in store.all() if e.channel.value == "EXT"]
    assert len(ext_events) == 1
    assert "ppa:ngx/latest" in str(ext_events[0].value)
