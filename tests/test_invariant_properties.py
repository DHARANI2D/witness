"""Property-based tests for the Corroborated Remediation Invariant (CRI)
-- see README.md's "The central invariant":

    ADMIT(a)  iff
        (all load-bearing claims corroborated)
      and (all concrete arguments trusted)
      and (the action is schema-valid)

Everything above this line, `security_evaluation.py`'s 313-trial corpus,
and every scenario/unit test is a *curated* fixture: a human (or a
prior Claude session) picked the inputs. This file instead generates
hundreds of randomized EvidenceStore/Claim/argument combinations with
Hypothesis and checks that properties which must hold for *any* input
-- not just the ones anyone thought to write by hand -- actually do.
This is the practical, dependency-free version of "formal verification"
this project's constraints allow (no paid tooling, no external SMT
solver): not a machine-checked proof, but much broader coverage than
example-based tests alone, and it can find a counterexample a curated
fixture never would.

Run just this file (slower than the rest of the suite -- each property
runs its default ~50-100 generated examples):
    PYTHONPATH=. python3 -m pytest tests/test_invariant_properties.py -v
"""

from __future__ import annotations

import sys

# Defensive, narrowly-scoped workaround: if a local AIOpsLab checkout is
# present (tests/test_aiopslab_integration.py's optional real-integration
# path, collected alphabetically before this file), importing AIOpsLab's
# own third-party package code inserts a raw pathlib.Path into sys.path
# rather than a str. That's harmless on its own, but hypothesis>=6.168's
# import-time sys.path scan (`hypothesis.internal.scrutineer`) assumes
# every entry is a str and crashes on the first non-str one -- breaking
# collection of this entire file, even though this file has nothing to
# do with AIOpsLab. CI never hits this (no AIOpsLab checkout exists
# there), but a local dev setup following this repo's own docs would.
# Coercing to str here is a no-op for every entry that was already a
# str and fixes the only case that mattered.
sys.path[:] = [str(p) for p in sys.path]

from hypothesis import given, settings, strategies as st

from witness_core import (
    Channel,
    Claim,
    CorroborationStatus,
    EvidenceStore,
    Lineage,
    ProposedRemediation,
    RemediationAction,
    TelemetryEvent,
    Verdict,
    WitnessCatalog,
    WitnessGate,
    sign_event,
)
from witness_core.licensing import LicenseCatalog

# A small, fixed alphabet keeps Hypothesis's shrinker fast and its
# generated examples legible when a property does fail -- the point is
# broad structural coverage of the *decision logic*, not an exhaustive
# fuzz of arbitrary Unicode.
_CHANNELS = [Channel.SYS, Channel.EXT, Channel.K]
_CLASSES = ["alpha", "beta", "gamma"]
_LITERALS = ["lit-a", "lit-b", "lit-c"]
_SENTINEL_MISSING_SOURCE = "source-event-id-guaranteed-absent"

_event_strategy = st.fixed_dictionaries({
    "channel": st.sampled_from(_CHANNELS),
    "class_": st.sampled_from(_CLASSES),
    "value": st.sampled_from(_LITERALS),
    "numeric": st.floats(min_value=-10, max_value=200, allow_nan=False, allow_infinity=False),
})


def _make_catalog(min_witnesses: int = 2, attestation_key: bytes | None = None) -> WitnessCatalog:
    catalog = WitnessCatalog(attestation_key=attestation_key)

    def query(claim, store):
        return [e for e in store.by_field("numeric", channel=Channel.SYS) if e.value > 0]

    catalog.register("p", query, min_witnesses=min_witnesses)
    return catalog


def _build_store(event_specs: list[dict]) -> tuple[EvidenceStore, list[TelemetryEvent]]:
    events = []
    for i, spec in enumerate(event_specs):
        events.append(TelemetryEvent(
            event_id=f"evt-{i}",
            channel=spec["channel"],
            channel_id=f"{spec['class_']}:field",
            field="numeric",
            value=spec["numeric"],
        ))
    return EvidenceStore(events), events


# ---------------------------------------------------------------------------
# Property A: ADMIT is only reachable when every load-bearing claim is
# corroborated AND every argument literal is trusted -- no partial credit.
# ---------------------------------------------------------------------------

@given(
    event_specs=st.lists(_event_strategy, max_size=6),
    literal_value=st.sampled_from(_LITERALS),
    literal_channel=st.sampled_from(_CHANNELS),
    claim_source_present=st.booleans(),
)
@settings(max_examples=150)
def test_admit_implies_every_claim_corroborated_and_every_argument_trusted(
    event_specs, literal_value, literal_channel, claim_source_present,
):
    store, events = _build_store(event_specs)
    literal_event = TelemetryEvent(
        event_id="literal-evt", channel=literal_channel, channel_id="lit:src",
        field="literal_field", value=literal_value,
    )
    store.add(literal_event)

    source_id = events[0].event_id if (claim_source_present and events) else _SENTINEL_MISSING_SOURCE
    claim = Claim("p", "subject", "true", source_event_id=source_id)
    remediation = ProposedRemediation(
        incident_id="prop-a",
        claims=(claim,),
        action=RemediationAction("do_thing", "target", {"arg": literal_value}),
    )

    gate = WitnessGate(_make_catalog())
    decision = gate.evaluate(remediation, store)

    if decision.verdict is Verdict.ADMIT:
        assert all(r.status is CorroborationStatus.CORROBORATED for r in decision.claim_results)
        assert all(r.lineage is Lineage.TRUSTED for r in decision.lineage_results)


# ---------------------------------------------------------------------------
# Property B: any attacker-sourced (EXT-only) argument forces BLOCK,
# regardless of how well-corroborated the claims are.
# ---------------------------------------------------------------------------

@given(
    event_specs=st.lists(_event_strategy, max_size=6),
    literal_value=st.sampled_from(_LITERALS),
)
@settings(max_examples=150)
def test_attacker_sourced_argument_always_blocks(event_specs, literal_value):
    store, events = _build_store(event_specs)
    # The literal exists ONLY in an EXT field -- never K or SYS -- so its
    # lineage must resolve to ATTACKER_SOURCED regardless of `event_specs`.
    store.add(TelemetryEvent("literal-evt", Channel.EXT, "lit:src", "literal_field", literal_value))

    claim = Claim("p", "subject", "true", source_event_id="literal-evt")  # may or may not corroborate
    remediation = ProposedRemediation(
        incident_id="prop-b",
        claims=(claim,),
        action=RemediationAction("do_thing", "target", {"arg": literal_value}),
    )

    gate = WitnessGate(_make_catalog())
    decision = gate.evaluate(remediation, store)

    lineages = [r.lineage for r in decision.lineage_results]
    if Lineage.ATTACKER_SOURCED in lineages:
        assert decision.verdict is Verdict.BLOCK


# ---------------------------------------------------------------------------
# Property C: a load-bearing claim whose source_event_id can't be
# resolved must never result in ADMIT -- the fail-safe this project
# regression-tested at the unit level (test_engine_upgrades.py), now
# checked against many random surrounding-evidence shapes too.
# ---------------------------------------------------------------------------

@given(event_specs=st.lists(_event_strategy, max_size=6))
@settings(max_examples=150)
def test_unresolvable_load_bearing_source_never_admits(event_specs):
    store, _events = _build_store(event_specs)
    claim = Claim("p", "subject", "true", source_event_id=_SENTINEL_MISSING_SOURCE, load_bearing=True)
    remediation = ProposedRemediation(
        incident_id="prop-c",
        claims=(claim,),
        action=RemediationAction("do_thing", "target", {}),
    )

    gate = WitnessGate(_make_catalog())
    decision = gate.evaluate(remediation, store)

    assert decision.verdict is not Verdict.ADMIT


# ---------------------------------------------------------------------------
# Property D: no two witnesses in a final *accepted* set ever share a
# declared dependency_id -- the actual guarantee the dependency-graph
# check (corroboration.py's `seen_dependency_ids`) exists to provide,
# checked under both attestation-off and attestation-on.
#
# This property test's first draft asserted something stronger and
# intuitively appealing -- "enabling attestation can only ever remove
# witnesses, never increase the accepted count relative to the same
# candidate list with attestation off." Hypothesis disproved it on the
# very first run, with a genuinely instructive counterexample: four
# candidates -- two unsigned witnesses sharing "dep-1" (one alpha-class,
# one beta-class) plus two signed ones (alpha-class/"dep-2" and
# beta-class/"dep-1"). With attestation off, the first unsigned
# alpha/dep-1 candidate is accepted as the alpha representative and
# registers "dep-1" as claimed; the signed beta/dep-1 candidate is then
# rejected as a dependency collision with it -- 1 witness total. With
# attestation on, that same unsigned candidate is filtered out *before*
# it can register "dep-1"; the signed alpha/dep-2 and signed beta/dep-1
# candidates are then both accepted as genuinely dependency-distinct --
# 2 witnesses. Attestation-on produced *more* accepted witnesses for
# the identical candidate list.
#
# This is not a security regression: both outcomes independently
# satisfy the real invariant (below), and the two extra accepted
# witnesses under attestation-on really are pairwise dependency-distinct
# -- attestation removing an untrustworthy candidate can "unstick" a
# separate, genuinely-independent witness that had been needlessly
# blocked by an arbitrary, iteration-order-dependent collision with the
# now-removed one. But it means "attestation is strictly conservative
# relative to no attestation" is FALSE for this greedy, order-sensitive
# algorithm, and this project would rather have Hypothesis catch a
# false intuition here than assert it in README as if it were obviously
# true. See "What 'independent' actually means here" in README.md for
# the write-up.
# ---------------------------------------------------------------------------

_ATTESTATION_KEY = b"property-test-key"

_witness_strategy = st.fixed_dictionaries({
    "class_": st.sampled_from(_CLASSES),
    "dependency_id": st.sampled_from(["dep-1", "dep-2", None]),
    "signed": st.booleans(),
})


@given(
    witness_specs=st.lists(_witness_strategy, min_size=0, max_size=8),
    attestation_on=st.booleans(),
)
@settings(max_examples=200)
def test_accepted_witnesses_never_share_a_dependency_id(witness_specs, attestation_on):
    source = TelemetryEvent("src", Channel.EXT, "attacker:claim", "numeric", 0.0)
    events = []
    for i, spec in enumerate(witness_specs):
        e = TelemetryEvent(
            event_id=f"w{i}", channel=Channel.SYS, channel_id=f"{spec['class_']}:numeric",
            field="numeric", value=1.0, dependency_id=spec["dependency_id"],
        )
        if spec["signed"]:
            e = sign_event(e, _ATTESTATION_KEY)
        events.append(e)

    store = EvidenceStore([source] + events)
    claim = Claim("p", "subject", "true", source_event_id="src")
    key = _ATTESTATION_KEY if attestation_on else None
    result = _make_catalog(min_witnesses=1, attestation_key=key).corroborate(claim, store)

    accepted_deps = [w.dependency_id for w in result.witnesses if w.dependency_id is not None]
    assert len(accepted_deps) == len(set(accepted_deps)), (
        f"two accepted witnesses shared a dependency_id: {accepted_deps}"
    )
    # Every accepted witness must also have genuinely passed attestation
    # when it's enabled -- never a silently-admitted unsigned one.
    if attestation_on:
        from witness_core import verify_event
        assert all(verify_event(w, _ATTESTATION_KEY) for w in result.witnesses)


# ---------------------------------------------------------------------------
# Property E: a literal's TRUSTED lineage, once established, survives
# adding arbitrary further evidence -- more information can only add
# corroborating context, never retroactively un-trust a literal that a
# K/SYS record already vouched for.
# ---------------------------------------------------------------------------

from witness_core import check_argument_lineage  # noqa: E402


@given(
    literal_value=st.sampled_from(_LITERALS),
    extra_specs=st.lists(_event_strategy, max_size=6),
)
@settings(max_examples=150)
def test_trusted_lineage_survives_adding_more_evidence(literal_value, extra_specs):
    trusted_event = TelemetryEvent("trusted-evt", Channel.K, "golden_config:approved", "literal_field", literal_value)
    store = EvidenceStore([trusted_event])
    baseline = check_argument_lineage(literal_value, store)
    assert baseline.lineage is Lineage.TRUSTED

    for i, spec in enumerate(extra_specs):
        store.add(TelemetryEvent(f"extra-{i}", spec["channel"], f"{spec['class_']}:x", "literal_field", spec["value"]))

    after = check_argument_lineage(literal_value, store)
    assert after.lineage is Lineage.TRUSTED


# ---------------------------------------------------------------------------
# Property F: zero load-bearing claims never admits -- the vacuous-
# admission gap this engine was found to have (test_engine_upgrades.py's
# `test_a_remediation_with_no_claims_at_all_never_admits` unit-tests one
# fixed case; this generalizes it across random surrounding stores,
# verbs, and whether the (absent) action carries trusted arguments).
# ---------------------------------------------------------------------------

@given(
    event_specs=st.lists(_event_strategy, max_size=6),
    verb=st.sampled_from(["do_thing", "restart_service", "anything"]),
    arguments_trusted=st.booleans(),
)
@settings(max_examples=150)
def test_no_load_bearing_claims_never_admits(event_specs, verb, arguments_trusted):
    store, _events = _build_store(event_specs)
    arguments = {}
    if arguments_trusted:
        store.add(TelemetryEvent("trusted-evt", Channel.K, "golden_config:approved", "literal_field", "trusted-lit"))
        arguments = {"arg": "trusted-lit"}

    remediation = ProposedRemediation(
        incident_id="prop-f", claims=(), action=RemediationAction(verb, "target", arguments),
    )
    gate = WitnessGate(_make_catalog())
    decision = gate.evaluate(remediation, store)
    assert decision.verdict is not Verdict.ADMIT


# ---------------------------------------------------------------------------
# Property G: ADMIT requires a corroborated claim whose predicate is in
# the proposed verb's license contract (mechanism 4) -- a true,
# well-sourced claim about an unrelated verb must never be enough.
# ---------------------------------------------------------------------------

_LICENSED_VERB = "licensed_action"
_UNLICENSED_VERBS = ["unlicensed_action_1", "unlicensed_action_2"]


@given(
    event_specs=st.lists(_event_strategy, max_size=6),
    verb=st.sampled_from([_LICENSED_VERB] + _UNLICENSED_VERBS),
    literal_value=st.sampled_from(_LITERALS),
)
@settings(max_examples=150)
def test_admit_requires_the_verb_to_be_licensed_by_a_corroborated_claim(event_specs, verb, literal_value):
    store, _events = _build_store(event_specs)
    store.add(TelemetryEvent("src", Channel.EXT, "attacker:claim", "numeric", 0.0))
    store.add(TelemetryEvent("witness-1", Channel.SYS, "alpha:numeric", "numeric", 1.0))
    store.add(TelemetryEvent("trusted-evt", Channel.K, "golden_config:approved", "literal_field", literal_value))

    claim = Claim("p", "subject", "true", source_event_id="src")
    remediation = ProposedRemediation(
        incident_id="prop-g", claims=(claim,),
        action=RemediationAction(verb, "target", {"arg": literal_value}),
    )

    license_catalog = LicenseCatalog()
    license_catalog.register(_LICENSED_VERB, {"p"})
    gate = WitnessGate(_make_catalog(min_witnesses=1), license_catalog=license_catalog)
    decision = gate.evaluate(remediation, store)

    if decision.verdict is Verdict.ADMIT:
        assert verb == _LICENSED_VERB
