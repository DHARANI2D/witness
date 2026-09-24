# WITNESS — a working reference implementation of the admission gate

This repository is a practical, runnable implementation of the deterministic
core described in the *WITNESS: Unforgeable Corroboration for Safe Autonomous
Remediation by AI Operations and Security Agents* abstract: the principle
**corroboration, not attribution**.

A proposed remediation is admitted only if every load-bearing causal claim
behind it is confirmed by an independent, system-generated "witness" signal
on a channel disjoint from where the claim first appeared, **and** every
concrete action argument (package source, version, account name, ...) traces
to a trusted source.

## What's actually here vs. what's stubbed

This is the part of WITNESS that is buildable and testable without a
Kubernetes cluster, a GPU testbed, or network access to AIOpsLab / Loghub /
the AIOpsDoom attack tool — the deterministic admission gate itself, plus
three concrete scenarios that exercise it end to end:

| Piece | Status |
|---|---|
| Provenance-typed evidence labeling (`SYS` / `EXT` / `K`) | Real, working |
| Action-argument lineage check (normalization, TRUSTED/ATTACKER_SOURCED/UNKNOWN) | Real, working |
| Two-witness corroboration rule (channel disjointness + consistency) | Real, working |
| Hash-chained evidence certificate | Real, working |
| Admission gate (ADMIT / HOLD / BLOCK) | Real, working |
| The LLM's schema-constrained parse of an agent's free-text RCA into `Claim`/`RemediationAction` objects | **Stubbed.** Scenarios construct these objects directly. This matches the abstract's own design principle — "an LLM may act only as a schema-constrained parser; every later step is deterministic" — so the gate under test is exactly the part that must not depend on model behavior. |
| Live telemetry from AIOpsLab / Loghub / a Kubernetes cluster | **Synthetic.** Each scenario builds a small, explicit `EvidenceStore` by hand instead of running the published attack tool against a live testbed. |

The 9-day prototype plan in the abstract's evaluation section (wiring this
gate up as a pre-execution hook in front of AIOpsLab, replaying the released
attack tool, measuring ASR/utility/false-hold rate/latency against four
baselines) is the natural next step and is **not** attempted here — it needs
infrastructure this environment doesn't have. What's here is the part every
reviewer will actually read line by line: does the admission logic itself
work, is it deterministic, and does it catch the attacks it claims to.

## Architecture

```
witness_core/
  provenance.py     Mechanism 1: Channel (SYS/EXT/K), TelemetryEvent, EvidenceStore
  lineage.py         Mechanism 2: normalization + action-argument lineage check
  schema.py          Closed schema an LLM parser would fill: Claim, RemediationAction
  corroboration.py   Mechanism 3: WitnessCatalog, two-witness corroboration rule
  catalog.py         Default predicate -> witness-query registrations for the demo domain
  certificate.py     Hash-chained EvidenceCertificate / CertificateChain
  gate.py            WitnessGate: combines 1-3 into ADMIT / HOLD / BLOCK

scenarios/
  nginx_attack.py            The abstract's worked example -> BLOCK
  cpu_saturation_benign.py   A genuine incident -> ADMIT
  admin_lockout_attack.py    A "legitimate values" attack -> HOLD (defeats a naive allowlist)

demo.py    Runs all three scenarios, prints decisions + certificates
tests/     pytest suite covering the gate, the catalog, and the certificate chain
```

Decision flow inside `WitnessGate.evaluate`:

```
for each load-bearing claim:  is there a SYS witness on a disjoint channel
                               whose value is consistent with the claim?
for each action argument:     does the literal occur in K or SYS (trusted),
                               only in EXT (attacker-sourced), or nowhere
                               (model-invented)?

any argument EXT-only          -> BLOCK  (raise an attributed alert)
else any claim uncorroborated,
     or any argument unknown   -> HOLD   (human review + evidence diff)
else                            -> ADMIT
```

Every decision — regardless of verdict — appends one `EvidenceCertificate`
to a SHA-256 hash chain, so a SOC analyst can answer "why did WITNESS block
this?" from the certificate alone.

## Running it

```bash
python3 demo.py                 # runs all 3 scenarios, prints certificates
pip install -r requirements-dev.txt
python3 -m pytest -v            # 9 tests, no external dependencies
```

No network access, database, or external services are required — the whole
engine is Python standard library only.

## The three scenarios

### 1. The published nginx attack (`scenarios/nginx_attack.py`) → **BLOCK**

Replicates the abstract's worked example. An attacker plants a plausible
root cause and a matching malicious fix inside a request-controlled field
(`EXT`). WITNESS splits the RCA into two claims:

- `error_rate_elevated` — **corroborated**: the 404 spike is real, and an
  independent Prometheus counter confirms it on a channel disjoint from the
  access-log counter the claim was sourced from.
- `protocol_unsupported` (the fabricated TLS claim) — **not corroborated**:
  the TLS handshake-error counters are flat, so no SYS witness exists.

Independently, the literal `ppa:ngx/latest` occurs only in the attacker's
`EXT` text and matches nothing in trusted knowledge (`K`) or `SYS` state, so
its lineage is `ATTACKER_SOURCED`. That alone is enough to **BLOCK** the fix
and raise an attributed alert — the attack becomes a detection.

### 2. Genuine CPU saturation (`scenarios/cpu_saturation_benign.py`) → **ADMIT**

A real incident: two independent `SYS` signals (a container metric from
cAdvisor, a host metric from the node exporter) agree the service is
CPU-saturated, and the restart target is a known service. This is the
false-hold check the abstract's evaluation plan calls for — a gate that
also blocks legitimate automation isn't useful.

### 3. The "legitimate values" attack (`scenarios/admin_lockout_attack.py`) → **HOLD**

This is the experiment the abstract's evaluation plan explicitly calls out
as necessary and that a critical review of the draft flagged as the most
important missing test: an attack where **every literal is legitimate**, so
a naive allowlist (are these real accounts/actions we already know about?)
would wrongly admit it.

An attacker-controlled SIEM alert claims "impossible travel" for a real
admin account (`alice`) and asks the agent to disable it. `alice` is a
known admin — lineage is `TRUSTED`. But the real auth backend never
actually flagged impossible travel for that session, so the
`session_from_new_geo` claim has no `SYS` witness and is `NOT_CORROBORATED`.
WITNESS **HOLDs** the action for human review.

`tests/test_gate.py::test_admin_lockout_defeats_naive_allowlist` makes this
concrete: it runs a bare allowlist check (`naive_allowlist_verdict`) against
the same scenario and shows it returns `ADMIT` where WITNESS returns `HOLD`
— demonstrating that lineage checking alone is not the same protection as
the two-witness corroboration rule.

## Extending this toward the full evaluation plan

To move from this reference implementation to the abstract's Table 1
(attack success rate, benign utility, false-hold rate, SOC utility, latency
against four baselines), the remaining work is integration, not new gate
logic:

1. Replace hand-built `EvidenceStore` fixtures with a real-time adapter that
   labels live AIOpsLab/Prometheus/Kubernetes telemetry as `SYS`/`EXT`/`K`
   (mechanism 1 already supports this — it just needs a labeler in front of
   it, per log template).
2. Replace directly-constructed `Claim`/`RemediationAction` objects with a
   schema-constrained parse of the agent's actual RCA text (mechanism 3 is
   explicit that this parse is the *only* place an LLM is involved).
3. Wire `WitnessGate.evaluate` in as a pre-execution hook and run it against
   the released attack tool and the four baselines (no defense, Prompt
   Guard-2, Spotlighting, telemetry masking) to fill in Table 1.

None of that changes `witness_core/` — it is the same deterministic gate
either way, which is the point.
