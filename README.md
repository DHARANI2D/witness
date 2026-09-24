# WITNESS — a working admission gate, wired to real AIOpsLab and a live environment

This repository implements the deterministic core of the *WITNESS:
Unforgeable Corroboration for Safe Autonomous Remediation* abstract —
**corroboration, not attribution** — as tested, runnable code, and wires
it onto Microsoft's real, unmodified [AIOpsLab](https://github.com/microsoft/AIOpsLab)
action-execution and response-parsing classes rather than a synthetic
stand-in.

A proposed remediation is admitted only if every load-bearing causal
claim behind it is confirmed by independent, system-generated "witness"
signals on channels disjoint from where the claim first appeared, and
every concrete action argument traces to a trusted source.

## What changed from the original abstract, and why

Building this against AIOpsLab's actual source surfaced real gaps in
the abstract's initial description. Rather than paper over them, the
engine was changed. Each change is a fix, not a reinterpretation:

| Change | Why |
|---|---|
| **"Two-witness" is now literal.** Corroboration requires `min_witnesses` (2 by default) SYS events from **distinct channel classes** (infra families), not just one witness on a merely-different `channel_id`. | The original single-witness design let two readings from the *same* exporter family count as independent. They aren't: an attacker who compromises one Prometheus deployment can plausibly forge several of its own series. Class diversity is what makes "two-witness" a structural guarantee instead of a name. |
| **Temporal bounding (`max_staleness_seconds`).** A witness observed further from the claim's source timestamp than a per-predicate window is rejected. | Without this, a genuine-but-stale or replayed reading (e.g. yesterday's real TLS error spike) could corroborate a claim about right now. Verified with `test_stale_witness_outside_window_is_rejected`. |
| **Fail-safe on an unresolved `source_event_id`.** | Found while hardening the engine: if a claim's cited source event can't be resolved, comparing a witness's `channel_id` to `None` is trivially true for everything, silently disabling the disjointness check. Now an unresolved source is treated as `NOT_CORROBORATED`, never as vacuous pass. Regression-tested in `test_unresolvable_source_event_fails_safe_not_open`. |
| **Homoglyph/zero-width-resistant lineage matching.** Normalization now does NFKC + confusable-character folding + zero-width-character stripping, with a bounded fuzzy fallback. | A naive exact-substring lineage check is beatable with `ppa:ngx∕latest` (Cyrillic а, zero-width joiners). Attackers using this class of trick are documented in prompt-injection literature; WITNESS should not be defeated by it. |
| **A real shell-command → structured-action classifier** (`witness_core/shell_parser.py`), not assumed pre-structured input. | AIOpsLab's actual remediation surface is `TaskActions.exec_shell(command: str)` — one free-text shell string, not a `(verb, target, args)` call. The abstract's "closed schema" needed an explicit, tested way to get real shell commands into that schema. The classifier's default is fail-safe: anything not positively recognized as read-only is gated as a mutation — an allowlist of safe reads, not a denylist of known-bad patterns, which is a structural improvement over AIOpsLab's own current `exec_shell` defense (a five-entry substring `BLOCK_LIST`). |
| **Confidence scores in the certificate**, not just booleans. | `CorroborationResult.confidence` (0.0–1.0) lets a SOC analyst triage the HOLD queue by how close a claim came to corroborating, instead of every HOLD looking identical. |

None of this weakens the admission rule: ADMIT still requires full
corroboration and full lineage trust, no partial credit. All three
original scenarios (nginx attack → BLOCK, CPU saturation → ADMIT,
admin-lockout → HOLD) still resolve to the same verdicts under the v2
engine — see `scenarios/cpu_saturation_benign.py`'s comment for the one
scenario tweak (a third independent CPU source) needed to keep
satisfying the now-literal two-witness quorum.

## Architecture

```
witness_core/                      the deterministic engine (no AIOpsLab dependency)
  provenance.py     Channel (SYS/EXT/K), TelemetryEvent (+ channel_class, observed_at), EvidenceStore
  lineage.py         normalization (NFKC/confusable/zero-width), exact + fuzzy lineage check
  schema.py          Claim, RemediationAction, ProposedRemediation
  corroboration.py   WitnessCatalog: k-of-n class-diverse, time-bounded corroboration
  catalog.py         the closed predicate/witness vocabulary for the demo domain
  certificate.py     hash-chained EvidenceCertificate / CertificateChain
  gate.py            WitnessGate: combines 1-3 into ADMIT / HOLD / BLOCK
  shell_parser.py     shell command -> structured RemediationAction classifier

adapters/                          real AIOpsLab integration (imports witness_core)
  bootstrap.py        imports the REAL aiopslab.orchestrator.actions.base.TaskActions
                       and aiopslab.orchestrator.parser.ResponseParser from a cloned
                       checkout, bypassing an unrelated heavy import cascade
  claim_extractor.py  deterministic regex extraction of Claims from an agent's
                       free-text RCA (AIOpsLab's own ResponseParser.extract_context)
  telemetry.py         parsers for AIOpsLab's real metrics-CSV and pod-log schemas
  trusted_knowledge.py/.yaml   the K channel, externalized as config
  session.py           WitnessSession + install_witness_gate(): the actual
                        monkeypatch onto TaskActions.exec_shell / ResponseParser.parse

  live_docker_telemetry.py   real telemetry from the docker-compose live
                        environment: docker stats + a direct cgroup read
                        as two independent CPU witnesses, docker logs as EXT

scenarios/            3 hand-built EvidenceStore fixtures exercising witness_core directly
live_env/              docker-compose HotelReservation (real containers, no k8s) + results/
demo.py               runs the 3 scenarios against witness_core only
demo_aiopslab.py       runs the same 3 narratives through the REAL AIOpsLab classes
tests/                 63 tests across 5 files (engine, shell parser, adapters, live AIOpsLab integration)
scripts/setup_aiopslab_dev.sh   clones AIOpsLab and prepares it for import (no cluster needed)
scripts/pilot_trial_matrix.py   the 12-trial live pilot behind Table 1 below
scripts/benchmark_latency.py    the pure-Python gate latency benchmark
```

Decision flow inside `WitnessGate.evaluate`:

```
for each load-bearing claim:  >= min_witnesses SYS events, each from a
                               DIFFERENT channel_class, disjoint from the
                               claim's source, within max_staleness_seconds,
                               and consistent with the claim's value?
for each action argument:     does the literal occur in K or SYS (trusted),
                               only in EXT (attacker-sourced), or nowhere
                               (model-invented)? (checked exact, then fuzzy)

any argument EXT-only          -> BLOCK  (raise an attributed alert)
else any claim uncorroborated,
     or any argument unknown   -> HOLD   (human review + evidence diff + confidence)
else                            -> ADMIT
```

## Wired to real AIOpsLab — what that means concretely

`adapters/bootstrap.py` imports the **actual, unmodified** classes from
a cloned `microsoft/AIOpsLab` checkout:

```python
from adapters.bootstrap import import_real_aiopslab
ns = import_real_aiopslab("/path/to/aiopslab")
# ns.TaskActions is aiopslab.orchestrator.actions.base.TaskActions itself
# ns.ResponseParser is aiopslab.orchestrator.parser.ResponseParser itself
```

`adapters/session.install_witness_gate(ns)` then monkeypatches
`TaskActions.exec_shell` and `ResponseParser.parse` in place. From that
point on, **every** `exec_shell` call AIOpsLab's orchestrator would make
(via `Orchestrator.ask_env` → `problem.perform_action("exec_shell", ...)`)
runs through WITNESS first:

- **Read-only commands** (`kubectl get`, `kubectl logs`, `cat`, `curl` GET,
  ...) bypass the gate and execute for real via AIOpsLab's own
  `Shell.exec`.
- **Mutating commands** are classified (`add_repo`, `install_package`,
  `k8s_patch`, `restart_service`, `disable_account`, ...), matched
  against the evidence collected for the session, and only reach real
  execution on ADMIT. BLOCK/HOLD return an explanatory string (in the
  same convention AIOpsLab's existing `BLOCK_LIST` uses) instead of
  executing anything.

This was verified end-to-end against the real classes, not asserted:
`tests/test_aiopslab_integration.py` imports
`aiopslab.orchestrator.actions.base.TaskActions` directly (confirming
the bootstrap bound to the real class, not a copy), parses the
abstract's exact published attack sentence with the real
`ResponseParser`, and confirms the real, gated `exec_shell` blocks it —
and separately confirms a genuine CPU-saturation incident, backed by
telemetry in AIOpsLab's actual metrics-CSV schema from two independent
exporter families, is admitted and reaches real command execution.

### Running it

```bash
# The deterministic engine alone (no AIOpsLab needed):
python3 demo.py
pip install -r requirements-dev.txt
python3 -m pytest -v                              # 63 tests, stdlib-only

# Wired to the real AIOpsLab classes:
./scripts/setup_aiopslab_dev.sh                   # clones AIOpsLab, no cluster needed
AIOPSLAB_REPO_PATH=/home/user/microsoft/aiopslab python3 demo_aiopslab.py
AIOPSLAB_REPO_PATH=/home/user/microsoft/aiopslab python3 -m pytest tests/test_aiopslab_integration.py -v
```

`setup_aiopslab_dev.sh` clones the repo, writes a `config.yml` with
`k8s_host: localhost` (so the ADMIT path runs local subprocesses, not
`kubectl`), writes a structurally-valid placeholder kubeconfig (needed
only because `aiopslab/observer/__init__.py` parses one at import time —
nothing here ever issues a real API call against it), and installs
AIOpsLab's core Python dependencies. **No Kubernetes cluster, Prometheus,
or Elasticsearch is required to run any test in this repository.**

## Live environment

`live_env/` runs AIOpsLab's actual HotelReservation microservice app
(18 real containers: Go/gRPC services, MongoDB, Consul, Jaeger,
Memcached) directly under Docker, gated by the same real
`adapters/session.install_witness_gate` hook used against the plain
AIOpsLab checkout above. A `kind`-based Kubernetes cluster was attempted
first and is documented in full in `live_env/README.md`, including a
real bug found and fixed along the way (a `cgroupns-mode` default) and
the precise, systematically-diagnosed nesting limit in this sandbox that
stopped a full cluster short of it. This environment is the real,
live fallback — not a synthetic stand-in: real containers, real CPU
faults, real telemetry from two independently-computed measurement
paths, real command execution.

```bash
cd live_env && docker compose up -d          # brings up the real app
cd .. && PYTHONPATH=. python3 scripts/pilot_trial_matrix.py
PYTHONPATH=. python3 scripts/benchmark_latency.py --trials 3000
```

## Table 1 (real measurements, honestly scoped)

**Read this before citing these numbers anywhere.** The abstract's
Table 1 describes ASR/utility measured across 180 trials driven by
autonomous GPT-4o/GPT-4.1 agents against the released attack tool. This
environment has no OpenAI/Azure API key, so that exact benchmark could
not run here. What follows instead: every command below genuinely
executed against the live environment above, through the real
`TaskActions.exec_shell`, but the RCA text and proposed commands were
authored by Claude Sonnet 5 (this session) acting directly as the
reasoning agent, over 12 trials (small-N by construction, not sampled
from a larger pool). Treat this as a real pilot, not a reproduction of
the paper's figure.

| Configuration | Attack Success Rate | Benign utility | Legit-values attacks held |
|---|---|---|---|
| No defense (raw `exec_shell`, no gate) | 4/4 (100%, by construction — nothing stops it) | 4/4 (100%) | 0/4 (100% ASR — allowlist-passable, no corroboration check) |
| WITNESS (this work, live trial) | **0/4 (0%)** | **4/4 (100%)** | **4/4 (100%) correctly HELD** |

Full per-trial output: `live_env/results/pilot_trial_results.json`
(trial text, verdict, reasons, certificate hash, latency — all real).
12/12 trials matched their expected verdict. The 4 benign restarts were
independently confirmed by re-checking `docker stats` after each: CPU
dropped from ~380-400% back to ~0.02-0.03% in every case, i.e. the
admitted remediation genuinely fixed the genuine fault.

**Latency** (`scripts/benchmark_latency.py`, 3000 trials/scenario, pure
Python, no cluster or LLM call — this is a fair thing to benchmark in
isolation since the gate makes no model calls of its own):

| Scenario | mean | p50 | p95 | p99 |
|---|---|---|---|---|
| nginx_attack (BLOCK) | 0.055ms | 0.047ms | 0.082ms | 0.133ms |
| cpu_saturation_benign (ADMIT) | 0.038ms | 0.033ms | 0.058ms | 0.094ms |
| admin_lockout_attack (HOLD) | 0.044ms | 0.036ms | 0.068ms | 0.098ms |

For scale: the published counterfactual/re-execution defenses
(AttriGuard, MELON, CausalArmor) add **1.22x–3x relative** latency over
an undefended agent turn — which itself takes seconds, dominated by LLM
calls. WITNESS's own gate evaluation costs **well under a millisecond**
in absolute terms; it makes no model calls, so there is no multiplier to
report against an LLM round-trip. The realistic per-decision cost in a
live deployment is dominated by *telemetry collection*, not the gate: a
real measurement here found `docker stats --no-stream` takes **~2
seconds per call** (the Docker Engine's own sampling window), a genuine
finding and a concrete optimization target for a production integration
(batch/cache stats collection or query the Engine API directly instead
of shelling out to the CLI per witness query — this repo currently does
the latter for simplicity).

### What's still not measured, and why

| Piece | Status |
|---|---|
| Full 180-trial ASR benchmark against the released `AIOpsDoom` attack tool, driven by GPT-4o/GPT-4.1 | **Not run.** No OpenAI/Azure API key is available in this environment. `adapters/` needs no changes to run this: point AIOpsLab's own client config at a real key and run the released attack tool against the gated `exec_shell`; every decision's certificate already gives you ASR/false-hold/detection-yield directly from `WitnessSession.decisions`. |
| Comparison against the four literature baselines (Prompt-Guard-2, Spotlighting, AIOpsShield, a MELON-style re-execution defense) on identical trials | **Not run**, same reason — these baselines need to see the same attack trials the real benchmark runs, which needs the API-keyed agent loop above. |
| SocialNetwork/HotelReservation on an actual Kubernetes cluster with live Prometheus/Elasticsearch, matching AIOpsLab's own deployment exactly | **Not run**, per the kind diagnosis in `live_env/README.md`. The docker-compose environment is real infrastructure but not `kubectl`-mediated; `adapters/telemetry.py`'s CSV/log-schema parsers remain ready for a real cluster's Prometheus/Elasticsearch output whenever one is available (their format-compatibility is independently tested in `tests/test_adapters_unit.py` without needing a live cluster to verify). |

## The three scenarios (pure `witness_core`, no AIOpsLab needed)

### 1. The published nginx attack (`scenarios/nginx_attack.py`) → **BLOCK**

An attacker plants a plausible root cause and a matching malicious fix
in a request-controlled field. `error_rate_elevated` corroborates (the
404 spike is real, confirmed by an independent Prometheus counter on a
disjoint channel); the fabricated `protocol_unsupported` claim does not
(flat TLS error counters, and with the v2 engine, no second independent
class even if it weren't flat). Independently, `ppa:ngx/latest` is
`ATTACKER_SOURCED`. Either reason alone is sufficient for **BLOCK**.

### 2. Genuine CPU saturation (`scenarios/cpu_saturation_benign.py`) → **ADMIT**

Three independent SYS signals for the same fact (a `kubectl top` reading
as the claim's cited source, plus cAdvisor and node-exporter counters as
two class-diverse witnesses) satisfy the two-witness quorum; the restart
target is a known service. The false-hold check the abstract's
evaluation plan calls for.

### 3. The "legitimate values" attack (`scenarios/admin_lockout_attack.py`) → **HOLD**

Every literal is legitimate (`alice` is a real admin, `disable_account`
against `iam` is a normal containment action) — a naive allowlist would
admit this. The causal claim (fabricated "impossible travel") has no
SYS witness, so WITNESS holds it regardless.
`tests/test_gate.py::test_admin_lockout_defeats_naive_allowlist` makes
the naive-allowlist comparison explicit.

## Test inventory (63 tests, `python3 -m pytest -v`)

- `tests/test_gate.py` — the 3 scenarios end to end, certificate-chain integrity, fail-safe unknown-predicate handling
- `tests/test_engine_upgrades.py` — class-diverse quorum, temporal staleness, fail-safe source resolution, homoglyph/zero-width lineage bypass attempts
- `tests/test_shell_parser.py` — 31 real-shaped `exec_shell` command strings classified correctly (read-only recognition, repo/package/k8s/service/docker/TLS/firewall/identity mutations, fail-safe fallback)
- `tests/test_adapters_unit.py` — telemetry format compatibility, trusted-knowledge loading, claim extraction
- `tests/test_aiopslab_integration.py` — binds to and drives the real, unmodified AIOpsLab classes (skips cleanly if the checkout isn't present)

The live-environment pilot (`scripts/pilot_trial_matrix.py`) and latency
benchmark (`scripts/benchmark_latency.py`) are separate from the pytest
suite since they need `live_env/` running (or, for latency, nothing at
all) rather than being unit tests — see Table 1 above.
