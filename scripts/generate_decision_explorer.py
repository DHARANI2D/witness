#!/usr/bin/env python3
"""Render a certificate chain as a static, offline, searchable HTML
report -- the "decision explorer" a SOC analyst (or a paper reviewer)
can open to answer "why did WITNESS decide X" without re-running the
agent, reading its chain of thought, or asking anyone to add another
LLM to the security gate to explain itself. Every certificate rendered
here is the real, unedited output of EvidenceCertificate.to_dict();
this script only lays it out as HTML + a small amount of client-side
JavaScript for filtering -- no server, no network calls, no model in
the loop, matching the project's central thesis that the decision layer
stays deterministic even as everything around it gets richer.

Two ways to get certificates in:

  1. (default) Run a real, diverse set of WITNESS decisions locally --
     the 4 canonical scenarios plus a handful of representative attack/
     benign fixtures -- through one shared WitnessGate, so the report
     demonstrates a genuinely hash-chained sequence of real decisions.
  2. --input <path.json>: load a previously-exported list of certificate
     dicts, e.g. from the running service's GET /v1/certificates
     (see service/app.py), or any other real WitnessGate.chain export.
     Curl example:
       curl -H "X-API-Key: $KEY" http://localhost:8080/v1/certificates?limit=500 \
         | python3 -c "import json,sys; json.dump(json.load(sys.stdin)['certificates'], sys.stdout)" \
         > certs.json
       python3 scripts/generate_decision_explorer.py --input certs.json

Usage:
    PYTHONPATH=. python3 scripts/generate_decision_explorer.py
    PYTHONPATH=. python3 scripts/generate_decision_explorer.py --input certs.json --output report.html
"""

from __future__ import annotations

import argparse
import html
import json
import os
from datetime import datetime, timezone

from witness_core import (
    Channel,
    Claim,
    EvidenceStore,
    ProposedRemediation,
    RemediationAction,
    TelemetryEvent,
    WitnessGate,
    build_default_catalog,
)
from scenarios import admin_lockout_attack, cpu_saturation_benign, mixed_truth_attack, nginx_attack

DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "docs", "decision_explorer.html")

try:
    from adapters.trusted_knowledge import load_trusted_knowledge

    K_EVENTS = load_trusted_knowledge()
except Exception:  # pyyaml missing, or run outside the repo
    K_EVENTS = [
        TelemetryEvent("k-repo-0", Channel.K, "golden_config:approved_repositories", "approved_repository", "ppa:nginx/stable"),
    ]


# ---------------------------------------------------------------------------
# Demo dataset: the 4 canonical scenarios plus a handful of hand-picked
# fixtures illustrating mechanisms the scenarios alone don't cover
# (witness-dependency collision, staleness, attestation) -- all real
# WitnessGate.evaluate() calls against one shared gate/chain, so
# prev_hash linkage in the report is a genuine chain, not a per-trial
# fresh one (unlike scripts/security_evaluation.py, which deliberately
# uses a fresh gate per trial to isolate each verdict).
# ---------------------------------------------------------------------------

def _extra_fixtures():
    """A few additional real (store, remediation) pairs beyond the 4
    canonical scenarios, chosen to show mechanisms a decision explorer
    should let an analyst inspect: dependency-graph rejection and
    staleness rejection specifically (both easy to misread from a bare
    verdict without the certificate's `note` field)."""
    fixtures = []

    # Dependency-collision attack: two SYS witnesses, different channel
    # classes, but a shared dependency_id -- must not corroborate.
    src = TelemetryEvent("dc-src", Channel.EXT, "log:claim", "cpu_utilization_pct", "n/a")
    w1 = TelemetryEvent("dc-w1", Channel.SYS, "docker_stats:cpu_pct", "cpu_utilization_pct", 95,
                         dependency_id="cgroup_cpuacct_usage:demo-svc")
    w2 = TelemetryEvent("dc-w2", Channel.SYS, "cgroup_direct:cpu_pct", "cpu_utilization_pct", 96,
                         dependency_id="cgroup_cpuacct_usage:demo-svc")
    store = EvidenceStore([src, w1, w2])
    remediation = ProposedRemediation(
        incident_id="INC-DEMO-dependency-collision",
        claims=(Claim("cpu_saturated", "demo-svc", "true", source_event_id="dc-src"),),
        action=RemediationAction("restart_service", "docker", {"container": "demo-svc"}),
    )
    fixtures.append((store, remediation))

    # Staleness: a genuinely correct corroborating reading, just replayed
    # from well outside the predicate's staleness window.
    now = 1_800_000_000.0
    src = TelemetryEvent("st-src", Channel.EXT, "log:claim", "tls_handshake_errors_per_min", "n/a", observed_at=now)
    w1 = TelemetryEvent("st-w1", Channel.SYS, "prometheus:tls_pct", "tls_handshake_errors_per_min", 11,
                         observed_at=now - 86400, dependency_id="prom_scrape_stale")
    w2 = TelemetryEvent("st-w2", Channel.SYS, "elasticsearch:tls_pct", "tls_handshake_errors_per_min", 10,
                         observed_at=now - 86400, dependency_id="es_index_stale")
    store = EvidenceStore([src, w1, w2])
    remediation = ProposedRemediation(
        incident_id="INC-DEMO-stale-replay",
        claims=(Claim("protocol_unsupported", "demo-svc", "TLS1.0", source_event_id="st-src"),),
        action=RemediationAction("modify_tls_config", "nginx", {"config_value": "ssl_protocols TLSv1.2 TLSv1.3"}),
    )
    fixtures.append((store, remediation))

    # A second, distinct legitimate remediation (repo-add against a
    # K-approved repository) so the report isn't dominated by CPU cases.
    src = TelemetryEvent("ra-src", Channel.EXT, "access_log:404_rate", "http_404_rate_per_min", 40)
    w1 = TelemetryEvent("ra-w1", Channel.SYS, "prometheus:http_404_rate_per_min", "http_404_rate_per_min", 38)
    store = EvidenceStore(list(K_EVENTS) + [src, w1])
    remediation = ProposedRemediation(
        incident_id="INC-DEMO-legit-repo-add",
        claims=(Claim("error_rate_elevated", "demo-svc", "true", source_event_id="ra-src"),),
        action=RemediationAction("add_repo", "apt", {"repository": "ppa:nginx/stable"}),
    )
    fixtures.append((store, remediation))

    return fixtures


def generate_demo_chain() -> tuple[list[dict], bool]:
    gate = WitnessGate(build_default_catalog())

    for module in [nginx_attack, cpu_saturation_benign, admin_lockout_attack, mixed_truth_attack]:
        store, remediation, _expected, _description = module.build()
        gate.evaluate(remediation, store)

    for store, remediation in _extra_fixtures():
        gate.evaluate(remediation, store)

    certs = [c.to_dict() for c in gate.chain]
    return certs, gate.chain.verify()


def load_certificates(path: str) -> tuple[list[dict], bool]:
    with open(path, "r", encoding="utf-8") as f:
        certs = json.load(f)
    if not isinstance(certs, list):
        raise SystemExit(f"{path}: expected a JSON list of certificate dicts")
    # Structural chain check only (prev_hash linkage) -- a full
    # cryptographic re-verification of externally-supplied certificates
    # would need the same canonicalization certificate.py uses
    # internally; that's a private implementation detail this script
    # deliberately doesn't reach into, so this is honestly scoped as
    # "linkage looks intact," not "hashes cryptographically verified."
    chain_intact = True
    prev = "0" * 64
    for c in certs:
        if c.get("prev_hash") != prev:
            chain_intact = False
            break
        prev = c.get("certificate_hash", "")
    return certs, chain_intact


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WITNESS decision explorer</title>
<style>
  :root {{
    --bg: #f7f8fa; --panel: #ffffff; --text: #1a1d23; --muted: #5b6472;
    --border: #e2e5ea; --admit: #1a7f4b; --admit-bg: #e6f6ee;
    --hold: #a05a00; --hold-bg: #fdf1de; --block: #b3261e; --block-bg: #fdeaea;
    --accent: #2f5fda; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg: #14161a; --panel: #1c1f25; --text: #e7e9ee; --muted: #9aa3b2;
      --border: #2b2f38; --admit: #4ade9a; --admit-bg: #113526;
      --hold: #f2b155; --hold-bg: #3a2a10; --block: #ff8f87; --block-bg: #3a1414;
      --accent: #7ea2ff;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg: #14161a; --panel: #1c1f25; --text: #e7e9ee; --muted: #9aa3b2;
    --border: #2b2f38; --admit: #4ade9a; --admit-bg: #113526;
    --hold: #f2b155; --hold-bg: #3a2a10; --block: #ff8f87; --block-bg: #3a1414;
    --accent: #7ea2ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
  header {{ padding: 20px 20px 12px; border-bottom: 1px solid var(--border); background: var(--panel); }}
  header h1 {{ margin: 0 0 4px; font-size: 19px; }}
  header p {{ margin: 0; color: var(--muted); font-size: 13px; }}
  .stats {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }}
  .stat {{ border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; background: var(--bg); font-size: 13px; }}
  .stat b {{ font-size: 16px; display: block; }}
  .chain-ok {{ color: var(--admit); }} .chain-bad {{ color: var(--block); }}
  .controls {{ display: flex; gap: 8px; flex-wrap: wrap; padding: 14px 20px; background: var(--panel);
    border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 5; }}
  .controls input[type=search] {{ flex: 1; min-width: 200px; padding: 8px 10px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 14px; }}
  .chip {{ border: 1px solid var(--border); background: var(--bg); color: var(--text);
    border-radius: 999px; padding: 6px 12px; font-size: 13px; cursor: pointer; user-select: none; }}
  .chip[data-active="true"] {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
  main {{ padding: 16px 20px 60px; max-width: 980px; margin: 0 auto; }}
  .cert {{ border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; background: var(--panel);
    overflow: hidden; }}
  .cert summary {{ list-style: none; cursor: pointer; padding: 12px 14px; display: flex; align-items: center;
    gap: 10px; }}
  .cert summary::-webkit-details-marker {{ display: none; }}
  .badge {{ font-weight: 600; font-size: 12px; border-radius: 6px; padding: 3px 9px; white-space: nowrap; }}
  .badge.ADMIT {{ color: var(--admit); background: var(--admit-bg); }}
  .badge.HOLD {{ color: var(--hold); background: var(--hold-bg); }}
  .badge.BLOCK {{ color: var(--block); background: var(--block-bg); }}
  .cert summary .incident {{ font-family: var(--mono); font-size: 13px; flex: 1; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; }}
  .cert summary .ts {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .cert-body {{ padding: 0 14px 14px; border-top: 1px solid var(--border); }}
  .cert-body h4 {{ margin: 12px 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
    color: var(--muted); }}
  .reasons {{ margin: 0; padding-left: 18px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 500; }}
  code, .mono {{ font-family: var(--mono); font-size: 12px; }}
  .hash {{ color: var(--muted); }}
  .empty {{ text-align: center; color: var(--muted); padding: 40px 0; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }}
</style>
</head>
<body>
<header>
  <h1>WITNESS decision explorer</h1>
  <p>Every entry below is the real, unedited output of <code>EvidenceCertificate.to_dict()</code> -- static, offline, no model in the loop. Generated {generated_at}.</p>
  <div class="stats">
    <div class="stat"><b>{total}</b>decisions</div>
    <div class="stat"><b class="badge ADMIT">{admit}</b>ADMIT</div>
    <div class="stat"><b class="badge HOLD">{hold}</b>HOLD</div>
    <div class="stat"><b class="badge BLOCK">{block}</b>BLOCK</div>
    <div class="stat">Chain linkage: <b class="{chain_class}">{chain_label}</b></div>
  </div>
</header>
<div class="controls">
  <input type="search" id="search" placeholder="Search incident id, reason, literal, predicate...">
  <button class="chip" data-verdict="ADMIT">ADMIT</button>
  <button class="chip" data-verdict="HOLD">HOLD</button>
  <button class="chip" data-verdict="BLOCK">BLOCK</button>
</div>
<main id="main"></main>
<footer>witness_core -- corroboration, not attribution. Generated by scripts/generate_decision_explorer.py</footer>
<script>
const CERTS = {certs_json};

function esc(s) {{
  const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML;
}}

function renderCert(c) {{
  const claimsRows = (c.claims || []).map(r => `
    <tr>
      <td class="mono">${{esc(r.predicate)}}(${{esc(r.subject)}}=${{esc(r.value)}})</td>
      <td><span class="badge ${{r.status === 'CORROBORATED' ? 'ADMIT' : (r.status === 'NO_WITNESS_DEFINED' ? 'BLOCK' : 'HOLD')}}">${{esc(r.status)}}</span></td>
      <td>${{r.confidence}}</td>
      <td class="mono">${{(r.witness_channel_classes || []).join(', ') || '—'}}</td>
      <td>${{esc(r.note || '')}}</td>
    </tr>`).join('');
  const lineageRows = (c.lineage || []).map(r => `
    <tr>
      <td class="mono">${{esc(r.literal)}}</td>
      <td><span class="badge ${{r.lineage === 'TRUSTED' ? 'ADMIT' : (r.lineage === 'ATTACKER_SOURCED' ? 'BLOCK' : 'HOLD')}}">${{esc(r.lineage)}}</span></td>
      <td class="mono">${{(r.supporting_channel_ids || []).join(', ') || '—'}}</td>
      <td>${{r.fuzzy ? `fuzzy (ratio=${{r.fuzzy_ratio}})` : ''}}</td>
    </tr>`).join('');
  const reasons = (c.reasons || []).map(r => `<li>${{esc(r)}}</li>`).join('');

  return `
  <details class="cert" data-verdict="${{c.verdict}}"
    data-search="${{esc((c.incident_id + ' ' + (c.reasons||[]).join(' ') + ' ' +
      (c.claims||[]).map(x=>x.predicate).join(' ') + ' ' +
      (c.lineage||[]).map(x=>x.literal).join(' ')).toLowerCase())}}">
    <summary>
      <span class="badge ${{c.verdict}}">${{c.verdict}}</span>
      <span class="incident">${{esc(c.incident_id)}}</span>
      <span class="ts">${{new Date(c.timestamp * 1000).toISOString()}}</span>
    </summary>
    <div class="cert-body">
      <h4>Reasons</h4>
      <ul class="reasons">${{reasons || '<li>(none recorded)</li>'}}</ul>
      ${{claimsRows ? `<h4>Claim corroboration</h4><table><tr><th>Claim</th><th>Status</th><th>Confidence</th><th>Witness classes</th><th>Note</th></tr>${{claimsRows}}</table>` : ''}}
      ${{lineageRows ? `<h4>Argument lineage</h4><table><tr><th>Literal</th><th>Lineage</th><th>Supporting channels</th><th></th></tr>${{lineageRows}}</table>` : ''}}
      <h4>Certificate</h4>
      <table>
        <tr><th>Hash</th><td class="mono hash">${{esc(c.certificate_hash)}}</td></tr>
        <tr><th>Prev hash</th><td class="mono hash">${{esc(c.prev_hash)}}</td></tr>
      </table>
    </div>
  </details>`;
}}

const main = document.getElementById('main');
const search = document.getElementById('search');
const chips = Array.from(document.querySelectorAll('.chip'));
let activeVerdicts = new Set();

function draw() {{
  const q = search.value.trim().toLowerCase();
  const html = CERTS
    .filter(c => activeVerdicts.size === 0 || activeVerdicts.has(c.verdict))
    .filter(c => !q || (c.incident_id + ' ' + (c.reasons||[]).join(' ')).toLowerCase().includes(q)
      || (c.claims||[]).some(x => x.predicate.toLowerCase().includes(q))
      || (c.lineage||[]).some(x => String(x.literal).toLowerCase().includes(q)))
    .map(renderCert).join('');
  main.innerHTML = html || '<p class="empty">No decisions match this filter.</p>';
}}

search.addEventListener('input', draw);
chips.forEach(chip => chip.addEventListener('click', () => {{
  const v = chip.dataset.verdict;
  if (activeVerdicts.has(v)) {{ activeVerdicts.delete(v); chip.dataset.active = 'false'; }}
  else {{ activeVerdicts.add(v); chip.dataset.active = 'true'; }}
  draw();
}}));

draw();
</script>
</body>
</html>
"""


def render_html(certs: list[dict], chain_intact: bool) -> str:
    admit = sum(1 for c in certs if c["verdict"] == "ADMIT")
    hold = sum(1 for c in certs if c["verdict"] == "HOLD")
    block = sum(1 for c in certs if c["verdict"] == "BLOCK")
    return _PAGE_TEMPLATE.format(
        generated_at=html.escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
        total=len(certs),
        admit=admit,
        hold=hold,
        block=block,
        chain_class="chain-ok" if chain_intact else "chain-bad",
        chain_label="intact" if chain_intact else "BROKEN",
        certs_json=json.dumps(certs),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", help="JSON file with a list of certificate dicts (default: generate a real demo chain locally)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"output HTML path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()

    if args.input:
        certs, chain_intact = load_certificates(args.input)
        source = f"loaded from {args.input}"
    else:
        certs, chain_intact = generate_demo_chain()
        source = "generated locally from the 4 canonical scenarios + 3 mechanism-specific fixtures"

    out_path = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render_html(certs, chain_intact))

    print(f"{len(certs)} certificate(s) ({source})")
    print(f"chain linkage: {'intact' if chain_intact else 'BROKEN'}")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
