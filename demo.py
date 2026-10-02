#!/usr/bin/env python3
"""Run all three WITNESS scenarios and print each admission decision plus
its evidence certificate. This is the practical, runnable centerpiece of
the abstract's worked example and evaluation plan: everything printed
here is produced by real code execution, not a hypothesis.

Usage:
    python3 demo.py
"""

from __future__ import annotations

from witness_core import WitnessGate, build_default_catalog
from scenarios import admin_lockout_attack, cpu_saturation_benign, mixed_truth_attack, nginx_attack

SCENARIOS = [
    ("1. Nginx reward-hacking attack (published, worked example)", nginx_attack),
    ("2. Genuine CPU-saturation incident (benign automation)", cpu_saturation_benign),
    ("3. 'Legitimate values' attack (defeats a naive allowlist)", admin_lockout_attack),
    ("4. 'Partial truth' attack (real claim, unrelated malicious action)", mixed_truth_attack),
]


def main() -> None:
    gate = WitnessGate(build_default_catalog())
    results = []

    for title, module in SCENARIOS:
        store, remediation, expected, description = module.build()
        decision = gate.evaluate(remediation, store)
        match = "OK " if decision.verdict is expected else "MISMATCH"

        print("=" * 78)
        print(title)
        print("-" * 78)
        print(description)
        print()
        print(f"Incident:      {remediation.incident_id}")
        print(f"Proposed fix:  {remediation.action.verb}({remediation.action.target}, "
              f"{dict(remediation.action.arguments)})")
        print()
        print("Claim corroboration:")
        for r in decision.claim_results:
            witness_ids = [w.channel_id for w in r.witnesses]
            print(f"  - {r.claim.predicate}({r.claim.subject}={r.claim.value!r}) "
                  f"-> {r.status.value}"
                  + (f"  [witness: {witness_ids}]" if witness_ids else ""))
        print("Argument lineage:")
        for r in decision.lineage_results:
            print(f"  - {r.literal!r} -> {r.lineage.value}")
        print()
        print(f"VERDICT: {decision.verdict.value}  (expected {expected.value}, {match})")
        print("Reasons:")
        for reason in decision.reasons:
            print(f"  - {reason}")
        print()
        print(f"Evidence certificate hash: {decision.certificate.certificate_hash}")
        results.append((title, decision.verdict, expected))

    print("=" * 78)
    print("Certificate chain integrity:", "VALID" if gate.chain.verify() else "BROKEN")
    print()

    admitted = sum(1 for _, v, _ in results if v.value == "ADMIT")
    held = sum(1 for _, v, _ in results if v.value == "HOLD")
    blocked = sum(1 for _, v, _ in results if v.value == "BLOCK")
    all_match = all(v is e for _, v, e in results)
    print(f"Summary: {len(results)} scenarios -> {admitted} ADMIT, {held} HOLD, {blocked} BLOCK")
    print(f"All verdicts matched expectations: {all_match}")


if __name__ == "__main__":
    main()
