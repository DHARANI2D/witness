#!/usr/bin/env python3
"""Real latency benchmark for the WITNESS admission gate.

Unlike the ASR/utility numbers, this needs no LLM agent and no live
cluster: WitnessGate.evaluate() is pure, deterministic Python, so its
latency is measured directly and honestly, over real repeated calls,
against the same three scenarios used throughout this repo. Reported
alongside literature figures for the counterfactual/re-execution
baselines the abstract compares against (AttriGuard ~3x, MELON
2.21-2.31x, CausalArmor 1.22-1.38x undefended latency) so the relative
overhead claim can be checked, though those figures measure a different
undefended baseline and aren't directly comparable without also timing
AIOpsLab's own agent loop -- see README's Table 1 notes.

Usage:
    python3 scripts/benchmark_latency.py [--trials N]
"""

from __future__ import annotations

import argparse
import statistics
import time

from witness_core import WitnessGate, build_default_catalog
from scenarios import admin_lockout_attack, cpu_saturation_benign, mixed_truth_attack, nginx_attack


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * p
    f, c = int(k), min(int(k) + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def benchmark_scenario(name: str, module, trials: int) -> dict:
    store, remediation, _expected, _desc = module.build()
    gate = WitnessGate(build_default_catalog())

    # Warm up (import caches, regex compilation, etc.) before timing.
    for _ in range(5):
        gate.evaluate(remediation, store)

    samples_ms = []
    for _ in range(trials):
        start = time.perf_counter()
        gate.evaluate(remediation, store)
        samples_ms.append((time.perf_counter() - start) * 1000)

    samples_ms.sort()
    return {
        "name": name,
        "trials": trials,
        "mean_ms": statistics.mean(samples_ms),
        "p50_ms": percentile(samples_ms, 0.50),
        "p95_ms": percentile(samples_ms, 0.95),
        "p99_ms": percentile(samples_ms, 0.99),
        "min_ms": min(samples_ms),
        "max_ms": max(samples_ms),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=2000)
    args = parser.parse_args()

    print(f"WITNESS gate latency benchmark ({args.trials} trials/scenario, pure Python, no cluster/LLM)")
    print("=" * 78)

    results = []
    for name, module in [
        ("nginx_attack (BLOCK)", nginx_attack),
        ("cpu_saturation_benign (ADMIT)", cpu_saturation_benign),
        ("admin_lockout_attack (HOLD)", admin_lockout_attack),
        ("mixed_truth_attack (BLOCK)", mixed_truth_attack),
    ]:
        r = benchmark_scenario(name, module, args.trials)
        results.append(r)
        print(f"{r['name']:35s} mean={r['mean_ms']:.4f}ms  p50={r['p50_ms']:.4f}ms  "
              f"p95={r['p95_ms']:.4f}ms  p99={r['p99_ms']:.4f}ms  "
              f"min={r['min_ms']:.4f}ms  max={r['max_ms']:.4f}ms")

    overall_mean = statistics.mean(r["mean_ms"] for r in results)
    overall_p99 = max(r["p99_ms"] for r in results)
    print("=" * 78)
    print(f"Overall mean across scenarios: {overall_mean:.4f}ms")
    print(f"Worst-case p99 across scenarios: {overall_p99:.4f}ms")
    print()
    print("For scale: the published counterfactual/re-execution defenses add")
    print("1.22x-3x *relative* latency over an undefended agent turn (which itself")
    print("takes seconds, dominated by LLM calls). WITNESS's own gate evaluation")
    print(f"here costs {overall_mean:.2f}ms in absolute terms -- effectively free")
    print("next to any LLM round-trip, since it makes no model calls of its own.")

    import json
    import os
    out_path = os.path.join(os.path.dirname(__file__), "..", "live_env", "results", "latency_benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump({"trials_per_scenario": args.trials, "scenarios": results,
                    "overall_mean_ms": overall_mean, "overall_p99_ms": overall_p99}, f, indent=2)
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
