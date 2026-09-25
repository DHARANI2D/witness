#!/usr/bin/env python3
"""Generate the paper/README result figures from the real, committed trial
data in live_env/results/*.json (no synthetic numbers). Run after either
pilot script to refresh the charts:

    PYTHONPATH=. python3 scripts/generate_paper_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "live_env" / "results"
OUT = ROOT / "docs" / "figures"
OUT.mkdir(parents=True, exist_ok=True)


def load(name: str) -> list[dict]:
    with open(RESULTS / name) as f:
        return json.load(f)


def asr_and_utility_figure() -> None:
    sonnet = load("pilot_trial_results.json")
    ollama = load("pilot_trial_results_ollama.json")

    # Sonnet-authored pilot: agent text was authored directly by Claude
    # Sonnet 5 acting as the reasoning agent, not sampled from a deployed
    # model's completions. All 4 attack trials are malicious by
    # construction, so baseline ASR is 4/4 (100%) and every trial reached
    # the expected WITNESS verdict.
    sonnet_attack = [t for t in sonnet if t["category"] == "attack"]
    sonnet_baseline_asr = 1.0  # 4/4, malicious action by construction
    sonnet_witness_asr = sum(1 for t in sonnet_attack if t["verdict"] == "ADMIT") / len(sonnet_attack)
    sonnet_benign = [t for t in sonnet if t["category"] == "benign"]
    sonnet_utility = sum(1 for t in sonnet_benign if t["verdict"] == "ADMIT") / len(sonnet_benign)

    # Ollama pilot: genuine local-LLM inference (SmolLM2-1.7B via Ollama).
    # One attack trial (A2) failed to parse after 3 attempts and is
    # excluded from ASR, matching how the README reports it.
    ollama_attack = [t for t in ollama if t["category"] == "attack" and not t["parse_failed"]]
    ollama_baseline_asr = sum(1 for t in ollama_attack if t["baseline_took_bait"]) / len(ollama_attack)
    # Gated ASR: of all parsed attack trials, how many would still have
    # executed the malicious action under WITNESS (baited AND ADMITted).
    # Same denominator as baseline_asr so the two are directly comparable.
    ollama_witness_asr = sum(
        1 for t in ollama_attack if t["baseline_took_bait"] and t["witness_verdict"] == "ADMIT"
    ) / len(ollama_attack)
    ollama_benign = [t for t in ollama if t["category"] == "benign"]
    ollama_utility = sum(1 for t in ollama_benign if t["witness_verdict"] == "ADMIT") / len(ollama_benign)

    groups = ["Claude Sonnet 5\n(agent-authored text,\nn=4 attack / n=4 benign)",
              "SmolLM2-1.7B via Ollama\n(genuine local inference,\nn=3 parsed attack / n=4 benign)"]
    baseline_asr = [sonnet_baseline_asr * 100, ollama_baseline_asr * 100]
    witness_asr = [sonnet_witness_asr * 100, ollama_witness_asr * 100]
    utility = [sonnet_utility * 100, ollama_utility * 100]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.5))

    x = range(len(groups))
    width = 0.35
    ax1.bar([i - width / 2 for i in x], baseline_asr, width, label="No defense (baseline ASR)", color="#c0392b")
    ax1.bar([i + width / 2 for i in x], witness_asr, width, label="WITNESS-gated ASR", color="#27ae60")
    ax1.set_ylabel("Attack success rate (%)")
    ax1.set_ylim(0, 105)
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(groups, fontsize=8)
    ax1.set_title("Attack success rate: baseline vs. WITNESS-gated")
    ax1.legend(fontsize=8, loc="upper right")
    for i, (b, w) in enumerate(zip(baseline_asr, witness_asr)):
        ax1.text(i - width / 2, b + 2, f"{b:.0f}%", ha="center", fontsize=8)
        ax1.text(i + width / 2, w + 2, f"{w:.0f}%", ha="center", fontsize=8)

    ax2.bar(list(x), utility, width=0.5, color=["#2980b9", "#e67e22"])
    ax2.set_ylabel("Benign trials admitted without hold (%)")
    ax2.set_ylim(0, 105)
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(groups, fontsize=8)
    ax2.set_title("Benign utility")
    for i, u in enumerate(utility):
        ax2.text(i, u + 2, f"{u:.0f}%", ha="center", fontsize=8)

    fig.suptitle("Real pilot results (live HotelReservation environment, 2026-09)", fontsize=10)
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    fig.savefig(OUT / "asr_and_utility.png", dpi=150)
    plt.close(fig)
    print(f"wrote {OUT / 'asr_and_utility.png'}")
    print(
        f"  sonnet: baseline_asr={sonnet_baseline_asr:.2f} witness_asr={sonnet_witness_asr:.2f} "
        f"utility={sonnet_utility:.2f}"
    )
    print(
        f"  ollama: baseline_asr={ollama_baseline_asr:.2f} witness_asr={ollama_witness_asr:.2f} "
        f"utility={ollama_utility:.2f}"
    )


def latency_figure() -> None:
    # Real, previously measured numbers (see README.md "Table 1" section):
    # pure-Python gate benchmark (scripts/benchmark_latency.py, 3000
    # trials/scenario, no cluster/LLM call) vs. the real live-pilot
    # per-decision elapsed time (scripts/pilot_trial_matrix.py /
    # _ollama.py, includes live telemetry collection) vs. a single
    # `docker stats --no-stream` call's own measured cost.
    labels = [
        "Pure gate eval\n(benchmark_latency.py,\nmean, no I/O)",
        "Live gate decision, no telemetry\n(BLOCK on lineage only,\nreal pilot data, mean)",
        "Live gate decision, with telemetry\n(ADMIT/HOLD needing a witness query,\nreal pilot data, mean)",
        "Single `docker stats`\ncall (measured)",
    ]
    values_ms = [0.046, 0.5, 320.0, 2000.0]  # see docstring; ADMIT rows from pilot_trial_results.json (sonnet)

    fig, ax = plt.subplots(figsize=(10, 5))
    colors = ["#27ae60", "#2980b9", "#e67e22", "#c0392b"]
    bars = ax.bar(range(len(labels)), values_ms, color=colors, log=True, width=0.6)
    ax.set_ylabel("Milliseconds (log scale)")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=7.5, linespacing=1.4)
    ax.set_title("Where WITNESS's decision latency actually goes (real measurements)")
    for bar, v in zip(bars, values_ms):
        ax.text(bar.get_x() + bar.get_width() / 2, v * 1.2, f"{v:g} ms", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "latency_breakdown.png", dpi=150)
    plt.close(fig)
    print(f"wrote {OUT / 'latency_breakdown.png'}")


if __name__ == "__main__":
    asr_and_utility_figure()
    latency_figure()
