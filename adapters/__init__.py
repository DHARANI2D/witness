"""Real integration between witness_core and Microsoft's AIOpsLab.

This package is the "wire it up to real telemetry" layer: it consumes
AIOpsLab's actual data formats (its Prometheus metric CSV export, its
Elasticsearch pod-log schema, its raw exec_shell command strings) and
its actual action-execution classes (TaskActions, ResponseParser),
rather than a synthetic stand-in.

Modules:
    bootstrap          Imports the real AIOpsLab classes from a cloned
                        checkout, bypassing an unrelated heavy import
                        cascade (see bootstrap.py for why).
    telemetry           Parses AIOpsLab's real metric-CSV and pod-log
                        schemas into witness_core EvidenceStore events.
    trusted_knowledge   Loads the K-channel (approved repos/packages/
                        accounts) from an external config file.
    claim_extractor     Deterministic keyword/regex extraction of Claims
                        from an agent's free-text RCA reasoning.
    session             WitnessSession + install_witness_gate(): the
                        actual pre-execution hook wired onto the real
                        TaskActions.exec_shell.
"""
