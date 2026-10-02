"""Runnable scenarios exercising the WITNESS gate.

Each scenario module exposes a `build()` function returning
`(EvidenceStore, ProposedRemediation, expected_verdict, description)`
so both `demo.py` and the pytest suite can share the same fixtures.
"""
