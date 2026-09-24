"""Closed schema for parsed remediations.

An LLM may act only as a schema-constrained parser that fills these
dataclasses from the agent's free-text root-cause analysis; every step
after this parse is deterministic and never re-invokes the model. This
prototype takes the parse as given (scenarios construct these objects
directly) so the gate logic under test does not depend on any
particular model's behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Claim:
    """One atomic, load-bearing causal claim extracted from the agent's RCA."""

    predicate: str
    subject: str
    value: str
    source_event_id: str  # the telemetry event the agent cited as evidence for this claim
    load_bearing: bool = True


@dataclass(frozen=True)
class RemediationAction:
    verb: str
    target: str
    arguments: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedRemediation:
    """The structured output of the LLM's schema-constrained parse."""

    incident_id: str
    claims: tuple
    action: RemediationAction
