"""The live pre-execution hook: installs WITNESS onto the real AIOpsLab
`TaskActions.exec_shell` and `ResponseParser.parse`.

Why two hooks, not one: AIOpsLab's `Orchestrator.ask_env` parses the
agent's full response (free-text reasoning + code block) with
`ResponseParser.parse`, which already separates the two
(`extract_context` vs `extract_codeblock`) -- but only the parsed
*command* is threaded down into `TaskActions.exec_shell`; the reasoning
text is not passed along. To gate on the agent's actual stated causal
claims (not just the command it issues), WITNESS needs that reasoning
text at the moment `exec_shell` runs. Hooking `Orchestrator.ask_env`
directly would require importing the real `Orchestrator` class, which
pulls in AIOpsLab's evaluator cascade (see `bootstrap.py`'s docstring).
Hooking `ResponseParser.parse` instead gets the same information from a
class this package already imports cascade-free: every `parse()` call
captures the current reasoning text into a shared `WitnessSession`
*before* `exec_shell` is invoked in the same request/response cycle
(parse always runs first -- `ask_env` calls `self.parser.parse(input)`
and only then dispatches the parsed action), so by the time
`gated_exec_shell` runs, the session holds the freshest context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from witness_core import (
    EvidenceStore,
    GateDecision,
    ProposedRemediation,
    Verdict,
    WitnessGate,
    build_default_catalog,
)
from witness_core.shell_parser import parse_shell_command

from .claim_extractor import RCAClaimExtractor
from .trusted_knowledge import load_trusted_knowledge


@dataclass
class WitnessSession:
    """Mutable per-incident state shared between the parser hook (which
    captures the agent's free-text reasoning) and the exec_shell hook
    (which needs that reasoning to build claims against real telemetry)."""

    store: EvidenceStore = field(default_factory=EvidenceStore)
    current_rca_text: str = ""
    incident_id: str = "aiopslab-session"
    decisions: list[GateDecision] = field(default_factory=list)

    def reset_evidence(self, events=None) -> None:
        self.store = EvidenceStore(events or [])


@dataclass
class InstalledGate:
    session: WitnessSession
    gate: WitnessGate
    uninstall: Callable[[], None]


def _format_verdict_message(part_raw: str, decision: GateDecision) -> str:
    tag = {Verdict.BLOCK: "WITNESS BLOCK", Verdict.HOLD: "WITNESS HOLD"}[decision.verdict]
    action_word = "refused" if decision.verdict is Verdict.BLOCK else "not executed (insufficient independent corroboration)"
    return (
        f"[{tag}] Command {action_word}: {part_raw!r}. "
        f"Reasons: {'; '.join(decision.reasons)}. "
        f"certificate={decision.certificate.certificate_hash}"
    )


def install_witness_gate(
    aiopslab_ns,
    session: Optional[WitnessSession] = None,
    gate: Optional[WitnessGate] = None,
    claim_extractor: Optional[RCAClaimExtractor] = None,
    load_k_channel: bool = True,
) -> InstalledGate:
    """Monkeypatch the real `TaskActions.exec_shell` and `ResponseParser.parse`
    with WITNESS-gated versions. Returns an `InstalledGate` whose
    `uninstall()` restores the originals.
    """
    session = session or WitnessSession()
    gate = gate or WitnessGate(build_default_catalog())
    claim_extractor = claim_extractor or RCAClaimExtractor()

    if load_k_channel:
        for event in load_trusted_knowledge():
            if session.store.by_id(event.event_id) is None:
                session.store.add(event)

    TaskActions = aiopslab_ns.TaskActions
    ResponseParser = aiopslab_ns.ResponseParser

    original_exec_shell = TaskActions.exec_shell
    original_parse = ResponseParser.parse

    def captured_parse(self, response: str) -> dict:
        result = original_parse(self, response)
        context = result.get("context")
        if context:
            session.current_rca_text = "\n".join(context) if isinstance(context, list) else str(context)
        return result

    def gated_exec_shell(command: str, timeout: int = 30) -> str:
        classified = parse_shell_command(command)
        outputs = []

        for part in classified:
            if part.read_only:
                outputs.append(original_exec_shell(part.raw, timeout=timeout))
                continue

            claims = claim_extractor.extract(session.current_rca_text, session.store)
            remediation = ProposedRemediation(
                incident_id=session.incident_id,
                claims=claims,
                action=part.action,
            )
            decision = gate.evaluate(remediation, session.store)
            session.decisions.append(decision)

            if decision.verdict in (Verdict.BLOCK, Verdict.HOLD):
                outputs.append(_format_verdict_message(part.raw, decision))
            else:
                outputs.append(original_exec_shell(part.raw, timeout=timeout))

        return "\n".join(outputs)

    gated_exec_shell.is_action = True
    gated_exec_shell.__doc__ = original_exec_shell.__doc__
    captured_parse.__doc__ = original_parse.__doc__

    TaskActions.exec_shell = staticmethod(gated_exec_shell)
    ResponseParser.parse = captured_parse

    def uninstall() -> None:
        TaskActions.exec_shell = staticmethod(original_exec_shell)
        ResponseParser.parse = original_parse

    return InstalledGate(session=session, gate=gate, uninstall=uninstall)
