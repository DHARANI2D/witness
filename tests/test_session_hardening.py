"""Fail-safe behavior of adapters/session.py's gated_exec_shell, tested
against minimal stub TaskActions/ResponseParser classes so this doesn't
require a real AIOpsLab checkout -- these tests exercise WITNESS's own
error handling, not AIOpsLab's.
"""

from __future__ import annotations

import re
import types

from adapters.session import install_witness_gate
from witness_core import WitnessCatalog, WitnessGate


class StubTaskActions:
    @staticmethod
    def exec_shell(command: str, timeout: int = 30) -> str:
        return f"ran: {command}"


class StubResponseParser:
    """Extracts the exec_shell("...") argument the same way the real
    AIOpsLab parser would, and treats everything before the code fence
    as the reasoning context -- just enough fidelity for these tests to
    exercise gated_exec_shell's own error handling, not AIOpsLab's."""

    def parse(self, response: str) -> dict:
        match = re.search(r'exec_shell\(\s*"([^"]*)"\s*\)', response)
        command = match.group(1) if match else ""
        context_text = response.split("```")[0].strip()
        return {
            "api_name": "exec_shell",
            "args": [command],
            "kwargs": {},
            "context": [context_text] if context_text else [],
        }


def _stub_ns():
    return types.SimpleNamespace(TaskActions=StubTaskActions, ResponseParser=StubResponseParser)


def _raising_gate():
    class ExplodingGate(WitnessGate):
        def evaluate(self, remediation, store):
            raise RuntimeError("simulated internal WITNESS bug")

    return ExplodingGate(WitnessCatalog())


def test_gate_internal_error_fails_safe_to_block_not_a_crash():
    ns = _stub_ns()
    installed = install_witness_gate(ns, gate=_raising_gate())
    parser = ns.ResponseParser()

    response = (
        "The disk is full on the target host.\n"
        "```\n"
        'exec_shell("docker restart some-service")\n'
        "```"
    )
    parsed = parser.parse(response)

    # Must not raise, even though the gate's own corroboration logic explodes.
    result = ns.TaskActions.exec_shell(*parsed["args"])
    assert "WITNESS BLOCK" in result
    assert "internal error" in result
    installed.uninstall()


def test_read_only_command_still_bypasses_even_with_a_broken_gate():
    ns = _stub_ns()
    installed = install_witness_gate(ns, gate=_raising_gate())
    parser = ns.ResponseParser()

    response = 'Checking status.\n```\nexec_shell("kubectl get pods")\n```'
    parsed = parser.parse(response)

    result = ns.TaskActions.exec_shell(*parsed["args"])
    assert result == "ran: kubectl get pods"
    assert len(installed.session.decisions) == 0
    installed.uninstall()


def test_non_string_command_returns_explanatory_refusal():
    ns = _stub_ns()
    installed = install_witness_gate(ns)

    # Call the patched exec_shell directly with a non-string argument,
    # simulating a caller that doesn't respect the expected type.
    result = ns.TaskActions.exec_shell(None)
    assert "WITNESS BLOCK" in result
    assert "string" in result
    installed.uninstall()
