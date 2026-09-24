"""WITNESS: a deterministic admission gate for autonomous remediation.

Principle: corroboration, not attribution. A proposed remediation is
admitted only if every load-bearing causal claim behind it is confirmed
by an independent, system-generated witness signal on a channel disjoint
from where the claim first appeared, and every concrete action argument
traces to a trusted source.
"""

from .provenance import Channel, TelemetryEvent, EvidenceStore
from .schema import Claim, RemediationAction, ProposedRemediation
from .lineage import Lineage, LineageResult, check_argument_lineage
from .corroboration import (
    WitnessCatalog,
    CorroborationStatus,
    CorroborationResult,
)
from .certificate import Verdict, EvidenceCertificate, CertificateChain
from .gate import WitnessGate, GateDecision
from .catalog import build_default_catalog
from .shell_parser import ClassifiedCommand, split_compound_command, classify_subcommand, parse_shell_command

__all__ = [
    "Channel",
    "TelemetryEvent",
    "EvidenceStore",
    "Claim",
    "RemediationAction",
    "ProposedRemediation",
    "Lineage",
    "LineageResult",
    "check_argument_lineage",
    "WitnessCatalog",
    "CorroborationStatus",
    "CorroborationResult",
    "Verdict",
    "EvidenceCertificate",
    "CertificateChain",
    "WitnessGate",
    "GateDecision",
    "build_default_catalog",
    "ClassifiedCommand",
    "split_compound_command",
    "classify_subcommand",
    "parse_shell_command",
]
