"""WITNESS: a deterministic admission gate for autonomous remediation.

Principle: corroboration, not attribution. A proposed remediation is
admitted only if every load-bearing causal claim behind it is confirmed
by an independent, system-generated witness signal on a channel disjoint
from where the claim first appeared, every concrete action argument
traces to a trusted source, and at least one corroborated claim actually
licenses the specific action being taken (see licensing.py) -- a true,
well-sourced claim is not itself a reason to admit whatever action
happens to be attached to it.
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
from .licensing import LicenseCatalog, build_default_license_catalog
from .gate import WitnessGate, GateDecision
from .catalog import build_default_catalog
from .shell_parser import ClassifiedCommand, split_compound_command, classify_subcommand, parse_shell_command
from .attestation import sign_event, verify_event

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
    "LicenseCatalog",
    "build_default_license_catalog",
    "build_default_catalog",
    "ClassifiedCommand",
    "split_compound_command",
    "classify_subcommand",
    "parse_shell_command",
    "sign_event",
    "verify_event",
]
