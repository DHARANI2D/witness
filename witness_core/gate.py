"""The WITNESS admission gate: binds mechanisms 1-3 into ADMIT/HOLD/BLOCK.

Decision priority (most to least severe):
  BLOCK - any action argument is attacker-sourced (EXT-only lineage).
  HOLD  - any argument has unknown lineage, or any load-bearing claim
          is not corroborated.
  ADMIT - every load-bearing claim is corroborated and every argument
          is trusted.
"""

from __future__ import annotations

from dataclasses import dataclass

from .certificate import CertificateChain, EvidenceCertificate, Verdict
from .corroboration import CorroborationResult, CorroborationStatus, WitnessCatalog
from .lineage import Lineage, LineageResult, check_argument_lineage
from .provenance import EvidenceStore
from .schema import ProposedRemediation


@dataclass
class GateDecision:
    verdict: Verdict
    reasons: list
    certificate: EvidenceCertificate
    claim_results: list
    lineage_results: list


class WitnessGate:
    def __init__(self, catalog: WitnessCatalog, chain: CertificateChain | None = None):
        self._catalog = catalog
        self._chain = chain if chain is not None else CertificateChain()

    @property
    def chain(self) -> CertificateChain:
        return self._chain

    def evaluate(self, remediation: ProposedRemediation, store: EvidenceStore) -> GateDecision:
        claim_results: list[CorroborationResult] = [
            self._catalog.corroborate(c, store) for c in remediation.claims if c.load_bearing
        ]
        lineage_results: list[LineageResult] = [
            check_argument_lineage(str(v), store) for v in remediation.action.arguments.values()
        ]

        reasons: list[str] = []
        attacker_sourced = [r for r in lineage_results if r.lineage is Lineage.ATTACKER_SOURCED]
        unknown_args = [r for r in lineage_results if r.lineage is Lineage.UNKNOWN]
        uncorroborated = [r for r in claim_results if r.status is not CorroborationStatus.CORROBORATED]

        if attacker_sourced:
            verdict = Verdict.BLOCK
            for r in attacker_sourced:
                reasons.append(f"argument '{r.literal}' has EXT-only provenance (attacker-sourced)")
        elif unknown_args or uncorroborated:
            verdict = Verdict.HOLD
            for r in unknown_args:
                reasons.append(f"argument '{r.literal}' has no lineage in K/SYS/EXT (model-invented)")
            for r in uncorroborated:
                reasons.append(
                    f"claim {r.claim.predicate}({r.claim.subject}={r.claim.value}) is {r.status.value.lower()}"
                )
        else:
            verdict = Verdict.ADMIT
            reasons.append("all load-bearing claims corroborated; all arguments trusted")

        cert = self._chain.append(
            remediation.incident_id, verdict, claim_results, lineage_results, reasons
        )
        return GateDecision(verdict, reasons, cert, claim_results, lineage_results)
