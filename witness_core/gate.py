"""The WITNESS admission gate: binds mechanisms 1-4 into ADMIT/HOLD/BLOCK.

Decision priority (most to least severe):
  BLOCK - any action argument is attacker-sourced (EXT-only lineage).
  HOLD  - any argument has unknown lineage, or no load-bearing claim was
          extracted at all, or any load-bearing claim is not
          corroborated, or (when licensing is enforced) no corroborated
          claim licenses the proposed action's verb.
  ADMIT - at least one load-bearing claim exists and all are
          corroborated, every argument is trusted, and (when licensing
          is enforced) a corroborated claim licenses the verb.

The "no load-bearing claim was extracted at all" case closes a real
gap found while hardening this engine: with zero claims, the original
admission rule's `all(...)`-style checks over an empty claim list were
vacuously true, so a remediation citing *no evidence whatsoever* (and
carrying no action arguments, or only already-trusted ones) could reach
ADMIT. `test_engine_upgrades.py::test_a_remediation_with_no_claims_at_all_never_admits`
and the property-based suite both regression-test this directly now.
"""

from __future__ import annotations

from dataclasses import dataclass

from .certificate import CertificateChain, EvidenceCertificate, Verdict
from .corroboration import CorroborationResult, CorroborationStatus, WitnessCatalog
from .licensing import LicenseCatalog, build_default_license_catalog
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
    def __init__(
        self,
        catalog: WitnessCatalog,
        chain: CertificateChain | None = None,
        license_catalog: LicenseCatalog | None = None,
        enforce_licensing: bool = True,
    ):
        self._catalog = catalog
        self._chain = chain if chain is not None else CertificateChain()
        # Opt-out, not opt-in: mechanism 4 is pure logic over data this
        # gate already has (no operational key management like
        # attestation needs), so it defaults ON. `enforce_licensing=False`
        # exists for the licensing-study ablation
        # (scripts/security_evaluation.py) that measures what mechanism 4
        # specifically buys over mechanisms 1-3 alone, not as a
        # recommended production configuration.
        self._license_catalog = license_catalog if license_catalog is not None else build_default_license_catalog()
        self._enforce_licensing = enforce_licensing

    @property
    def chain(self) -> CertificateChain:
        return self._chain

    @property
    def catalog(self) -> WitnessCatalog:
        return self._catalog

    @property
    def license_catalog(self) -> LicenseCatalog:
        return self._license_catalog

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
        corroborated = [r for r in claim_results if r.status is CorroborationStatus.CORROBORATED]
        no_claims_at_all = len(claim_results) == 0

        verb = remediation.action.verb
        licensed = any(self._license_catalog.licenses(verb, r.claim.predicate) for r in corroborated)
        licensing_failed = self._enforce_licensing and not no_claims_at_all and not uncorroborated and not licensed

        if attacker_sourced:
            verdict = Verdict.BLOCK
            for r in attacker_sourced:
                fuzzy_note = f" (fuzzy match, ratio={r.fuzzy_ratio:.2f})" if r.fuzzy else ""
                reasons.append(
                    f"argument '{r.literal}' has EXT-only provenance (attacker-sourced){fuzzy_note}"
                )
        elif unknown_args or no_claims_at_all or uncorroborated or licensing_failed:
            verdict = Verdict.HOLD
            for r in unknown_args:
                reasons.append(f"argument '{r.literal}' has no lineage in K/SYS/EXT (model-invented)")
            if no_claims_at_all:
                reasons.append(
                    f"no load-bearing claim was extracted to justify verb '{verb}'; "
                    f"a remediation citing no evidence is never admitted"
                )
            for r in uncorroborated:
                detail = f" ({r.note})" if r.note else ""
                reasons.append(
                    f"claim {r.claim.predicate}({r.claim.subject}={r.claim.value}) is "
                    f"{r.status.value.lower()}, confidence={r.confidence:.2f}{detail}"
                )
            if licensing_failed:
                if not self._license_catalog.has_contract(verb):
                    reasons.append(f"action verb '{verb}' has no registered license contract")
                else:
                    corroborated_predicates = sorted({r.claim.predicate for r in corroborated})
                    reasons.append(
                        f"verb '{verb}' is not licensed by any corroborated claim "
                        f"(corroborated predicates: {corroborated_predicates})"
                    )
        else:
            verdict = Verdict.ADMIT
            reasons.append("all load-bearing claims corroborated; a corroborated claim licenses the verb; all arguments trusted")

        cert = self._chain.append(
            remediation.incident_id, verdict, claim_results, lineage_results, reasons
        )
        return GateDecision(verdict, reasons, cert, claim_results, lineage_results)
