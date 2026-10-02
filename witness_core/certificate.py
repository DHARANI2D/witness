"""Hash-chained evidence certificate emitted for every admission decision.

Each decision's certificate records the claims examined, their witness
results, the argument lineage results, and the verdict, chained to the
previous certificate's hash. A SOC analyst (or auditor) can answer
"why did WITNESS block this remediation?" from the certificate alone,
without interrogating the agent.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum

from .corroboration import CorroborationResult
from .lineage import LineageResult


class Verdict(Enum):
    ADMIT = "ADMIT"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


@dataclass
class EvidenceCertificate:
    incident_id: str
    verdict: Verdict
    claims: list
    lineage: list
    reasons: list
    prev_hash: str
    timestamp: float
    certificate_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.certificate_hash = hashlib.sha256(_canonical(self._payload()).encode()).hexdigest()

    def _payload(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "verdict": self.verdict.value,
            "claims": self.claims,
            "lineage": self.lineage,
            "reasons": self.reasons,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
        }

    def to_dict(self) -> dict:
        return {**self._payload(), "certificate_hash": self.certificate_hash}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str, indent=2)


class CertificateChain:
    """Append-only hash chain of evidence certificates, one per gate decision."""

    GENESIS = "0" * 64

    def __init__(self):
        self._chain: list[EvidenceCertificate] = []

    @property
    def last_hash(self) -> str:
        return self._chain[-1].certificate_hash if self._chain else self.GENESIS

    def append(
        self,
        incident_id: str,
        verdict: Verdict,
        claim_results: list[CorroborationResult],
        lineage_results: list[LineageResult],
        reasons: list[str],
    ) -> EvidenceCertificate:
        cert = EvidenceCertificate(
            incident_id=incident_id,
            verdict=verdict,
            claims=[
                {
                    "predicate": r.claim.predicate,
                    "subject": r.claim.subject,
                    "value": r.claim.value,
                    "status": r.status.value,
                    "confidence": round(r.confidence, 3),
                    "witness_channel_ids": [w.channel_id for w in r.witnesses],
                    "witness_channel_classes": sorted({w.channel_class for w in r.witnesses}),
                    "note": r.note,
                }
                for r in claim_results
            ],
            lineage=[
                {
                    "literal": r.literal,
                    "lineage": r.lineage.value,
                    "supporting_channel_ids": [e.channel_id for e in r.supporting_events],
                    "fuzzy": r.fuzzy,
                    "fuzzy_ratio": round(r.fuzzy_ratio, 3) if r.fuzzy_ratio is not None else None,
                }
                for r in lineage_results
            ],
            reasons=list(reasons),
            prev_hash=self.last_hash,
            timestamp=time.time(),
        )
        self._chain.append(cert)
        return cert

    def verify(self) -> bool:
        """Recompute each certificate's hash and check the prev_hash links."""
        prev = self.GENESIS
        for cert in self._chain:
            if cert.prev_hash != prev:
                return False
            recomputed = hashlib.sha256(_canonical(cert._payload()).encode()).hexdigest()
            if recomputed != cert.certificate_hash:
                return False
            prev = cert.certificate_hash
        return True

    def __iter__(self):
        return iter(self._chain)

    def __len__(self) -> int:
        return len(self._chain)
