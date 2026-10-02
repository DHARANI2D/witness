"""WITNESS as a standalone HTTP admission-control service.

Why this exists: `witness_core` is a library, used so far by importing
it directly into an agent process (`adapters/session.py`'s
`install_witness_gate`). An enterprise deployment with several agent
frameworks, or one that wants the admission gate to run as a separately
deployable, independently scaled, independently audited process (a
sidecar in front of an agent's action-execution step, called over the
network rather than in-process), needs a service boundary instead. This
module is that boundary: it changes nothing about the gate's logic --
every request still runs the real, unmodified `WitnessGate` -- it only
adds the HTTP request/response shape, structured audit logging, a
lightweight API-key check, and a `/healthz` a load balancer or
orchestrator can poll.

Run it:
    pip install -e '.[service]'
    uvicorn service.app:app --host 0.0.0.0 --port 8080

Or via Docker: see Dockerfile at the repo root.

Configuration is via environment variables (12-factor style, no config
file to accidentally ship with a secret baked in):

  WITNESS_SERVICE_API_KEY   If set, every request must carry a matching
                            `X-API-Key` header, checked with a
                            constant-time comparison. If unset, the
                            service runs with no request auth at all --
                            fine for local development, never for a
                            real deployment reachable from anywhere
                            else. A missing key is logged once at
                            startup as a loud warning, not silently
                            accepted.
  WITNESS_ATTESTATION_KEY   If set, enables SYS-channel attestation
                            (see witness_core/attestation.py) for every
                            request this process serves: a SYS witness
                            without a valid signature for this key is
                            rejected exactly like a witness that
                            doesn't exist. Unset by default, matching
                            witness_core's own opt-in default.
  WITNESS_K_CHANNEL_PATH    Path to the trusted-knowledge YAML (see
                            adapters/trusted_knowledge.py). Defaults to
                            adapters/trusted_knowledge.yaml. A real
                            deployment points this at a file synced
                            from its actual CMDB/IAM system of record.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import sys
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from witness_core import (
    Channel,
    Claim,
    EvidenceStore,
    ProposedRemediation,
    RemediationAction,
    TelemetryEvent,
    Verdict,
    WitnessGate,
    build_default_catalog,
)

logger = logging.getLogger("witness.service")
audit_logger = logging.getLogger("witness.audit")

# The audit trail is a distinct, structured (JSON-lines) log stream from
# the ordinary application/access logs -- an enterprise deployment ships
# this one to its SIEM, not just wherever stdout happens to go. Wired
# with its own handler and `propagate = False` deliberately: relying on
# root-logger configuration (which uvicorn does not set up for arbitrary
# loggers, and which defaults to WARNING with no handlers at all absent
# an explicit basicConfig() call) silently drops every audit record --
# a gap this project would rather close here than document as a known
# limitation, since silent audit-log loss is exactly the kind of thing
# an enterprise security review flags immediately.
if not audit_logger.handlers:
    _audit_handler = logging.StreamHandler(sys.stdout)
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(_audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False


def _audit(incident_id: str, verdict: str, certificate_hash: str, reasons: list[str], *, level: int = logging.INFO) -> None:
    audit_logger.log(
        level,
        json.dumps(
            {
                "incident_id": incident_id,
                "verdict": verdict,
                "certificate_hash": certificate_hash,
                "reasons": reasons,
                "timestamp": time.time(),
            },
            default=str,
        ),
    )


# ---------------------------------------------------------------------------
# Configuration (read once at import time; a real deployment sets these
# via its orchestrator's secret/config injection, not a checked-in file)
# ---------------------------------------------------------------------------

_API_KEY = os.environ.get("WITNESS_SERVICE_API_KEY")
_ATTESTATION_KEY_RAW = os.environ.get("WITNESS_ATTESTATION_KEY")
_ATTESTATION_KEY = _ATTESTATION_KEY_RAW.encode("utf-8") if _ATTESTATION_KEY_RAW else None
_K_CHANNEL_PATH = os.environ.get("WITNESS_K_CHANNEL_PATH")

if not _API_KEY:
    logger.warning(
        "WITNESS_SERVICE_API_KEY is not set -- this service is accepting requests with NO "
        "authentication. Fine for local development; never deploy this way. Set "
        "WITNESS_SERVICE_API_KEY before exposing this service to anything but localhost."
    )
if not _ATTESTATION_KEY:
    logger.info(
        "WITNESS_ATTESTATION_KEY is not set -- SYS-channel attestation is OFF. See "
        "witness_core/attestation.py; this is the same opt-in default the library has."
    )


def _load_k_events() -> list[TelemetryEvent]:
    try:
        from adapters.trusted_knowledge import load_trusted_knowledge

        return load_trusted_knowledge(_K_CHANNEL_PATH)
    except Exception:
        logger.exception(
            "failed to load the K (trusted-knowledge) channel; starting with an EMPTY K "
            "channel instead of crashing -- every request will simply see no K-trusted "
            "literals, which is the fail-safe direction (more HOLDs, never a silently "
            "wider trust surface)"
        )
        return []


_K_EVENTS: list[TelemetryEvent] = _load_k_events()
_GATE = WitnessGate(build_default_catalog(attestation_key=_ATTESTATION_KEY))

app = FastAPI(
    title="WITNESS admission gate",
    description="Deterministic admission control for autonomous AIOps/SOC remediation: corroboration, not attribution.",
    version="0.2.0",
)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if _API_KEY is None:
        return  # explicitly configured (by omission) to run unauthenticated
    if x_api_key is None or not hmac.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(status_code=401, detail="missing or invalid X-API-Key")


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class TelemetryEventIn(BaseModel):
    event_id: str
    channel: str = Field(description="One of SYS, EXT, K")
    channel_id: str
    field: str
    value: object
    observed_at: Optional[float] = None
    dependency_id: Optional[str] = None
    signature: Optional[str] = None

    def to_event(self) -> TelemetryEvent:
        try:
            channel = Channel[self.channel.strip().upper()]
        except KeyError:
            raise HTTPException(
                status_code=400,
                detail=f"evidence[].channel must be one of {[c.name for c in Channel]}, got {self.channel!r}",
            )
        kwargs = dict(
            event_id=self.event_id,
            channel=channel,
            channel_id=self.channel_id,
            field=self.field,
            value=self.value,
            dependency_id=self.dependency_id,
            signature=self.signature,
        )
        if self.observed_at is not None:
            kwargs["observed_at"] = self.observed_at
        return TelemetryEvent(**kwargs)


class ClaimIn(BaseModel):
    predicate: str
    subject: str
    value: str
    source_event_id: str
    load_bearing: bool = True

    def to_claim(self) -> Claim:
        return Claim(
            predicate=self.predicate,
            subject=self.subject,
            value=self.value,
            source_event_id=self.source_event_id,
            load_bearing=self.load_bearing,
        )


class ActionIn(BaseModel):
    verb: str
    target: str
    arguments: dict[str, object] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    incident_id: str
    evidence: list[TelemetryEventIn] = Field(default_factory=list)
    claims: list[ClaimIn] = Field(default_factory=list)
    action: ActionIn


class EvaluateResponse(BaseModel):
    verdict: str
    reasons: list[str]
    certificate: dict


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
    """Liveness/readiness probe. No auth required -- an orchestrator's
    health checker generally can't be handed a secret, and this leaks
    nothing sensitive (no evidence, no certificates, no key material)."""
    return {
        "status": "ok",
        "chain_length": len(_GATE.chain),
        "attestation_enabled": _ATTESTATION_KEY is not None,
        "k_channel_events": len(_K_EVENTS),
        "predicates": _GATE.catalog.predicates(),
    }


@app.get("/v1/catalog")
def catalog(_: None = Depends(require_api_key)) -> dict:
    """The closed predicate vocabulary this deployment enforces --
    useful for an integrator building the `claims` an agent's RCA maps
    to, without reading witness_core/catalog.py directly."""
    return {"predicates": _GATE.catalog.predicates()}


@app.post("/v1/evaluate", response_model=EvaluateResponse)
def evaluate(req: EvaluateRequest, _: None = Depends(require_api_key)) -> EvaluateResponse:
    """Evaluate one proposed remediation. This is the whole service: every
    other endpoint exists to support or audit this one call. The real,
    unmodified WitnessGate.evaluate() does the deciding; this function's
    only job is translating HTTP JSON into/out of witness_core's own
    types and logging the outcome."""
    events = [e.to_event() for e in req.evidence]
    store = EvidenceStore(list(_K_EVENTS) + events)
    remediation = ProposedRemediation(
        incident_id=req.incident_id,
        claims=tuple(c.to_claim() for c in req.claims),
        action=RemediationAction(verb=req.action.verb, target=req.action.target, arguments=req.action.arguments),
    )

    try:
        decision = _GATE.evaluate(remediation, store)
    except Exception:
        # Fail safe exactly like adapters/session.py's gated_exec_shell:
        # an internal error in the gate must never be indistinguishable
        # from "nothing to worry about" to a caller that only checks
        # HTTP status. Return 200 with an explicit synthetic BLOCK
        # rather than a 5xx a naive retry loop might paper over.
        logger.exception("WITNESS gate raised while evaluating incident_id=%r; failing safe to BLOCK", req.incident_id)
        reasons = ["an internal error occurred while evaluating this remediation; refused, not executed"]
        _audit(req.incident_id, Verdict.BLOCK.value, "", reasons, level=logging.ERROR)
        return EvaluateResponse(verdict=Verdict.BLOCK.value, reasons=reasons, certificate={})

    _audit(req.incident_id, decision.verdict.value, decision.certificate.certificate_hash, decision.reasons)
    return EvaluateResponse(
        verdict=decision.verdict.value,
        reasons=decision.reasons,
        certificate=decision.certificate.to_dict(),
    )


@app.get("/v1/certificates/{incident_id}")
def get_certificate(incident_id: str, _: None = Depends(require_api_key)) -> dict:
    """Look up the most recent certificate for `incident_id`. This is a
    linear scan of the in-process chain -- fine for a demo/prototype
    process lifetime; a real deployment persists the chain (its whole
    point is outliving any single process) and indexes by incident_id,
    e.g. in the same store backing the SOC ticketing integration.
    """
    matches = [c for c in _GATE.chain if c.incident_id == incident_id]
    if not matches:
        raise HTTPException(status_code=404, detail=f"no certificate found for incident_id={incident_id!r}")
    return matches[-1].to_dict()


@app.get("/v1/certificates")
def list_certificates(limit: int = 50, _: None = Depends(require_api_key)) -> dict:
    """The most recent `limit` certificates, newest first -- a minimal
    feed a decision-explorer UI (see scripts/generate_decision_explorer.py)
    or a SIEM poller can consume without needing chain internals."""
    all_certs = list(_GATE.chain)
    tail = all_certs[-limit:] if limit > 0 else all_certs
    return {"count": len(tail), "chain_length": len(all_certs), "certificates": [c.to_dict() for c in reversed(tail)]}
