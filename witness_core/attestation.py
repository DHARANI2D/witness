"""Cryptographic attestation for SYS-typed telemetry events.

Provenance labeling (mechanism 1) says a channel *claims* to be
system-generated; nothing before this module verified that claim
cryptographically -- a compromised or misconfigured collector could
mislabel an EXT-influenced reading as SYS, and the gate would trust it
exactly like a genuine one. This closes that specific, narrow gap with
a real, limited mechanism: HMAC-SHA256 over each event's fields, keyed
with a secret the collector holds and the gate verifies against.

**What this proves and what it doesn't.** A valid signature proves the
event was produced (or endorsed) by whoever holds `attestation_key`,
and that none of its fields were altered after signing -- genuine
tamper-evidence and origin authentication for events that carry a
signature. It does **not** prove the *collector itself* wasn't
compromised at the moment it read the telemetry (that needs a TEE
attestation or a signed hardware root of trust, out of scope here), and
it does not extend to events that were never signed -- attestation is
opt-in per catalog (see `WitnessCatalog.__init__`'s `attestation_key`),
so a deployment that hasn't wired real key management yet is unaffected
and behaves exactly as before. This is "provenance-corroborated," a
step toward "unforgeable," not the finished claim -- see README's
Roadmap for the remaining gap (attesting the collection process itself,
not just the reading it produced).

Design choices, and why:
  - **HMAC-SHA256, not asymmetric signatures.** A real deployment with
    many independent collector processes (Prometheus, cAdvisor,
    node-exporter, ...) would want per-collector asymmetric keys so a
    compromised collector can't forge another's signature; HMAC with a
    single shared secret is the right complexity for this prototype and
    upgrading to Ed25519 per collector is a drop-in replacement of
    `_mac()` below, not a design change.
  - **Signs the logical fields, not the dataclass repr.** Canonicalizing
    to a stable, explicit tuple (not `repr()` or `__dict__`) means
    field-order changes or added-later fields (like `dependency_id`)
    can't silently change what a signature covers without a deliberate
    update here.
  - **`hmac.compare_digest`, not `==`.** A signature comparison is a
    security boundary; a naive `==` on the hex digest is timing-attack
    fodder for no benefit.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace

from .provenance import TelemetryEvent


def _canonical_fields(event: TelemetryEvent) -> bytes:
    parts = [
        event.event_id,
        event.channel.value,
        event.channel_id,
        event.field,
        repr(event.value),
        repr(event.observed_at),
        event.dependency_id or "",
    ]
    return "\x1f".join(parts).encode("utf-8")


def _mac(event: TelemetryEvent, key: bytes) -> str:
    return hmac.new(key, _canonical_fields(event), hashlib.sha256).hexdigest()


def sign_event(event: TelemetryEvent, key: bytes) -> TelemetryEvent:
    """Return a copy of `event` with a valid `signature` for `key`.

    `TelemetryEvent` is frozen (immutable) by design -- signing produces
    a new instance rather than mutating the one a collector already
    handed to other code, so nothing downstream of the original
    reference is silently changed by a signing step it didn't ask for.
    """
    return replace(event, signature=_mac(event, key))


def verify_event(event: TelemetryEvent, key: bytes) -> bool:
    """True iff `event.signature` is present and matches `key`.

    Fails safe: a missing signature, a wrong key, or a tampered field
    (which changes what `_mac` recomputes) all return False, never
    raise -- callers (the corroboration engine) treat False exactly
    like "this witness doesn't count," the same fail-safe posture as
    every other rejection path in `corroboration.py`.
    """
    if not event.signature:
        return False
    expected = _mac(event, key)
    return hmac.compare_digest(expected, event.signature)
