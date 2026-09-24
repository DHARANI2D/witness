"""Action-argument lineage check (WITNESS mechanism 2).

Every concrete literal in a proposed remediation's arguments (a repo
URL, a package version, a port, a username) is looked up in the
evidence store under normalization. A literal that occurs only in an
EXT-labeled field has no trustworthy origin: the agent could only have
learned it from attacker-controlled text, so the action is blocked
outright rather than merely held for review.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote

from .provenance import Channel, EvidenceStore, TelemetryEvent

# Strips prompt-injection-style decorators (e.g. "[SOLUTION]", "#HUMAN HINT: ...")
# that attackers wrap around payloads to make them read as trusted instructions.
_DECORATORS = re.compile(r"\[[A-Z0-9_ ]{2,40}\]|#\s*HUMAN HINT.*$", re.IGNORECASE)


def normalize(text: str) -> str:
    """Case-fold, URL-decode, base64-decode, and strip decorators before matching."""
    if text is None:
        return ""
    t = str(text)
    t = _DECORATORS.sub(" ", t)
    t = unquote(t)
    try:
        padded = t + "=" * (-len(t) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="strict")
        if decoded.isprintable() and len(decoded) > 3:
            t = f"{t} {decoded}"
    except Exception:
        pass
    return " ".join(t.split()).casefold()


class Lineage(Enum):
    TRUSTED = "TRUSTED"                     # literal occurs in K or SYS
    ATTACKER_SOURCED = "ATTACKER_SOURCED"   # literal occurs only in EXT fields
    UNKNOWN = "UNKNOWN"                     # literal occurs nowhere (model-invented)


@dataclass
class LineageResult:
    literal: str
    lineage: Lineage
    supporting_events: list[TelemetryEvent]


def check_argument_lineage(literal: str, store: EvidenceStore) -> LineageResult:
    hits = store.contains_literal(literal)
    if not hits:
        return LineageResult(literal, Lineage.UNKNOWN, [])
    trusted_hits = [h for h in hits if h.channel in (Channel.K, Channel.SYS)]
    if trusted_hits:
        return LineageResult(literal, Lineage.TRUSTED, trusted_hits)
    return LineageResult(literal, Lineage.ATTACKER_SOURCED, hits)
