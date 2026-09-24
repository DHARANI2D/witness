"""Deterministic extraction of closed-vocabulary Claims from an agent's
free-text root-cause reasoning.

AIOpsLab's own `ResponseParser.extract_context()` already separates an
agent's natural-language reasoning from the code block it submits (see
`aiopslab/orchestrator/parser.py` in the vendored checkout) -- that
reasoning is where a claim like "nginx doesn't support the current TLS
version" actually appears, before the agent ever issues the exec_shell
call that acts on it.

This module is the abstract's "LLM may act only as a schema-constrained
parser; every later step is deterministic" principle applied literally:
instead of a second model call to structure the RCA, a fixed table of
keyword/regex patterns maps free text onto the same closed predicate
vocabulary `witness_core.catalog` registers witness queries for. That
keeps the gate's behavior reproducible and independent of any model's
sampling -- the same RCA text always yields the same claims.

The extracted claim's source event is always labeled EXT: the agent's
own stated reasoning is not a system-generated signal (the agent can be
wrong, or manipulated), so it must never be trusted by default -- it is
exactly the thing the two-witness rule is there to check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from witness_core import Channel, Claim, EvidenceStore, TelemetryEvent


@dataclass(frozen=True)
class ClaimPattern:
    predicate: str
    pattern: re.Pattern


DEFAULT_PATTERNS: tuple[ClaimPattern, ...] = (
    ClaimPattern(
        "protocol_unsupported",
        re.compile(
            r"\b(ssl|tls)\b[^.]{0,60}\b(not support\w*|unsupported|incompatib\w*|outdated|too old)\b"
            r"|\b(not support\w*|unsupported|incompatib\w*|doesn'?t support|does not support)\b[^.]{0,60}\b(ssl|tls)\b",
            re.IGNORECASE,
        ),
    ),
    ClaimPattern(
        "error_rate_elevated",
        re.compile(r"\b(404|5\d\d|error rate|error count|failure rate)\b[^.]{0,60}\b(elevat\w*|spik\w*|high|increas\w*|surg\w*)\b", re.IGNORECASE),
    ),
    ClaimPattern(
        "cpu_saturated",
        re.compile(r"\bcpu\b[^.]{0,60}\b(satura\w*|\d{2,3}\s*%|high|spik\w*|throttl\w*|pegged|maxed)\b", re.IGNORECASE),
    ),
    ClaimPattern(
        "session_from_new_geo",
        re.compile(r"\b(impossible travel|new (geo|location|region)|anomalous login|geo.?velocity|logged in from \w+ then \w+)\b", re.IGNORECASE),
    ),
)


class RCAClaimExtractor:
    """Deterministic keyword/regex claim extractor over agent free text."""

    def __init__(self, patterns: tuple[ClaimPattern, ...] = DEFAULT_PATTERNS):
        self._patterns = patterns

    def extract(self, rca_text: str, store: EvidenceStore, subject: str = "target") -> tuple[Claim, ...]:
        """Extract claims from `rca_text`, registering it as one EXT
        telemetry event in `store` (idempotently) that all extracted
        claims cite as their source_event_id.
        """
        if not rca_text or not rca_text.strip():
            return ()

        source_event = self._ensure_source_event(rca_text, store)
        claims = []
        for pat in self._patterns:
            if pat.pattern.search(rca_text):
                claims.append(
                    Claim(
                        predicate=pat.predicate,
                        subject=subject,
                        value="true",
                        source_event_id=source_event.event_id,
                    )
                )
        return tuple(claims)

    @staticmethod
    def _ensure_source_event(rca_text: str, store: EvidenceStore) -> TelemetryEvent:
        event_id = f"agent-rca-{abs(hash(rca_text)) % (10 ** 12)}"
        existing = store.by_id(event_id)
        if existing is not None:
            return existing
        event = TelemetryEvent(
            event_id=event_id,
            channel=Channel.EXT,
            channel_id="agent_response:rca_text",
            field="rca_free_text",
            value=rca_text,
        )
        store.add(event)
        return event
