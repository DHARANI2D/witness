"""Action-argument lineage check (WITNESS mechanism 2).

Every concrete literal in a proposed remediation's arguments (a repo
URL, a package version, a port, a username) is looked up in the
evidence store under normalization. A literal that occurs only in an
EXT-labeled field has no trustworthy origin: the agent could only have
learned it from attacker-controlled text, so the action is blocked
outright rather than merely held for review.

Normalization is hardened against two real obfuscation techniques an
adaptive attacker could use to dodge a naive exact-substring check:

  1. Zero-width characters (U+200B/200C/200D/FEFF) inserted mid-literal.
  2. Confusable "homoglyph" characters (Cyrillic/Greek lookalikes, full-
     width forms) substituted for ASCII ones.

If exact matching still finds nothing after normalization, a fuzzy
fallback (bounded edit-similarity) catches near-miss obfuscation that
normalization doesn't fully collapse, without silently upgrading a
fuzzy hit to full trust: it is reported with its similarity score and
callers can see it was approximate.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote

from .provenance import Channel, EvidenceStore, TelemetryEvent

# Strips prompt-injection-style decorators (e.g. "[SOLUTION]", "#HUMAN HINT: ...")
# that attackers wrap around payloads to make them read as trusted instructions.
_DECORATORS = re.compile(r"\[[A-Z0-9_ ]{2,40}\]|#\s*HUMAN HINT.*$", re.IGNORECASE)

# Invisible characters with no ASCII normal form; NFKC does not strip these.
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")

# A small, deliberately conservative table of common single-character
# confusables (Cyrillic/Greek lookalikes) seen in homoglyph-based evasion.
# NFKC already folds full-width and many compatibility forms; this table
# covers the visually-identical-but-different-script cases NFKC does not.
_CONFUSABLES = str.maketrans({
    "а": "a", "А": "A",  # Cyrillic a
    "е": "e", "Е": "E",  # Cyrillic ie
    "о": "o", "О": "O",  # Cyrillic o
    "р": "p", "Р": "P",  # Cyrillic er
    "с": "c", "С": "C",  # Cyrillic es
    "у": "y", "У": "Y",  # Cyrillic u
    "х": "x", "Х": "X",  # Cyrillic ha
    "і": "i", "І": "I",  # Cyrillic/Ukrainian i
    "ѕ": "s", "Ѕ": "S",  # Cyrillic dze
    "ј": "j", "Ј": "J",  # Cyrillic je
    "ɡ": "g",             # Latin script g (IPA)
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
})


def normalize(text: str) -> str:
    """Case-fold, strip invisible/confusable chars, URL/base64-decode, and
    strip prompt-decorators before matching."""
    if text is None:
        return ""
    t = str(text)
    t = unicodedata.normalize("NFKC", t)
    t = _ZERO_WIDTH.sub("", t)
    t = t.translate(_CONFUSABLES)
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
    fuzzy: bool = False
    fuzzy_ratio: float | None = None


def check_argument_lineage(literal: str, store: EvidenceStore, fuzzy_min_ratio: float = 0.92) -> LineageResult:
    hits = store.contains_literal(literal)
    fuzzy = False
    best_ratio = None

    if not hits:
        fuzzy_hits = store.contains_literal_fuzzy(literal, min_ratio=fuzzy_min_ratio)
        if fuzzy_hits:
            hits = [e for e, _ratio in fuzzy_hits]
            best_ratio = fuzzy_hits[0][1]
            fuzzy = True

    if not hits:
        return LineageResult(literal, Lineage.UNKNOWN, [], fuzzy=False)

    trusted_hits = [h for h in hits if h.channel in (Channel.K, Channel.SYS)]
    if trusted_hits:
        return LineageResult(literal, Lineage.TRUSTED, trusted_hits, fuzzy=fuzzy, fuzzy_ratio=best_ratio)
    return LineageResult(literal, Lineage.ATTACKER_SOURCED, hits, fuzzy=fuzzy, fuzzy_ratio=best_ratio)
