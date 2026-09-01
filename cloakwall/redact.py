"""
cloakwall.redact — local PII/PHI detection and redaction.

No network calls, no model downloads, no sidecar containers. Pure stdlib, so
this runs unchanged in an air-gapped cluster and adds no attack surface a
security reviewer has to assess.

Three redaction modes, because compliance teams want different things:

    mask      "alice@corp.com"  ->  "<EMAIL>"
              Nothing recoverable. Use when the model has no business seeing
              the field at all.

    hash      "alice@corp.com"  ->  "<EMAIL:7f3a91c2>"
              Deterministic under a local secret, so the same person maps to
              the same token across requests. Lets you correlate a support
              conversation in your logs without storing the address.

    partial   "4111111111111111" ->  "<CARD:****1111>"
              Keeps the operationally useful tail. Common for cards and phone
              numbers where support staff need the last four.

Detectors are ordered: the more specific pattern must win, or a credit card
gets partly eaten by the phone-number rule.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Callable


def _luhn(digits: str) -> bool:
    """Card check digit. Without this, any 16-digit order number gets
    flagged and users lose trust in the redactor within a day."""
    n = [int(c) for c in digits if c.isdigit()]
    if len(n) < 13:
        return False
    total, parity = 0, len(n) % 2
    for i, d in enumerate(n):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _nhs(value: str) -> bool:
    """NHS numbers are 10 digits in a 3-3-4 grouping -- identical in shape to
    a US phone number. Without the modulus-11 check digit this detector
    swallows every phone number it sees and labels it a health identifier."""
    n = [int(c) for c in value if c.isdigit()]
    if len(n) != 10:
        return False
    total = sum(d * w for d, w in zip(n[:9], range(10, 1, -1)))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == n[9]


@dataclass(frozen=True)
class Detector:
    name: str                       # label used in the redaction token
    pattern: re.Pattern
    validate: Callable[[str], bool] | None = None
    keep_tail: int = 0              # digits/chars preserved in partial mode


# Order matters. Specific formats first so they claim their text before a
# looser pattern can chew into it.
DETECTORS: list[Detector] = [
    Detector("CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), _luhn, keep_tail=4),
    Detector("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    Detector("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    Detector("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("API_KEY", re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b")),
    Detector("BEARER", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    Detector("MRN", re.compile(r"\b(?:MRN|mrn)[:\s#]*([A-Z0-9]{6,12})\b")),
    Detector("NHS", re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b"), _nhs),
    # Handles +94 77 123 4567 and +1 (555) 867-5309 as well as bare US-style
    # numbers. Group sizes vary by country, so 2-4 digits per group.
    Detector("PHONE", re.compile(
        r"(?<![\d.])(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)|\d{2,4})[ -]\d{2,4}[ -]?\d{2,4}(?![\d.])"
        r"|(?<![\d.])\d{3}-\d{3}-\d{4}(?![\d.])"), keep_tail=4),
    Detector("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    Detector("DOB", re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b")),
]

DEFAULT_ENTITIES = {d.name for d in DETECTORS}


@dataclass
class Redaction:
    """One replacement made, for the audit record. Deliberately holds no
    original value -- an audit log that quotes the PII it redacted is worse
    than no audit log."""
    entity: str
    start: int
    end: int
    token: str


@dataclass
class Result:
    text: str
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.redactions:
            out[r.entity] = out.get(r.entity, 0) + 1
        return out


class Redactor:
    def __init__(self, mode: str = "mask", entities: set[str] | None = None,
                 secret: bytes | None = None, extra: list[Detector] | None = None):
        if mode not in ("mask", "hash", "partial"):
            raise ValueError("mode must be mask, hash or partial")
        self.mode = mode
        self.entities = entities or set(DEFAULT_ENTITIES)

        # The pseudonymisation secret never leaves the process. If none is
        # supplied we generate one per boot, which means tokens are stable
        # within a run but not across restarts -- safe default, since a
        # persistent secret is a key the operator should own deliberately.
        self.secret = secret or os.environ.get("CLOAKWALL_SECRET", "").encode() or os.urandom(32)
        self.detectors = [d for d in (list(DETECTORS) + (extra or []))
                          if d.name in self.entities]

    def _token(self, entity: str, value: str, keep_tail: int) -> str:
        if self.mode == "mask":
            return f"<{entity}>"
        if self.mode == "hash":
            h = hmac.new(self.secret, value.encode(), hashlib.sha256).hexdigest()[:8]
            return f"<{entity}:{h}>"
        if keep_tail:
            tail = "".join(c for c in value if c.isalnum())[-keep_tail:]
            return f"<{entity}:{'*' * 4}{tail}>"
        return f"<{entity}>"

    def redact(self, text: str) -> Result:
        if not text:
            return Result(text="", redactions=[])

        # Collect spans from every detector first, then resolve overlaps in
        # one pass. Replacing as we go would shift offsets under later
        # detectors and corrupt the audit record.
        spans: list[tuple[int, int, Detector, str]] = []
        for det in self.detectors:
            for m in det.pattern.finditer(text):
                value = m.group(0)
                if det.validate and not det.validate(value):
                    continue
                spans.append((m.start(), m.end(), det, value))

        # Earliest start wins; on a tie the longer match wins. This is what
        # keeps a 16-digit card from being claimed by the phone pattern.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))

        out: list[str] = []
        redactions: list[Redaction] = []
        cursor = 0
        for start, end, det, value in spans:
            if start < cursor:
                continue                      # overlapped by an earlier span
            token = self._token(det.name, value, det.keep_tail)
            out.append(text[cursor:start])
            out.append(token)
            redactions.append(Redaction(det.name, start, end, token))
            cursor = end
        out.append(text[cursor:])

        return Result(text="".join(out), redactions=redactions)

    def redact_messages(self, messages: list[dict]) -> tuple[list[dict], list[Redaction]]:
        """Redact an OpenAI-style messages array in place-safe fashion."""
        cleaned, all_r = [], []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                r = self.redact(content)
                msg = {**msg, "content": r.text}
                all_r.extend(r.redactions)
            elif isinstance(content, list):
                # multimodal: text parts only, image parts pass through
                parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        r = self.redact(part.get("text", ""))
                        parts.append({**part, "text": r.text})
                        all_r.extend(r.redactions)
                    else:
                        parts.append(part)
                msg = {**msg, "content": parts}
            cleaned.append(msg)
        return cleaned, all_r
