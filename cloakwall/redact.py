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
    gate: tuple[str, ...] = ()      # skip this detector unless one of these
                                    # literals appears; a plain substring test
                                    # is far cheaper than a regex scan


# Order matters. Specific formats first so they claim their text before a
# looser pattern can chew into it.
DETECTORS: list[Detector] = [
    Detector("CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), _luhn, keep_tail=4),
    Detector("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), gate=("-",)),
    Detector("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    Detector("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"), gate=("@",)),
    Detector("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), gate=("AKIA", "ASIA")),
    # Provider API keys. The body allows - and _ because real keys contain
    # them (sk-proj-..., sk-ant-api03-...): stopping at the first dash would
    # redact the head of a key and leave the tail in the prompt. The
    # lookahead wants a digit or capital somewhere in the body, so
    # hyphenated lower-case words that merely start with "sk-" are left alone.
    Detector("API_KEY", re.compile(r"\b(?:sk|pk|rk)[-_](?=[A-Za-z0-9_-]*[0-9A-Z])[A-Za-z0-9_-]{16,}"),
             gate=("sk-", "sk_", "pk-", "pk_", "rk-", "rk_")),
    Detector("API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), gate=("AIza",)),        # Google / Gemini
    Detector("API_KEY", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
             gate=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),          # GitHub
    Detector("API_KEY", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), gate=("xox",)),  # Slack
    Detector("API_KEY", re.compile(r"\bgsk_[A-Za-z0-9]{20,}"), gate=("gsk_",)),        # Groq
    Detector("API_KEY", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), gate=("hf_",)),          # Hugging Face
    # A PEM private key: the whole block when it is all there. When the END
    # line has not arrived (a stream, a truncated paste), the header plus the
    # base64 lines that follow it, so the key body is never left behind.
    Detector("PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
        r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|(?:\r?\n[A-Za-z0-9+/=]{16,})*)"),
        gate=("-----BEGIN",)),
    # Credentials in a connection string: postgres://user:secret@host. The
    # user and password are replaced together; the host stays readable.
    Detector("PASSWORD", re.compile(r"(?<=://)[^\s:/@]+:[^\s@/]+(?=@)"), gate=("://",)),
    Detector("BEARER", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), gate=("ey",)),
    Detector("MRN", re.compile(r"\b(?:MRN|mrn)[:\s#]*([A-Z0-9]{6,12})\b"), gate=("MRN", "mrn")),
    Detector("NHS", re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b"), _nhs),
    # Handles +94 77 123 4567 and +1 (555) 867-5309 as well as bare US-style
    # numbers. Group sizes vary by country, so 2-4 digits per group.
    Detector("PHONE", re.compile(
        r"(?<![\d.])(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)|\d{2,4})[ -]\d{2,4}[ -]?\d{2,4}(?![\d.])"
        r"|(?<![\d.])\d{3}-\d{3}-\d{4}(?![\d.])"), keep_tail=4),
    Detector("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), gate=(".",)),
    Detector("DOB", re.compile(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b"), gate=("19", "20")),
]

DEFAULT_ENTITIES = {d.name for d in DETECTORS}

# Prefixes of key formats that may contain no digit at all.
_KEY_PREFIXES = ("sk-", "sk_", "pk-", "pk_", "rk-", "rk_", "AKIA", "ASIA", "eyJ",
                 "AIza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox",
                 "gsk_", "hf_", "-----BEGIN")


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
                 secret: bytes | None = None, extra: list[Detector] | None = None,
                 strict_cards: bool = False):
        if mode not in ("mask", "hash", "partial"):
            raise ValueError("mode must be mask, hash or partial")
        self.mode = mode
        self.entities = entities or set(DEFAULT_ENTITIES)
        self.strict_cards = strict_cards

        # The pseudonymisation secret never leaves the process. If none is
        # supplied we generate one per boot, which means tokens are stable
        # within a run but not across restarts -- safe default, since a
        # persistent secret is a key the operator should own deliberately.
        self.secret = secret or os.environ.get("CLOAKWALL_SECRET", "").encode() or os.urandom(32)
        self.detectors = [d for d in (list(DETECTORS) + (extra or []))
                          if d.name in self.entities]

        # Cheap global gate: prose that cannot contain any entity skips the
        # regex engine entirely. Most entities need a digit or an "@", but key
        # formats can be letters only (sk-..., AKIA..., a JWT's eyJ...), so
        # their prefixes open the gate too -- checked as plain substrings,
        # which is several times faster than adding them to the regex. Most
        # system prompts and most model output still land on the fast path.
        self._gate = re.compile(r"[\d@]")

    def _may_contain(self, text: str) -> bool:
        return bool(self._gate.search(text)) or any(p in text for p in _KEY_PREFIXES)

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

        if not self._may_contain(text):
            return Result(text=text, redactions=[])

        # Per-detector literal gate. A substring test runs at C speed and is
        # orders of magnitude cheaper than a regex scan, so a detector whose
        # required literal is absent never runs. On typical traffic this
        # skips most of them.
        spans: list[tuple[int, int, Detector, str]] = []
        for det in self.detectors:
            if det.gate and not any(g in text for g in det.gate):
                continue
            for m in det.pattern.finditer(text):
                value = m.group(0)
                if (det.validate and not (self.strict_cards and det.name == "CARD")
                        and not det.validate(value)):
                    continue      # e.g. a 16-digit order number failing Luhn
                spans.append((m.start(), m.end(), det, value))

        if not spans:
            return Result(text=text, redactions=[])

        # Earliest start wins; on a tie the longer match wins. This is what
        # keeps a card from being claimed by the phone pattern, and it is why
        # a detector failing its validator falls through to the next one --
        # the reason a single combined alternation could not be used here.
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
        """Redact an OpenAI-style messages array.

        Covers tool_call arguments as well as content. Those are a JSON string
        an agent assembled, frequently from the very record you are trying to
        protect -- a lookup_patient call carries the MRN in its arguments and
        never touches the content field at all. Redacting content alone leaks
        exactly the payloads agentic workloads generate most."""
        cleaned, all_r = self.redact_value(messages)
        return cleaned, all_r

    def redact_value(self, value):
        """Redact every text-bearing field of a request or response payload.

        One walker for every shape a LiteLLM proxy forwards, because each
        shape a redactor forgets is a field that leaks:

            OpenAI chat       messages[].content, tool_calls[].function.arguments
            Anthropic         top-level system, content blocks, tool_use.input,
                              tool_result.content
            Responses API     input (string or items), function_call.arguments,
                              function_call_output.output
            completions /     prompt, input (strings or lists of strings;
            images/embeddings token-id lists pass through)

        Only the keys in _TEXT_KEYS are descended into, so ids, roles, model
        names and image URLs are never rewritten. Returns new objects; the
        input is not mutated."""
        if isinstance(value, str):
            r = self.redact(value)
            return r.text, r.redactions
        if isinstance(value, list):
            out, reds = [], []
            for item in value:
                v, r = self.redact_value(item)
                out.append(v)
                reds.extend(r)
            return out, reds
        if isinstance(value, dict):
            if value.get("type") in _BINARY_PARTS:
                return value, []
            out, reds = dict(value), []
            for key, v in value.items():
                if key == "input" and value.get("type") == "tool_use":
                    # Anthropic tool_use input is a structured dict, not a
                    # JSON string: any string inside it may carry the record.
                    v, r = self._redact_leaves(v)
                elif key in _TEXT_KEYS:
                    v, r = self.redact_value(v)
                else:
                    continue
                out[key] = v
                reds.extend(r)
            return out, reds
        return value, []

    def _redact_leaves(self, value):
        """Redact every string anywhere inside value, whatever its key."""
        if isinstance(value, str):
            r = self.redact(value)
            return r.text, r.redactions
        if isinstance(value, list):
            out, reds = [], []
            for item in value:
                v, r = self._redact_leaves(item)
                out.append(v)
                reds.extend(r)
            return out, reds
        if isinstance(value, dict):
            out, reds = {}, []
            for k, item in value.items():
                v, r = self._redact_leaves(item)
                out[k] = v
                reds.extend(r)
            return out, reds
        return value, []


# Keys whose values can carry user or model text. Everything else (role, id,
# name, model, type, image_url...) is structure and is left alone.
_TEXT_KEYS = frozenset({
    "content", "text", "arguments", "output", "input", "prompt", "system",
    "tool_calls", "function", "function_call",
})

# Content parts that carry binary data or URLs, never prose.
_BINARY_PARTS = frozenset({
    "image_url", "image", "input_image", "input_audio", "file", "input_file",
    "document",
})


class StreamRedactor:
    """Redacts text that arrives in fragments, as a streamed response does.

    Redacting each chunk on its own leaks: "4111 1111" in one chunk and
    "1111 1111" in the next are both harmless, together they are a card. So
    the last `holdback` characters are held back until more text arrives,
    and text is only released at a whitespace boundary that no detected
    entity spans. Every detector matches less than `holdback` characters, so
    anything that starts in the released part is complete by the time it is
    released. flush() releases the rest when the stream ends.

    The cost is latency, not tokens: the client sees text `holdback`
    characters later than it would otherwise, and sees all of it."""

    def __init__(self, redactor: Redactor, holdback: int = 64,
                 max_pending: int = 4096):
        self.redactor = redactor
        self.holdback = holdback
        # A long run with no safe boundary (base64, minified JSON) must not
        # be held forever; past this size it is cut at the holdback line.
        self.max_pending = max(max_pending, holdback * 2)
        self._pending = ""

    def feed(self, fragment: str) -> Result:
        self._pending += fragment
        limit = len(self._pending) - self.holdback
        if limit <= 0:
            return Result(text="", redactions=[])
        cut = self._safe_cut(limit)
        if cut <= 0:
            return Result(text="", redactions=[])
        ready, self._pending = self._pending[:cut], self._pending[cut:]
        return self.redactor.redact(ready)

    def flush(self) -> Result:
        ready, self._pending = self._pending, ""
        return self.redactor.redact(ready)

    @property
    def pending(self) -> bool:
        return bool(self._pending)

    def _safe_cut(self, limit: int) -> int:
        p = self._pending
        spans = [(r.start, r.end) for r in self.redactor.redact(p).redactions]

        def inside(c: int) -> bool:
            return any(s < c < e for s, e in spans)

        for c in range(limit, 0, -1):
            # Cut just after whitespace, and never between two digit groups:
            # "+94 77 123 4567" and "4111 1111 1111 1111" contain spaces.
            if not p[c - 1].isspace():
                continue
            before = p[c - 2] if c >= 2 else ""
            if (before.isdigit() or before in "+(") and (p[c].isdigit() or p[c] in "+("):
                continue
            if not inside(c):
                return c
        if len(p) > self.max_pending and not inside(limit):
            return limit
        return 0
