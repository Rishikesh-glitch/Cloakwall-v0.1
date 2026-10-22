"""
cloakwall.guardrail — the LiteLLM adapter.

LiteLLM's OSS guardrail framework lets you register a CustomGuardrail without
an enterprise licence. This class implements the hooks that matter:

    async_pre_call_hook          runs before the request leaves. This is where
                                 redaction has to happen -- LiteLLM documents
                                 that pre_call is the mode to use when you
                                 modify content, because during_call runs in
                                 parallel with the LLM call and your edits may
                                 not land before the request goes out.
                                 Covers messages, the top-level system field,
                                 prompt (completions, image generation) and
                                 input (embeddings, Responses API).

    async_post_call_success_hook runs on a non-streamed response. Always
                                 audited; redacted too when redact_output is
                                 on, so PII the model generates is masked
                                 before the caller sees it.

    async_post_call_streaming_iterator_hook
                                 runs on a streamed response, chunk by chunk.
                                 With redact_output on, text and tool-call
                                 arguments go through a StreamRedactor so an
                                 entity split across chunks is still caught.
                                 (LiteLLM runs the success hook on streams
                                 only after delivery, too late to redact.)

Config (litellm config.yaml):

    guardrails:
      - guardrail_name: cloakwall
        litellm_params:
          guardrail: cloakwall.guardrail.Cloakwall
          mode: [pre_call, post_call]   # post_call only needed for redact_output
          redaction_mode: mask          # mask | hash | partial
          redact_output: true           # also mask PII in model responses
          audit_path: /var/log/cloakwall/audit.log
          fail_closed: true

Everything runs in-process. No sidecar, no external endpoint, no model
download -- which is the point: it works unchanged in an air-gapped cluster.
"""

from __future__ import annotations

import copy
import os
from typing import Any, AsyncGenerator, Optional, Union

from .audit import AuditLog, SIEMExporter
from .redact import Redaction, Redactor, StreamRedactor

try:
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ImportError:      # allows the core to be imported and tested standalone
    class CustomGuardrail:  # type: ignore
        def __init__(self, **kwargs): pass


# Request fields that carry text, across every endpoint the proxy forwards.
# Anything else in the request body (model, tools, temperature...) is config.
REQUEST_FIELDS = ("messages", "system", "prompt", "input")


class Cloakwall(CustomGuardrail):
    def __init__(self,
                 redaction_mode: str = "mask",
                 entities: Optional[list] = None,
                 audit_path: str = "./cloakwall-audit.log",
                 fail_closed: bool = True,
                 anchor_every: int = 100,
                 block_on: Optional[list] = None,
                 redact_output: bool = False,
                 stream_holdback: int = 64,
                 **kwargs):
        self.redactor = Redactor(
            mode=redaction_mode,
            entities=set(entities) if entities else None,
        )
        self.audit = AuditLog(audit_path)
        self.siem = SIEMExporter.from_env()
        # fail_closed decides what happens if redaction itself throws. In a
        # regulated deployment the safe answer is to reject the request rather
        # than forward text that may not have been scrubbed.
        self.fail_closed = fail_closed
        self.anchor_every = max(1, int(anchor_every))
        # Entities that must never reach the model at all. Redaction is the
        # default because it keeps the request useful, but some policies want
        # the call rejected outright -- a card number in a tool-call argument
        # is a bug upstream, and silently masking it hides the bug.
        self.block_on = set(block_on or [])
        # Off by default: masking output changes what callers receive, and an
        # app that asks the model to draft an email to a known address would
        # break. Turn it on where the model may echo or invent identifiers.
        self.redact_output = bool(redact_output)
        self.stream_holdback = int(stream_holdback)
        self.blocked = 0
        self.requests = 0
        self.redacted = 0
        self.responses_redacted = 0
        super().__init__(**kwargs)

    def _record(self, event: str, **fields) -> None:
        entry = self.audit.append(event, **fields)
        self.siem.send(entry)
        # Mirror the chain head to the SIEM on a cadence. The SIEM sits under
        # different access control from the log's filesystem, so an anchor
        # held there is what makes end-truncation detectable by someone who
        # can write to the pod. Every N entries rather than every entry, to
        # keep the export volume sane.
        if self.siem.enabled and entry["seq"] % self.anchor_every == 0:
            self.siem.send({
                "event": "cloakwall.anchor",
                "seq": entry["seq"],
                "hash": entry["hash"],
                "ts": entry["ts"],
                "host": entry["host"],
            })

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any,
                                  data: dict, call_type: Any
                                  ) -> Optional[Union[Exception, str, dict]]:
        self.requests += 1
        present = [f for f in REQUEST_FIELDS if data.get(f) is not None]
        if not present:
            return data

        try:
            cleaned, redactions = {}, []
            for f in present:
                if f == "messages" and isinstance(data[f], list):
                    cleaned[f], r = self.redactor.redact_messages(data[f])
                else:
                    cleaned[f], r = self.redactor.redact_value(data[f])
                redactions.extend(r)
        except Exception as exc:
            self._record("cloakwall.error", stage="pre_call", error=str(exc))
            if self.fail_closed:
                raise
            return data

        hits = {r.entity for r in redactions}
        blocked = hits & self.block_on
        if blocked:
            self.blocked += 1
            self._record("cloakwall.blocked",
                         model=data.get("model"),
                         key_alias=getattr(user_api_key_dict, "key_alias", None),
                         entities=_counts(redactions), blocked_on=sorted(blocked))
            raise ValueError(
                "Cloakwall blocked this request: "
                f"{', '.join(sorted(blocked))} present in prompt or tool-call arguments")

        if redactions:
            self.redacted += 1
            data.update(cleaned)
            # Note what was found, never what it was.
            self._record(
                "cloakwall.redacted",
                model=data.get("model"),
                key_alias=getattr(user_api_key_dict, "key_alias", None),
                team_id=getattr(user_api_key_dict, "team_id", None),
                entities=_counts(redactions),
                total=len(redactions),
                mode=self.redactor.mode,
            )
        return data

    async def async_post_call_success_hook(self, data: dict,
                                           user_api_key_dict: Any,
                                           response: Any) -> Any:
        # A streamed response was already redacted chunk by chunk; LiteLLM
        # hands this hook the assembled copy after delivery.
        if self.redact_output and not data.get("stream"):
            try:
                redactions = self._redact_response(response)
            except Exception as exc:
                self._record("cloakwall.error", stage="post_call", error=str(exc))
                if self.fail_closed:
                    raise
                redactions = []
            self._record_output(data, user_api_key_dict, redactions, stream=False)
        self._record(
            "cloakwall.response",
            model=data.get("model"),
            key_alias=getattr(user_api_key_dict, "key_alias", None),
            finish_reason=_finish_reason(response),
        )
        return response

    async def async_post_call_streaming_iterator_hook(
            self, user_api_key_dict: Any, response: Any, request_data: dict
    ) -> AsyncGenerator[Any, None]:
        if not self.redact_output:
            async for chunk in response:
                yield chunk
            return

        # One StreamRedactor per text stream: each choice's content, and each
        # tool call's arguments, arrive as separate interleaved fragments.
        streams: dict[tuple, StreamRedactor] = {}
        templates: dict[tuple, Any] = {}
        redactions: list[Redaction] = []

        def feed(key, chunk, text):
            sr = streams.get(key)
            if sr is None:
                sr = streams[key] = StreamRedactor(self.redactor, self.stream_holdback)
            templates[key] = chunk
            r = sr.feed(text)
            redactions.extend(r.redactions)
            return r.text

        def flush(choice_index=None):
            # Held-back text goes out in a chunk of its own, cloned from the
            # last chunk that carried that stream, before the finish chunk.
            out = []
            for key in list(streams):
                if choice_index is not None and key[1] != choice_index:
                    continue
                sr = streams.pop(key)
                template = templates.pop(key)
                if not sr.pending:
                    continue
                r = sr.flush()
                redactions.extend(r.redactions)
                out.append(_flush_chunk(template, key, r.text))
            return out

        try:
            async for chunk in response:
                finishing = []
                for ch in _get(chunk, "choices") or []:
                    idx = _get(ch, "index") or 0
                    delta = _get(ch, "delta")
                    if delta is not None:
                        text = _get(delta, "content")
                        if isinstance(text, str) and text:
                            _set(delta, "content", feed(("content", idx), chunk, text))
                        for tc in _get(delta, "tool_calls") or []:
                            fn = _get(tc, "function")
                            args = _get(fn, "arguments") if fn is not None else None
                            if isinstance(args, str) and args:
                                key = ("tool", idx, _get(tc, "index") or 0)
                                _set(fn, "arguments", feed(key, chunk, args))
                    if _get(ch, "finish_reason"):
                        finishing.append(idx)
                for idx in finishing:
                    for extra in flush(idx):
                        yield extra
                yield chunk
            for extra in flush():
                yield extra
        except Exception as exc:
            self._record("cloakwall.error", stage="stream", error=str(exc))
            raise
        finally:
            self._record_output(request_data, user_api_key_dict, redactions, stream=True)

    def _redact_response(self, response: Any) -> list[Redaction]:
        """Mask PII in a completed response, in place. Handles LiteLLM's
        ModelResponse objects and plain dicts: chat choices (content and
        tool-call arguments), text-completion choices, and Anthropic-style
        content blocks."""
        reds: list[Redaction] = []
        for ch in _get(response, "choices") or []:
            msg = _get(ch, "message")
            if msg is not None:
                reds += self._redact_field(msg, "content")
                for tc in _get(msg, "tool_calls") or []:
                    fn = _get(tc, "function")
                    if fn is not None:
                        reds += self._redact_field(fn, "arguments")
            reds += self._redact_field(ch, "text")
        content = _get(response, "content")
        if isinstance(content, list):
            for block in content:
                kind = _get(block, "type")
                if kind == "text":
                    reds += self._redact_field(block, "text")
                elif kind == "tool_use":
                    new, r = self.redactor.redact_value(
                        {"type": "tool_use", "input": _get(block, "input")})
                    if r:
                        _set(block, "input", new["input"])
                        reds += r
        return reds

    def _redact_field(self, obj: Any, key: str) -> list[Redaction]:
        value = _get(obj, key)
        if value is None:
            return []
        new, r = self.redactor.redact_value(value)
        if r:
            _set(obj, key, new)
        return r

    def _record_output(self, data: dict, user_api_key_dict: Any,
                       redactions: list[Redaction], stream: bool) -> None:
        if not redactions:
            return
        self.responses_redacted += 1
        self._record(
            "cloakwall.redacted_output",
            model=(data or {}).get("model"),
            key_alias=getattr(user_api_key_dict, "key_alias", None),
            team_id=getattr(user_api_key_dict, "team_id", None),
            entities=_counts(redactions),
            total=len(redactions),
            mode=self.redactor.mode,
            stream=stream,
        )

    def stats(self) -> dict:
        ok, msg = self.audit.verify()
        anchor = self.audit.read_anchor()
        return {
            "requests": self.requests,
            "requests_with_redactions": self.redacted,
            "requests_blocked": self.blocked,
            "responses_with_redactions": self.responses_redacted,
            "redact_output": self.redact_output,
            "block_on": sorted(self.block_on),
            "redaction_mode": self.redactor.mode,
            "entities_enabled": sorted(self.redactor.entities),
            "audit_chain": msg,
            "audit_intact": ok,
            "audit_entries": (anchor or {}).get("seq", 0),
            "anchor_every": self.anchor_every,
            "siem": self.siem.kind if self.siem.enabled else "disabled",
            "siem_failures": self.siem.failures,
        }


def _counts(redactions: list[Redaction]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in redactions:
        out[r.entity] = out.get(r.entity, 0) + 1
    return out


def _get(obj: Any, key: str) -> Any:
    """Field access that works on LiteLLM's response objects and on dicts."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _set(obj: Any, key: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[key] = value
    else:
        setattr(obj, key, value)


def _flush_chunk(template: Any, key: tuple, text: str) -> Any:
    """A copy of `template` carrying only the flushed text for one stream:
    a single choice, no finish_reason, and for tool calls only the arguments
    (id and name were already sent; repeating them makes clients that
    concatenate deltas double the function name)."""
    chunk = copy.deepcopy(template)
    choice_index = key[1]
    choices = [c for c in (_get(chunk, "choices") or [])
               if (_get(c, "index") or 0) == choice_index]
    _set(chunk, "choices", choices[:1])
    for ch in choices[:1]:
        _set(ch, "finish_reason", None)
        delta = _get(ch, "delta")
        if key[0] == "content":
            _set(delta, "content", text)
            _set(delta, "tool_calls", None)
        else:
            tool_index = key[2]
            calls = [tc for tc in (_get(delta, "tool_calls") or [])
                     if (_get(tc, "index") or 0) == tool_index]
            for tc in calls[:1]:
                _set(tc, "id", None)
                fn = _get(tc, "function")
                _set(fn, "name", None)
                _set(fn, "arguments", text)
            _set(delta, "tool_calls", calls[:1])
            _set(delta, "content", None)
    return chunk


def _finish_reason(response: Any) -> Optional[str]:
    try:
        return response.choices[0].finish_reason
    except Exception:
        return None
