"""
cloakwall.guardrail — the LiteLLM adapter.

LiteLLM's OSS guardrail framework lets you register a CustomGuardrail without
an enterprise licence. This class implements the two hooks that matter:

    async_pre_call_hook          runs before the request leaves. This is where
                                 redaction has to happen -- LiteLLM documents
                                 that pre_call is the mode to use when you
                                 modify content, because during_call runs in
                                 parallel with the LLM call and your edits may
                                 not land before the request goes out.

    async_post_call_success_hook runs on the response. Audit-only here: we
                                 record what came back, we do not rewrite it.

Config (litellm config.yaml):

    guardrails:
      - guardrail_name: cloakwall
        litellm_params:
          guardrail: cloakwall.guardrail.Cloakwall
          mode: pre_call
          redaction_mode: mask          # mask | hash | partial
          audit_path: /var/log/cloakwall/audit.log
          fail_closed: true

Everything runs in-process. No sidecar, no external endpoint, no model
download -- which is the point: it works unchanged in an air-gapped cluster.
"""

from __future__ import annotations

import os
from typing import Any, Optional, Union

from .audit import AuditLog, SIEMExporter
from .redact import Redactor

try:
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ImportError:      # allows the core to be imported and tested standalone
    class CustomGuardrail:  # type: ignore
        def __init__(self, **kwargs): pass


class Cloakwall(CustomGuardrail):
    def __init__(self,
                 redaction_mode: str = "mask",
                 entities: Optional[list] = None,
                 audit_path: str = "./cloakwall-audit.log",
                 fail_closed: bool = True,
                 anchor_every: int = 100,
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
        self.requests = 0
        self.redacted = 0
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
        messages = data.get("messages")
        if not isinstance(messages, list):
            return data

        try:
            cleaned, redactions = self.redactor.redact_messages(messages)
        except Exception as exc:
            self._record("cloakwall.error", stage="pre_call", error=str(exc))
            if self.fail_closed:
                raise
            return data

        if redactions:
            self.redacted += 1
            data["messages"] = cleaned
            counts: dict[str, int] = {}
            for r in redactions:
                counts[r.entity] = counts.get(r.entity, 0) + 1
            # Note what was found, never what it was.
            self._record(
                "cloakwall.redacted",
                model=data.get("model"),
                key_alias=getattr(user_api_key_dict, "key_alias", None),
                team_id=getattr(user_api_key_dict, "team_id", None),
                entities=counts,
                total=len(redactions),
                mode=self.redactor.mode,
            )
        return data

    async def async_post_call_success_hook(self, data: dict,
                                           user_api_key_dict: Any,
                                           response: Any) -> Any:
        self._record(
            "cloakwall.response",
            model=data.get("model"),
            key_alias=getattr(user_api_key_dict, "key_alias", None),
            finish_reason=_finish_reason(response),
        )
        return response

    def stats(self) -> dict:
        ok, msg = self.audit.verify()
        anchor = self.audit.read_anchor()
        return {
            "requests": self.requests,
            "requests_with_redactions": self.redacted,
            "redaction_mode": self.redactor.mode,
            "entities_enabled": sorted(self.redactor.entities),
            "audit_chain": msg,
            "audit_intact": ok,
            "audit_entries": (anchor or {}).get("seq", 0),
            "anchor_every": self.anchor_every,
            "siem": self.siem.kind if self.siem.enabled else "disabled",
            "siem_failures": self.siem.failures,
        }


def _finish_reason(response: Any) -> Optional[str]:
    try:
        return response.choices[0].finish_reason
    except Exception:
        return None
