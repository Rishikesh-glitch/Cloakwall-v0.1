"""
cloakwall.proxy — a standalone OpenAI-compatible redaction proxy.

Point any OpenAI-compatible client (an agent harness, an SDK, an app) at this
proxy instead of at the provider. Requests are redacted before they leave the
machine, forwarded to the upstream you configure, and every redaction goes
into the same tamper-evident audit log the LiteLLM guardrail uses.

    your app  ->  cloakwall serve (127.0.0.1)  ->  any OpenAI-compatible API

No LiteLLM, no third-party packages: standard library only, so there is
nothing in the request path for a supply-chain attack to replace.

Two optional output modes, mutually exclusive:

    redact_output   mask PII in model replies too. For callers that must
                    never see personal data.

    restore         the reverse: requests are redacted with per-value tokens
                    (<EMAIL:7f3a91c2>), and the original values are put back
                    into the reply before it reaches the caller. The model
                    never sees the data; the caller gets a normal answer, and
                    an agent can run a command with the real API key without
                    the key ever leaving the machine. The token -> value map
                    lives in memory for one request and is never logged.

Both work on streamed replies: text is held back briefly so an entity, or a
token, split across chunks is still caught whole.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from .audit import AuditLog, SIEMExporter
from .redact import Redaction, Redactor, StreamRedactor

# Request fields that carry text, across every endpoint the proxy forwards.
REQUEST_FIELDS = ("messages", "system", "prompt", "input")

# Response fields that carry model text. Everything else is structure.
OUTPUT_KEYS = frozenset({"content", "text", "arguments", "refusal"})

# Headers worth passing upstream. Anything else (cookies, hop-by-hop headers,
# the caller's host) stays here.
FORWARD_HEADERS = ("authorization", "openai-organization", "openai-project",
                   "anthropic-version", "http-referer", "x-title")

TOKEN = re.compile(r"<[A-Z_]+:[0-9a-f]{8,64}>")


# ------------------------------------------------------------------ #
# Restore: remember token -> value for one request, then swap back    #
# ------------------------------------------------------------------ #

class _Vault(Redactor):
    """A Redactor that issues a distinct token per value and remembers the
    value, in memory, for the lifetime of one request."""

    def __init__(self, base: Redactor):
        # Share the base redactor's configuration; skip its constructor so no
        # new secret is generated and tokens match across requests.
        self.mode = "hash"
        self.entities = base.entities
        self.secret = base.secret
        self.detectors = base.detectors
        self.strict_cards = base.strict_cards
        self._gate = base._gate
        self.values: dict[str, str] = {}

    def _token(self, entity: str, value: str, keep_tail: int) -> str:
        digest = hmac.new(self.secret, value.encode(), hashlib.sha256).hexdigest()
        # Lengthen the token on the (very unlikely) chance two values collide
        # on the short form within one request.
        for n in (8, 16, 64):
            token = f"<{entity}:{digest[:n]}>"
            if self.values.get(token, value) == value:
                self.values[token] = value
                return token
        return token


def restore_text(text: str, values: dict[str, str], json_escape: bool = False) -> tuple[str, int]:
    """Swap tokens back to their values. Inside tool-call arguments (a JSON
    string) the value is escaped so the arguments stay valid JSON."""
    count = 0

    def sub(m: re.Match) -> str:
        nonlocal count
        value = values.get(m.group(0))
        if value is None:
            return m.group(0)       # a token this request did not issue
        count += 1
        return json.dumps(value)[1:-1] if json_escape else value

    return TOKEN.sub(sub, text), count


class StreamRestorer:
    """Restores tokens in text that arrives in fragments. A token split
    across chunks ("<EMAIL:7f3a" + "91c2>") is held back until it closes."""

    MAX_TOKEN = 90

    def __init__(self, values: dict[str, str], json_escape: bool = False):
        self.values = values
        self.json_escape = json_escape
        self._pending = ""

    def feed(self, fragment: str) -> tuple[str, int]:
        self._pending += fragment
        i = self._pending.rfind("<")
        if i != -1 and ">" not in self._pending[i:] and len(self._pending) - i < self.MAX_TOKEN:
            ready, self._pending = self._pending[:i], self._pending[i:]
        else:
            ready, self._pending = self._pending, ""
        return restore_text(ready, self.values, self.json_escape)

    def flush(self) -> tuple[str, int]:
        ready, self._pending = self._pending, ""
        return restore_text(ready, self.values, self.json_escape)

    @property
    def pending(self) -> bool:
        return bool(self._pending)


# ------------------------------------------------------------------ #
# Output transforms: one interface over redaction and restore         #
# ------------------------------------------------------------------ #

class _Output:
    """What happens to model text on the way back: redact it, restore it, or
    leave it alone. Tallies what it did for the audit record."""

    def __init__(self, kind: str, redactor: Optional[Redactor] = None,
                 values: Optional[dict] = None, holdback: int = 64):
        self.kind = kind                    # "redact" | "restore"
        self.redactor = redactor
        self.values = values or {}
        self.holdback = holdback
        self.redactions: list[Redaction] = []
        self.restored = 0

    def text(self, value: str, key: str) -> str:
        if self.kind == "redact":
            r = self.redactor.redact(value)
            self.redactions.extend(r.redactions)
            return r.text
        out, n = restore_text(value, self.values, json_escape=(key == "arguments"))
        self.restored += n
        return out

    def stream(self, key: str) -> "_OutputStream":
        return _OutputStream(self, key)

    def walk(self, obj: Any, key: str = "") -> Any:
        """Apply to every string under an output key, anywhere in a reply."""
        if isinstance(obj, str):
            return self.text(obj, key) if key in OUTPUT_KEYS else obj
        if isinstance(obj, list):
            return [self.walk(v, key) for v in obj]
        if isinstance(obj, dict):
            return {k: self.walk(v, k) for k, v in obj.items()}
        return obj


class _OutputStream:
    def __init__(self, out: _Output, key: str):
        self.out = out
        if out.kind == "redact":
            self._s = StreamRedactor(out.redactor, out.holdback)
        else:
            self._s = StreamRestorer(out.values, json_escape=(key == "arguments"))

    def feed(self, fragment: str) -> str:
        return self._take(self._s.feed(fragment))

    def flush(self) -> str:
        return self._take(self._s.flush())

    @property
    def pending(self) -> bool:
        return self._s.pending

    def _take(self, result) -> str:
        if self.out.kind == "redact":
            self.out.redactions.extend(result.redactions)
            return result.text
        text, n = result
        self.out.restored += n
        return text


class _SSEProcessor:
    """Applies an _Output to an OpenAI chat-completions or completions SSE
    stream, chunk by chunk. Held-back text is released in a chunk of its own,
    cloned from the last chunk that carried that stream, before the chunk
    that finishes the choice."""

    def __init__(self, out: _Output):
        self.out = out
        self.streams: dict[tuple, _OutputStream] = {}
        self.templates: dict[tuple, dict] = {}

    def _feed(self, key: tuple, chunk: dict, text: str) -> str:
        s = self.streams.get(key)
        if s is None:
            field = "arguments" if key[0] == "tool" else "content"
            s = self.streams[key] = self.out.stream(field)
        self.templates[key] = chunk
        return s.feed(text)

    def process(self, chunk: dict) -> list[dict]:
        emit: list[dict] = []
        finishing = []
        for ch in chunk.get("choices") or []:
            idx = ch.get("index") or 0
            delta = ch.get("delta")
            if isinstance(delta, dict):
                if isinstance(delta.get("content"), str) and delta["content"]:
                    delta["content"] = self._feed(("content", idx), chunk, delta["content"])
                for tc in delta.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    if isinstance(fn.get("arguments"), str) and fn["arguments"]:
                        fn["arguments"] = self._feed(("tool", idx, tc.get("index") or 0),
                                                     chunk, fn["arguments"])
            if isinstance(ch.get("text"), str) and ch["text"]:      # legacy completions
                ch["text"] = self._feed(("text", idx), chunk, ch["text"])
            if ch.get("finish_reason"):
                finishing.append(idx)
        for idx in finishing:
            emit.extend(self.flush(idx))
        emit.append(chunk)
        return emit

    def flush(self, choice_index: Optional[int] = None) -> list[dict]:
        out = []
        for key in list(self.streams):
            if choice_index is not None and key[1] != choice_index:
                continue
            s = self.streams.pop(key)
            template = self.templates.pop(key)
            if not s.pending:
                continue
            text = s.flush()
            if text:
                out.append(_flush_chunk(template, key, text))
        return out


def _flush_chunk(template: dict, key: tuple, text: str) -> dict:
    chunk = copy.deepcopy(template)
    chunk["choices"] = [c for c in chunk.get("choices") or []
                        if (c.get("index") or 0) == key[1]][:1]
    for ch in chunk["choices"]:
        ch["finish_reason"] = None
        if key[0] == "text":
            ch["text"] = text
        elif key[0] == "content":
            ch["delta"] = {"content": text}
        else:
            # Only index + arguments: id and name were already sent, and
            # clients that concatenate deltas would otherwise repeat them.
            ch["delta"] = {"tool_calls": [{"index": key[2], "function": {"arguments": text}}]}
    return chunk


# ------------------------------------------------------------------ #
# The proxy                                                           #
# ------------------------------------------------------------------ #

class CloakwallProxy:
    """An OpenAI-compatible forwarding proxy that redacts and audits.

    upstream    base URL of the real API, including /v1, for example
                https://api.openai.com/v1. A request to /v1/chat/completions
                on the proxy goes to <upstream>/chat/completions.
    upstream_key  if set, sent as the bearer token upstream instead of the
                caller's Authorization header. Never logged.
    """

    def __init__(self, upstream: str, host: str = "127.0.0.1", port: int = 8787,
                 redaction_mode: str = "mask", entities: Optional[list] = None,
                 audit_path: str = "./cloakwall-audit.log",
                 block_on: Optional[list] = None, redact_output: bool = False,
                 restore: bool = False, upstream_key: Optional[str] = None,
                 timeout: float = 600.0, max_body: int = 10 * 1024 * 1024,
                 stream_holdback: int = 64, fail_closed: bool = True,
                 audit_hmac_key: bytes | None = None, strict_cards: bool = False,
                 anchor_every: int = 100):
        if redact_output and restore:
            raise ValueError("redact_output and restore are opposites: redact_output hides "
                             "PII from the caller, restore gives it back. Choose one.")
        parts = urlsplit(upstream)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"upstream must be an http(s) URL, got {upstream!r}")
        self.upstream = upstream.rstrip("/")
        self.upstream_key = upstream_key
        self.redactor = Redactor(mode=redaction_mode,
                                 entities=set(entities) if entities else None,
                                 strict_cards=strict_cards)
        self.block_on = set(block_on or [])
        self.redact_output = redact_output
        self.restore = restore
        self.timeout = timeout
        self.max_body = max_body
        self.stream_holdback = stream_holdback
        self.fail_closed = fail_closed
        self.audit = AuditLog(audit_path, hmac_key=audit_hmac_key)
        self.siem = SIEMExporter.from_env()
        self.anchor_every = max(1, int(anchor_every))
        self._lock = threading.Lock()
        self.counters = {"requests": 0, "requests_with_redactions": 0, "requests_blocked": 0,
                         "responses_with_redactions": 0, "responses_restored": 0,
                         "upstream_errors": 0}
        handler = type("Handler", (_Handler,), {"proxy": self})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True

    # -------------------------------------------------------------- utils
    @property
    def address(self) -> tuple[str, int]:
        return self.httpd.server_address[:2]

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}/v1"

    def count(self, name: str) -> None:
        with self._lock:
            self.counters[name] += 1

    def record(self, event: str, **fields) -> None:
        entry = self.audit.append(event, **fields)
        self.siem.send(entry)
        if self.siem.enabled and entry["seq"] % self.anchor_every == 0:
            self.siem.send({
                "event": "cloakwall.anchor",
                "seq": entry["seq"],
                "hash": entry["hash"],
                "ts": entry["ts"],
                "host": entry["host"],
            })

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def stats(self) -> dict:
        ok, msg = self.audit.verify()
        with self._lock:
            out = dict(self.counters)
        out.update({"upstream": self.upstream, "redaction_mode": self.redactor.mode,
                    "redact_output": self.redact_output, "restore": self.restore,
                    "block_on": sorted(self.block_on), "audit_intact": ok, "audit_chain": msg})
        return out


def _counts(redactions: list[Redaction]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in redactions:
        out[r.entity] = out.get(r.entity, 0) + 1
    return out


class _Handler(BaseHTTPRequestHandler):
    proxy: CloakwallProxy
    server_version = "cloakwall"

    def log_message(self, fmt: str, *args) -> None:
        pass    # request lines can carry query strings; the audit log is the record

    # -------------------------------------------------------------- replies
    def _send_json(self, status: int, obj: Any) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str, kind: str) -> None:
        self._send_json(status, {"error": {"message": message, "type": kind, "code": kind}})

    def _record(self, event: str, *, after_upstream: bool = False, **fields) -> bool:
        try:
            self.proxy.record(event, **fields)
            return True
        except OSError:
            message = ("audit write failed after upstream call; response not delivered"
                       if after_upstream else
                       "audit write failed; request not forwarded")
            self._error(503, message, "audit_unavailable")
            return False

    # -------------------------------------------------------------- upstream
    def _upstream_url(self) -> str:
        path = self.path
        if path.startswith("/v1/"):
            path = path[3:]
        elif path == "/v1":
            path = ""
        return self.proxy.upstream + path

    def _upstream_headers(self) -> dict:
        headers = {"Accept-Encoding": "identity", "User-Agent": "cloakwall-proxy"}
        for name in FORWARD_HEADERS:
            value = self.headers.get(name)
            if value:
                headers[name] = value
        if self.proxy.upstream_key:
            headers["authorization"] = f"Bearer {self.proxy.upstream_key}"
        return headers

    def _open_upstream(self, method: str, data: Optional[bytes]):
        headers = self._upstream_headers()
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self._upstream_url(), data=data, headers=headers,
                                     method=method)
        return urllib.request.urlopen(req, timeout=self.proxy.timeout)

    def _relay_error(self, exc: urllib.error.HTTPError) -> None:
        self.proxy.count("upstream_errors")
        if not self._record("cloakwall.response", after_upstream=True,
                            status=exc.code, stream=False):
            return
        body = exc.read()
        self.send_response(exc.code)
        self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -------------------------------------------------------------- GET
    def do_GET(self) -> None:
        if self.path == "/cloakwall/health":
            self._send_json(200, {"status": "ok", **self.proxy.stats()})
            return
        if not self._record("cloakwall.request", method="GET", path=self.path,
                            entities={}, total=0):
            return
        try:
            with self._open_upstream("GET", None) as resp:
                body = resp.read()
                if not self._record("cloakwall.response", after_upstream=True,
                                    status=resp.status, stream=False):
                    return
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as exc:
            self._relay_error(exc)
        except (urllib.error.URLError, OSError) as exc:
            self._error(502, f"upstream unreachable: {exc.__class__.__name__}", "upstream_error")

    # -------------------------------------------------------------- POST
    def do_POST(self) -> None:
        p = self.proxy
        p.count("requests")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > p.max_body:
            self._error(413, "request body too large", "request_too_large")
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("body must be a JSON object")
        except ValueError:
            self._error(400, "request body must be a JSON object", "invalid_request")
            return

        redactor = _Vault(p.redactor) if p.restore else p.redactor
        try:
            redactions: list[Redaction] = []
            for f in REQUEST_FIELDS:
                if data.get(f) is None:
                    continue
                if f == "messages" and isinstance(data[f], list):
                    data[f], r = redactor.redact_messages(data[f])
                else:
                    data[f], r = redactor.redact_value(data[f])
                redactions.extend(r)
        except Exception as exc:
            if not self._record("cloakwall.error", stage="request",
                                error=exc.__class__.__name__):
                return
            if p.fail_closed:
                self._error(500, "redaction failed; request not forwarded", "cloakwall_error")
                return
            redactions = []

        model = data.get("model")
        if not self._record("cloakwall.request", method="POST", model=model, path=self.path,
                            entities=_counts(redactions), total=len(redactions)):
            return
        blocked = {r.entity for r in redactions} & p.block_on
        if blocked:
            p.count("requests_blocked")
            if not self._record("cloakwall.blocked", model=model, path=self.path,
                                entities=_counts(redactions), blocked_on=sorted(blocked)):
                return
            self._error(400, "Cloakwall blocked this request: "
                             f"{', '.join(sorted(blocked))} present", "cloakwall_blocked")
            return
        if redactions:
            p.count("requests_with_redactions")
            if not self._record("cloakwall.redacted", model=model, path=self.path,
                                entities=_counts(redactions), total=len(redactions),
                                mode="restore" if p.restore else p.redactor.mode):
                return

        out = None
        if p.redact_output:
            out = _Output("redact", redactor=p.redactor, holdback=p.stream_holdback)
        elif p.restore and getattr(redactor, "values", None):
            out = _Output("restore", values=redactor.values)

        streaming = bool(data.get("stream"))
        if streaming and out is not None and not self.path.rstrip("/").endswith(
                ("/chat/completions", "/completions")):
            # Unknown stream format: refuse rather than pass unprocessed text.
            self._error(400, "streaming with redact_output or restore is supported for "
                             "chat/completions and completions only", "cloakwall_unsupported")
            return

        try:
            resp = self._open_upstream("POST", json.dumps(data).encode())
        except urllib.error.HTTPError as exc:
            self._relay_error(exc)
            return
        except (urllib.error.URLError, OSError) as exc:
            p.count("upstream_errors")
            self._error(502, f"upstream unreachable: {exc.__class__.__name__}", "upstream_error")
            return

        with resp:
            if streaming and "text/event-stream" in resp.headers.get("Content-Type", ""):
                self._stream(resp, out, model)
            else:
                self._complete(resp, out, model)

    # -------------------------------------------------------------- replies
    def _complete(self, resp, out: Optional[_Output], model) -> None:
        body = resp.read()
        if out is not None:
            try:
                body = json.dumps(out.walk(json.loads(body))).encode()
            except ValueError:
                pass        # not JSON: nothing we know how to process
            if not self._record_output(out, model, stream=False):
                return
        if not self._record("cloakwall.response", after_upstream=True,
                            model=model, status=resp.status, stream=False):
            return
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream(self, resp, out: Optional[_Output], model) -> None:
        if not self._record("cloakwall.response_started", after_upstream=True,
                            model=model, status=resp.status, stream=True):
            return
        self.send_response(resp.status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        proc = _SSEProcessor(out) if out is not None else None

        def write(chunk: dict) -> None:
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")

        try:
            for raw in resp:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if proc is None:
                    self.wfile.write(raw)
                    self.wfile.flush()
                    continue
                if not line:
                    continue
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        for c in proc.flush():
                            write(c)
                        self.wfile.write(b"data: [DONE]\n\n")
                    else:
                        try:
                            chunk = json.loads(payload)
                        except ValueError:
                            self.wfile.write(raw if raw.endswith(b"\n") else raw + b"\n")
                            continue
                        for c in proc.process(chunk) if isinstance(chunk, dict) else [chunk]:
                            write(c)
                else:
                    self.wfile.write(line.encode() + b"\n")
                self.wfile.flush()
            if proc is not None:
                for c in proc.flush():
                    write(c)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass        # the caller went away
        finally:
            if out is not None:
                self._record_output(out, model, stream=True)
            try:
                self.proxy.record("cloakwall.response", model=model,
                                  status=resp.status, stream=True)
            except OSError:
                print("cloakwall: audit write failed after streaming response",
                      file=sys.stderr)

    def _record_output(self, out: _Output, model, stream: bool) -> bool:
        p = self.proxy
        if out.kind == "redact" and out.redactions:
            p.count("responses_with_redactions")
            fields = {
                "model": model, "stream": stream,
                "entities": _counts(out.redactions), "total": len(out.redactions),
                "mode": p.redactor.mode,
            }
            if stream:
                try:
                    p.record("cloakwall.redacted_output", **fields)
                    return True
                except OSError:
                    print("cloakwall: audit write failed after streaming response",
                          file=sys.stderr)
                    return False
            return self._record("cloakwall.redacted_output", after_upstream=True,
                                **fields)
        elif out.kind == "restore" and out.restored:
            p.count("responses_restored")
            # How many tokens were put back -- never which values.
            if stream:
                try:
                    p.record("cloakwall.restored", model=model, stream=True,
                             total=out.restored)
                    return True
                except OSError:
                    print("cloakwall: audit write failed after streaming response",
                          file=sys.stderr)
                    return False
            return self._record("cloakwall.restored", after_upstream=True,
                                model=model, stream=stream, total=out.restored)
        return True
