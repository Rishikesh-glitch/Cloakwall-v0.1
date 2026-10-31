#!/usr/bin/env python3
"""
Cloakwall proxy tests.  python3 tests/test_proxy.py

Standard library only. Starts a fake OpenAI-compatible upstream that records
every request it receives, puts the proxy in front of it, and checks what
each side saw.
"""

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.audit import AuditLog
from cloakwall.cli import main as cli_main
from cloakwall.proxy import CloakwallProxy, StreamRestorer, restore_text

PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}\n          got  {got!r}\n          want {want!r}")


def section(t):
    print(f"\n{t}")


# ---------------------------------------------------------------- fake upstream
PII_REPLY = "Card on file is 4111 1111 1111 1111, email bob@clinic.org."


class Upstream(BaseHTTPRequestHandler):
    seen: list = []          # (path, headers, body) for every request

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Upstream.seen.append((self.path, dict(self.headers), None))
        self._json(200, {"object": "list", "data": [{"id": "fake-model", "object": "model"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Upstream.seen.append((self.path, dict(self.headers), body))
        model = body.get("model")
        if model == "fail":
            self._json(429, {"error": {"message": "rate limited", "type": "rate_limit"}})
            return
        if self.path.endswith("/embeddings"):
            self._json(200, {"object": "list", "data": [{"embedding": [0.1, 0.2], "index": 0}]})
            return
        last = (body.get("messages") or [{}])[-1].get("content") or body.get("prompt") or ""
        reply = last if model == "echo" else PII_REPLY
        tool_args = json.dumps({"email": last}) if model == "tool" else None

        if self.path.endswith("/completions") and not self.path.endswith("/chat/completions"):
            if body.get("stream"):
                return self._sse([{"choices": [{"index": 0, "text": reply[i:i + 3],
                                                "finish_reason": None}]}
                                  for i in range(0, len(reply), 3)]
                                 + [{"choices": [{"index": 0, "text": "", "finish_reason": "stop"}]}])
            return self._json(200, {"choices": [{"index": 0, "text": reply, "finish_reason": "stop"}]})

        if body.get("stream"):
            chunks = [{"id": "c", "object": "chat.completion.chunk",
                       "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}]
            if tool_args:
                chunks.append({"choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "id": "call_1", "type": "function",
                     "function": {"name": "send", "arguments": ""}}]}}]})
                chunks += [{"choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "function": {"arguments": tool_args[i:i + 3]}}]}}]}
                    for i in range(0, len(tool_args), 3)]
                chunks.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
            else:
                chunks += [{"choices": [{"index": 0, "delta": {"content": reply[i:i + 3]}}]}
                           for i in range(0, len(reply), 3)]
                chunks.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            return self._sse(chunks)

        message = {"role": "assistant", "content": reply}
        if tool_args:
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "send", "arguments": tool_args}}]}
        self._json(200, {"id": "c", "object": "chat.completion",
                         "choices": [{"index": 0, "message": message, "finish_reason": "stop"}]})

    def _sse(self, chunks):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for c in chunks:
            self.wfile.write(b"data: " + json.dumps(c).encode() + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")


upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
upstream.daemon_threads = True
threading.Thread(target=upstream.serve_forever, daemon=True).start()
UPSTREAM = f"http://127.0.0.1:{upstream.server_address[1]}/v1"
TMP = tempfile.mkdtemp()


def make(**kw):
    p = CloakwallProxy(upstream=UPSTREAM, port=0,
                       audit_path=os.path.join(TMP, kw.pop("log", "audit.log")), **kw)
    p.start()
    return p


def call(proxy, path, body=None, headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(proxy.url[:-3] + path, data=data,
                                 headers={"Content-Type": "application/json", **(headers or {})},
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


def sse_text(raw):
    """Join streamed content (or tool-call arguments) back together."""
    text, args, finishes, done = "", "", [], False
    for line in raw.decode().splitlines():
        if not line.startswith("data: "):
            continue
        if line == "data: [DONE]":
            done = True
            continue
        c = json.loads(line[6:])
        for ch in c.get("choices", []):
            d = ch.get("delta") or {}
            text += d.get("content") or ch.get("text") or ""
            for tc in d.get("tool_calls") or []:
                args += (tc.get("function") or {}).get("arguments") or ""
            if ch.get("finish_reason"):
                finishes.append(ch["finish_reason"])
    return text, args, finishes, done


def read_log(name, min_entries=1):
    """Wait for the requested audit entries to be present."""
    import time
    path = os.path.join(TMP, name)
    for _ in range(100):
        if os.path.exists(path) and len(open(path).read().splitlines()) >= min_entries:
            break
        time.sleep(0.05)
    return open(path).read() if os.path.exists(path) else ""


def last_upstream_body():
    return Upstream.seen[-1][2]


USER = "Email bob@clinic.org about card 4111 1111 1111 1111, MRN: A1234567"
VALUES = ("bob@clinic.org", "4111 1111 1111 1111", "4111111111111111", "A1234567")


# ---------------------------------------------------------------- requests
section("Requests are redacted before they leave")
p = make()
status, _, body = call(p, "/v1/chat/completions", {
    "model": "echo", "messages": [{"role": "system", "content": "Patient MRN: A1234567"},
                                  {"role": "user", "content": USER}]},
    headers={"Authorization": "Bearer sk-caller-key"})
check("chat request succeeds", status, 200)
sent = json.dumps(last_upstream_body())
check("upstream never saw a raw value", any(v in sent for v in VALUES), False)
check("upstream saw the placeholders", "<EMAIL>" in sent and "<CARD>" in sent and "<MRN>" in sent, True)
check("caller's Authorization passed through",
      Upstream.seen[-1][1].get("Authorization") or Upstream.seen[-1][1].get("authorization"),
      "Bearer sk-caller-key")
check("reply passes through unchanged by default",
      json.loads(body)["choices"][0]["message"]["content"], last_upstream_body()["messages"][-1]["content"])

status, _, _ = call(p, "/v1/embeddings", {"model": "emb", "input": ["mail z@y.com", "clean"]})
check("embeddings input redacted", last_upstream_body()["input"], ["mail <EMAIL>", "clean"])

call(p, "/v1/completions", {"model": "x", "prompt": "ssn 123-45-6789"})
check("completions prompt redacted", last_upstream_body()["prompt"], "ssn <SSN>")

status, _, body = call(p, "/v1/models")
check("GET /v1/models passes through", (status, json.loads(body)["data"][0]["id"]), (200, "fake-model"))
check("upstream path mapping", Upstream.seen[-1][0], "/v1/models")

status, _, body = call(p, "/cloakwall/health")
check("health endpoint", (status, json.loads(body)["status"]), (200, "ok"))
p.shutdown()

section("Strict card detection and keyed audit")
p = make(strict_cards=True, audit_hmac_key=b"proxy-audit-key", log="strict-keyed.log")
status, _, _ = call(p, "/v1/chat/completions",
                    {"model": "echo", "messages": [
                        {"role": "user", "content": "order 1234567890123456"}]})
check("strict mode redacts invalid card-shaped number upstream",
      last_upstream_body()["messages"][0]["content"], "order <CARD>")
check("keyed proxy audit verifies",
      AuditLog(os.path.join(TMP, "strict-keyed.log"),
               hmac_key=b"proxy-audit-key").verify()[0], True)
os.environ["CLOAKWALL_TEST_AUDIT_KEY"] = "proxy-audit-key"
check("CLI verifies HMAC log from environment",
      cli_main(["verify", os.path.join(TMP, "strict-keyed.log"),
                "--audit-hmac-key-env", "CLOAKWALL_TEST_AUDIT_KEY"]), 0)
anchor_path = os.path.join(TMP, "trusted-checkpoint.json")
with open(anchor_path, "w") as anchor_file:
    json.dump(AuditLog(os.path.join(TMP, "strict-keyed.log")).read_anchor(), anchor_file)
check("CLI accepts separately supplied checkpoint",
      cli_main(["verify", os.path.join(TMP, "strict-keyed.log"),
                "--audit-hmac-key-env", "CLOAKWALL_TEST_AUDIT_KEY",
                "--anchor-file", anchor_path]), 0)
os.environ.pop("CLOAKWALL_TEST_AUDIT_KEY")
p.shutdown()

section("Audit write failure")
p = make(log="audit-failure.log")
def fail_audit(*args, **kwargs):
    raise OSError("disk unavailable")
p.audit.append = fail_audit
before = len(Upstream.seen)
status, _, body = call(p, "/v1/chat/completions",
                       {"model": "echo", "messages": [{"role": "user", "content": "hello"}]})
check("audit write failure returns service unavailable",
      (status, json.loads(body)["error"]["type"]), (503, "audit_unavailable"))
check("audit failure prevents forwarding", len(Upstream.seen), before)
p.shutdown()

section("Upstream key from the environment")
p = make(upstream_key="sk-server-key", log="key.log")
call(p, "/v1/chat/completions", {"model": "x", "messages": [{"role": "user", "content": "hi"}]},
     headers={"Authorization": "Bearer sk-caller-dummy"})
check("server key replaces caller key",
      Upstream.seen[-1][1].get("authorization") or Upstream.seen[-1][1].get("Authorization"),
      "Bearer sk-server-key")
raw_log = read_log("key.log")
check("no key in the audit log", "sk-server-key" in raw_log or "sk-caller" in raw_log, False)
p.shutdown()

section("Blocking and bad input")
p = make(block_on=["CARD"], log="block.log")
before = len(Upstream.seen)
status, _, body = call(p, "/v1/chat/completions",
                       {"model": "x", "messages": [{"role": "user", "content": USER}]})
check("block_on rejects with 400", (status, json.loads(body)["error"]["type"]), (400, "cloakwall_blocked"))
check("blocked request never forwarded", len(Upstream.seen), before)
status, _, _ = call(p, "/v1/chat/completions", raw=b"{not json")
check("invalid JSON rejected", status, 400)
p.shutdown()
p = make(max_body=100, log="big.log")
status, _, _ = call(p, "/v1/chat/completions", {"model": "x", "messages": [{"role": "user", "content": "a" * 500}]})
check("oversized body rejected", status, 413)
status, _, body = call(p, "/v1/chat/completions", {"model": "fail", "messages": []})
check("upstream error relayed", (status, json.loads(body)["error"]["type"]), (429, "rate_limit"))
p.shutdown()

# ---------------------------------------------------------------- redact_output
section("redact_output")
p = make(redact_output=True, log="out.log")
status, _, body = call(p, "/v1/chat/completions",
                       {"model": "pii", "messages": [{"role": "user", "content": "hi"}]})
check("reply redacted", json.loads(body)["choices"][0]["message"]["content"],
      "Card on file is <CARD>, email <EMAIL>.")
status, ctype, body = call(p, "/v1/chat/completions",
                           {"model": "pii", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
text, _, finishes, done = sse_text(body)
check("stream is SSE", "text/event-stream" in ctype, True)
check("streamed reply redacted across 3-char chunks", text, "Card on file is <CARD>, email <EMAIL>.")
check("no raw value reaches the caller", any(v in body.decode() for v in VALUES), False)
check("finish then [DONE]", (finishes, done), (["stop"], True))
status, _, body = call(p, "/v1/completions", {"model": "pii", "stream": True, "prompt": "hi"})
check("legacy completions stream redacted", sse_text(body)[0], "Card on file is <CARD>, email <EMAIL>.")
status, _, _ = call(p, "/v1/responses", {"model": "pii", "stream": True, "input": "hi"})
check("unsupported stream format refused, not leaked", status, 400)
p.shutdown()

# ---------------------------------------------------------------- restore
section("restore")
p = make(restore=True, log="restore.log")
status, _, body = call(p, "/v1/chat/completions",
                       {"model": "echo", "messages": [{"role": "user", "content": USER}]})
sent = json.dumps(last_upstream_body())
check("model never saw the values", any(v in sent for v in VALUES), False)
check("model saw per-value tokens", "<EMAIL:" in sent and "<CARD:" in sent, True)
check("caller gets the real values back", json.loads(body)["choices"][0]["message"]["content"], USER)

status, _, body = call(p, "/v1/chat/completions",
                       {"model": "echo", "stream": True, "messages": [{"role": "user", "content": USER}]})
check("streamed restore across split tokens", sse_text(body)[0], USER)

status, _, body = call(p, "/v1/chat/completions",
                       {"model": "tool", "stream": True, "messages": [{"role": "user", "content": "bob@clinic.org"}]})
_, args, finishes, _ = sse_text(body)
check("streamed tool arguments restored as valid JSON", json.loads(args), {"email": "bob@clinic.org"})
check("tool stream still finishes", finishes, ["tool_calls"])

status, _, body = call(p, "/v1/chat/completions",
                       {"model": "tool", "messages": [{"role": "user", "content": "bob@clinic.org"}]})
args = json.loads(body)["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
check("tool arguments restored", json.loads(args), {"email": "bob@clinic.org"})

call(p, "/v1/chat/completions", {"model": "echo", "messages": [{"role": "user", "content": "a@b.com"}]})
t1 = last_upstream_body()["messages"][0]["content"]
call(p, "/v1/chat/completions", {"model": "echo", "messages": [{"role": "user", "content": "a@b.com"}]})
check("same value, same token across requests", last_upstream_body()["messages"][0]["content"], t1)
raw_log = read_log("restore.log", min_entries=12)
check("restore log holds no values", any(v in raw_log for v in VALUES + ("a@b.com",)), False)
check("restores are audited", '"event": "cloakwall.restored"' in raw_log, True)
check("audit chain intact", AuditLog(os.path.join(TMP, "restore.log")).verify()[0], True)
p.shutdown()

section("Restore helpers")
vals = {"<EMAIL:7f3a91c2>": 'x"y@z.io'}
check("unknown tokens left alone", restore_text("<EMAIL:00000000>", vals)[0], "<EMAIL:00000000>")
check("JSON-escaped inside arguments", restore_text('{"e":"<EMAIL:7f3a91c2>"}', vals, True)[0],
      '{"e":"x\\"y@z.io"}')
sr = StreamRestorer({"<EMAIL:7f3a91c2>": "a@b.com"})
pieces = [sr.feed(c)[0] for c in ("mail <EMA", "IL:7f3a", "91c2> now ", "a < b")]
check("split token restored", "".join(pieces) + sr.flush()[0], "mail a@b.com now a < b")

section("Configuration")
try:
    CloakwallProxy(upstream=UPSTREAM, port=0, redact_output=True, restore=True,
                   audit_path=os.path.join(TMP, "x.log"))
    check("redact_output + restore rejected", False, True)
except ValueError:
    check("redact_output + restore rejected", True, True)
try:
    CloakwallProxy(upstream="ftp://nope", port=0, audit_path=os.path.join(TMP, "x.log"))
    check("non-http upstream rejected", False, True)
except ValueError:
    check("non-http upstream rejected", True, True)
check("default listens on localhost only",
      CloakwallProxy(upstream=UPSTREAM, port=0, audit_path=os.path.join(TMP, "y.log")).address[0],
      "127.0.0.1")
check("cli verify: intact log exits 0", cli_main(["verify", os.path.join(TMP, "restore.log")]), 0)

upstream.shutdown()
print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
