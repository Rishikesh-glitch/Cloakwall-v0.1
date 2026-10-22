#!/usr/bin/env python3
"""
Cloakwall test suite.  python3 tests/test_cloakwall.py

No pytest dependency on purpose: someone evaluating this in a locked-down
environment should be able to run the tests with nothing but python3.
"""

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.audit import AuditLog
from cloakwall.guardrail import Cloakwall
from cloakwall.redact import Redactor, _luhn, _nhs

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


# ---------------------------------------------------------------- detection
section("Detection")
r = Redactor(mode="mask", secret=b"test")
check("email", r.redact("write to a.b+c@x.co.uk now").text, "write to <EMAIL> now")
check("valid card redacted", r.redact("card 4111111111111111").text, "card <CARD>")
check("invalid card left alone", r.redact("order 1234567890123456").text,
      "order 1234567890123456")
check("ssn", r.redact("ssn 123-45-6789").text, "ssn <SSN>")
check("aws key", r.redact("AKIAIOSFODNN7EXAMPLE").text, "<AWS_KEY>")
check("sri lankan phone", r.redact("call +94 77 123 4567").text, "call <PHONE>")
check("us phone is PHONE not NHS", r.redact("call 555-867-5309").text, "call <PHONE>")
check("real nhs number", r.redact("nhs 943 476 5919").text, "nhs <NHS>")
check("clean text untouched", r.redact("the quick brown fox").text,
      "the quick brown fox")

# ---------------------------------------------------------------- validators
section("Validators")
check("luhn accepts real card", _luhn("4111111111111111"), True)
check("luhn rejects sequence", _luhn("1234567890123456"), False)
check("nhs accepts valid", _nhs("9434765919"), True)
check("nhs rejects phone", _nhs("5558675309"), False)

# ---------------------------------------------------------------- modes
section("Redaction modes")
check("hash is deterministic",
      Redactor(mode="hash", secret=b"k").redact("a@b.com").text
      == Redactor(mode="hash", secret=b"k").redact("a@b.com").text, True)
check("hash differs under another secret",
      Redactor(mode="hash", secret=b"k1").redact("a@b.com").text
      != Redactor(mode="hash", secret=b"k2").redact("a@b.com").text, True)
check("partial keeps card tail",
      Redactor(mode="partial").redact("4111111111111111").text, "<CARD:****1111>")

# ---------------------------------------------------------------- overlaps
section("Overlapping spans")
out = r.redact("bob@x.com 4111111111111111 123-45-6789")
check("three distinct entities", sorted(out.counts), ["CARD", "EMAIL", "SSN"])
check("no nested tokens", "<<" in out.text, False)

# ---------------------------------------------------------------- audit
section("Audit chain")
with tempfile.TemporaryDirectory() as d:
    log = AuditLog(os.path.join(d, "a.log"))
    for i in range(5):
        log.append("test.event", n=i)
    check("intact chain verifies", log.verify()[0], True)

    lines = open(log.path).read().splitlines()
    e = json.loads(lines[2]); e["n"] = 99
    lines[2] = json.dumps(e, sort_keys=True)
    open(log.path, "w").write("\n".join(lines) + "\n")
    ok, msg = log.verify()
    check("tampered entry detected", ok, False)
    check("names the right line", msg, "line 3: entry altered after writing")

with tempfile.TemporaryDirectory() as d:
    log = AuditLog(os.path.join(d, "b.log"))
    for i in range(5):
        log.append("test.event", n=i)
    lines = open(log.path).read().splitlines()
    del lines[2]
    open(log.path, "w").write("\n".join(lines) + "\n")
    check("deleted entry detected", log.verify()[0], False)

section("Truncation resistance")
with tempfile.TemporaryDirectory() as d:
    log = AuditLog(os.path.join(d, "t.log"))
    for i in range(10):
        log.append("test.event", n=i)
    anchor = log.read_anchor()
    check("anchor records entry count", anchor["seq"], 10)
    check("intact log matches anchor", log.verify()[0], True)

    lines = open(log.path).read().splitlines()[:6]
    open(log.path, "w").write("\n".join(lines) + "\n")
    ok, msg = log.verify(anchor=anchor)
    check("end-truncation detected", ok, False)
    check("reports the shortfall", "anchor records 10" in msg, True)

with tempfile.TemporaryDirectory() as d:
    log = AuditLog(os.path.join(d, "s.log"))
    for i in range(5):
        log.append("e", n=i)
    seqs = [json.loads(l)["seq"] for l in open(log.path) if l.strip()]
    check("sequence numbers are contiguous", seqs, [1, 2, 3, 4, 5])

# ---------------------------------------------------------------- guardrail
section("Guardrail hook")


class Key:
    key_alias = "team-a"
    team_id = "t1"


async def guardrail_tests():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "g.log")
        g = Cloakwall(redaction_mode="mask", audit_path=path)

        data = {"model": "m", "messages": [
            {"role": "user", "content": "card 4111111111111111 mail z@y.com"}]}
        out = await g.async_pre_call_hook(Key(), None, data, "acompletion")
        check("request redacted in place",
              out["messages"][0]["content"], "card <CARD> mail <EMAIL>")

        raw = open(path).read()
        check("card absent from audit log", "4111111111111111" in raw, False)
        check("email absent from audit log", "z@y.com" in raw, False)
        check("entity counts recorded", '"CARD": 1' in raw, True)

        await g.async_pre_call_hook(
            Key(), None,
            {"model": "m", "messages": [{"role": "user", "content": "hello"}]},
            "acompletion")
        check("clean request logs nothing extra",
              len([l for l in open(path) if l.strip()]), 1)

        multimodal = {"model": "m", "messages": [{"role": "user", "content": [
            {"type": "text", "text": "ssn 123-45-6789"},
            {"type": "image_url", "image_url": {"url": "http://x/y.png"}}]}]}
        out = await g.async_pre_call_hook(Key(), None, multimodal, "acompletion")
        parts = out["messages"][0]["content"]
        check("multimodal text redacted", parts[0]["text"], "ssn <SSN>")
        check("multimodal image untouched", parts[1]["type"], "image_url")

        out = await g.async_pre_call_hook(
            Key(), None, {"model": "m"}, "acompletion")
        check("request with no messages survives", out, {"model": "m"})

        check("stats report intact chain", g.stats()["audit_intact"], True)

        tc = {"model": "m", "messages": [{"role": "assistant", "tool_calls": [
            {"id": "c1", "type": "function", "function": {
                "name": "lookup",
                "arguments": '{"card":"4111111111111111","mail":"a@b.com"}'}}]}]}
        out = await g.async_pre_call_hook(Key(), None, tc, "acompletion")
        args = out["messages"][0]["tool_calls"][0]["function"]["arguments"]
        check("tool-call arguments redacted", args,
              '{"card":"<CARD>","mail":"<EMAIL>"}')

    with tempfile.TemporaryDirectory() as d:
        b = Cloakwall(audit_path=os.path.join(d, "b.log"), block_on=["CARD"])
        blocked = False
        try:
            await b.async_pre_call_hook(Key(), None, {"model": "m", "messages": [
                {"role": "user", "content": "card 4111111111111111"}]}, "acompletion")
        except ValueError:
            blocked = True
        check("block_on rejects the request", blocked, True)

        ok = await b.async_pre_call_hook(Key(), None, {"model": "m", "messages": [
            {"role": "user", "content": "mail a@b.com"}]}, "acompletion")
        check("non-blocked entity still redacted",
              ok["messages"][0]["content"], "mail <EMAIL>")
        check("block counted in stats", b.stats()["requests_blocked"], 1)


asyncio.run(guardrail_tests())

# ---------------------------------------------------------------- coverage
section("Request fields beyond messages")


async def coverage_tests():
    with tempfile.TemporaryDirectory() as d:
        g = Cloakwall(audit_path=os.path.join(d, "c.log"))

        out = await g.async_pre_call_hook(Key(), None, {
            "model": "claude", "system": "Patient MRN: A1234567",
            "messages": [{"role": "user", "content": "hi"}]}, "anthropic_messages")
        check("anthropic system string", out["system"], "Patient <MRN>")

        out = await g.async_pre_call_hook(Key(), None, {
            "model": "claude", "system": [{"type": "text", "text": "mail a@b.com"}],
            "messages": []}, "anthropic_messages")
        check("anthropic system blocks", out["system"][0]["text"], "mail <EMAIL>")

        out = await g.async_pre_call_hook(Key(), None, {"model": "claude", "messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "lookup",
                 "input": {"patient": {"email": "p@q.org"}, "n": 3}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": "card 4111111111111111"}]}]}, "anthropic_messages")
        blocks = out["messages"]
        check("tool_use input redacted",
              blocks[0]["content"][0]["input"], {"patient": {"email": "<EMAIL>"}, "n": 3})
        check("tool_use name untouched", blocks[0]["content"][0]["name"], "lookup")
        check("tool_result redacted", blocks[1]["content"][0]["content"], "card <CARD>")

        out = await g.async_pre_call_hook(Key(), None, {
            "model": "dall-e", "prompt": "a badge reading ssn 123-45-6789"},
            "aimage_generation")
        check("image-generation prompt", out["prompt"], "a badge reading ssn <SSN>")

        out = await g.async_pre_call_hook(Key(), None, {
            "model": "emb", "input": ["mail z@y.com", "clean"]}, "aembedding")
        check("embeddings input list", out["input"], ["mail <EMAIL>", "clean"])

        out = await g.async_pre_call_hook(Key(), None, {
            "model": "emb", "input": [101, 2023, 102]}, "aembedding")
        check("token ids untouched", out["input"], [101, 2023, 102])

        out = await g.async_pre_call_hook(Key(), None, {"model": "gpt", "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "a@b.com"},
                                         {"type": "input_image", "image_url": "http://x/1@2.png"}]},
            {"type": "function_call", "call_id": "c", "name": "f",
             "arguments": '{"ssn":"123-45-6789"}'},
            {"type": "function_call_output", "call_id": "c", "output": "a@b.com"}]},
            "aresponses")
        items = out["input"]
        check("responses input_text", items[0]["content"][0]["text"], "<EMAIL>")
        check("responses input_image untouched",
              items[0]["content"][1]["image_url"], "http://x/1@2.png")
        check("responses function_call args", items[1]["arguments"], '{"ssn":"<SSN>"}')
        check("responses function_call_output", items[2]["output"], "<EMAIL>")

        raw = open(os.path.join(d, "c.log")).read()
        check("no request value in audit log",
              any(v in raw for v in ("A1234567", "p@q.org", "123-45-6789", "z@y.com")), False)

        b = Cloakwall(audit_path=os.path.join(d, "b.log"), block_on=["SSN"])
        blocked = False
        try:
            await b.async_pre_call_hook(Key(), None,
                                        {"model": "m", "prompt": "ssn 123-45-6789"}, "x")
        except ValueError:
            blocked = True
        check("block_on applies to prompt field", blocked, True)


asyncio.run(coverage_tests())

# ---------------------------------------------------------------- streaming
section("Stream redaction")

from cloakwall.redact import StreamRedactor


def stream_through(text, pieces, mode="mask"):
    sr = StreamRedactor(Redactor(mode=mode, secret=b"s"), holdback=64)
    out, size = [], max(1, len(text) // pieces)
    for i in range(0, len(text), size):
        out.append(sr.feed(text[i:i + size]).text)
    out.append(sr.flush().text)
    return "".join(out)


msg = ("Your card 4111 1111 1111 1111 is on file, call +94 77 123 4567 "
       "or mail alice@corp.com. " * 4)
whole = Redactor(mode="mask", secret=b"s").redact(msg).text
for n in (len(msg), 40, 7):
    check(f"split into {n} pieces matches whole-text redaction",
          stream_through(msg, n), whole)
check("hash tokens stable across chunks", stream_through(msg, len(msg), "hash"),
      Redactor(mode="hash", secret=b"s").redact(msg).text)
check("clean text passes through intact", stream_through("plain words " * 30, 50),
      "plain words " * 30)
sr = StreamRedactor(Redactor(), holdback=64)
check("short text held until flush", sr.feed("hi a@b.com").text, "")
check("flush releases it redacted", sr.flush().text, "hi <EMAIL>")

# ---------------------------------------------------------------- output
section("Response redaction")

from types import SimpleNamespace as NS


def chunk(content=None, finish=None, tool_args=None, tool_id=None, name=None):
    tcs = None
    if tool_args is not None:
        tcs = [NS(index=0, id=tool_id, type="function",
                  function=NS(name=name, arguments=tool_args))]
    return NS(choices=[NS(index=0, delta=NS(content=content, tool_calls=tcs),
                          finish_reason=finish)])


async def agen(items):
    for i in items:
        yield i


async def output_tests():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "o.log")
        off = Cloakwall(audit_path=path)
        resp = {"choices": [{"index": 0, "message": {"content": "mail a@b.com"},
                             "finish_reason": "stop"}]}
        await off.async_post_call_success_hook({"model": "m"}, Key(), resp)
        check("redact_output off leaves response", resp["choices"][0]["message"]["content"],
              "mail a@b.com")

        g = Cloakwall(audit_path=path, redact_output=True)
        resp = NS(choices=[NS(index=0, finish_reason="tool_calls", message=NS(
            content="card 4111111111111111",
            tool_calls=[NS(function=NS(name="f", arguments='{"m":"a@b.com"}'))]))])
        await g.async_post_call_success_hook({"model": "m"}, Key(), resp)
        check("response content redacted", resp.choices[0].message.content, "card <CARD>")
        check("response tool args redacted",
              resp.choices[0].message.tool_calls[0].function.arguments, '{"m":"<EMAIL>"}')

        resp = {"content": [{"type": "text", "text": "ssn 123-45-6789"},
                            {"type": "tool_use", "name": "f", "input": {"e": "x@y.io"}}]}
        await g.async_post_call_success_hook({"model": "claude"}, Key(), resp)
        check("anthropic response text", resp["content"][0]["text"], "ssn <SSN>")
        check("anthropic response tool_use", resp["content"][1]["input"], {"e": "<EMAIL>"})

        resp = {"choices": [{"index": 0, "text": "mail a@b.com"}]}
        await g.async_post_call_success_hook({"model": "m", "stream": True}, Key(), resp)
        check("assembled stream copy not re-redacted", resp["choices"][0]["text"],
              "mail a@b.com")

        text = "Sure. The card on file is 4111 1111 1111 1111 and the email is bob@clinic.org."
        parts = [text[i:i + 5] for i in range(0, len(text), 5)]
        chunks = [chunk(p) for p in parts] + [chunk(None, finish="stop")]
        got = [c async for c in g.async_post_call_streaming_iterator_hook(
            Key(), agen(chunks), {"model": "m"})]
        streamed = "".join(c.choices[0].delta.content or "" for c in got)
        check("stream redacts PII split across chunks", streamed,
              "Sure. The card on file is <CARD> and the email is <EMAIL>.")
        check("finish chunk still last", got[-1].choices[0].finish_reason, "stop")
        check("no raw card reaches the client", "1111" in streamed, False)

        args = '{"patient_email":"bob@clinic.org","mrn":"MRN A1234567"}'
        chunks = [chunk(None, tool_args="", tool_id="call_1", name="lookup")]
        chunks += [chunk(None, tool_args=args[i:i + 4]) for i in range(0, len(args), 4)]
        chunks += [chunk(None, finish="tool_calls")]
        got = [c async for c in g.async_post_call_streaming_iterator_hook(
            Key(), agen(chunks), {"model": "m"})]
        streamed_args = "".join(
            tc.function.arguments or ""
            for c in got for tc in (c.choices[0].delta.tool_calls or []))
        check("streamed tool args redacted", streamed_args,
              '{"patient_email":"<EMAIL>","mrn":"<MRN>"}')
        names = [tc.function.name for c in got for tc in (c.choices[0].delta.tool_calls or [])
                 if tc.function.name]
        check("function name sent once", names, ["lookup"])

        raw = open(path).read()
        check("output values absent from audit log",
              any(v in raw for v in ("bob@clinic.org", "4111", "A1234567")), False)
        check("output redactions audited", raw.count("cloakwall.redacted_output"), 4)
        check("stats count redacted responses", g.stats()["responses_with_redactions"], 4)
        check("chain intact after output events", g.stats()["audit_intact"], True)


asyncio.run(output_tests())

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
