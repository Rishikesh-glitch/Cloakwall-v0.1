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


asyncio.run(guardrail_tests())

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
