#!/usr/bin/env python3
"""
Cloakwall benchmarks.  python3 benchmarks/bench.py [--markdown]

Standard library only, like the rest of the project, so anyone can reproduce
the numbers in BENCHMARKS.md on their own hardware with nothing but python3.

Each scenario is timed per call with time.perf_counter_ns after a warm-up,
and reported as P50 / P90 / P99. Numbers depend heavily on the CPU and, for
the audit log, on the disk: run it on the hardware you will deploy on.
"""

import asyncio
import os
import platform
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.audit import AuditLog
from cloakwall.guardrail import Cloakwall
from cloakwall.redact import Redactor, StreamRedactor

PROSE = ("The quarterly review covered onboarding, the support backlog and the "
         "migration plan. The team agreed to revisit the timeline next week. ")


def sized(seed: str, n: int = 2048) -> str:
    return (seed * (n // len(seed) + 1))[:n]


CLEAN_2K = sized(PROSE)
DIGITS_2K = sized(PROSE + "Order 1234567890123456 shipped on 2026-03-04, ticket 48213, room 12. ")
ONE_2K = CLEAN_2K[:2000] + " mail a@b.com"
MULTI_2K = sized(PROSE + "Contact bob@clinic.org, SSN 123-45-6789, card 4111 1111 1111 1111, "
                         "phone +94 77 123 4567, host 10.0.0.12. ")

CHAT = [{"role": "system", "content": CLEAN_2K[:600]}] + [
    {"role": "user" if i % 2 == 0 else "assistant",
     "content": MULTI_2K[:400] if i % 3 == 0 else CLEAN_2K[:400]}
    for i in range(8)
] + [{"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {
    "name": "lookup", "arguments": '{"mrn":"MRN A1234567","email":"p@q.org"}'}}]}]


def percentiles(samples_ns: list[int]) -> tuple[float, float, float]:
    q = statistics.quantiles(samples_ns, n=100, method="inclusive")
    return q[49] / 1e6, q[89] / 1e6, q[98] / 1e6


def bench(fn, n: int, warmup: int = 50) -> tuple[float, float, float]:
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - t)
    return percentiles(out)


def stream_once(redactor: Redactor, text: str, chunk: int) -> None:
    sr = StreamRedactor(redactor)
    for i in range(0, len(text), chunk):
        sr.feed(text[i:i + chunk])
    sr.flush()


class Key:
    key_alias = "bench"
    team_id = "bench"


def main() -> None:
    markdown = "--markdown" in sys.argv
    n = 2000
    mask = Redactor(mode="mask", secret=b"bench")
    hashed = Redactor(mode="hash", secret=b"bench")
    rows = []

    def add(name, what, result):
        rows.append((name, what) + result)

    add("Clean text, no digits or @", "redact 2 KB", bench(lambda: mask.redact(CLEAN_2K), n))
    add("Clean text with numbers and dates", "redact 2 KB", bench(lambda: mask.redact(DIGITS_2K), n))
    add("One entity (email)", "redact 2 KB", bench(lambda: mask.redact(ONE_2K), n))
    add("Mixed entities, mask", "redact 2 KB", bench(lambda: mask.redact(MULTI_2K), n))
    add("Mixed entities, hash", "redact 2 KB", bench(lambda: hashed.redact(MULTI_2K), n))
    add("Chat request, 10 messages + tool call", "redact_messages ~4 KB",
        bench(lambda: mask.redact_messages(CHAT), n))
    add("Streamed response, 4-char chunks", "whole 2 KB stream",
        bench(lambda: stream_once(mask, MULTI_2K, 4), 300, warmup=10))
    add("Streamed response, 4-char chunks", "clean 2 KB stream",
        bench(lambda: stream_once(mask, CLEAN_2K, 4), 300, warmup=10))

    with tempfile.TemporaryDirectory() as d:
        log = AuditLog(os.path.join(d, "a.log"))
        add("Audit log append (fsync log + anchor)", "one entry",
            bench(lambda: log.append("bench", entities={"EMAIL": 1}), 300, warmup=10))

        g = Cloakwall(audit_path=os.path.join(d, "g.log"))
        loop = asyncio.new_event_loop()

        def hook(messages):
            data = {"model": "m", "messages": messages}
            loop.run_until_complete(g.async_pre_call_hook(Key(), None, data, "acompletion"))

        add("Full pre_call hook, nothing found", "clean chat request",
            bench(lambda: hook([{"role": "user", "content": CLEAN_2K}]), 1000))
        add("Full pre_call hook, PII found", "redact + audit entry",
            bench(lambda: hook([{"role": "user", "content": MULTI_2K}]), 300, warmup=10))
        loop.close()

    # Single-core throughput on the redaction path alone (no audit write).
    t = time.perf_counter()
    count = 0
    while time.perf_counter() - t < 2.0:
        mask.redact(MULTI_2K)
        count += 1
    rps_multi = count / (time.perf_counter() - t)
    t = time.perf_counter()
    count = 0
    while time.perf_counter() - t < 2.0:
        mask.redact(CLEAN_2K)
        count += 1
    rps_clean = count / (time.perf_counter() - t)

    env = (f"{platform.processor() or platform.machine()} · {os.cpu_count()} logical CPUs · "
           f"Python {platform.python_version()} · {platform.platform()}")
    if markdown:
        print(f"Environment: {env}\n")
        print("| Scenario | Measured | P50 | P90 | P99 |")
        print("| --- | --- | ---: | ---: | ---: |")
        for name, what, p50, p90, p99 in rows:
            print(f"| {name} | {what} | {p50:.3f} ms | {p90:.3f} ms | {p99:.3f} ms |")
        print(f"\nSingle-core redaction throughput: {rps_multi:,.0f} calls/s on 2 KB with "
              f"mixed PII, {rps_clean:,.0f} calls/s on 2 KB clean text.")
    else:
        print(env)
        for name, what, p50, p90, p99 in rows:
            print(f"{name:<42} {what:<24} p50 {p50:8.3f} ms  p90 {p90:8.3f} ms  p99 {p99:8.3f} ms")
        print(f"throughput: {rps_multi:,.0f}/s mixed PII, {rps_clean:,.0f}/s clean (single core)")


if __name__ == "__main__":
    main()
