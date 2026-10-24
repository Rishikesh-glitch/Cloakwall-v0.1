# Cloakwall benchmarks

Every number here comes from [`benchmarks/bench.py`](benchmarks/bench.py), a standard-library script anyone can run:

```bash
python3 benchmarks/bench.py --markdown
```

It times each operation call by call after a warm-up and reports P50 / P90 / P99. Results depend on the CPU and, for the audit log, on the disk. **Run it on the hardware you plan to deploy on**; these numbers are a floor, not a promise.

> **Why this file looks the way it does.** A security product is only as trustworthy as its claims, so this file contains only numbers produced by the script above. What hasn't been measured is listed at the end rather than guessed. First measured on 2026-10-22; the Linux table was re-measured on 2026-10-24.

## Test machine

A deliberately modest one: a 2015 laptop, **Intel Core i3-5005U @ 2.0 GHz, 4 logical CPUs**, Python 3.14.4, single process, single thread.

- **Linux:** Ubuntu under WSL2 (kernel 6.18), files on the Linux filesystem. This is the closest to a real deployment, since the Dockerfile targets Linux.
- **Windows:** Windows 10 on the same machine, shown for completeness.

## Results (Linux)

Re-measured 2026-10-24 for 0.3.0. The fast-path check now also looks for key
prefixes (`sk-`, `AKIA`, `eyJ`...), because API keys made only of letters
were slipping past it; clean text costs about 0.01 ms more than in 0.2.0.

| Scenario | Measured | P50 | P90 | P99 |
| --- | --- | ---: | ---: | ---: |
| Clean text, no digits or @ | redact 2 KB | 0.031 ms | 0.033 ms | 0.134 ms |
| Clean text with numbers and dates | redact 2 KB | 1.050 ms | 1.327 ms | 2.384 ms |
| One entity (email) | redact 2 KB | 0.870 ms | 1.186 ms | 2.165 ms |
| Mixed entities, mask | redact 2 KB | 1.179 ms | 1.451 ms | 2.538 ms |
| Mixed entities, hash | redact 2 KB | 1.417 ms | 1.852 ms | 3.535 ms |
| Chat request, 10 messages + tool call | redact_messages ~4 KB | 0.864 ms | 1.150 ms | 2.766 ms |
| Streamed response, 4-char chunks (mixed PII) | whole 2 KB stream (512 chunks) | 24.406 ms | 28.321 ms | 33.930 ms |
| Streamed response, 4-char chunks (clean) | whole 2 KB stream (512 chunks) | 3.679 ms | 4.814 ms | 9.258 ms |
| Audit log append (fsync log + anchor) | one entry | 0.277 ms | 0.416 ms | 1.376 ms |
| **Full pre_call hook, nothing found** | clean chat request | **0.063 ms** | 0.119 ms | 0.255 ms |
| **Full pre_call hook, PII found** | redact + audit entry | **1.818 ms** | 11.918 ms | 15.101 ms |

The P90 and P99 of the last row are dominated by the two `fsync` calls in the
audit write, which vary with the disk: in the 0.2.0 run on the same machine
they were 2.6 ms and 4.6 ms. Measure on your own storage.

Single-core redaction throughput (no audit write): **684 calls/s** on 2 KB with mixed PII, **28,634 calls/s** on 2 KB of clean text. A LiteLLM proxy normally runs several worker processes, so a multi-core server scales roughly with its cores. That has not been measured here.

## Results (Windows 10, same laptop, measured with 0.2.0)

| Scenario | P50 | P99 |
| --- | ---: | ---: |
| Clean text, no digits or @ | 0.043 ms | 0.090 ms |
| Mixed entities, mask | 1.582 ms | 7.083 ms |
| Audit log append (fsync log + anchor) | **107.8 ms** | 200.6 ms |
| Full pre_call hook, PII found | **111.7 ms** | 244.7 ms |

The audit append is about 400× slower on Windows than on Linux on the same hardware. It doesn't grow with log size (the log reads only its last 4 KB). The cost is Windows file I/O: around 20 ms to open the file and atomically replace the anchor, plus about 85 ms for the two `fsync` calls on this laptop's disk. **Don't run the audit log on Windows in production.**

## What the numbers mean

- **Requests with no PII cost almost nothing.** A cheap pre-check skips the regex engine for text with no digits, no `@` and no key prefix: about 0.06 ms for the whole hook.
- **Requests with PII cost about 1–2 ms on Linux,** most of it regex scanning. An LLM call takes hundreds of milliseconds to seconds, so this is well under 1% of the round trip.
- **The audit write is durable by design.** Each entry is `fsync`ed to disk, together with its anchor, before the request continues. That way a crash can't lose the record of a redaction. On Linux this costs 0.3 ms.
- **Streaming adds about 0.05 ms per chunk with PII** (24.4 ms / 512 chunks) and under 0.01 ms per chunk on clean text. The client also sees text 64 characters later than it would otherwise (`stream_holdback`). Nothing is dropped.

## Known slow spots (not yet optimised)

- **The phone-number detector** is the most expensive pattern: about 0.5 ms of the ~1.4 ms spent on 2 KB of number-heavy text on Windows.
- **The stream redactor** re-scans its pending buffer on every chunk. Scanning only the new tail would cut the per-chunk cost.

## Not measured yet

- **Detection accuracy** (how much PII it catches and how often it's wrong) on a labelled dataset. Regex can't catch names or conditions written in prose; see the README's Limitations section. This is the next benchmark to add.
- **A head-to-head comparison with Presidio** or other tools on the same machine.
- **Server-class hardware**, multiple worker processes, or end-to-end latency through a running LiteLLM proxy.
