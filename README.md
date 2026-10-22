# Cloakwall

PII/PHI redaction and tamper-evident audit logging for LiteLLM. Runs
in-process — no sidecar container, no external endpoint, no model download.

LiteLLM's open-source guardrail framework supports custom guardrails plus
Presidio, but Presidio means deploying and maintaining two extra containers,
and audit logs, SIEM export and SSO sit behind the Enterprise licence.
Cloakwall gives you redaction and a compliance-grade audit trail as one
dependency-free plugin.

```yaml
guardrails:
  - guardrail_name: cloakwall
    litellm_params:
      guardrail: cloakwall.guardrail.Cloakwall
      mode: pre_call
      default_on: true
      redaction_mode: mask
      audit_path: /var/log/cloakwall/audit.log
```

To mask PII in model responses as well, add `redact_output: true` and set
`mode: [pre_call, post_call]`.

```
user:  "Patient MRN: A1234567, email bob@clinic.org, card 4111111111111111"
model: "Patient <MRN>, email <EMAIL>, card <CARD>"
```

## Install

```bash
pip install litellm
git clone https://github.com/Rishikesh-glitch/Cloakwall-v0.1.git cloakwall
PYTHONPATH=./cloakwall litellm --config cloakwall/examples/config.yaml
```

Or run the container:

```bash
docker build -t cloakwall .
docker run -p 4000:4000 -e OPENAI_API_KEY=sk-... cloakwall
```

## What it detects

Email, credit cards (Luhn-validated), SSN, IBAN, AWS keys, API keys, JWTs,
medical record numbers, NHS numbers (modulus-11 validated), phone numbers
including international formats, IPv4, and dates of birth.

The validators matter more than the patterns. Without a Luhn check every
16-digit order number gets flagged; without the NHS checksum every US phone
number gets labelled a health identifier. Both are the reason teams turn
regex redaction off after a week.

## Where it looks

Every request field LiteLLM forwards that can carry text, on every endpoint:

| Request | Fields redacted |
|---------|-----------------|
| Chat completions | `messages[].content` (text parts), `tool_calls[].function.arguments` |
| Anthropic `/v1/messages` | top-level `system`, text blocks, `tool_use.input` (every string inside), `tool_result.content` |
| Responses API | `input` (string or items), `function_call.arguments`, `function_call_output.output` |
| Completions, image generation | `prompt` |
| Embeddings | `input` strings (token-id lists pass through) |

Image, audio and file parts pass through untouched. Ids, roles, model names
and function names are never rewritten.

With `redact_output: true`, responses are redacted too: chat content and
tool-call arguments, text completions, and Anthropic content blocks.
Streamed responses go through a stream redactor that holds back the last 64
characters (`stream_holdback`) and only releases text at a boundary no
entity spans, so a card number split across two chunks is still caught. The
cost is that streamed text reaches the client 64 characters later; none of
it is dropped. Output redaction is off by default, because it changes what
callers receive.

## Three redaction modes

| Mode | `alice@corp.com` becomes | Use when |
|------|--------------------------|----------|
| `mask` | `<EMAIL>` | the model has no business seeing the field |
| `hash` | `<EMAIL:7f3a91c2>` | you need to correlate a user across requests without storing the value |
| `partial` | `<CARD:****1111>` | support staff need the tail |

`hash` is deterministic under a local HMAC secret set with
`CLOAKWALL_SECRET`. Same person, same token, every request. Without a secret
one is generated per boot, so tokens are stable within a run only.

## Audit trail

Every entry commits to the SHA-256 of the entry before it and carries a
monotonic sequence number. The chain head is mirrored to a separate anchor
file after every append, and pushed to your SIEM every `anchor_every`
entries.

That combination catches all four tamper modes:

```
chain intact, 10 entries, anchor matches
line 2: entry altered after writing
line 3: chain break
truncated: anchor records 10 entries, log holds 6
```

The last one is why the anchor exists. A bare hash chain does not survive
truncation — a prefix of a valid chain is itself a valid chain, so dropping
the final entries verifies clean. The anchor still knows how many there
should be.

An anchor on the same filesystem stops accidental truncation and a careless
attacker. An anchor in your SIEM, under different access control, stops
someone who can write to the pod. Pass a SIEM-retrieved anchor to
`verify(anchor=...)` to check against a copy the log cannot reach.

The log records which entity types were found and how many. **It never
records the values that were redacted** — an audit log that quotes the PII it
scrubbed is a second copy of the problem.

## SIEM export

```bash
export CLOAKWALL_SIEM=splunk          # splunk | datadog | elastic
export CLOAKWALL_SIEM_URL=https://splunk.internal:8088/services/collector
export CLOAKWALL_SIEM_TOKEN=...
```

Export runs on a worker thread. A slow or unreachable SIEM never adds latency
to, or fails, an LLM request — the local log is the system of record.

## Air-gapped

The core is pure standard library. Nothing in the redaction, audit or hashing
path opens a socket, so it runs unchanged in an isolated cluster. Point
LiteLLM at a local vLLM or Ollama endpoint and no data leaves your network at
all.

Verify it yourself:

```bash
strace -f -e trace=connect python3 tests/test_cloakwall.py
```

## Benchmarks

Measured, reproducible numbers are in [BENCHMARKS.md](BENCHMARKS.md):
`python3 benchmarks/bench.py`. On a 2015 Core i3 under Linux, a clean
request costs 0.05 ms and a request with PII, including its fsynced audit
entry, about 1.8 ms.

## Tests

```bash
python3 tests/test_cloakwall.py     # 76 tests, no pytest required
```

## Limitations

Regex detection does not catch contextual PII — a person's name in free text,
or a medical condition described in prose. If you need that, Presidio's NLP
models are better and Cloakwall is not a replacement for them. What Cloakwall
gives up in recall it gains in having no dependencies, no sidecar and no
model to ship into an air-gapped environment.

Redaction is one-way. There is no un-redaction path, by design.

Status: working, tested, not yet run in production anywhere.

## Licence

AGPL-3.0. Commercial licences for closed-source use are available.
