# Cloakwall

PII/PHI redaction and tamper-evident audit logging for LLM traffic. It
strips emails, card numbers, SSNs, medical record numbers, API keys and more
from requests **before they leave your machine**, and records every
redaction in a hash-chained audit log that shows if anyone edits it.

No sidecar, no external service, no model download, no third-party
dependencies. It runs unchanged in an air-gapped network.

```
user:  "Patient MRN: A1234567, email bob@clinic.org, card 4111111111111111"
model: "Patient <MRN>, email <EMAIL>, card <CARD>"
```

Start by checking what you would be leaking:

```bash
pip install cloakwall
cloakwall scan ./my-project ./chat-logs
```

```
Found 266 sensitive values in 5 files:
  EMAIL        214
  CARD          38
  API_KEY       12
  AWS_KEY        2
```

`scan` reads files on your machine, including `.env` files and JSON or JSONL
chat logs, and reports what kind of sensitive value it found, how many and
where (`--details` adds file and line). It never prints a value, never
writes anything and never connects to the network. It exits with 1 when it
finds something, so it can also guard a CI pipeline. (The numbers above are
an illustration of the format.)

Then protect the traffic, one of two ways:

| | Standalone proxy (`cloakwall serve`) | LiteLLM guardrail |
|---|---|---|
| Works with | any OpenAI-compatible app, SDK or agent | an existing LiteLLM proxy |
| Dependencies | none (standard library only) | LiteLLM |
| Restore real values in replies | yes (`--restore`) | no |

## Standalone proxy

```bash
pip install cloakwall
export OPENAI_API_KEY=sk-...
cloakwall serve --upstream https://api.openai.com/v1 --upstream-key-env OPENAI_API_KEY
```

Then point your app at `http://127.0.0.1:8787/v1` instead of the provider.
Any OpenAI-compatible upstream works: OpenAI, OpenRouter, Together, a
company gateway, a local vLLM. The proxy listens on localhost only unless
you pass `--host`.

What happens to replies:

- **default:** passed through unchanged.
- **`--redact-output`:** PII in replies is masked too, streamed or not.
- **`--restore`:** the reverse. Requests are redacted with one token per value
  (`<EMAIL:7f3a91c2>`), and the original values are put back into the reply
  before your app sees it. The model never sees the data and your app gets a
  normal answer. For an agent this means a command can use your real API key
  without the key ever leaving your machine. The token-to-value map lives in
  memory for one request and is never written anywhere.

Both work on streamed replies: text is held back briefly so a value, or a
token, split across chunks is still caught whole. Tool-call arguments are
restored as valid JSON.

Other options: `--block-on CARD SSN` rejects requests containing those
entities instead of redacting them. `--entities` limits what is detected.
`--audit-path` sets the log file, and `cloakwall verify <log>` checks it.

If you omit `--upstream-key-env`, the caller's `Authorization` header is
passed upstream instead. Keys are never logged, and never read from the
command line, which ends up in shell history.

### Agent harnesses

Coding and agent tools read whole projects, `.env` files included, and send
what they read to the model. Run the proxy with `--restore` and point the tool
at it.

**pi** (`~/.pi/agent/models.json`):

```json
{
  "providers": {
    "cloakwall": {
      "baseUrl": "http://127.0.0.1:8787/v1",
      "api": "openai-completions",
      "apiKey": "$OPENAI_API_KEY",
      "models": [{ "id": "gpt-4o" }]
    }
  }
}
```

Then `pi --model cloakwall/gpt-4o`. **oh-my-pi** is built on pi: add the
same provider through its custom-provider settings (see the oh-my-pi docs).

**Hermes Agent:** run `hermes model`, choose *Custom endpoint*, and enter
`http://127.0.0.1:8787/v1` as the base URL.

Streaming output processing (`--redact-output`, `--restore`) covers
`/chat/completions` and `/completions`, which is what these tools use. A
streamed request to another endpoint with output processing on is refused
rather than passed through unprocessed.

### Point every app at it at once

The official OpenAI SDKs, and many tools built on them, read
`OPENAI_BASE_URL`. Set it once and every such app on the machine goes
through Cloakwall, with no code change:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1      # macOS / Linux: add to ~/.zshrc or ~/.bashrc
setx OPENAI_BASE_URL http://127.0.0.1:8787/v1        # Windows: permanent, for new terminals
```

### Run it permanently

The proxy is a background service: start it once and it keeps running.
Each recipe below is a file in
[`examples/run/`](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/tree/main/examples/run),
and each is installed for real on a fresh machine of that OS by
[CI](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/blob/main/.github/workflows/recipes.yml)
on every change. None of them puts the provider key on a command line or in
the service definition.

**Linux (systemd user service),** which starts at login and restarts if it stops:

```bash
pipx install cloakwall
mkdir -p ~/.config/cloakwall ~/.config/systemd/user
printf 'CLOAKWALL_UPSTREAM=https://api.openai.com/v1\nOPENAI_API_KEY=sk-...\n' > ~/.config/cloakwall/env
chmod 600 ~/.config/cloakwall/env
curl -fsSL https://raw.githubusercontent.com/Rishikesh-glitch/Cloakwall-v0.1/main/examples/run/cloakwall.service \
  | sed "s#__CLOAKWALL__#$(command -v cloakwall)#" > ~/.config/systemd/user/cloakwall.service
systemctl --user daemon-reload && systemctl --user enable --now cloakwall
```

**macOS (launchd agent),** with the key kept in the Keychain:

```bash
pipx install cloakwall
security add-generic-password -s cloakwall-upstream -a "$USER" -w     # prompts for the key
mkdir -p ~/.cloakwall ~/Library/LaunchAgents
B=https://raw.githubusercontent.com/Rishikesh-glitch/Cloakwall-v0.1/main/examples/run
curl -fsSL "$B/cloakwall-macos.sh" | sed "s#__CLOAKWALL__#$(command -v cloakwall)#" > ~/.cloakwall/run.sh
chmod 700 ~/.cloakwall/run.sh
curl -fsSL "$B/com.cloakwall.proxy.plist" | sed "s#__HOME__#$HOME#g" > ~/Library/LaunchAgents/com.cloakwall.proxy.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cloakwall.proxy.plist
```

**Windows (scheduled task at logon, no window),** in PowerShell:

```powershell
pip install cloakwall
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-...", "User")
Invoke-WebRequest -OutFile windows-task.ps1 `
  https://raw.githubusercontent.com/Rishikesh-glitch/Cloakwall-v0.1/main/examples/run/windows-task.ps1
powershell -ExecutionPolicy Bypass -File windows-task.ps1
```

**Docker,** from a clone of this repository, reachable from this machine only,
running as a non-root user:

```bash
docker build -t cloakwall-proxy -f examples/run/Dockerfile.proxy .
docker run -d --name cloakwall --restart unless-stopped \
  -p 127.0.0.1:8787:8787 -e OPENAI_API_KEY -v cloakwall-audit:/data \
  cloakwall-proxy --upstream https://api.openai.com/v1 --upstream-key-env OPENAI_API_KEY --restore
```

**GitHub Codespaces / dev containers:** copy
[`devcontainer.json`](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/blob/main/examples/run/devcontainer.json)
into the project's `.devcontainer/`, and add the key as a Codespaces secret
named `OPENAI_API_KEY`. Every Codespace then starts with the proxy running and
`OPENAI_BASE_URL` already pointing at it.

Each recipe uses `--restore` and OpenAI as the upstream; change either in the
file. Check it is running with `curl http://127.0.0.1:8787/cloakwall/health`.

**One proxy for a team or company.** Run it once on a server inside your
network rather than on every laptop, so there is one audit trail to send to
your SIEM. The proxy has no client authentication of its own yet, so on a
shared host: don't set `--upstream-key-env` (each app then sends its own
provider key, which is passed through), and put the proxy behind your
existing ingress or gateway for TLS and access control.

## LiteLLM guardrail

LiteLLM's open-source guardrail framework supports custom guardrails plus
Presidio, but Presidio means deploying and maintaining two extra containers,
and audit logs, SIEM export and SSO sit behind the Enterprise licence.
Cloakwall adds redaction and a compliance-grade audit trail as one plugin.

```bash
pip install "cloakwall[litellm]"
```

The `litellm` extra excludes 1.82.7, 1.82.8 and 1.107.0, LiteLLM releases
that were hijacked to steal credentials in 2026. Pin the version you deploy.

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

LiteLLM refuses to start without a master key (an API key for the proxy
itself), so set one, then point LiteLLM at a config that enables the
guardrail, such as [examples/config.yaml](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/blob/main/examples/config.yaml):

```bash
export LITELLM_MASTER_KEY="sk-$(openssl rand -hex 32)"
litellm --config config.yaml
```

Clients then call the proxy with `Authorization: Bearer $LITELLM_MASTER_KEY`.

Or run the container, which installs the same packages from PyPI with
LiteLLM pinned:

```bash
docker build -t cloakwall .
docker run -p 4000:4000 \
  -e LITELLM_MASTER_KEY="sk-$(openssl rand -hex 32)" \
  -e OPENAI_API_KEY=sk-... cloakwall
```

Run it on Linux in production. The audit log fsyncs every entry; that costs
about 0.3 ms on Linux and about 100 ms on Windows (see Benchmarks).

## What it detects

**Personal and health data:** email addresses, credit cards (Luhn-validated),
SSNs, IBANs, medical record numbers, NHS numbers (modulus-11 validated),
phone numbers including international formats, IPv4 addresses and dates of
birth.

**Secrets:** API keys from OpenAI, Anthropic, Stripe, Google / Gemini,
GitHub, Slack, Groq and Hugging Face, AWS access keys, JWTs and bearer
tokens, PEM private keys (the whole block, even when it arrives in pieces
over a stream), and the credentials in connection strings
(`postgres://user:password@host` becomes `postgres://<PASSWORD>@host`).
The whole key is always replaced: real keys contain `-` and `_`, and a
redactor that stops at the first one leaves the tail of the key in the prompt.

The validators matter more than the patterns. Without a Luhn check every
16-digit order number gets flagged; without the NHS checksum every US phone
number gets labelled a health identifier. Both are the reason teams turn
regex redaction off after a week.

Missing a format you use? Open an issue with its *shape* (prefix and
length), never a real key.

## Where it looks

Every request field that can carry text, on every endpoint. The proxy and
the guardrail check the same fields:

| Request | Fields redacted |
|---------|-----------------|
| Chat completions | `messages[].content` (text parts), `tool_calls[].function.arguments` |
| Anthropic `/v1/messages` | top-level `system`, text blocks, `tool_use.input` (every string inside), `tool_result.content` |
| Responses API | `input` (string or items), `function_call.arguments`, `function_call_output.output` |
| Completions, image generation | `prompt` |
| Embeddings | `input` strings (token-id lists pass through) |

Image, audio and file parts pass through untouched. Ids, roles, model names
and function names are never rewritten.

With `redact_output: true` (`--redact-output` on the proxy), responses are redacted too: chat content and
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
path opens a socket, so it runs unchanged in an isolated cluster. The proxy
connects to exactly one place, the upstream you give it. Point that (or
LiteLLM) at a local vLLM or Ollama endpoint and no data leaves your network
at all.

Verify it yourself:

```bash
strace -f -e trace=connect python3 tests/test_cloakwall.py
```

## Benchmarks

Measured, reproducible numbers are in [BENCHMARKS.md](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/blob/main/BENCHMARKS.md):
`python3 benchmarks/bench.py`. On a 2015 Core i3 under Linux, a clean
request costs about 0.06 ms and a request with PII, including its fsynced audit
entry, about 1.8 ms.

## Tests

```bash
python3 tests/test_cloakwall.py     # 101 tests, no pytest required
python3 tests/test_proxy.py         # 42 proxy tests, fake upstream included
python3 tests/test_scan.py          # 22 scanner tests
```

## Limitations

Regex detection does not catch contextual PII — a person's name in free text,
or a medical condition described in prose. If you need that, Presidio's NLP
models are better and Cloakwall is not a replacement for them. What Cloakwall
gives up in recall it gains in having no dependencies, no sidecar and no
model to ship into an air-gapped environment.

Redaction is one-way in the guardrail and in the proxy's default and
`--redact-output` modes. Only `--restore` puts values back, and only into the
reply to the request they came from, from a map held in memory for that
request alone.

Cloakwall runs inside your process. If the process around it is compromised
(a hijacked dependency, say), no in-process control can protect the data.
Pin and verify what you deploy.

Status: working, tested, not yet run in production anywhere.

## Security

Found a vulnerability, or a way PII gets past the redactor? Please report it
privately; see [SECURITY.md](https://github.com/Rishikesh-glitch/Cloakwall-v0.1/blob/main/SECURITY.md).

## Licence

AGPL-3.0. Commercial licences for closed-source use are available.
