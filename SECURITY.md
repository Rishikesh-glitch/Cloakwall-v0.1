# Security policy

Cloakwall exists to keep sensitive data away from LLMs, so a bug that lets
PII through is treated as a security issue, not just a detection bug.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository
(https://github.com/Rishikesh-glitch/Cloakwall-v0.1/security/advisories/new).

Please include:

- what is affected: redaction, the audit chain, the LiteLLM adapter, packaging;
- steps to reproduce, using **made-up values only**. Describe the *shape* of an
  identifier ("a 10-digit number grouped 3-3-4"), never a real one;
- the Cloakwall and LiteLLM versions.

## What to expect

- An acknowledgement within 3 working days.
- An assessment and a fix plan within 14 days for confirmed issues.
- Credit in the release notes if you'd like it, once a fix is released.

## In scope

- PII or PHI that passes through a redaction path Cloakwall claims to cover
  (see "Where it looks" in the README).
- Ways to alter, delete or truncate audit-log entries without `verify()`
  detecting it.
- Redacted values appearing in the audit log, the SIEM export or error messages.
- Anything that makes Cloakwall open a network connection other than the
  optional SIEM export.

Known limitation, not a vulnerability: regex detection does not catch
contextual PII such as names in free text (README, Limitations).

## Supported versions

Only the latest release on PyPI receives fixes.
