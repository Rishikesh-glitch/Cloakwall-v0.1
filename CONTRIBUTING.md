# Contributing

Thanks for looking at this.

## Running the tests

    python3 tests/test_cloakwall.py

No pytest required — it's stdlib only, so it runs anywhere.

## What I'd like in a PR

- A test alongside the change. The suite is plain asserts; follow the
  existing style.
- If you're adding a detector, include a validator where the format has a
  check digit. Regex alone produces false positives that make people turn
  redaction off.
- Keep the core dependency-free. The whole point is that it runs in an
  air-gapped cluster with nothing to install.

## Reporting detection bugs

Post the *shape* of the identifier, never a real value.
