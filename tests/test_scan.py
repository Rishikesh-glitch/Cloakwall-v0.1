#!/usr/bin/env python3
"""
cloakwall scan tests.  python3 tests/test_scan.py

Standard library only. Builds a small project on disk with secrets in the
places they really end up, and checks what the scanner reports, and that it
never reports a value.
"""

import contextlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.cli import main as cli_main
from cloakwall.redact import Redactor
from cloakwall.scan import format_report, scan

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


def write(path, text, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as fh:
        fh.write(text)


def run_cli(argv, stdin_text=None):
    out = io.StringIO()
    old_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out):
            code = cli_main(argv)
    finally:
        sys.stdin = old_stdin
    return code, out.getvalue()


SECRETS = ("sk-proj-AbCdEfGhIjKlMnOpQrStUv", "AKIAABCDEFGHIJKLMNOP", "4111 1111 1111 1111",
           "bob@clinic.org", "a@b.com", "A1234567", "123-45-6789")

root = tempfile.mkdtemp()
write(os.path.join(root, ".env"),
      "OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUv\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nDEBUG=true\n")
write(os.path.join(root, "logs", "chat.jsonl"),
      '{"role":"user","content":"card 4111 1111 1111 1111, email bob@clinic.org"}\n'
      '{"role":"user","content":"reach me at a\\u0040b.com"}\n'
      'not json at all, ssn 123-45-6789\n')
write(os.path.join(root, "src", "notes.txt"), "order 1234567890123456 shipped\npatient MRN: A1234567\n")
write(os.path.join(root, "data", "export.json"),
      json.dumps({"patients": [{"bob@clinic.org": {"card": "4111111111111111"}}]}))
write(os.path.join(root, ".git", "config"), "token sk-live-AAAAAAAAAAAAAAAAAAAA\n")
write(os.path.join(root, "node_modules", "pkg", "x.txt"), "x@y.com\n")
write(os.path.join(root, "image.bin"), b"\x00\x01 bob@x.com", mode="wb")
write(os.path.join(root, "big.log"), "a@b.com\n" * 200)

# ---------------------------------------------------------------- findings
section("What the scanner finds")
rep = scan([root], max_bytes=1000)
t = rep.totals
check("letters-only API key in .env", t.get("API_KEY"), 1)
check("letters-only AWS key in .env", t.get("AWS_KEY"), 1)
check("emails: jsonl, escaped \\u0040, json key", t.get("EMAIL"), 3)
check("cards: jsonl and json value", t.get("CARD"), 2)
check("SSN in a non-JSON line of a .jsonl file", t.get("SSN"), 1)
check("MRN in a text file", t.get("MRN"), 1)
check("order number failing Luhn is not a card", t.get("CARD"), 2)
paths = {os.path.relpath(f.path, root) for f in rep.findings}
check(".git and node_modules skipped", any(p.startswith((".git", "node_modules")) for p in paths), False)
skipped = {os.path.basename(p): why for p, why in rep.skipped}
check("binary file skipped", skipped.get("image.bin"), "binary")
check("oversized file skipped", skipped.get("big.log"), "larger than the size limit")
env = [f for f in rep.findings if f.path.endswith(".env")]
check("line numbers reported", sorted(f.line for f in env), [1, 2])

section("It never shows a value")
text = format_report(rep, details=True)
check("text report has no values", [s for s in SECRETS if s in text], [])
blob = json.dumps(rep.to_dict(details=True))
check("JSON report has no values", [s for s in SECRETS if s in blob], [])
check("report says nothing was sent", "Nothing was sent anywhere" in text, True)

section("Filters and input")
rep = scan([root], redactor=Redactor(entities={"EMAIL"}), max_bytes=1000)
check("--entities limits detection", set(rep.totals), {"EMAIL"})
rep = scan(["-"], stdin=io.StringIO("call +94 77 123 4567\n"))
check("reads standard input", rep.totals, {"PHONE": 1})
rep = scan([os.path.join(root, "nope")])
check("missing path reported as skipped", rep.skipped[0][1], "not found")

section("Command line")
code, out = run_cli(["scan", root, "--max-mb", "0.001"])
check("exit 1 when something is found", code, 1)
check("summary printed", "sensitive values in" in out, True)
code, out = run_cli(["scan", "-"], stdin_text="nothing to see here\n")
check("exit 0 when clean", (code, "No sensitive values found." in out), (0, True))
code, out = run_cli(["scan", root, "--json", "--max-mb", "0.001"])
check("--json is valid JSON", json.loads(out)["total_found"] > 0, True)
code, _ = run_cli(["scan", os.path.join(root, "does-not-exist")])
check("exit 2 when nothing could be scanned", code, 2)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
