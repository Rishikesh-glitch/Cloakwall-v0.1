"""
cloakwall command line.

    cloakwall serve --upstream https://api.openai.com/v1 --upstream-key-env OPENAI_API_KEY
    cloakwall verify ./cloakwall-audit.log

The upstream API key is read from an environment variable you name, never
from the command line: arguments end up in shell history and process lists.
"""

from __future__ import annotations

import argparse
import os
import sys

from .redact import DEFAULT_ENTITIES


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("cloakwall")
    except Exception:
        return "dev"


def _serve(args: argparse.Namespace) -> int:
    from .proxy import CloakwallProxy

    key = None
    if args.upstream_key_env:
        key = os.environ.get(args.upstream_key_env)
        if not key:
            print(f"error: environment variable {args.upstream_key_env} is not set", file=sys.stderr)
            return 2
    try:
        proxy = CloakwallProxy(
            upstream=args.upstream, host=args.host, port=args.port,
            redaction_mode=args.mode, entities=args.entities, audit_path=args.audit_path,
            block_on=args.block_on, redact_output=args.redact_output, restore=args.restore,
            upstream_key=key, stream_holdback=args.stream_holdback,
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = ("restore (real values put back in replies)" if args.restore
              else "redact (PII masked in replies too)" if args.redact_output
              else "unchanged")
    print(f"cloakwall {_version()} proxy", flush=True)
    print(f"  point your client at  {proxy.url}", flush=True)
    print(f"  forwarding to         {args.upstream}", flush=True)
    print(f"  replies               {output}", flush=True)
    print(f"  audit log             {os.path.abspath(args.audit_path)}", flush=True)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"  WARNING: listening on {args.host}: anyone who can reach this address "
              "can send requests through it with your upstream key.", file=sys.stderr)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        proxy.httpd.server_close()
    return 0


def _scan(args: argparse.Namespace) -> int:
    import json
    from .redact import Redactor
    from .scan import format_report, scan

    redactor = Redactor(entities=set(args.entities) if args.entities else None)
    report = scan(args.paths, redactor=redactor, max_bytes=int(args.max_mb * 1024 * 1024),
                  stdin=sys.stdin)
    if args.json:
        print(json.dumps(report.to_dict(details=args.details), indent=2))
    else:
        print(format_report(report, details=args.details))
    if report.files_scanned == 0 and report.skipped:
        return 2
    return 1 if report.findings else 0


def _verify(args: argparse.Namespace) -> int:
    from .audit import AuditLog
    ok, msg = AuditLog(args.path).verify()
    print(("OK    " if ok else "FAIL  ") + msg)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cloakwall",
                                 description="PII redaction and tamper-evident audit logging for LLM traffic.")
    ap.add_argument("--version", action="version", version=f"cloakwall {_version()}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="run an OpenAI-compatible redaction proxy")
    s.add_argument("--upstream", required=True,
                   help="base URL of the real API, including /v1 (e.g. https://api.openai.com/v1)")
    s.add_argument("--upstream-key-env", metavar="VAR",
                   help="environment variable holding the upstream API key; "
                        "if omitted, the caller's Authorization header is passed through")
    s.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    s.add_argument("--port", type=int, default=8787, help="port to listen on (default 8787)")
    s.add_argument("--mode", choices=["mask", "hash", "partial"], default="mask",
                   help="how redacted values appear (ignored with --restore)")
    out = s.add_mutually_exclusive_group()
    out.add_argument("--redact-output", action="store_true",
                     help="also mask PII in model replies, streamed or not")
    out.add_argument("--restore", action="store_true",
                     help="put the original values back into replies; the model never sees them")
    s.add_argument("--entities", nargs="+", choices=sorted(DEFAULT_ENTITIES), metavar="ENTITY",
                   help=f"only redact these (default: all of {', '.join(sorted(DEFAULT_ENTITIES))})")
    s.add_argument("--block-on", nargs="+", choices=sorted(DEFAULT_ENTITIES), metavar="ENTITY",
                   help="reject requests containing these entities instead of redacting")
    s.add_argument("--audit-path", default="./cloakwall-audit.log", help="audit log file")
    s.add_argument("--stream-holdback", type=int, default=64,
                   help="characters held back while streaming with --redact-output")
    s.set_defaults(func=_serve)

    sc = sub.add_parser("scan", help="report the sensitive data in files, without showing it",
                        description="Scan files or folders on this machine for emails, card "
                                    "numbers, API keys and other sensitive values. Values are "
                                    "never shown and nothing is sent anywhere. Exit status: "
                                    "0 nothing found, 1 found, 2 error.")
    sc.add_argument("paths", nargs="+", help="files or folders to scan; - reads standard input")
    sc.add_argument("--details", action="store_true",
                    help="list each finding's file and line (never the value)")
    sc.add_argument("--json", action="store_true", help="print the report as JSON")
    sc.add_argument("--entities", nargs="+", choices=sorted(DEFAULT_ENTITIES), metavar="ENTITY",
                    help="only look for these")
    sc.add_argument("--max-mb", type=float, default=10.0,
                    help="skip files larger than this many MB (default 10)")
    sc.set_defaults(func=_scan)

    v = sub.add_parser("verify", help="check an audit log's hash chain and anchor")
    v.add_argument("path", help="audit log file")
    v.set_defaults(func=_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
