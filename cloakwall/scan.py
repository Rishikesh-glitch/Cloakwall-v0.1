"""
cloakwall.scan — find the sensitive data in files before an AI tool does.

    cloakwall scan ./project
    cloakwall scan chat-logs.jsonl --details
    cat prompts.txt | cloakwall scan -

Reads files on this machine and reports how many emails, card numbers, API
keys, medical record numbers and so on they contain, and where. It never
prints a value, never writes anything, and opens no network connection: the
report says what kind of thing was found and how many, the same rule the
audit log follows.

The point is to answer one question quickly: if an AI agent or chat app read
these files, what would it have sent to the model provider?

Exit status: 0 if nothing was found, 1 if something was, 2 on error. So it
can also run in CI, like a secret scanner.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional, TextIO

from .redact import Redactor

# Directories that are tooling, not content. Dot-files such as .env are still
# scanned: they are exactly where secrets live.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".idea", ".vscode", "site-packages",
})

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


@dataclass
class Finding:
    path: str
    line: int
    entity: str


@dataclass
class Report:
    files_scanned: int = 0
    lines_scanned: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (path, reason)
    findings: list[Finding] = field(default_factory=list)

    @property
    def totals(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.entity] = out.get(f.entity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    def by_file(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for f in self.findings:
            counts = out.setdefault(f.path, {})
            counts[f.entity] = counts.get(f.entity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])))

    def to_dict(self, details: bool = False) -> dict:
        d = {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "files_skipped": len(self.skipped),
            "total_found": len(self.findings),
            "by_entity": self.totals,
            "by_file": self.by_file(),
        }
        if details:
            d["findings"] = [{"path": f.path, "line": f.line, "entity": f.entity}
                             for f in self.findings]
        return d


# ------------------------------------------------------------------ #
# Reading                                                             #
# ------------------------------------------------------------------ #

def _iter_files(paths: Iterable[str], report: Report) -> Iterator[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    yield os.path.normpath(os.path.join(root, name))
        elif os.path.isfile(p):
            yield os.path.normpath(p)
        else:
            report.skipped.append((p, "not found"))


def _strings(value) -> Iterator[str]:
    """Every string inside parsed JSON, keys included: a key can be a value
    too ({"bob@clinic.org": {...}})."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)


def _texts_in_line(line: str, json_lines: bool) -> Iterator[str]:
    # JSON is parsed so escaped characters (\\u0040 for @) are seen decoded.
    if json_lines:
        try:
            yield from _strings(json.loads(line))
            return
        except ValueError:
            pass
    yield line


def scan_stream(name: str, stream: TextIO, redactor: Redactor, report: Report) -> None:
    json_lines = name.endswith((".jsonl", ".ndjson"))
    for n, line in enumerate(stream, 1):
        report.lines_scanned += 1
        for text in _texts_in_line(line.rstrip("\n"), json_lines):
            for r in redactor.redact(text).redactions:
                report.findings.append(Finding(name, n, r.entity))


def _scan_json_file(path: str, redactor: Redactor, report: Report) -> bool:
    """A whole-file .json document. Findings are reported at line 0 (the
    file) because parsing loses line numbers. False if it isn't valid JSON."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (ValueError, UnicodeDecodeError):
        return False
    with open(path, encoding="utf-8") as fh:
        report.lines_scanned += sum(1 for _ in fh)
    for text in _strings(data):
        for r in redactor.redact(text).redactions:
            report.findings.append(Finding(path, 0, r.entity))
    return True


def _looks_binary(path: str) -> bool:
    with open(path, "rb") as fh:
        return b"\x00" in fh.read(8192)


def scan(paths: Iterable[str], redactor: Optional[Redactor] = None,
         max_bytes: int = DEFAULT_MAX_BYTES, stdin: Optional[TextIO] = None) -> Report:
    redactor = redactor or Redactor()
    report = Report()
    paths = list(paths)
    if "-" in paths:
        paths.remove("-")
        if stdin is not None:
            report.files_scanned += 1
            scan_stream("<stdin>", stdin, redactor, report)
    for path in _iter_files(paths, report):
        try:
            if os.path.getsize(path) > max_bytes:
                report.skipped.append((path, "larger than the size limit"))
                continue
            if _looks_binary(path):
                report.skipped.append((path, "binary"))
                continue
            report.files_scanned += 1
            if path.endswith(".json") and _scan_json_file(path, redactor, report):
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                scan_stream(path, fh, redactor, report)
        except OSError as exc:
            report.skipped.append((path, exc.__class__.__name__))
    return report


# ------------------------------------------------------------------ #
# Reporting                                                           #
# ------------------------------------------------------------------ #

def format_report(report: Report, details: bool = False, top: int = 15) -> str:
    nf = report.files_scanned
    out = [f"Cloakwall scan: {nf} file{'s' if nf != 1 else ''}, {report.lines_scanned:,} lines"
           + (f" ({len(report.skipped)} skipped)" if report.skipped else ""),
           "Scanned on this machine only. Nothing was sent anywhere, and values are never shown.",
           ""]
    if not report.findings:
        out.append("No sensitive values found.")
        return "\n".join(out)

    files = report.by_file()
    out.append(f"Found {len(report.findings):,} sensitive values in {len(files)} "
               f"file{'s' if len(files) != 1 else ''}:")
    width = max(len(e) for e in report.totals)
    for entity, n in report.totals.items():
        out.append(f"  {entity:<{width}}  {n:>7,}")
    out.append("")
    out.append("Files with the most:")
    shown = list(files.items())[:top]
    pw = max(len(p) for p, _ in shown)
    for path, counts in shown:
        parts = ", ".join(f"{e} {n}" for e, n in sorted(counts.items(), key=lambda kv: -kv[1]))
        out.append(f"  {path:<{pw}}  {sum(counts.values()):>6,}  ({parts})")
    if len(files) > top:
        out.append(f"  ... and {len(files) - top} more files")
    if details:
        out.append("")
        out.append("Locations (line 0 = somewhere in a .json file):")
        for f in report.findings:
            out.append(f"  {f.path}:{f.line}  {f.entity}")
    out.append("")
    out.append("If an AI tool reads these files or logs, these values go to the model provider.")
    out.append("`cloakwall serve` replaces them before they leave this machine.")
    return "\n".join(out)
