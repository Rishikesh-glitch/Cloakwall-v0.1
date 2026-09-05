"""
cloakwall.audit — tamper-evident local audit trail, plus SIEM export.

What a compliance officer asks for after an incident is not "were you
redacting" but "prove what happened on 14 March and prove the record has not
been edited since". A plain log file cannot answer the second half.

Every entry commits to the SHA-256 of the entry before it, so rewriting any
line breaks the chain from that point on and `verify()` names the line.

A bare hash chain does not survive truncation, though: a prefix of a valid
chain is itself a valid chain, so dropping the last N entries verifies
clean. Two things close that gap.

  1. Each entry carries a monotonic sequence number, so gaps in the middle
     are caught even when the hashes are recomputed.

  2. The head (sequence number plus hash) is mirrored to a separate anchor
     file after every append, and optionally pushed to your SIEM. Verifying
     against the anchor detects truncation, because the anchor still knows
     how many entries there should be.

The anchor is only as good as its separation from the log. On the same
filesystem it stops accidental truncation and a careless attacker; pushed to
a SIEM under different access control, it stops a determined one. That trust
boundary is the operator's to choose, so both are supported and neither is
claimed to be the other.

The log never stores the values that were redacted. It stores what kind of
entity was found and how many -- enough to prove the control was working,
without becoming a second copy of the data you were protecting.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str = "./cloakwall-audit.log"):
        self.path = path
        self._lock = threading.Lock()   # hooks run concurrently under uvicorn
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    @property
    def anchor_path(self) -> str:
        return self.path + ".head"

    def _last(self) -> tuple[int, str]:
        """Sequence number and hash of the final entry."""
        if not os.path.exists(self.path):
            return 0, GENESIS
        # Read the tail rather than the whole file: this log grows fast and
        # loading it on every request would be O(n) per request.
        with open(self.path, "rb") as fh:
            try:
                fh.seek(-4096, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", "replace").splitlines()
        for line in reversed(tail):
            if line.strip():
                try:
                    e = json.loads(line)
                    return int(e.get("seq", 0)), e["hash"]
                except Exception:
                    continue
        return 0, GENESIS

    def _write_anchor(self, seq: int, head: str) -> None:
        """Written atomically: a torn anchor would be worse than none."""
        tmp = self.anchor_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"seq": seq, "hash": head,
                       "ts": datetime.now(timezone.utc).isoformat()}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.anchor_path)

    def read_anchor(self) -> dict | None:
        try:
            with open(self.anchor_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def append(self, event: str, **fields) -> dict:
        with self._lock:
            prev_seq, prev = self._last()
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "seq": prev_seq + 1,
                "event": event,
                "host": socket.gethostname(),
                "prev": prev,
                **fields,
            }
            body = json.dumps(entry, sort_keys=True)
            entry["hash"] = hashlib.sha256((prev + body).encode()).hexdigest()
            with open(self.path, "a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())   # survive a pod kill mid-write
            self._write_anchor(entry["seq"], entry["hash"])
            return entry

    def verify(self, anchor: dict | None = None) -> tuple[bool, str]:
        """Verify the chain, and if an anchor is available, verify the log has
        not been truncated. Pass an anchor retrieved from your SIEM to check
        against a copy the log's own filesystem cannot reach."""
        if not os.path.exists(self.path):
            return True, "no audit log yet"

        prev = GENESIS
        expected_seq = 0
        last_hash = GENESIS
        with open(self.path) as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                e = json.loads(line)
                claimed = e.pop("hash", None)
                if e.get("prev") != prev:
                    return False, f"line {n}: chain break"
                expected_seq += 1
                if int(e.get("seq", -1)) != expected_seq:
                    return False, (f"line {n}: sequence gap "
                                   f"(expected {expected_seq}, found {e.get('seq')})")
                recomputed = hashlib.sha256(
                    (prev + json.dumps(e, sort_keys=True)).encode()).hexdigest()
                if recomputed != claimed:
                    return False, f"line {n}: entry altered after writing"
                prev = last_hash = claimed

        a = anchor if anchor is not None else self.read_anchor()
        if a:
            if expected_seq < int(a.get("seq", 0)):
                return False, (f"truncated: anchor records {a['seq']} entries, "
                               f"log holds {expected_seq}")
            if expected_seq == int(a.get("seq", 0)) and last_hash != a.get("hash"):
                return False, "head does not match anchor"
            return True, f"chain intact, {expected_seq} entries, anchor matches"
        return True, f"chain intact, {expected_seq} entries (no anchor to check truncation)"


# ------------------------------------------------------------------ #
# SIEM export                                                         #
#                                                                     #
# Fire-and-forget on a worker thread. An audit sink that is slow or   #
# down must never add latency to, or fail, an LLM request -- the log  #
# on disk is the system of record and the SIEM is a copy.             #
# ------------------------------------------------------------------ #

class SIEMExporter:
    def __init__(self, kind: str | None = None, url: str = "", token: str = "",
                 timeout: float = 3.0, verify_tls: bool = True):
        self.kind = (kind or "").lower()
        self.url = url
        self.token = token
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.failures = 0

    @classmethod
    def from_env(cls) -> "SIEMExporter":
        return cls(
            kind=os.environ.get("CLOAKWALL_SIEM", ""),
            url=os.environ.get("CLOAKWALL_SIEM_URL", ""),
            token=os.environ.get("CLOAKWALL_SIEM_TOKEN", ""),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.kind and self.url and self.token)

    def _payload(self, entry: dict) -> tuple[bytes, dict]:
        if self.kind == "splunk":
            body = {
                "time": time.time(),
                "host": entry.get("host"),
                "source": "cloakwall",
                "sourcetype": "_json",
                "event": entry,
            }
            return json.dumps(body).encode(), {
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            }
        if self.kind == "datadog":
            body = [{
                "ddsource": "cloakwall",
                "service": "cloakwall",
                "hostname": entry.get("host"),
                "message": json.dumps(entry),
            }]
            return json.dumps(body).encode(), {
                "DD-API-KEY": self.token,
                "Content-Type": "application/json",
            }
        # elasticsearch and anything else that accepts a bare JSON document
        return json.dumps(entry).encode(), {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _post(self, entry: dict) -> None:
        try:
            data, headers = self._payload(entry)
            req = urllib.request.Request(self.url, data=data, headers=headers)
            ctx = None
            if not self.verify_tls:
                import ssl
                ctx = ssl._create_unverified_context()   # self-signed on-prem SIEM
            urllib.request.urlopen(req, timeout=self.timeout, context=ctx).read()
        except (urllib.error.URLError, OSError, ValueError):
            self.failures += 1     # counted and surfaced in /healthz, never raised

    def send(self, entry: dict) -> None:
        if not self.enabled:
            return
        threading.Thread(target=self._post, args=(entry,), daemon=True).start()
