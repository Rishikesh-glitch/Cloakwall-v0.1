"""
cloakwall.audit — tamper-evident local audit trail, plus SIEM export.

What a compliance officer asks for after an incident is not "were you
redacting" but "prove what happened on 14 March and prove the record has not
been edited since". A plain log file cannot answer the second half.

Every entry commits to the SHA-256 of the entry before it, so removing or
rewriting any line breaks the chain from that point on and `verify()` names
the line. This is the same construction as the Z-Egress control plane, which
is why the code is short: it was already right.

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

    def _last_hash(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS
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
                    return json.loads(line)["hash"]
                except Exception:
                    continue
        return GENESIS

    def append(self, event: str, **fields) -> dict:
        with self._lock:
            prev = self._last_hash()
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
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
            return entry

    def verify(self) -> tuple[bool, str]:
        if not os.path.exists(self.path):
            return True, "no audit log yet"
        prev = GENESIS
        with open(self.path) as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                e = json.loads(line)
                claimed = e.pop("hash", None)
                if e.get("prev") != prev:
                    return False, f"line {n}: chain break"
                recomputed = hashlib.sha256(
                    (prev + json.dumps(e, sort_keys=True)).encode()).hexdigest()
                if recomputed != claimed:
                    return False, f"line {n}: entry altered after writing"
                prev = claimed
        return True, "chain intact"


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
