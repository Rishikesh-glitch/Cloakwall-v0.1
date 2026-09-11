"""
Cloakwall Guardrail Middleware
Engineered by Spatial App Studio

Provides pre-execution payload inspection, argument drift detection, 
and execution audit receipts for FastAPI tool execution endpoints.
"""

import json
import time
import hashlib
from typing import Dict, Any, Optional
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class CloakwallGuardrailMiddleware(BaseHTTPMiddleware):
    """
    Sub-millisecond pre-execution inspection layer for FastAPI.
    Gates state-modifying tool calls if argument drift is detected between 
    preview and final execution, and injects execution audit receipts.
    """
    def __init__(self, app, strict_mode: bool = True):
        super().__init__(app)
        self.strict_mode = strict_mode

    async def dispatch(self, request: Request, call_next) -> Response:
        # Non-payload methods pass through immediately
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        start_time = time.perf_counter()

        try:
            # Read request body without consuming the stream permanently
            body_bytes = await request.body()
            if not body_bytes:
                return await call_next(request)

            payload = json.loads(body_bytes)

            # Re-bind stream so downstream route handlers can re-read request.body()
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive

        except Exception:
            # Pass through invalid or non-JSON payloads
            return await call_next(request)

        # 1. Argument Drift Check for Write Actions (alexuvlab logic)
        drift_detected, tool_name = self._detect_argument_drift(payload)
        if drift_detected:
            receipt = self._build_receipt(payload, action_status="BLOCKED", reason="Argument drift detected")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": "Cloakwall Security Gate Triggered",
                    "reason": f"Argument mismatch between preview and execution in write tool: '{tool_name}'",
                    "audit_receipt": receipt
                }
            )

        # 2. Proceed with request execution
        response = await call_next(request)

        # 3. Inject DRNT-style Audit Receipt Headers
        latency_ms = (time.perf_counter() - start_time) * 1000
        receipt_hash = hashlib.sha256(body_bytes).hexdigest()[:16]

        response.headers["X-Cloakwall-Latency-MS"] = f"{latency_ms:.3f}"
        response.headers["X-Cloakwall-Receipt-ID"] = f"receipt_v1_{receipt_hash}"

        return response

    def _detect_argument_drift(self, payload: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Inspects payload for tool calls. Read-only passes; Write-actions with modified
        arguments after preview are flagged.
        """
        tools = payload.get("tools", []) or payload.get("tool_calls", [])
        
        for tool in tools:
            # Check if payload contains action metadata
            action_type = tool.get("type", "").lower() or tool.get("action", "").lower()
            
            # Target state-modifying actions (Write, Mutate, Exec)
            if action_type in ("write", "mutate", "execute", "state_change"):
                preview_args = tool.get("preview_arguments")
                final_args = tool.get("arguments") or tool.get("final_arguments")

                # Drift condition: Both exist but payloads do not match
                if preview_args is not None and final_args is not None:
                    if preview_args != final_args:
                        return True, tool.get("name", "unknown_tool")

        return False, None

    def _build_receipt(self, payload: Dict[str, Any], action_status: str, reason: str) -> Dict[str, Any]:
        """Generates deterministic tamper-evident execution receipt."""
        raw_encoded = json.dumps(payload, sort_keys=True).encode()
        return {
            "timestamp": time.time(),
            "status": action_status,
            "gate_reason": reason,
            "payload_sha256": hashlib.sha256(raw_encoded).hexdigest(),
            "protocol_version": "DRNT-v2-Lightweight"
        }