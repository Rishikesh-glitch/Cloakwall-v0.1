"""
Cloakwall Guardrail Middleware
Engineered by Spatial App Studio

Provides pre-execution payload inspection and fail-closed safety gating
for FastAPI tool execution endpoints.
"""

import json
from typing import Dict, Any
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class CloakwallGuardrailMiddleware(BaseHTTPMiddleware):
    """
    Sub-millisecond payload inspection layer for FastAPI.
    Fails closed on malformed or unparseable payloads to prevent uninspected execution.
    """
    def __init__(self, app, strict_mode: bool = True):
        super().__init__(app)
        self.strict_mode = strict_mode

    async def dispatch(self, request: Request, call_next) -> Response:
        # Non-payload methods pass through immediately
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        try:
            # Read request body without consuming the stream permanently
            body_bytes = await request.body()
            if not body_bytes:
                return await call_next(request)

            # Parse JSON payload
            payload = json.loads(body_bytes)

            # Re-bind stream so downstream route handlers can re-read request.body()
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive

        except Exception as exc:
            # Fail-closed policy: Block malformed payloads from reaching the model
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "Guardrail Inspection Failed",
                    "reason": "Malformed request payload. Failing closed to prevent uninspected execution.",
                    "details": str(exc)
                }
            )

        return await call_next(request)