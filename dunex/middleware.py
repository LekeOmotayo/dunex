"""
ASGI / FastAPI Middleware for transparent, zero-touch LLM guardrails enforcement.
Intercepts inbound prompts, checks boundaries, sanitizes payloads, and records audit trails.
"""

from __future__ import annotations

import json
from typing import Callable, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from dunex.pipeline import GuardrailPipeline
from dunex.models import GuardrailVerdict


class GuardrailsMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that intercepts and inspects requests.
    Sanitizes inbound PII, blocks prompt injections, and attaches guardrail audit headers.
    """

    def __init__(
        self,
        app: Callable,
        pipeline: Optional[GuardrailPipeline] = None,
        protected_paths: Optional[list[str]] = None,
    ) -> None:
        super().__init__(app)
        self.pipeline = pipeline or GuardrailPipeline()
        self.protected_paths = protected_paths or ["/v1/chat/completions", "/v1/completions", "/api/chat"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if the requested path is in the protected routes list
        path = request.url.path
        is_protected = any(path.startswith(p) for p in self.protected_paths)

        if not is_protected or request.method != "POST":
            return await call_next(request)

        agent_id = request.headers.get("X-Agent-ID", "default-agent")
        tenant_id = request.headers.get("X-Tenant-ID", "default-tenant")

        # Read and inspect body
        try:
            body_bytes = await request.body()
            if not body_bytes:
                return await call_next(request)

            body_json = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            # Fall back to un-intercepted request if not valid JSON
            return await call_next(request)

        # Extract text prompt from OpenAI-compatible schemas or generic prompt
        extracted_text = ""
        if "messages" in body_json and isinstance(body_json["messages"], list):
            # Concatenate user messages
            user_texts = [
                m.get("content", "")
                for m in body_json["messages"]
                if isinstance(m, dict) and m.get("role") == "user"
            ]
            extracted_text = "\n".join(user_texts)
        elif "prompt" in body_json and isinstance(body_json["prompt"], str):
            extracted_text = body_json["prompt"]
        elif "text" in body_json and isinstance(body_json["text"], str):
            extracted_text = body_json["text"]

        if not extracted_text:
            return await call_next(request)

        # Inspect through guardrails pipeline
        result = self.pipeline.inspect(
            text=extracted_text,
            agent_id=agent_id,
            tenant_id=tenant_id,
            direction="input",
        )

        # Handle Blocked requests
        if result.verdict == GuardrailVerdict.BLOCKED:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Request blocked by Dunex Guardrails",
                        "type": "guardrail_violation",
                        "violations": result.violations,
                        "risk_score": result.risk_score,
                        "request_id": result.request_id,
                    }
                },
                headers={
                    "X-Guardrails-Verdict": result.verdict.value,
                    "X-Guardrails-Risk-Score": str(result.risk_score),
                    "X-Guardrails-Request-ID": result.request_id,
                    "X-Guardrails-Execution-Time-MS": str(result.execution_time_ms),
                },
            )

        # If text was sanitized (e.g. PII masked), rewrite the body for downstream handlers
        if result.verdict == GuardrailVerdict.MASKED and result.sanitized_text != extracted_text:
            if "messages" in body_json and isinstance(body_json["messages"], list):
                # Update user messages with sanitized text
                for m in body_json["messages"]:
                    if isinstance(m, dict) and m.get("role") == "user":
                        m["content"] = result.sanitized_text
            elif "prompt" in body_json:
                body_json["prompt"] = result.sanitized_text
            elif "text" in body_json:
                body_json["text"] = result.sanitized_text

            # Update request._body
            new_bytes = json.dumps(body_json).encode("utf-8")
            request._body = new_bytes

        # Proceed to downstream route handler
        response = await call_next(request)

        # Inject telemetry headers
        response.headers["X-Guardrails-Verdict"] = result.verdict.value
        response.headers["X-Guardrails-Risk-Score"] = str(result.risk_score)
        response.headers["X-Guardrails-Request-ID"] = result.request_id
        response.headers["X-Guardrails-Execution-Time-MS"] = str(result.execution_time_ms)

        return response
